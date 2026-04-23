# Go OIDC — `github.com/coreos/go-oidc/v3`

Browser-based OpenID Connect sign-in using the standard [go-oidc](https://github.com/coreos/go-oidc) library and `golang.org/x/oauth2`, without the AuthGate SDK. This is useful when you want to integrate AuthGate (or any OIDC provider) into an existing Go web app that already uses the upstream OAuth2 toolchain.

## OAuth Flow

**Authorization Code** with:

- **State** cookie — CSRF protection on the redirect back to `/callback`.
- **Nonce** — CSRF / replay protection tied to the ID token. Generated on `/login`, verified against `id_token.nonce` on callback.
- **PKCE (S256)** — required by most modern providers (AuthGate rejects public clients without it: `invalid_request: pkce required for public clients`). Verifier generated on `/login`, challenge sent via `oauth2.S256ChallengeOption`, verifier sent back on code exchange via `oauth2.VerifierOption`.
- **ID token verification** — signature checked against the provider's JWKS; `iss`, `aud`, `exp` validated automatically by `verifier.Verify`.
- **`at_hash`** — when present, access token is bound to the ID token via `idToken.VerifyAccessToken`.

## Prerequisites

- Go 1.25+
- An OIDC provider (e.g., AuthGate) with a confidential client that allows `http://localhost:8088/callback` as a redirect URI

## Environment Variables

| Variable        | Required | Description                                                                 |
| --------------- | -------- | --------------------------------------------------------------------------- |
| `ISSUER_URL`    | Yes      | OIDC issuer URL (discovery: `$ISSUER_URL/.well-known/openid-configuration`) |
| `CLIENT_ID`     | Yes      | OAuth 2.0 client identifier                                                 |
| `CLIENT_SECRET` | No       | OAuth 2.0 client secret. Omit for **public** clients (PKCE-only)            |
| `REDIRECT_URL`  | No       | Defaults to `http://localhost:8088/callback`                                |

## Usage

```bash
export ISSUER_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret
go run main.go
```

Or create a `.env` file in the `go-oidc/` directory:

```bash
ISSUER_URL=https://auth.example.com
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
REDIRECT_URL=http://localhost:8088/callback
```

Then open <http://localhost:8088/> in a browser and click **Sign in**.

## Routes

| Route       | Description                                                                                |
| ----------- | ------------------------------------------------------------------------------------------ |
| `/`         | Landing page with a sign-in link                                                           |
| `/login`    | Generates state + nonce, sets cookies, redirects to the provider's authorize endpoint      |
| `/callback` | Validates state, exchanges code, verifies ID token + nonce, fetches userinfo, renders JSON |

## How It Works

1. `oidc.NewProvider(ctx, issuerURL)` fetches the discovery document and extracts the authorize/token/userinfo/JWKS endpoints.
2. `provider.Verifier(&oidc.Config{ClientID: ...})` builds an `*oidc.IDTokenVerifier` that caches JWKS keys and validates `iss`, `aud`, `exp`, and signature.
3. `oauth2.Config` is wired to `provider.Endpoint()` so the upstream OAuth2 helpers do the heavy lifting of the code exchange.
4. On `/login`, fresh random state, nonce, and PKCE verifier are stored in short-lived HttpOnly cookies. The nonce is passed via `oidc.Nonce(nonce)` so the provider echoes it into the ID token, and the PKCE challenge is added via `oauth2.S256ChallengeOption(verifier)`.
5. On `/callback`, the handler:
   - Rejects the response if `state` does not match the cookie.
   - Exchanges the code via `oauth2Config.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))`.
   - Extracts the raw ID token from `oauth2Token.Extra("id_token")`.
   - Calls `verifier.Verify` to cryptographically validate it.
   - Rejects the response if `idToken.Nonce` does not match the cookie.
   - Calls `idToken.VerifyAccessToken` when an `at_hash` claim is present.
   - Queries the UserInfo endpoint via `provider.UserInfo` and returns both ID token claims and UserInfo claims as JSON.

## Example Response

`GET /callback` (successful flow) returns something like:

```json
{
  "subject": "user-uuid-1234",
  "issuer": "https://auth.example.com",
  "audience": ["your-client-id"],
  "expiry": "2026-04-23T14:23:45Z",
  "id_token_claims": {
    "sub": "user-uuid-1234",
    "email": "alice@example.com",
    "email_verified": true,
    "nonce": "..."
  },
  "access_token": "eyJhbGci...",
  "refresh_token": "abcdef12...",
  "token_type": "Bearer",
  "token_expiry": "2026-04-23T15:23:45Z",
  "userinfo": {
    "sub": "user-uuid-1234",
    "email": "alice@example.com",
    "name": "Alice"
  },
  "userinfo_fetch_ok": true
}
```

## Notes

- For production, store `id_token`, `access_token`, and `refresh_token` in a session (e.g., encrypted cookie, server-side store) rather than echoing them to the browser — this example prints them to make the flow transparent.
- The `Secure` cookie flag is set automatically when the server is reached over TLS (`r.TLS != nil`). Behind a reverse proxy that terminates TLS, configure the proxy to pass the correct scheme or set the flag explicitly.
- `go-oidc` handles JWKS key rotation transparently — you do not need to refresh the verifier manually.
