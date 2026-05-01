# Go Resource Server — Offline JWKS Validation

Protect HTTP endpoints by validating AuthGate-issued JWT access tokens **offline** using the provider's public keys (JWKS). No callback, introspection, or round-trip to AuthGate per request.

## Flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RS as Resource Server
    participant AG as AuthGate

    Note over RS,AG: Startup / on-demand (cached)
    RS->>AG: GET /.well-known/openid-configuration
    AG-->>RS: issuer, jwks_uri
    RS->>AG: GET {jwks_uri}
    AG-->>RS: JWKS (public keys)

    Note over C,RS: Every API request (no network to AuthGate)
    C->>RS: Authorization: Bearer <jwt>
    RS->>RS: verify signature (cached JWKS)<br/>check iss, aud, exp, nbf, scope
    RS-->>C: 200 OK / 401 / 403

    Note over RS,AG: Only on unknown kid (key rotation)
    RS->>AG: GET {jwks_uri} (refresh)
```

## Pros & Cons of Offline JWKS Validation

### Pros

- **Zero per-request round-trips.** Verification is local signature math — microseconds, not a network call. Introspection typically adds 10–50 ms of latency plus whatever the auth server's tail looks like.
- **Horizontally scalable.** Stateless — any replica can validate any token. No sticky sessions, no cache coherence between instances.
- **Survives auth-server outages.** After the first JWKS fetch, resource servers keep validating tokens even if AuthGate is unreachable. Introspection-based services go down with the auth server.
- **Works at the edge.** CDNs, serverless functions, regions far from the auth server, and air-gapped networks can all validate tokens without egress.
- **No auth-server load from hot APIs.** A 10 k req/s resource server doesn't translate into 10 k req/s of introspection traffic.
- **Standard and portable.** Any OIDC provider that publishes `jwks_uri` works — you're not coupling your services to a specific vendor's introspection semantics.

### Cons

- **No immediate revocation.** A leaked, stolen, or logged-out token stays valid until its `exp`. Introspection can honor revocation within one call.
- **Requires short access-token lifetimes.** To bound the revocation window you have to set TTLs to minutes (typically 5–15) and lean on refresh tokens. Long-lived access tokens + JWKS = risk.
- **Permission changes lag.** If you demote a user or revoke a scope in the auth server, already-issued tokens still carry the old claims until they expire.
- **JWT tokens only.** Opaque (non-JWT) access tokens can't be validated offline — introspection is the only option. Some providers emit opaque tokens by default.
- **Asymmetric signing only.** HS256 (symmetric) would require sharing the signing secret with every resource server — use RS256 / ES256 / PS256.
- **Token bloat.** JWT access tokens with many claims can push the `Authorization` header past 4–8 KB, which trips some proxies and load balancers.
- **Clock-skew sensitivity.** `exp` / `nbf` are compared to each resource server's local clock. The `coreos/go-oidc` verifier gives `nbf` a 5-minute leeway but `exp` is strict — clock drift across regions can cause spurious rejects.
- **First-time-unknown-kid latency.** When the issuer rotates keys, the first request carrying the new `kid` triggers a synchronous JWKS refresh on the resource server.
- **No centralized audit trail per use.** The auth server sees token issuance but not every use; audit logs have to live at the resource-server layer.

### Common mitigations

- **Keep access-token TTLs short** (5–15 min) so the revocation-lag window is bounded.
- **Use refresh tokens** to keep the UX smooth despite short access-token lives.
- **Maintain a small revocation denylist** (e.g. `jti` set with TTL ≤ max access-token lifetime) if you need faster-than-`exp` revocation for specific incidents.
- **Hybrid: JWKS for read paths, introspection for sensitive mutations** — get latency on the hot path, get revocation on the actions that matter.

## When to Use This vs. Introspection

| Situation                                    | Prefer                                               |
| -------------------------------------------- | ---------------------------------------------------- |
| High RPS, latency-sensitive APIs             | **JWKS (this example)**                              |
| Multi-region / edge / air-gapped deployments | **JWKS (this example)**                              |
| Instant revocation required                  | Introspection ([../go-webservice](../go-webservice)) |
| Opaque (non-JWT) access tokens               | Introspection ([../go-webservice](../go-webservice)) |

## Prerequisites

- Go 1.25+
- An AuthGate issuer whose `/.well-known/openid-configuration` advertises `jwks_uri` and RS256 (or other asymmetric) signing.

## Environment Variables

| Variable              | Required | Description                                                                                                          |
| --------------------- | -------- | -------------------------------------------------------------------------------------------------------------------- |
| `ISSUER_URL`          | Yes      | AuthGate issuer URL — must match the `iss` claim and the `issuer` field of the discovery document                    |
| `EXPECTED_AUDIENCE`   | \*       | Required value in the `aud` claim. Mandatory unless `SKIP_AUDIENCE_CHECK=1` is set.                                  |
| `SKIP_AUDIENCE_CHECK` | \*       | Set to `1` to explicitly disable `aud` enforcement. Only use for issuers that don't emit `aud` on access tokens.     |

\* Exactly one of `EXPECTED_AUDIENCE` or `SKIP_AUDIENCE_CHECK=1` must be set — the server refuses to start otherwise, so a forgotten audience never silently disables validation.

## Usage

```bash
export ISSUER_URL=https://auth.example.com
export EXPECTED_AUDIENCE=https://api.example.com   # or SKIP_AUDIENCE_CHECK=1
go run main.go
```

Or create a `.env` file in this directory:

```bash
ISSUER_URL=https://auth.example.com
EXPECTED_AUDIENCE=https://api.example.com
# or, for issuers that don't emit `aud` on access tokens:
# SKIP_AUDIENCE_CHECK=1
```

The server listens on port **8088**.

## API Endpoints

| Endpoint           | Auth | Scopes  | Domain allowlist | Service-account allowlist | Project allowlist |
| ------------------ | ---- | ------- | ---------------- | ------------------------- | ----------------- |
| `GET /api/profile` | Yes  | —       | (any)            | (any)                     | (any)             |
| `GET /api/data`    | Yes  | `email` | (any)            | (any)                     | (any)             |
| `GET /api/admin`   | Yes  | —       | `oa`             | `sync-bot@oa.local`       | `admin-tools`     |
| `GET /health`      | No   | —       | —                | —                         | —                 |

These rules live in `main()` as `jwksauth.AccessRule{...}` literals. The middleware enforces them with the following semantics:

- **Empty slice = "don't check this dimension"** — let routes opt in.
- **AND-combined** — token must pass every configured allowlist.
- **Fail-closed on missing claim** — if a route requires `Domains: []string{"oa"}` and the token has no `domain` claim, the empty string isn't `"oa"` → reject.
- **`Domain` compares case-insensitively** — allowlist values must be lower-case, the token side is folded automatically.
- **`service_account` / `project` compared exactly** — opaque identifiers, no normalization.
- **Reject reasons go to server log only** — clients see a generic `401 invalid_token` so allowlists aren't inferable from outside.

## Testing

### Quick path: `get-token.sh`

A tiny helper that runs the OAuth 2.0 **Client Credentials** grant and prints an access token you can paste into `curl`. Reads `ISSUER_URL` / `CLIENT_ID` / `CLIENT_SECRET` from this directory's `.env` (or the environment). Requires `curl` + `jq`; `--decode` also requires `base64`.

```bash
# Print just the access_token
TOKEN=$(bash get-token.sh)

# ...or see the full token response (useful to inspect `aud`, `scope`, `exp`)
bash get-token.sh --raw

# Decode the JWT header + payload locally (no network)
bash get-token.sh --decode

# Request specific scopes (default is "email profile")
bash get-token.sh --scope "read"

# For a self-signed AuthGate in development:
INSECURE=1 bash get-token.sh
```

`--decode` is handy for confirming what the resource server will actually see — `iss`, `aud`, `exp`, the granted `scope`, and the `kid` that selects the JWKS key.

### Other ways to get a token

- [`../go-cli`](../go-cli) — browser / device-code login (user token, not M2M)
- [`../go-m2m`](../go-m2m) — Go SDK version of client credentials (add `fmt.Println(tok.AccessToken)` after `ts.Token(ctx)` to print it)
- [`../bash-cli`](../bash-cli) — pure-shell device-code flow

### Calling the protected endpoints

```bash
# Any valid token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/profile

# Requires "email" scope
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/data

# Requires domain=oa, service_account=sync-bot@oa.local, project=admin-tools
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/admin

# No auth
curl http://localhost:8088/health
```

## How It Works

1. **Discovery** — `oidc.NewProvider` fetches `/.well-known/openid-configuration` and verifies that the returned `issuer` matches `ISSUER_URL`. This defeats attackers who control DNS but not the issuer.
2. **JWKS cache** — `oidc.NewRemoteKeySet` lazily loads the signing keys from `jwks_uri` and automatically refreshes when a token carries an unknown `kid` (key rotation support).
3. **Per-request validation** — fully local, via `provider.Verifier(...)`:
   - RS256 signature against the cached public key (`alg=none` and HMAC-confusion attacks are rejected by the library)
   - `iss` equals `ISSUER_URL`
   - `aud` contains `EXPECTED_AUDIENCE`, or `SKIP_AUDIENCE_CHECK=1` is explicitly set (fail-closed default — the server refuses to start with `aud` validation silently disabled)
   - `exp` is strict; `nbf` has a built-in 5 min leeway
4. **Per-route allowlists** — `jwksauth.AccessRule` enforces required scopes plus `domain` / `service_account` / `project` allowlists. Empty slice = "don't check"; non-empty = fail-closed. Handlers may also call `info.HasScope("profile")` for finer-grained checks.
5. **RFC 6750 errors** — `401 invalid_token` / `403 insufficient_scope` responses include a proper `WWW-Authenticate` header.

## Example Responses

**`GET /api/profile`** (valid token):

```json
{
  "subject": "user-uuid-1234",
  "client_id": "your-client-id",
  "audience": ["https://api.example.com"],
  "scope": "email profile",
  "expires": "2026-04-24T12:34:56Z",
  "domain": "oa"
}
```

`domain` is `""` if AuthGate did not emit a `domain` claim on the token.

**`GET /api/data`** (valid token with `email` scope):

```json
{
  "message": "You have email-only access",
  "subject": "user-uuid-1234"
}
```

**`GET /api/admin`** (token with `domain=oa`, `service_account=sync-bot@oa.local`, `project=admin-tools`):

```json
{
  "message": "admin endpoint",
  "domain": "oa",
  "service_account": "sync-bot@oa.local",
  "project": "admin-tools"
}
```

**Missing token** (no `Authorization` header):

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer
```

RFC 6750 §3 reserves the `error` attribute for cases where credentials were supplied but rejected — a request with no credentials gets a bare challenge.

**Invalid token** (present but signature / issuer / audience / expiry fails):

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="invalid token"
```

**Insufficient scope**:

```text
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", error_description="required scope: email", scope="email"
```
