# testissuer — local fake AuthGates for `go-jwks-multi`

Spins up two HTTP issuers that **sign your test tokens locally** so you can exercise the resource server's multi-issuer + multi-tenant code paths (happy path, cross-tenant defense, route policy reject) without standing up real AuthGates.

> ⚠️ This server signs **anything** you ask for. It's a test tool — bind it to localhost only, never expose it.

## What you get

| Issuer | URL                       | Default allowed tenants    |
| ------ | ------------------------- | -------------------------- |
| auth-a | `http://localhost:9001`   | `oa`, `hwrd`               |
| auth-b | `http://localhost:9002`   | `swrd`, `cdomain`          |

Each issuer:

- Generates an **ephemeral RSA-2048 keypair** at startup (restart → new `kid`, old tokens stop verifying — matches real key-rotation semantics).
- Serves `GET /.well-known/openid-configuration` (so the resource server can auto-discover).
- Serves `GET /jwks.json` (so the resource server can cache the public key).
- Exposes `GET /sign` to mint a JWT signed by THIS issuer's key.

## Run

```bash
# Terminal 1 — start the test issuers
cd go-jwks-multi
go run ./testissuer
```

The startup banner prints a copy-paste-ready env block:

```txt
─── resource server env (copy-paste) ──────────────────────────
TRUSTED_ISSUERS=http://localhost:9001,http://localhost:9002
EXPECTED_AUDIENCE=https://api.example.com
ISSUER_TENANTS='http://localhost:9001=oa,hwrd;http://localhost:9002=swrd,cdomain'
───────────────────────────────────────────────────────────────
```

```bash
# Terminal 2 — start the resource server with that env
cd go-jwks-multi
TRUSTED_ISSUERS=http://localhost:9001,http://localhost:9002 \
EXPECTED_AUDIENCE=https://api.example.com \
ISSUER_TENANTS='http://localhost:9001=oa,hwrd;http://localhost:9002=swrd,cdomain' \
go run .
```

## `/sign` query parameters

| Param       | Default                       | Notes                                                  |
| ----------- | ----------------------------- | ------------------------------------------------------ |
| `aud`       | `https://api.example.com`     | Sets the `aud` claim                                   |
| `sub`       | `test-user-1`                 | Sets the `sub` claim                                   |
| `scope`     | `email profile`               | Space-separated; URL-encode space as `+`               |
| `client_id` | `test-client`                 | Sets the `client_id` claim                             |
| `tenant`    | (omitted)                     | Custom claim — omit to test fail-closed behavior       |
| `sa`        | (omitted)                     | Sets `service_account` — omit to test fail-closed      |
| `project`   | (omitted)                     | Sets `project` — omit to test fail-closed              |
| `ttl`       | `300` (seconds)               | `exp` is `iat + ttl`                                   |

`iss` is implicit — it's whichever port you call (`http://localhost:9001` for auth-a, `9002` for auth-b).

## Test scenarios

### Happy path — auth-a tenant `oa`

```bash
TOK=$(curl -s 'http://localhost:9001/sign?tenant=oa&sa=sync-bot@oa.local&project=admin-tools&scope=email+profile')
curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/profile
# → 200; response shows issuer=auth-a, tenant=oa, all claims populated
```

### Cross-tenant attack — auth-a tries to sign for `swrd`

```bash
TOK=$(curl -s 'http://localhost:9001/sign?tenant=swrd')
curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/profile
# → 401; resource server log: "issuer×tenant reject: iss=...:9001 tenant=\"swrd\""
```

### Route policy reject — `/api/data` only allows `oa`, `hwrd`

```bash
TOK=$(curl -s 'http://localhost:9002/sign?tenant=swrd&scope=email')   # legitimate auth-b token
curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/data
# → 401 "token not authorized for this resource"
# → resource server log: "policy reject: tenant=\"swrd\" not in allowlist"
```

### Insufficient scope — `/api/data` requires `email`

```bash
TOK=$(curl -s 'http://localhost:9001/sign?tenant=oa&scope=profile')   # email scope missing
curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/data
# → 403; WWW-Authenticate: ... error="insufficient_scope", scope="email"
```

### Missing required custom claim (fail-closed)

```bash
TOK=$(curl -s 'http://localhost:9001/sign?tenant=oa')  # no `sa` or `project`
curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/admin
# → 401; /api/admin requires sync-bot@oa.local SA + admin-tools project
```

### Untrusted issuer

```bash
# Mint a token from the right server but tamper with the prefix on the wire,
# OR run a third unauthorized issuer on a port not in TRUSTED_ISSUERS.
# Either way the resource server rejects with 401 + "untrusted iss" in its log.
```

### Expired token (server doesn't auto-rotate; just request a tiny TTL)

```bash
TOK=$(curl -s 'http://localhost:9001/sign?tenant=oa&ttl=2')
sleep 3
curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/profile
# → 401; resource server log: "token verification failed: ...token is expired..."
```

## Decoding what you signed

```bash
TOK=$(curl -s 'http://localhost:9001/sign?tenant=oa')
echo "$TOK" | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq .
```

(BSD `base64` may need `-D`; URL-safe segments may need padding — use `../../go-jwks/get-token.sh --decode <token>` for a robust decoder.)
