# Go Web Service — API Token Validation

Protect HTTP endpoints with Bearer token middleware and scope-based access control using the standard `net/http` library.

## OAuth Flow

Uses **Bearer Token Validation**. The server validates access tokens sent by clients in the `Authorization` header by introspecting them against the AuthGate server.

## Prerequisites

- Go 1.25+
- An AuthGate server with a configured OAuth client

## Environment Variables

| Variable       | Required | Description                 |
| -------------- | -------- | --------------------------- |
| `AUTHGATE_URL` | Yes      | AuthGate server URL         |
| `CLIENT_ID`    | Yes      | OAuth 2.0 client identifier |

## Usage

```bash
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
go run main.go
```

The server starts on port **8080**.

## API Endpoints

| Endpoint           | Auth Required | Scopes | Description                         |
| ------------------ | ------------- | ------ | ----------------------------------- |
| `GET /api/profile` | Yes           | Any    | Returns user/client identity info   |
| `GET /api/data`    | Yes           | `read` | Returns data with access level info |
| `GET /health`      | No            | —      | Health check                        |

## Testing

First obtain a token (e.g., from the go-cli or python-cli example), then:

```bash
# Profile endpoint — any valid token
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/profile

# Data endpoint — requires "read" scope
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/data

# Health check — no auth needed
curl http://localhost:8080/health
```

## How It Works

1. Auto-discovers OIDC endpoints via `/.well-known/openid-configuration`
2. Creates an OAuth client for token validation
3. Configures two middleware instances:
   - `auth` — validates any Bearer token
   - `authWithScope` — validates the token and requires the `read` scope
4. Registers routes with the appropriate middleware
5. Handlers extract token info from the request context via `middleware.TokenInfoFromContext()`
6. The `/api/data` handler demonstrates in-handler scope checking with `middleware.HasScope()` to differentiate read vs read+write access

## Example Responses

**`GET /api/profile`** (valid token):

```json
{
  "user_id": "user-uuid-1234",
  "client_id": "your-client-id",
  "scope": "profile email read",
  "subject_type": "user"
}
```

**`GET /api/data`** (valid token with `read` scope):

```json
{
  "message": "You have read-only access",
  "user": "user-uuid-1234"
}
```

**`GET /api/data`** (valid token with `read` and `write` scopes):

```json
{
  "message": "You have read+write access",
  "user": "user-uuid-1234"
}
```

**`GET /health`**:

```json
{
  "status": "ok"
}
```
