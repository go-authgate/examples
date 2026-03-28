# Go M2M — Machine-to-Machine Authentication

Service-to-service authentication using the OAuth 2.0 Client Credentials grant. No user interaction required.

## OAuth Flow

Uses the **Client Credentials** grant. The service authenticates with its own `CLIENT_ID` and `CLIENT_SECRET` to obtain an access token.

## Prerequisites

- Go 1.25+
- An AuthGate server with a configured OAuth client (with client secret)

## Environment Variables

| Variable        | Required | Description                    |
| --------------- | -------- | ------------------------------ |
| `AUTHGATE_URL`  | Yes      | AuthGate server URL            |
| `CLIENT_ID`     | Yes      | OAuth 2.0 client identifier    |
| `CLIENT_SECRET` | Yes      | OAuth 2.0 client secret        |

## Usage

```bash
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret
go run main.go
```

Alternatively, create a `.env` file in the `go-m2m/` directory:

```bash
AUTHGATE_URL=https://auth.example.com
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret
```

Then simply run:

```bash
go run main.go
```

Environment variables take precedence over `.env` values. The `.env` file is optional — the program works without it.

## How It Works

1. Auto-discovers OIDC endpoints via `/.well-known/openid-configuration`
2. Creates an OAuth client with the client secret
3. Creates an auto-refreshing `TokenSource` with `profile` and `email` scopes and a 30-second expiry delta (refreshes token 30 seconds before it expires)
4. Obtains a pre-authenticated `http.Client` from the token source
5. Makes an authenticated GET request to `/oauth/userinfo`
6. Prints the response status and body (limited to 1 MB)

The token source automatically handles token acquisition and renewal — no manual refresh logic needed.

## Example Output

```
Status: 200
Body: {"sub":"service-uuid","client_id":"your-client-id",...}
```

## Use Cases

- Backend services calling protected APIs
- Cron jobs and scheduled tasks
- Microservice-to-microservice communication
- CI/CD pipeline authentication
