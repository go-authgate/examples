# Python M2M — Machine-to-Machine Authentication

Service-to-service authentication using the OAuth 2.0 Client Credentials grant. No user interaction required.

## OAuth Flow

Uses the **Client Credentials** grant. The service authenticates with its own `CLIENT_ID` and `CLIENT_SECRET` to obtain an access token.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
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
uv run python main.py
```

`uv run` automatically installs dependencies from `pyproject.toml` on first run.

## How It Works

1. Auto-discovers OIDC endpoints via `DiscoveryClient`
2. Creates an `OAuthClient` with the client secret
3. Creates an auto-refreshing `TokenSource` with `profile` and `email` scopes and a 30-second expiry delta
4. Wraps the token source in a `BearerAuth` handler for `httpx`
5. Streams an authenticated GET request to `/oauth/userinfo` (limited to 1 MB)
6. Prints the response status and body

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
