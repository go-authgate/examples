# CLI example with auto-detection of browser availability.
#
# If a browser is available (local machine), it uses Authorization Code + PKCE.
# If not (SSH session), it falls back to Device Code flow.
# Tokens are persisted to OS keyring (with file fallback) for reuse.
#
# Usage:
#
#   export AUTHGATE_URL=https://auth.example.com
#   export AUTHGATE_CLIENT_ID=your-client-id
#   uv run python main.py

import os
import sys

import authgate


def mask_token(s: str) -> str:
    if len(s) <= 8:
        return "****"
    return s[:8] + "..."


def print_token_info(client, token):
    try:
        info = client.userinfo(token.access_token)
    except Exception as e:
        print(f"Token: {mask_token(token.access_token)} (UserInfo error: {e})")
        return

    print(f"User: {info.name} ({info.email})")
    print(f"Subject: {info.sub}")
    print(f"Access Token: {mask_token(token.access_token)}")
    print(f"Refresh Token: {mask_token(token.refresh_token)}")
    print(f"Token Type: {token.token_type}")
    print(f"Expires In: {token.expires_in}")
    print(f"Expires At: {token.expires_at}")
    print(f"Scope: {token.scope}")
    print(f"ID Token: {mask_token(token.id_token)}")

    try:
        token_info = client.token_info(token.access_token)
    except Exception as e:
        print(f"TokenInfo error: {e}")
        return

    print(f"TokenInfo Active: {token_info.active}")
    print(f"TokenInfo UserID: {token_info.user_id}")
    print(f"TokenInfo ClientID: {token_info.client_id}")
    print(f"TokenInfo Scope: {token_info.scope}")
    print(f"TokenInfo SubjectType: {token_info.subject_type}")
    print(f"TokenInfo Issuer: {token_info.iss}")
    print(f"TokenInfo Exp: {token_info.exp}")


def main():
    authgate_url = os.getenv("AUTHGATE_URL")
    client_id = os.getenv("AUTHGATE_CLIENT_ID")

    if not authgate_url or not client_id:
        print(
            "Error: AUTHGATE_URL and AUTHGATE_CLIENT_ID environment variables are required",
            file=sys.stderr,
        )
        sys.exit(1)

    client, token = authgate.authenticate(
        authgate_url,
        client_id,
        scopes=["profile", "email"],
    )
    print_token_info(client, token)


if __name__ == "__main__":
    main()
