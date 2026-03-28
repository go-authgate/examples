# CLI example with auto-detection of browser availability.
#
# If a browser is available (local machine), it uses Authorization Code + PKCE.
# If not (SSH session), it falls back to Device Code flow.
# Tokens are persisted to OS keyring (with file fallback) for reuse.
#
# Configuration can be provided via environment variables or a .env file.
#
# Usage:
#
#   export AUTHGATE_URL=https://auth.example.com
#   export CLIENT_ID=your-client-id
#   uv run python main.py

import os
import sys

from dotenv import load_dotenv

import authgate
from authgate.credstore import default_token_secure_store


def mask_token(s: str) -> str:
    if len(s) <= 8:
        return "****"
    return s[:8] + "..."


def print_token_info(client, token, info=None):
    if info is None:
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
        token_info = client.token_info_request(token.access_token)
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
    load_dotenv()

    authgate_url = os.getenv("AUTHGATE_URL")
    client_id = os.getenv("CLIENT_ID")

    if not authgate_url or not client_id:
        print(
            "Error: AUTHGATE_URL and CLIENT_ID environment variables are required",
            file=sys.stderr,
        )
        sys.exit(1)

    client, token = authgate.authenticate(
        authgate_url,
        client_id,
        scopes=["profile", "email"],
    )

    # If the cached token is revoked/expired server-side, clear it and re-authenticate.
    try:
        info = client.userinfo(token.access_token)
    except Exception:
        print("Cached token is invalid, re-authenticating...")
        store = default_token_secure_store("authgate", ".authgate-tokens.json")
        store.delete(client_id)
        client, token = authgate.authenticate(
            authgate_url,
            client_id,
            scopes=["profile", "email"],
        )
        info = None

    print_token_info(client, token, info=info)


if __name__ == "__main__":
    main()
