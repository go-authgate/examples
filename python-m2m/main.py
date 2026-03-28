# M2M (Machine-to-Machine) example using Client Credentials grant.
#
# This example demonstrates service-to-service authentication where
# no user interaction is needed. The token is automatically cached
# and refreshed before expiry.
#
# Configuration can be provided via environment variables or a .env file.
#
# Usage:
#
#   export AUTHGATE_URL=https://auth.example.com
#   export CLIENT_ID=your-client-id
#   export CLIENT_SECRET=your-client-secret
#   uv run python main.py

import os
import sys

import httpx
from dotenv import load_dotenv

from authgate.clientcreds import BearerAuth, TokenSource
from authgate.discovery import DiscoveryClient
from authgate.oauth import OAuthClient

MAX_BODY_SIZE = 1 << 20  # 1 MB


def main():
    load_dotenv()

    authgate_url = os.getenv("AUTHGATE_URL")
    client_id = os.getenv("CLIENT_ID")
    client_secret = os.getenv("CLIENT_SECRET")

    if not authgate_url or not client_id or not client_secret:
        print(
            "Error: AUTHGATE_URL, CLIENT_ID, and CLIENT_SECRET environment variables are required",
            file=sys.stderr,
        )
        sys.exit(1)

    # 1. Auto-discover endpoints
    disco = DiscoveryClient(authgate_url)
    meta = disco.fetch()

    # 2. Create OAuth client
    client = OAuthClient(client_id, meta.to_endpoints(), client_secret=client_secret)

    # 3. Create auto-refreshing token source
    ts = TokenSource(client, scopes=["profile", "email"], expiry_delta=30.0)

    # 4. Use the auto-authenticated HTTP client
    auth = BearerAuth(ts)
    with httpx.Client(auth=auth) as http:
        with http.stream("GET", f"{authgate_url}/oauth/userinfo") as resp:
            status_code = resp.status_code
            body_bytes = bytearray()
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                remaining = (MAX_BODY_SIZE + 1) - len(body_bytes)
                if remaining <= 0:
                    break
                if len(chunk) > remaining:
                    body_bytes.extend(chunk[:remaining])
                    break
                body_bytes.extend(chunk)
            body = bytes(body_bytes)

    truncated = len(body) > MAX_BODY_SIZE
    if truncated:
        body = body[:MAX_BODY_SIZE]
    print(f"Status: {status_code}")
    print(f"Body: {body.decode(errors='replace')}")
    if truncated:
        print("(response body truncated to 1 MB)")


if __name__ == "__main__":
    main()
