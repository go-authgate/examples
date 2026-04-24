#!/usr/bin/env bash
# Fetches a test access token from AuthGate using the OAuth 2.0
# Client Credentials grant (RFC 6749 §4.4), for use against the
# go-jwks resource server.
#
# Prerequisites: curl, jq

set -euo pipefail

usage() {
  cat <<'EOF'
Fetch an access token from AuthGate via the Client Credentials grant.

Usage:
  bash get-token.sh                    # print access_token
  bash get-token.sh --raw              # print full token response JSON
  bash get-token.sh --decode           # print decoded JWT header + payload
  bash get-token.sh --debug            # echo raw server response to stderr
  bash get-token.sh --scope "read"     # request specific scopes
  INSECURE=1 bash get-token.sh         # skip TLS verification (self-signed issuer)

Env vars (loaded from ./.env if not already set):
  ISSUER_URL      required — AuthGate issuer, e.g. https://auth.example.com
  CLIENT_ID       required — OAuth client ID
  CLIENT_SECRET   required — OAuth client secret (M2M)
  SCOPE           optional — space-separated; default "email profile"
  INSECURE        optional — "1" to pass -k to curl (dev only)

Smoke test:
  TOKEN=$(bash get-token.sh)
  curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/api/profile
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# Decode a base64url-encoded segment (converts -/_ to +/, pads to multiple of 4).
b64url_decode() {
  local s
  s=$(printf '%s' "$1" | tr '_-' '/+')
  case $((${#s} % 4)) in
    2) s+="==" ;;
    3) s+="=" ;;
  esac
  printf '%s' "$s" | base64 -d
}

# Pretty-print a JWT's header + payload as a single JSON object.
decode_jwt() {
  local jwt="$1" h p _sig hdr pld
  IFS='.' read -r h p _sig <<<"$jwt"
  [[ -n "$h" && -n "$p" ]] || die "not a JWT (expected three dot-separated segments)"
  hdr=$(b64url_decode "$h") || die "failed to decode JWT header"
  pld=$(b64url_decode "$p") || die "failed to decode JWT payload"
  jq -n --argjson header "$hdr" --argjson payload "$pld" \
    '{header: $header, payload: $payload}'
}

load_dotenv() {
  local file="$1" line key value line_no=0
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    line="${line#"${line%%[![:space:]]*}"}"   # trim leading whitespace
    line="${line%"${line##*[![:space:]]}"}"   # trim trailing whitespace
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
    if [[ ! "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      printf 'Warning: %s:%d: skipping malformed entry (content redacted)\n' \
        "$file" "$line_no" >&2
      continue
    fi
    key="${line%%=*}"
    value="${line#*=}"
    if [[ -z "${!key+x}" ]]; then
      if ! export "$key=$value"; then
        printf 'Warning: %s:%d: failed to export %s (value redacted)\n' \
          "$file" "$line_no" "$key" >&2
      fi
    fi
  done < "$file"
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
load_dotenv "$script_dir/.env"

RAW=0
DECODE=0
DEBUG=0
SCOPE="${SCOPE:-email profile}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --raw)    RAW=1; shift ;;
    --decode) DECODE=1; shift ;;
    --debug)  DEBUG=1; shift ;;
    --scope)
      [[ $# -ge 2 && "$2" != -* ]] || die 'missing value for --scope (try --scope "read")'
      SCOPE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1 (try --help)" ;;
  esac
done

command -v curl >/dev/null || die "curl not found"
command -v jq   >/dev/null || die "jq not found"
if [[ "$DECODE" == "1" ]]; then
  command -v base64 >/dev/null || die "base64 not found (required for --decode)"
fi

: "${ISSUER_URL:?set ISSUER_URL (or add it to .env)}"
: "${CLIENT_ID:?set CLIENT_ID}"
: "${CLIENT_SECRET:?set CLIENT_SECRET}"

curl_opts=(-sS --connect-timeout 10 --max-time 30)
[[ "${INSECURE:-0}" == "1" ]] && curl_opts+=(-k)

discovery="${ISSUER_URL%/}/.well-known/openid-configuration"
meta=$(curl "${curl_opts[@]}" "$discovery") || die "discovery failed: $discovery"
# jq -er fails if the body isn't JSON OR if token_endpoint is absent, so a
# proxy HTML error page produces a clean message instead of a raw jq trace.
token_url=$(jq -er '.token_endpoint // empty' <<<"$meta" 2>/dev/null) \
  || die "discovery returned invalid JSON or missing token_endpoint: $discovery"

# Build the form body with each value URL-encoded separately.
# Secrets flow through jq's env (not argv) and curl's stdin (not argv) so
# they don't appear in /proc/<pid>/cmdline or `ps` output.
form=$(CID="$CLIENT_ID" SEC="$CLIENT_SECRET" SCP="$SCOPE" jq -rn '
  "grant_type=client_credentials"
  + "&client_id="     + (env.CID | @uri)
  + "&client_secret=" + (env.SEC | @uri)
  + "&scope="         + (env.SCP | @uri)')

response=$(printf '%s' "$form" | curl "${curl_opts[@]}" \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Accept: application/json' \
  --data-binary @- \
  -- "$token_url") || die "token request failed"

if [[ "$DEBUG" == "1" ]]; then
  printf -- '--- raw response from %s ---\n%s\n--- end ---\n' "$token_url" "$response" >&2
fi

# Parse once. Non-JSON responses (e.g. HTML error pages from a proxy) are
# reported explicitly instead of falling through to a confusing jq error.
# Fields are joined with ASCII RS (0x1e) — a non-whitespace separator so
# bash's `read` preserves empty fields (unlike tab, which `read` treats as
# IFS whitespace and collapses, turning "\t\tTOKEN" into a single field).
parsed=$(jq -r '[.error // "", .error_description // "", .access_token // ""] | join("\u001e")' \
  <<<"$response" 2>/dev/null) \
  || die "token endpoint returned non-JSON response (rerun with --debug to inspect the raw body)"
IFS=$'\x1e' read -r err desc token <<<"$parsed"
[[ -z "$err" ]] || die "token endpoint returned $err: $desc"
# Don't echo $response here: if parsing breaks on a valid 200 we'd leak
# the access_token to stderr / shell history. Use --debug to see the body.
[[ -n "$token" ]] || die "access_token missing from response (rerun with --debug to inspect the raw body)"

if [[ "$RAW" == "1" ]]; then
  jq . <<<"$response"
elif [[ "$DECODE" == "1" ]]; then
  decode_jwt "$token"
else
  printf '%s\n' "$token"
fi
