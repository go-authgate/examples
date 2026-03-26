#!/usr/bin/env bash
# Bash CLI example using OAuth 2.0 Device Authorization Grant (RFC 8628).
#
# Authenticates via the device code flow (no browser needed on this machine).
# Tokens are cached to ~/.authgate-tokens.json for reuse.
#
# Prerequisites: curl, jq
#
# Usage:
#
#   export AUTHGATE_URL=https://auth.example.com
#   export CLIENT_ID=your-client-id
#   bash main.sh

set -euo pipefail

# --- Configuration ---
SCOPE="profile email"
TOKEN_CACHE_FILE="${HOME}/.authgate-tokens.json"

# --- Global state (populated at runtime) ---
TOKEN_ENDPOINT=""
USERINFO_ENDPOINT=""
DEVICE_AUTH_ENDPOINT=""
TOKENINFO_URL=""

# Cached/obtained token fields
ACCESS_TOKEN=""
REFRESH_TOKEN=""
TOKEN_TYPE=""
EXPIRES_IN=""
EXPIRES_AT=""
TOKEN_SCOPE=""
ID_TOKEN=""

# --- Utilities ---

die() {
  echo "Error: $*" >&2
  exit 1
}

check_dependencies() {
  command -v curl >/dev/null 2>&1 || die "curl is required but not found"
  command -v jq >/dev/null 2>&1 || die "jq is required but not found (install: https://jqlang.github.io/jq/)"
}

mask_token() {
  local s="${1:-}"
  if [ ${#s} -le 8 ]; then
    echo "****"
  else
    echo "${s:0:8}..."
  fi
}

# Portable epoch → RFC 3339 conversion (macOS + Linux)
epoch_to_rfc3339() {
  local epoch="$1"
  if date -u -r 0 +%s >/dev/null 2>&1; then
    # BSD/macOS date
    date -u -r "$epoch" +"%Y-%m-%dT%H:%M:%SZ"
  else
    # GNU/Linux date
    date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ"
  fi
}

# --- HTTP helpers ---
# Sets global HTTP_STATUS and HTTP_BODY after each call.
HTTP_STATUS=""
HTTP_BODY=""

# _parse_response RAW_RESPONSE
# Splits curl output (body + status code on last line) into HTTP_BODY and HTTP_STATUS.
_parse_response() {
  local raw="$1"
  if [ -z "$raw" ]; then
    HTTP_STATUS="000"
    HTTP_BODY=""
    return
  fi
  HTTP_STATUS=$(echo "$raw" | tail -n1)
  HTTP_BODY=$(echo "$raw" | sed '$d')
}

# http_get URL [HEADER...]
http_get() {
  local url="$1"
  shift
  local -a headers=()
  for h in "$@"; do
    headers+=(-H "$h")
  done

  local response
  if [ ${#headers[@]} -gt 0 ]; then
    response=$(curl -s -w "\n%{http_code}" "${headers[@]}" "$url") || true
  else
    response=$(curl -s -w "\n%{http_code}" "$url") || true
  fi

  _parse_response "$response"
}

# http_post URL DATA
http_post() {
  local url="$1"
  local data="$2"

  local response
  response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$data" \
    "$url") || true

  _parse_response "$response"
}

# --- OIDC Discovery ---

discover_endpoints() {
  local discovery_url="${AUTHGATE_URL%/}/.well-known/openid-configuration"
  http_get "$discovery_url"

  if [ "$HTTP_STATUS" = "000" ]; then
    die "Cannot connect to ${AUTHGATE_URL} — is the server running?"
  fi
  if [ "$HTTP_STATUS" != "200" ]; then
    die "OIDC discovery failed (HTTP $HTTP_STATUS): $HTTP_BODY"
  fi

  local issuer
  issuer=$(echo "$HTTP_BODY" | jq -r '.issuer // empty') || die "Failed to parse discovery response"
  [ -n "$issuer" ] || die "Discovery response missing 'issuer'"

  TOKEN_ENDPOINT=$(echo "$HTTP_BODY" | jq -r '.token_endpoint // empty')
  USERINFO_ENDPOINT=$(echo "$HTTP_BODY" | jq -r '.userinfo_endpoint // empty')
  DEVICE_AUTH_ENDPOINT=$(echo "$HTTP_BODY" | jq -r '.device_authorization_endpoint // empty')

  [ -n "$TOKEN_ENDPOINT" ] || die "Discovery response missing 'token_endpoint'"

  # Derive endpoints if not advertised (matching Go SDK behavior)
  if [ -z "$DEVICE_AUTH_ENDPOINT" ]; then
    DEVICE_AUTH_ENDPOINT="${issuer%/}/oauth/device/code"
  fi

  TOKENINFO_URL="${issuer%/}/oauth/tokeninfo"
}

# --- Token Cache ---

load_cached_token() {
  [ -f "$TOKEN_CACHE_FILE" ] || return 1

  local entry
  entry=$(jq -r --arg cid "$CLIENT_ID" '.data[$cid] // empty' "$TOKEN_CACHE_FILE" 2>/dev/null) || return 1
  [ -n "$entry" ] || return 1

  # The value is a JSON string (double-encoded by Go/Python SDKs)
  local token_json
  token_json=$(echo "$entry" | jq -r 'fromjson? // .' 2>/dev/null) || return 1

  ACCESS_TOKEN=$(echo "$token_json" | jq -r '.access_token // empty')
  REFRESH_TOKEN=$(echo "$token_json" | jq -r '.refresh_token // empty')
  TOKEN_TYPE=$(echo "$token_json" | jq -r '.token_type // empty')
  EXPIRES_AT=$(echo "$token_json" | jq -r '.expires_at // empty')
  TOKEN_SCOPE=$(echo "$token_json" | jq -r '.scope // empty')
  ID_TOKEN=$(echo "$token_json" | jq -r '.id_token // empty')
  EXPIRES_IN=$(echo "$token_json" | jq -r '.expires_in // "0"')

  [ -n "$ACCESS_TOKEN" ] || return 1
  return 0
}

save_cached_token() {
  local token_obj
  token_obj=$(jq -n \
    --arg at "$ACCESS_TOKEN" \
    --arg rt "$REFRESH_TOKEN" \
    --arg tt "$TOKEN_TYPE" \
    --arg ea "$EXPIRES_AT" \
    --arg sc "$TOKEN_SCOPE" \
    --arg id "$ID_TOKEN" \
    --arg cid "$CLIENT_ID" \
    --argjson ei "${EXPIRES_IN:-0}" \
    '{
      access_token: $at,
      refresh_token: $rt,
      token_type: $tt,
      expires_in: $ei,
      expires_at: $ea,
      scope: $sc,
      id_token: $id,
      client_id: $cid
    }')

  # Double-encode as JSON string (matching Go/Python SDK format)
  local encoded
  encoded=$(echo "$token_obj" | jq -c '.' | jq -Rs '.')

  local existing='{}'
  if [ -f "$TOKEN_CACHE_FILE" ]; then
    existing=$(cat "$TOKEN_CACHE_FILE" 2>/dev/null || echo '{}')
  fi

  # Ensure .data exists, then set the entry
  local tmp="${TOKEN_CACHE_FILE}.tmp.$$"
  echo "$existing" | jq --arg cid "$CLIENT_ID" --argjson val "$encoded" \
    '.data[$cid] = $val' > "$tmp"

  chmod 600 "$tmp"
  mv "$tmp" "$TOKEN_CACHE_FILE"
}

delete_cached_token() {
  [ -f "$TOKEN_CACHE_FILE" ] || return 0

  local tmp="${TOKEN_CACHE_FILE}.tmp.$$"
  jq --arg cid "$CLIENT_ID" 'del(.data[$cid])' "$TOKEN_CACHE_FILE" > "$tmp" 2>/dev/null || return 0
  chmod 600 "$tmp"
  mv "$tmp" "$TOKEN_CACHE_FILE"
}

is_token_expired() {
  [ -z "$EXPIRES_AT" ] && return 0  # No expiry info → treat as expired

  local expires_epoch now_epoch

  # EXPIRES_AT may be a Unix timestamp or an RFC 3339 string
  if [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]]; then
    expires_epoch="$EXPIRES_AT"
  else
    # Try parsing as RFC 3339
    if date -u -r 0 +%s >/dev/null 2>&1; then
      # BSD/macOS
      expires_epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$EXPIRES_AT" +%s 2>/dev/null) || return 0
    else
      # GNU/Linux
      expires_epoch=$(date -u -d "$EXPIRES_AT" +%s 2>/dev/null) || return 0
    fi
  fi

  now_epoch=$(date +%s)
  [ "$now_epoch" -ge "$expires_epoch" ]
}

# --- OAuth Flows ---

refresh_token_request() {
  [ -n "$REFRESH_TOKEN" ] || return 1

  local data="grant_type=refresh_token&refresh_token=${REFRESH_TOKEN}&client_id=${CLIENT_ID}"
  http_post "$TOKEN_ENDPOINT" "$data"

  if [ "$HTTP_STATUS" != "200" ]; then
    return 1
  fi

  parse_token_response "$HTTP_BODY"
}

request_device_code() {
  local data="client_id=${CLIENT_ID}&scope=${SCOPE}"
  http_post "$DEVICE_AUTH_ENDPOINT" "$data"

  if [ "$HTTP_STATUS" != "200" ]; then
    local err_desc
    err_desc=$(echo "$HTTP_BODY" | jq -r '.error_description // .error // "unknown error"' 2>/dev/null)
    die "Device code request failed (HTTP $HTTP_STATUS): $err_desc"
  fi

  DEVICE_CODE=$(echo "$HTTP_BODY" | jq -r '.device_code')
  USER_CODE=$(echo "$HTTP_BODY" | jq -r '.user_code')
  VERIFICATION_URI=$(echo "$HTTP_BODY" | jq -r '.verification_uri')
  VERIFICATION_URI_COMPLETE=$(echo "$HTTP_BODY" | jq -r '.verification_uri_complete // empty')
  DEVICE_EXPIRES_IN=$(echo "$HTTP_BODY" | jq -r '.expires_in // 300')
  POLL_INTERVAL=$(echo "$HTTP_BODY" | jq -r '.interval // 5')
}

poll_for_token() {
  local deadline=$(($(date +%s) + DEVICE_EXPIRES_IN))
  local data="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=${DEVICE_CODE}&client_id=${CLIENT_ID}"

  while true; do
    sleep "$POLL_INTERVAL"

    local now
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      die "Device code expired. Please try again."
    fi

    http_post "$TOKEN_ENDPOINT" "$data"

    if [ "$HTTP_STATUS" = "200" ]; then
      parse_token_response "$HTTP_BODY"
      return 0
    fi

    local error_code
    error_code=$(echo "$HTTP_BODY" | jq -r '.error // "unknown"' 2>/dev/null)

    case "$error_code" in
      authorization_pending)
        printf "." >&2
        ;;
      slow_down)
        POLL_INTERVAL=$((POLL_INTERVAL + 5))
        printf "." >&2
        ;;
      expired_token)
        echo "" >&2
        die "Device code expired. Please try again."
        ;;
      access_denied)
        echo "" >&2
        die "Authorization denied by user."
        ;;
      *)
        echo "" >&2
        local err_desc
        err_desc=$(echo "$HTTP_BODY" | jq -r '.error_description // empty' 2>/dev/null)
        die "Token request failed: $error_code${err_desc:+ - $err_desc}"
        ;;
    esac
  done
}

parse_token_response() {
  local body="$1"
  local old_refresh="$REFRESH_TOKEN"

  ACCESS_TOKEN=$(echo "$body" | jq -r '.access_token // empty')
  TOKEN_TYPE=$(echo "$body" | jq -r '.token_type // empty')
  EXPIRES_IN=$(echo "$body" | jq -r '.expires_in // 0')
  TOKEN_SCOPE=$(echo "$body" | jq -r '.scope // empty')
  ID_TOKEN=$(echo "$body" | jq -r '.id_token // empty')

  local new_refresh
  new_refresh=$(echo "$body" | jq -r '.refresh_token // empty')
  REFRESH_TOKEN="${new_refresh:-$old_refresh}"

  # Compute expires_at as Unix epoch
  if [ "$EXPIRES_IN" -gt 0 ] 2>/dev/null; then
    EXPIRES_AT=$(( $(date +%s) + EXPIRES_IN ))
  else
    EXPIRES_AT=""
  fi
}

# --- API Calls ---

fetch_userinfo() {
  http_get "$USERINFO_ENDPOINT" "Authorization: Bearer $ACCESS_TOKEN"

  if [ "$HTTP_STATUS" != "200" ]; then
    return 1
  fi

  USER_NAME=$(echo "$HTTP_BODY" | jq -r '.name // empty')
  USER_EMAIL=$(echo "$HTTP_BODY" | jq -r '.email // empty')
  USER_SUB=$(echo "$HTTP_BODY" | jq -r '.sub // empty')
}

fetch_tokeninfo() {
  http_get "$TOKENINFO_URL" "Authorization: Bearer $ACCESS_TOKEN"

  if [ "$HTTP_STATUS" != "200" ]; then
    echo "TokenInfo error: HTTP $HTTP_STATUS"
    return 1
  fi

  TI_ACTIVE=$(echo "$HTTP_BODY" | jq -r '.active // empty')
  TI_USER_ID=$(echo "$HTTP_BODY" | jq -r '.user_id // empty')
  TI_CLIENT_ID=$(echo "$HTTP_BODY" | jq -r '.client_id // empty')
  TI_SCOPE=$(echo "$HTTP_BODY" | jq -r '.scope // empty')
  TI_SUBJECT_TYPE=$(echo "$HTTP_BODY" | jq -r '.subject_type // empty')
  TI_ISS=$(echo "$HTTP_BODY" | jq -r '.iss // empty')
  TI_EXP=$(echo "$HTTP_BODY" | jq -r '.exp // empty')
}

print_token_info() {
  local expires_at_display=""
  if [ -n "$EXPIRES_AT" ]; then
    expires_at_display=$(epoch_to_rfc3339 "$EXPIRES_AT")
  fi

  # UserInfo
  if fetch_userinfo; then
    echo "User: ${USER_NAME} (${USER_EMAIL})"
    echo "Subject: ${USER_SUB}"
  else
    echo "Token: $(mask_token "$ACCESS_TOKEN") (UserInfo error: HTTP $HTTP_STATUS)"
  fi

  # Token details
  echo "Access Token: $(mask_token "$ACCESS_TOKEN")"
  echo "Refresh Token: $(mask_token "$REFRESH_TOKEN")"
  echo "Token Type: ${TOKEN_TYPE}"
  echo "Expires In: ${EXPIRES_IN}"
  echo "Expires At: ${expires_at_display}"
  echo "Scope: ${TOKEN_SCOPE}"
  echo "ID Token: $(mask_token "$ID_TOKEN")"

  # TokenInfo
  if fetch_tokeninfo; then
    echo "TokenInfo Active: ${TI_ACTIVE}"
    echo "TokenInfo UserID: ${TI_USER_ID}"
    echo "TokenInfo ClientID: ${TI_CLIENT_ID}"
    echo "TokenInfo Scope: ${TI_SCOPE}"
    echo "TokenInfo SubjectType: ${TI_SUBJECT_TYPE}"
    echo "TokenInfo Issuer: ${TI_ISS}"
    echo "TokenInfo Exp: ${TI_EXP}"
  fi
}

# --- Main ---

main() {
  check_dependencies

  : "${AUTHGATE_URL:?Error: AUTHGATE_URL environment variable is required}"
  : "${CLIENT_ID:?Error: CLIENT_ID environment variable is required}"

  discover_endpoints

  local need_auth=true

  # Try cached token
  if load_cached_token; then
    if ! is_token_expired; then
      need_auth=false
    elif refresh_token_request; then
      need_auth=false
    fi
  fi

  # Device Code flow
  if [ "$need_auth" = true ]; then
    request_device_code

    echo ""
    echo "To sign in, open the following URL in a browser:"
    echo ""
    echo "  ${VERIFICATION_URI}"
    echo ""
    echo "Then enter the code: ${USER_CODE}"
    echo ""

    if [ -n "${VERIFICATION_URI_COMPLETE:-}" ]; then
      echo "Or open directly: ${VERIFICATION_URI_COMPLETE}"
      echo ""
    fi

    printf "Waiting for authorization" >&2
    poll_for_token
    echo "" >&2
  fi

  # Validate token with userinfo; re-auth if invalid
  if ! fetch_userinfo; then
    echo "Cached token is invalid, re-authenticating..."

    delete_cached_token
    request_device_code

    echo ""
    echo "To sign in, open the following URL in a browser:"
    echo ""
    echo "  ${VERIFICATION_URI}"
    echo ""
    echo "Then enter the code: ${USER_CODE}"
    echo ""

    if [ -n "${VERIFICATION_URI_COMPLETE:-}" ]; then
      echo "Or open directly: ${VERIFICATION_URI_COMPLETE}"
      echo ""
    fi

    printf "Waiting for authorization" >&2
    poll_for_token
    echo "" >&2
  fi

  save_cached_token
  print_token_info
}

main "$@"
