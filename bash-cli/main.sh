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
#   # Option 1 — use a .env file (must run from the directory containing .env):
#   cd bash-cli
#   cp .env.example .env
#   # edit .env with your values
#   bash main.sh   # .env is loaded from the current working directory
#
#   # Option 2 — export variables directly (can run from any directory):
#   export AUTHGATE_URL=https://auth.example.com
#   export CLIENT_ID=your-client-id
#   bash main.sh        # or: bash bash-cli/main.sh from the repo root

set -euo pipefail

# --- Load .env file safely from the current working directory if present ---
load_dotenv() {
  local dotenv_file=".env"
  [[ -f "$dotenv_file" ]] || return 0

  local lineno=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    (( lineno++ )) || true
    # Trim leading/trailing whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"

    # Skip empty lines and comments
    [[ -z "$line" || "${line:0:1}" == "#" ]] && continue

    # Require KEY=VALUE format with a safe key name
    if [[ ! "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      echo "Warning: $dotenv_file line $lineno: skipped malformed entry (content redacted)" >&2
      continue
    fi

    local key value
    key="${line%%=*}"
    value="${line#*=}"

    # Only set variables not already defined in the environment.
    # This guard also prevents overwriting shell internals (PATH, IFS, etc.)
    # since they are always present in the environment.
    if [[ -z "${!key+x}" ]]; then
      if ! export "$key=$value"; then
        echo "Warning: $dotenv_file line $lineno: failed to export '$key' (skipping)" >&2
      fi
    fi
  done < "$dotenv_file"
}

load_dotenv

# --- Configuration ---
SCOPE="profile email"
TOKEN_CACHE_FILE="${HOME}/.authgate-tokens.json"

# --- Global state (populated at runtime) ---
TOKEN_ENDPOINT=""
USERINFO_ENDPOINT=""
DEVICE_AUTH_ENDPOINT=""
TOKENINFO_URL=""

ACCESS_TOKEN=""
REFRESH_TOKEN=""
TOKEN_TYPE=""
EXPIRES_IN=""
EXPIRES_AT=""
TOKEN_SCOPE=""
ID_TOKEN=""

# Detect platform date flavor once at startup.
# Probe GNU-style (-d "@0") first to avoid ambiguity with BSD -r 0
# (which can match a file named "0" in CWD).
DATE_FLAVOR="bsd"
if date -u -d "@0" +%s >/dev/null 2>&1; then
  DATE_FLAVOR="gnu"
fi

# --- Utilities ---

die() {
  echo "Error: $*" >&2
  exit 1
}

check_dependencies() {
  command -v curl >/dev/null 2>&1 || die "curl is required but not found"
  command -v jq >/dev/null 2>&1 || die "jq is required but not found (install: https://jqlang.github.io/jq/)"
}

# URL-encode a string (RFC 3986)
urlencode() {
  local string="$1"
  printf '%s' "$string" | jq -sRr @uri
}

mask_token() {
  local s="${1:-}"
  if [ ${#s} -le 8 ]; then
    echo "****"
  else
    echo "${s:0:8}..."
  fi
}

epoch_to_rfc3339() {
  local epoch="$1"
  if [ "$DATE_FLAVOR" = "bsd" ]; then
    date -u -r "$epoch" +"%Y-%m-%dT%H:%M:%SZ"
  else
    date -u -d "@$epoch" +"%Y-%m-%dT%H:%M:%SZ"
  fi
}

# --- HTTP helpers ---
HTTP_STATUS=""
HTTP_BODY=""

_parse_response() {
  local raw="$1"
  if [ -z "$raw" ]; then
    HTTP_STATUS="000"
    HTTP_BODY=""
    return
  fi
  HTTP_STATUS="${raw##*$'\n'}"
  HTTP_BODY="${raw%$'\n'*}"
}

# Passes headers via --config stdin to avoid leaking tokens in process list
http_get() {
  local url="$1"
  shift
  local config=""
  for h in "$@"; do
    # Strip CR/LF to prevent curl config injection via newlines
    local clean_h="${h//$'\r'/}"
    clean_h="${clean_h//$'\n'/}"
    # Escape backslashes and double-quotes to prevent curl config injection
    local escaped_h="${clean_h//\\/\\\\}"
    escaped_h="${escaped_h//\"/\\\"}"
    config+="header = \"${escaped_h}\""$'\n'
  done

  local response
  if [ -n "$config" ]; then
    response=$(printf '%s' "$config" | curl -s --connect-timeout 10 --max-time 30 -w "\n%{http_code}" --config - -- "$url") || true
  else
    response=$(curl -s --connect-timeout 10 --max-time 30 -w "\n%{http_code}" -- "$url") || true
  fi

  _parse_response "$response"
}

# Passes POST data via stdin to avoid leaking tokens in process list
http_post() {
  local url="$1"
  local data="$2"

  local response
  response=$(printf '%s' "$data" | curl -s --connect-timeout 10 --max-time 30 -w "\n%{http_code}" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary @- \
    -- "$url") || true

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
    die "OIDC discovery failed (HTTP $HTTP_STATUS)"
  fi

  local fields
  fields=$(printf '%s' "$HTTP_BODY" | jq -r '[
    .issuer // "",
    .token_endpoint // "",
    .userinfo_endpoint // "",
    .device_authorization_endpoint // ""
  ] | join("\n")') || die "Failed to parse discovery response"

  local issuer
  {
    IFS= read -r issuer
    IFS= read -r TOKEN_ENDPOINT
    IFS= read -r USERINFO_ENDPOINT
    IFS= read -r DEVICE_AUTH_ENDPOINT
  } <<< "$fields"

  [ -n "$issuer" ] || die "Discovery response missing 'issuer'"
  [ -n "$TOKEN_ENDPOINT" ] || die "Discovery response missing 'token_endpoint'"

  # Derive endpoints if not advertised (matching Go SDK behavior)
  if [ -z "$DEVICE_AUTH_ENDPOINT" ]; then
    DEVICE_AUTH_ENDPOINT="${issuer%/}/oauth/device/code"
  fi

  # userinfo_endpoint is optional in OIDC; warn so callers know token
  # validation via UserInfo will be skipped.
  if [ -z "$USERINFO_ENDPOINT" ]; then
    echo "Warning: userinfo_endpoint not found in OIDC discovery; token validation via UserInfo will be skipped." >&2
  fi

  TOKENINFO_URL="${issuer%/}/oauth/tokeninfo"
}

# --- Token Cache ---

# Refuse to operate on a symlink or a file not owned by the current user
# to avoid following attacker-controlled links to credential files.
validate_cache_file() {
  if [ -L "$TOKEN_CACHE_FILE" ] || [ ! -O "$TOKEN_CACHE_FILE" ]; then
    echo "Warning: Refusing to use token cache file that is a symlink or not owned by the current user: $TOKEN_CACHE_FILE" >&2
    return 1
  fi
  return 0
}

load_cached_token() {
  [ -f "$TOKEN_CACHE_FILE" ] || return 1
  validate_cache_file || return 1

  chmod 600 "$TOKEN_CACHE_FILE" 2>/dev/null || true

  local entry
  entry=$(jq -r --arg cid "$CLIENT_ID" '.data[$cid] // empty' "$TOKEN_CACHE_FILE" 2>/dev/null) || return 1
  [ -n "$entry" ] || return 1

  # The value is a JSON string (double-encoded by Go/Python SDKs)
  local token_json
  token_json=$(printf '%s' "$entry" | jq -r 'fromjson? // .' 2>/dev/null) || return 1

  local fields
  fields=$(printf '%s' "$token_json" | jq -r '[
    .access_token // "",
    .refresh_token // "",
    .token_type // "",
    .expires_at // "",
    .scope // "",
    .id_token // "",
    (.expires_in // 0 | tostring)
  ] | join("\n")') || return 1

  {
    IFS= read -r ACCESS_TOKEN
    IFS= read -r REFRESH_TOKEN
    IFS= read -r TOKEN_TYPE
    IFS= read -r EXPIRES_AT
    IFS= read -r TOKEN_SCOPE
    IFS= read -r ID_TOKEN
    IFS= read -r EXPIRES_IN
  } <<< "$fields"

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
  encoded=$(printf '%s' "$token_obj" | jq -Rs '.')

  # If the cache file already exists, refuse to operate on a symlink or
  # a file not owned by the current user to prevent credential clobbering.
  if [ -e "$TOKEN_CACHE_FILE" ]; then
    validate_cache_file || return 1
  fi

  # Treat missing or corrupted cache as empty; fall back to {}
  local existing
  existing=$(jq '.' "$TOKEN_CACHE_FILE" 2>/dev/null || echo '{}')

  local tmp
  tmp=$(mktemp "${TOKEN_CACHE_FILE}.XXXXXX")

  if ! printf '%s' "$existing" | jq --arg cid "$CLIENT_ID" --argjson val "$encoded" \
    '.data[$cid] = $val' > "$tmp"; then
    rm -f "$tmp"
    return 1
  fi

  if ! chmod 600 "$tmp"; then
    rm -f "$tmp"
    return 1
  fi

  if ! mv "$tmp" "$TOKEN_CACHE_FILE"; then
    rm -f "$tmp"
    return 1
  fi
}

delete_cached_token() {
  [ -f "$TOKEN_CACHE_FILE" ] || return 0

  validate_cache_file || return 0

  local tmp
  tmp=$(mktemp "${TOKEN_CACHE_FILE}.XXXXXX")
  jq --arg cid "$CLIENT_ID" 'del(.data[$cid])' "$TOKEN_CACHE_FILE" > "$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }
  if ! chmod 600 "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv "$tmp" "$TOKEN_CACHE_FILE"; then
    rm -f "$tmp"
    return 1
  fi
}

is_token_expired() {
  [ -z "$EXPIRES_AT" ] && return 0

  local expires_epoch now_epoch

  if [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]]; then
    expires_epoch="$EXPIRES_AT"
  else
    if [ "$DATE_FLAVOR" = "bsd" ]; then
      expires_epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$EXPIRES_AT" +%s 2>/dev/null) || return 0
    else
      expires_epoch=$(date -u -d "$EXPIRES_AT" +%s 2>/dev/null) || return 0
    fi
  fi

  now_epoch=$(date +%s)
  [ "$now_epoch" -ge "$expires_epoch" ]
}

# --- OAuth Flows ---

refresh_token_request() {
  [ -n "$REFRESH_TOKEN" ] || return 1

  local data="grant_type=refresh_token&refresh_token=$(urlencode "$REFRESH_TOKEN")&client_id=$(urlencode "$CLIENT_ID")"
  http_post "$TOKEN_ENDPOINT" "$data"

  if [ "$HTTP_STATUS" != "200" ]; then
    return 1
  fi

  parse_token_response "$HTTP_BODY"
}

request_device_code() {
  local data="client_id=$(urlencode "$CLIENT_ID")&scope=$(urlencode "$SCOPE")"
  http_post "$DEVICE_AUTH_ENDPOINT" "$data"

  if [ "$HTTP_STATUS" = "000" ]; then
    die "Cannot connect to ${DEVICE_AUTH_ENDPOINT} — is the server running?"
  fi
  if [ "$HTTP_STATUS" != "200" ]; then
    local err_desc
    err_desc=$(printf '%s' "$HTTP_BODY" | jq -r '.error_description // .error // "unknown error"' 2>/dev/null) || err_desc="unknown error"
    die "Device code request failed (HTTP $HTTP_STATUS): $err_desc"
  fi

  local fields
  if ! fields=$(printf '%s' "$HTTP_BODY" | jq -r '[
    .device_code // "",
    .user_code // "",
    .verification_uri // "",
    .verification_uri_complete // "",
    (.expires_in // 300 | tostring),
    (.interval // 5 | tostring)
  ] | join("\n")' 2>/dev/null); then
    die "Failed to parse device code response (invalid or non-JSON body)"
  fi

  {
    IFS= read -r DEVICE_CODE
    IFS= read -r USER_CODE
    IFS= read -r VERIFICATION_URI
    IFS= read -r VERIFICATION_URI_COMPLETE
    IFS= read -r DEVICE_EXPIRES_IN
    IFS= read -r POLL_INTERVAL
  } <<< "$fields"

  [ -n "$DEVICE_CODE" ] || die "Device code response missing 'device_code'"
  [ -n "$USER_CODE" ] || die "Device code response missing 'user_code'"
  [ -n "$VERIFICATION_URI" ] || die "Device code response missing 'verification_uri'"
  [[ "$DEVICE_EXPIRES_IN" =~ ^[0-9]+$ ]] || DEVICE_EXPIRES_IN=300
  [[ "$POLL_INTERVAL" =~ ^[0-9]+$ ]] || POLL_INTERVAL=5
}

poll_for_token() {
  local deadline=$(($(date +%s) + DEVICE_EXPIRES_IN))
  local data="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=$(urlencode "$DEVICE_CODE")&client_id=$(urlencode "$CLIENT_ID")"

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

    if [ "$HTTP_STATUS" = "000" ]; then
      echo "" >&2
      die "Connection error while polling for token — is the server running?"
    fi

    local error_code
    error_code=$(printf '%s' "$HTTP_BODY" | jq -r '.error // "unknown"' 2>/dev/null) || error_code="unknown"

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
        err_desc=$(printf '%s' "$HTTP_BODY" | jq -r '.error_description // empty' 2>/dev/null) || err_desc=""
        die "Token request failed: $error_code${err_desc:+ - $err_desc}"
        ;;
    esac
  done
}

parse_token_response() {
  local body="$1"
  local old_refresh="$REFRESH_TOKEN"
  local old_scope="$TOKEN_SCOPE"
  local old_id_token="$ID_TOKEN"

  local fields
  if ! fields=$(printf '%s' "$body" | jq -r '[
    .access_token // "",
    .token_type // "",
    (.expires_in // 0 | tostring),
    .scope // "",
    .id_token // "",
    .refresh_token // ""
  ] | join("\n")' 2>/dev/null); then
    die "Failed to parse token response (invalid or non-JSON body; HTTP $HTTP_STATUS)"
  fi

  local new_refresh
  {
    IFS= read -r ACCESS_TOKEN
    IFS= read -r TOKEN_TYPE
    IFS= read -r EXPIRES_IN
    IFS= read -r TOKEN_SCOPE
    IFS= read -r ID_TOKEN
    IFS= read -r new_refresh
  } <<< "$fields"

  REFRESH_TOKEN="${new_refresh:-$old_refresh}"
  # Preserve prior scope/id_token when the server omits them (e.g. refresh responses)
  TOKEN_SCOPE="${TOKEN_SCOPE:-$old_scope}"
  ID_TOKEN="${ID_TOKEN:-$old_id_token}"

  [ -n "$ACCESS_TOKEN" ] || die "Token response missing 'access_token'"
  [ -n "$TOKEN_TYPE" ] || die "Token response missing 'token_type'"

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

  local fields
  fields=$(printf '%s' "$HTTP_BODY" | jq -r '[
    .name // "",
    .email // "",
    .sub // ""
  ] | join("\n")') || return 1

  {
    IFS= read -r USER_NAME
    IFS= read -r USER_EMAIL
    IFS= read -r USER_SUB
  } <<< "$fields"
}

fetch_tokeninfo() {
  http_get "$TOKENINFO_URL" "Authorization: Bearer $ACCESS_TOKEN"

  if [ "$HTTP_STATUS" != "200" ]; then
    echo "TokenInfo error: HTTP $HTTP_STATUS"
    return 1
  fi

  local fields
  fields=$(printf '%s' "$HTTP_BODY" | jq -r '[
    (.active // "" | tostring),
    .user_id // "",
    .client_id // "",
    .scope // "",
    .subject_type // "",
    .iss // "",
    (.exp // "" | tostring)
  ] | join("\n")') || return 1

  {
    IFS= read -r TI_ACTIVE
    IFS= read -r TI_USER_ID
    IFS= read -r TI_CLIENT_ID
    IFS= read -r TI_SCOPE
    IFS= read -r TI_SUBJECT_TYPE
    IFS= read -r TI_ISS
    IFS= read -r TI_EXP
  } <<< "$fields"
}

# Uses already-fetched USER_NAME/USER_EMAIL/USER_SUB if available
print_token_info() {
  local expires_at_display=""
  if [ -n "$EXPIRES_AT" ]; then
    if [[ "$EXPIRES_AT" =~ ^[0-9]+$ ]]; then
      expires_at_display=$(epoch_to_rfc3339 "$EXPIRES_AT")
    else
      expires_at_display="$EXPIRES_AT"
    fi
  fi

  if [ -n "${USER_SUB:-}" ]; then
    echo "User: ${USER_NAME} (${USER_EMAIL})"
    echo "Subject: ${USER_SUB}"
  elif [ -z "$USERINFO_ENDPOINT" ]; then
    echo "Token: $(mask_token "$ACCESS_TOKEN") (UserInfo not available)"
  else
    echo "Token: $(mask_token "$ACCESS_TOKEN") (UserInfo error: HTTP $HTTP_STATUS)"
  fi

  echo "Access Token: $(mask_token "$ACCESS_TOKEN")"
  echo "Refresh Token: $(mask_token "$REFRESH_TOKEN")"
  echo "Token Type: ${TOKEN_TYPE}"
  echo "Expires In: ${EXPIRES_IN}"
  echo "Expires At: ${expires_at_display}"
  echo "Scope: ${TOKEN_SCOPE}"
  echo "ID Token: $(mask_token "$ID_TOKEN")"

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

run_device_flow() {
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
}

main() {
  check_dependencies

  : "${AUTHGATE_URL:?Error: AUTHGATE_URL environment variable is required}"
  : "${CLIENT_ID:?Error: CLIENT_ID environment variable is required}"

  discover_endpoints

  local need_auth=true

  if load_cached_token; then
    if ! is_token_expired; then
      need_auth=false
    elif refresh_token_request; then
      need_auth=false
    fi
  fi

  if [ "$need_auth" = true ]; then
    run_device_flow
  fi

  # Validate token with userinfo; re-auth only on 401/403 (token invalid/expired).
  # Skip if userinfo_endpoint was not advertised by the server.
  if [ -n "$USERINFO_ENDPOINT" ]; then
    if ! fetch_userinfo; then
      if [ "$HTTP_STATUS" = "401" ] || [ "$HTTP_STATUS" = "403" ]; then
        echo "Cached token is invalid, re-authenticating..."
        delete_cached_token || echo "Warning: Failed to delete cached token; continuing with re-auth." >&2
        run_device_flow
        fetch_userinfo || true
      else
        echo "Warning: UserInfo request failed (HTTP $HTTP_STATUS); proceeding with cached token." >&2
      fi
    fi
  fi

  if ! save_cached_token; then
    echo "Warning: Failed to save token cache to ${TOKEN_CACHE_FILE}" >&2
  fi
  print_token_info
}

main "$@"
