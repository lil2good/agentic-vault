#!/usr/bin/env bash
# agentvault.sh — Sourceable shell helper for the Agentic Credential Vault
# Source this file in scripts: source /path/to/agentvault.sh
# All functions use VAULT_URL (default: http://127.0.0.1:8787)
# Admin functions use VAULT_ADMIN_TOKEN (auto-read from .env if not set)

VAULT_URL="${VAULT_URL:-http://127.0.0.1:8787}"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_agentvault_check_jq() {
  command -v jq >/dev/null 2>&1 || {
    echo "error: jq is required but not installed. Install it: https://jqlang.github.io/jq/download/" >&2
    return 1
  }
}

_agentvault_check_curl() {
  command -v curl >/dev/null 2>&1 || {
    echo "error: curl is required but not installed." >&2
    return 1
  }
}

_agentvault_require() {
  _agentvault_check_curl || return 1
  _agentvault_check_jq || return 1
}

_agentvault_find_env() {
  # Find .env in known skill locations
  local dirs=(
    "${AGENTVAULT_DIR:-}"
    "${BASH_SOURCE[0]%/*}"
    "$HOME/.openclaw/skills/agentic-credential-vault"
    "$HOME/openclaw/skills/agentic-credential-vault"
  )
  for d in "${dirs[@]}"; do
    [ -n "$d" ] && [ -f "$d/.env" ] && echo "$d/.env" && return 0
  done
  return 1
}

_agentvault_admin_token() {
  if [ -n "${VAULT_ADMIN_TOKEN:-}" ]; then
    echo "$VAULT_ADMIN_TOKEN"
    return 0
  fi
  local envfile
  envfile=$(_agentvault_find_env) || {
    echo "error: VAULT_ADMIN_TOKEN not set and no .env found. Export VAULT_ADMIN_TOKEN or set AGENTVAULT_DIR." >&2
    return 1
  }
  local token
  token=$(grep -E '^VAULT_ADMIN_TOKEN=' "$envfile" | head -1 | cut -d= -f2-)
  if [ -z "$token" ]; then
    echo "error: VAULT_ADMIN_TOKEN not found in $envfile" >&2
    return 1
  fi
  echo "$token"
}

_agentvault_post() {
  local endpoint="$1" body="$2"
  shift 2
  local -a headers=("-H" "content-type: application/json")
  # Additional headers passed as pairs
  while [ $# -ge 2 ]; do
    headers+=("-H" "$1: $2")
    shift 2
  done
  local resp http_code
  resp=$(curl -s -w "\n%{http_code}" "${headers[@]}" -d "$body" "${VAULT_URL}${endpoint}" 2>&1)
  http_code=$(echo "$resp" | tail -1)
  resp=$(echo "$resp" | sed '$d')

  if [ "$http_code" = "000" ]; then
    echo "error: vault not reachable at $VAULT_URL — is it running?" >&2
    return 1
  fi
  if [ "${http_code:0:1}" != "2" ]; then
    local msg
    msg=$(echo "$resp" | jq -r '.error // .message // "unknown error"' 2>/dev/null || echo "$resp")
    echo "error ($http_code): $msg" >&2
    return 1
  fi
  echo "$resp"
}

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

agentvault_health() {
  _agentvault_require || return 1
  local resp
  resp=$(curl -s -w "\n%{http_code}" "${VAULT_URL}/health" 2>&1)
  local http_code
  http_code=$(echo "$resp" | tail -1)
  resp=$(echo "$resp" | sed '$d')
  if [ "$http_code" = "000" ]; then
    echo "error: vault not reachable at $VAULT_URL" >&2
    return 1
  fi
  echo "$resp" | jq .
}

agentvault_token() {
  # Usage: agentvault_token <service> <scope1> [scope2 ...]
  #   Optional env: AGENTVAULT_AGENT_ID (default: "main"), AGENTVAULT_TTL (default: 300)
  _agentvault_require || return 1
  local service="$1"; shift
  if [ -z "$service" ] || [ $# -eq 0 ]; then
    echo "usage: agentvault_token <service> <scope1> [scope2 ...]" >&2
    return 1
  fi
  local scopes
  scopes=$(printf '%s\n' "$@" | jq -R . | jq -s .)
  local agent_id="${AGENTVAULT_AGENT_ID:-main}"
  local ttl="${AGENTVAULT_TTL:-300}"
  local body
  body=$(jq -n --arg svc "$service" --argjson scopes "$scopes" --arg agent "$agent_id" --argjson ttl "$ttl" \
    '{service: $svc, scope: $scopes, agentId: $agent, ttl: $ttl}')
  local resp
  resp=$(_agentvault_post "/vault.issueToken" "$body") || return 1
  echo "$resp" | jq -r '.token'
}

agentvault_call() {
  # Usage: agentvault_call <token> <service> <action> [json_payload]
  _agentvault_require || return 1
  local token="$1" service="$2" action="$3" payload="${4:-{}}"
  if [ -z "$token" ] || [ -z "$service" ] || [ -z "$action" ]; then
    echo "usage: agentvault_call <token> <service> <action> [json_payload]" >&2
    return 1
  fi
  local body
  body=$(jq -n --arg t "$token" --arg s "$service" --arg a "$action" --argjson p "$payload" \
    '{token: $t, service: $s, action: $a, params: $p}')
  local resp
  resp=$(_agentvault_post "/vault.call" "$body") || return 1
  echo "$resp" | jq .
}

agentvault_services() {
  # List configured services (requires admin token)
  _agentvault_require || return 1
  local admin_token
  admin_token=$(_agentvault_admin_token) || return 1
  local resp
  resp=$(_agentvault_post "/vault.admin.listServices" "{}" "Authorization" "Bearer $admin_token") || return 1
  echo "$resp" | jq .
}

agentvault_revoke() {
  # Usage: agentvault_revoke [--agent <id>] [--session <id>] [--token <id>] [--reason <text>]
  _agentvault_require || return 1
  local agent="" session="" token_id="" reason="manual revocation"
  while [ $# -gt 0 ]; do
    case "$1" in
      --agent)  agent="$2"; shift 2;;
      --session) session="$2"; shift 2;;
      --token)  token_id="$2"; shift 2;;
      --reason) reason="$2"; shift 2;;
      *) echo "usage: agentvault_revoke [--agent <id>] [--session <id>] [--token <id>] [--reason <text>]" >&2; return 1;;
    esac
  done
  local body="{}"
  body=$(jq -n --arg r "$reason" '{reason: $r}')
  [ -n "$agent" ]    && body=$(echo "$body" | jq --arg a "$agent" '. + {agentId: $a}')
  [ -n "$session" ]  && body=$(echo "$body" | jq --arg s "$session" '. + {sessionId: $s}')
  [ -n "$token_id" ] && body=$(echo "$body" | jq --arg t "$token_id" '. + {tokenId: $t}')
  local resp
  resp=$(_agentvault_post "/vault.revoke" "$body") || return 1
  echo "$resp" | jq .
}

agentvault_audit() {
  # Usage: agentvault_audit [--limit N] [--event <type>] [--agent <id>]
  _agentvault_require || return 1
  local limit=20 event="" agent=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --limit) limit="$2"; shift 2;;
      --event) event="$2"; shift 2;;
      --agent) agent="$2"; shift 2;;
      *) shift;;
    esac
  done
  local filters="{}"
  [ -n "$event" ] && filters=$(echo "$filters" | jq --arg e "$event" '. + {event: $e}')
  [ -n "$agent" ] && filters=$(echo "$filters" | jq --arg a "$agent" '. + {agentId: $a}')
  local body
  body=$(jq -n --argjson f "$filters" --argjson l "$limit" '{filters: $f, limit: $l}')
  local resp
  resp=$(_agentvault_post "/vault.audit.query" "$body") || return 1
  echo "$resp" | jq .
}
