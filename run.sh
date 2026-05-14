#!/usr/bin/env bash
#
# run.sh — one-click startup / teardown for the Malicious Email Scorer stack.
#
#   ./run.sh              Build and start db + backend + dashboard, wait for
#                         health, start the ngrok tunnel, print a summary.
#   ./run.sh --no-tunnel  Same, but skip the ngrok tunnel.
#   ./run.sh --stop       Tear down all containers and the ngrok tunnel.
#   ./run.sh --help       Show usage.
#
set -euo pipefail

# --------------------------------------------------------------------------
# Run from the project root regardless of where the script is invoked from.
# --------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
BACKEND_URL="http://localhost:8000"
DASHBOARD_URL="http://localhost:8501"
HEALTH_PATH="/docs"                       # backend is "up" once Swagger responds
NGROK_DOMAIN="${NGROK_DOMAIN:-routing-recant-worry.ngrok-free.dev}"
NGROK_INSPECTOR="http://127.0.0.1:4040"
NGROK_PID_FILE=".ngrok.pid"
NGROK_LOG_FILE=".ngrok.log"
HEALTH_RETRIES=30                        
HEALTH_INTERVAL=2

# --------------------------------------------------------------------------
# Colored output helpers
# --------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'; C_BOLD=$'\033[1m'
else
  C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""
fi

info()    { printf '%s[INFO]  %s%s\n' "$C_BLUE" "$1" "$C_RESET"; }
step()    { printf '%s%s==> %s%s\n' "$C_BOLD" "$C_BLUE" "$1" "$C_RESET"; }
success() { printf '%s[OK]    %s%s\n' "$C_GREEN" "$1" "$C_RESET"; }
warn()    { printf '%s[WARN]  %s%s\n' "$C_YELLOW" "$1" "$C_RESET"; }
error()   { printf '%s[ERROR] %s%s\n' "$C_RED" "$1" "$C_RESET" >&2; }

# --------------------------------------------------------------------------
# Resolve the docker compose command 
# --------------------------------------------------------------------------
detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    error "Neither 'docker compose' nor 'docker-compose' is available."
    error "Install Docker Desktop / the Compose plugin and retry."
    exit 1
  fi
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    error "Docker is not installed or not on PATH."
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    error "Docker daemon is not running. Start Docker Desktop and retry."
    exit 1
  fi
}

# --------------------------------------------------------------------------
# Teardown — stop containers, network, and the ngrok tunnel.
# --------------------------------------------------------------------------
stop_stack() {
  step "Tearing down the Malicious Email Scorer stack"

  if [[ -f "$NGROK_PID_FILE" ]]; then
    local pid
    pid="$(cat "$NGROK_PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      success "Stopped ngrok tunnel (pid $pid)."
    fi
    rm -f "$NGROK_PID_FILE"
  else
    # Best-effort: catch a tunnel started outside this script.
    pkill -f "ngrok http .*${NGROK_DOMAIN}" 2>/dev/null && \
      success "Stopped a running ngrok tunnel." || true
  fi
  rm -f "$NGROK_LOG_FILE"

  detect_compose
  "${COMPOSE[@]}" down
  success "Containers stopped and network removed."
  printf '%s\n' "${C_YELLOW}Note: the Postgres volume is preserved. Use '${COMPOSE[*]} down -v' to wipe it.${C_RESET}"
}

# --------------------------------------------------------------------------
# Health check — poll the backend until Swagger responds (or give up).
# --------------------------------------------------------------------------
wait_for_backend() {
  step "Waiting for the backend to become healthy"
  local attempt=1
  while (( attempt <= HEALTH_RETRIES )); do
    if curl -fsS -o /dev/null "${BACKEND_URL}${HEALTH_PATH}" 2>/dev/null; then
      success "Backend is healthy (${BACKEND_URL}${HEALTH_PATH} responding)."
      return 0
    fi
    printf '   ...attempt %d/%d — not ready yet\r' "$attempt" "$HEALTH_RETRIES"
    sleep "$HEALTH_INTERVAL"
    (( attempt++ ))
  done
  printf '\n'
  error "Backend did not become healthy within $(( HEALTH_RETRIES * HEALTH_INTERVAL ))s."
  warn  "Inspect the logs with: ${COMPOSE[*]} logs backend"
  exit 1
}

wait_for_db() {
  step "Waiting for PostgreSQL to report healthy"
  local attempt=1
  while (( attempt <= HEALTH_RETRIES )); do
    local status
    status="$("${COMPOSE[@]}" ps db --format '{{.Health}}' 2>/dev/null || true)"
    if [[ "$status" == "healthy" ]]; then
      success "PostgreSQL is healthy."
      return 0
    fi
    printf '   ...attempt %d/%d — db status: %s\r' "$attempt" "$HEALTH_RETRIES" "${status:-starting}"
    sleep "$HEALTH_INTERVAL"
    (( attempt++ ))
  done
  printf '\n'
  warn "Could not confirm DB health via compose; continuing — the backend check will catch a real failure."
}

# --------------------------------------------------------------------------
# ngrok tunnel — optional, only if ngrok is installed.
# --------------------------------------------------------------------------
start_tunnel() {
  step "Starting the ngrok tunnel"

  if ! command -v ngrok >/dev/null 2>&1; then
    warn "ngrok is not installed — skipping the public tunnel."
    warn "The backend is still reachable locally at ${BACKEND_URL}."
    TUNNEL_URL=""
    return 0
  fi

  # Reuse an already-running tunnel rather than starting a duplicate.
  if curl -fsS "${NGROK_INSPECTOR}/api/tunnels" >/dev/null 2>&1; then
    warn "An ngrok tunnel is already running — reusing it."
  else
    nohup ngrok http --domain="${NGROK_DOMAIN}" 8000 \
      > "$NGROK_LOG_FILE" 2>&1 &
    echo $! > "$NGROK_PID_FILE"
    # Give ngrok a moment to bring up its local inspector API.
    local attempt=1
    while (( attempt <= 10 )); do
      if curl -fsS "${NGROK_INSPECTOR}/api/tunnels" >/dev/null 2>&1; then
        break
      fi
      sleep 1
      (( attempt++ ))
    done
  fi

  # Pull the live public URL from the inspector API; fall back to the
  # reserved static domain if parsing fails.
  TUNNEL_URL="$(curl -fsS "${NGROK_INSPECTOR}/api/tunnels" 2>/dev/null \
    | grep -o '"public_url":"https:[^"]*"' \
    | head -n1 | cut -d'"' -f4 || true)"
  if [[ -z "$TUNNEL_URL" ]]; then
    TUNNEL_URL="https://${NGROK_DOMAIN}"
    warn "Could not read the ngrok API — assuming the reserved domain ${TUNNEL_URL}."
  else
    success "ngrok tunnel is live."
  fi
}

# --------------------------------------------------------------------------
# Final summary
# --------------------------------------------------------------------------
print_summary() {
  local line="────────────────────────────────────────────────────────────"
  printf '\n%s%s%s\n' "$C_GREEN" "$line" "$C_RESET"
  printf '%s%s  Malicious Email Scorer — system is ready%s\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
  printf '%s%s%s\n\n' "$C_GREEN" "$line" "$C_RESET"

  printf '  %sFastAPI backend %s   %s/docs\n'   "$C_BOLD" "$C_RESET" "$BACKEND_URL"
  printf '  %sStreamlit dashboard%s %s\n'        "$C_BOLD" "$C_RESET" "$DASHBOARD_URL"
  if [[ -n "${TUNNEL_URL:-}" ]]; then
    printf '  %sPublic tunnel (ngrok)%s %s\n'    "$C_BOLD" "$C_RESET" "$TUNNEL_URL"
    printf '  %sngrok inspector%s     %s\n'      "$C_BOLD" "$C_RESET" "$NGROK_INSPECTOR"
  fi

  printf '\n'
  if [[ -n "${TUNNEL_URL:-}" ]]; then
    success "The Gmail Add-on can now connect — point BACKEND_URL in apps-script/Code.gs at:"
    printf '         %s%s/api/analyze%s\n' "$C_BOLD" "$TUNNEL_URL" "$C_RESET"
  else
    warn "No public tunnel is running. Start one before connecting the Gmail Add-on:"
    printf '         ngrok http --domain=%s 8000\n' "$NGROK_DOMAIN"
  fi
  printf '\n%sStop everything with:%s  ./run.sh --stop\n\n' "$C_BOLD" "$C_RESET"
}

# --------------------------------------------------------------------------
# Startup flow
# --------------------------------------------------------------------------
start_stack() {
  local with_tunnel="$1"

  printf '%s%sMalicious Email Scorer — startup%s\n\n' "$C_BOLD" "$C_BLUE" "$C_RESET"

  # 1. Environment check.
  step "Checking the environment"
  if [[ ! -f .env ]]; then
    error "No .env file found in $(pwd)."
    warn  "Create one from the template:  cp .env.example .env"
    warn  "Then fill in POSTGRES_* and (optionally) VIRUSTOTAL_API_KEY."
    exit 1
  fi
  success ".env file found."

  require_docker
  detect_compose
  success "Docker and Compose are available."

  # 2. Orchestration.
  step "Building and starting containers (db + backend + dashboard)"
  "${COMPOSE[@]}" up --build -d
  success "Containers started in the background."

  # 3. Wait for services.
  wait_for_db
  wait_for_backend

  # 4. Tunnelling (optional).
  if [[ "$with_tunnel" == "true" ]]; then
    start_tunnel
  else
    info "Tunnel skipped (--no-tunnel)."
    TUNNEL_URL=""
  fi

  # 5. User feedback.
  print_summary
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
usage() {
  cat <<EOF
${C_BOLD}Malicious Email Scorer — run.sh${C_RESET}

Usage:
  ./run.sh                Build & start the full stack, wait for health,
                          start the ngrok tunnel, and print a summary.
  ./run.sh --no-tunnel    Start the stack but skip the ngrok tunnel.
  ./run.sh --stop         Tear down all containers and the ngrok tunnel.
  ./run.sh --help         Show this message.

Environment:
  NGROK_DOMAIN            Override the reserved ngrok domain
                          (default: ${NGROK_DOMAIN}).
EOF
}

main() {
  case "${1:-}" in
    --stop)
      stop_stack
      ;;
    --no-tunnel)
      start_stack "false"
      ;;
    --help|-h)
      usage
      ;;
    "")
      start_stack "true"
      ;;
    *)
      error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
}

main "$@"
