#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO_DIR="${ROOT_DIR}/targets/mutillidae"
TARGET_RUNTIME_DIR="${ROOT_DIR}/targets/mutillidae-docker"
MORCILLA_SRC_DIR="${MORCILLA_SRC_DIR:?Set MORCILLA_SRC_DIR to your morcilla extension source (https://github.com/mayflower/morcilla)}"
MORCILLA_SYNC_DIR="${TARGET_REPO_DIR}/.docker/morcilla/ext/morcilla"
APP_COMPOSE_FILE="${ROOT_DIR}/docker-compose.mutillidae.yml"
SCANNER_COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
STRICT_CONFIG_PATH="${ROOT_DIR}/padv.mutillidae.strict.toml"
APP_PROJECT="mutillidae-e2e"
SCANNER_PROJECT="haxor-scan"
SCANNER_IMAGE="haxor-scan-padv:latest"
LDAP_BIND_DN="cn=admin,dc=mutillidae,dc=localhost"
# Default credentials for Mutillidae (deliberately vulnerable test application)
LDAP_BIND_PASSWORD="mutillidae"
LDAP_BASE_DN="dc=mutillidae,dc=localhost"

log() {
  printf '[mutillidae-e2e] %s\n' "$*"
}

contains_text() {
  local haystack="$1"
  local needle="$2"
  grep -Fq -- "${needle}" <<<"${haystack}"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

clone_or_update_repo() {
  local url="$1"
  local dir="$2"
  mkdir -p "${ROOT_DIR}/targets"
  if [ ! -d "${dir}/.git" ]; then
    log "cloning ${url} into ${dir}"
    git clone --depth 1 "${url}" "${dir}"
    return 0
  fi

  log "updating checkout ${dir}"
  git -C "${dir}" fetch --depth 1 origin
  local branch
  branch="$(git -C "${dir}" symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null | sed 's@^origin/@@')"
  if [ -z "${branch}" ]; then
    branch="$(git -C "${dir}" branch --show-current)"
  fi
  git -C "${dir}" checkout "${branch}"
  git -C "${dir}" reset --hard "origin/${branch}"
}

sync_morcilla_sources() {
  if [ ! -d "${MORCILLA_SRC_DIR}" ]; then
    echo "morcilla source dir not found: ${MORCILLA_SRC_DIR}" >&2
    exit 1
  fi
  mkdir -p "${MORCILLA_SYNC_DIR}"
  log "syncing morcilla extension sources"
  rsync -a --delete \
    --exclude='.DS_Store' \
    --exclude='*.o' \
    --exclude='*.lo' \
    --exclude='*.dep' \
    --exclude='*.la' \
    --exclude='*.libs' \
    "${MORCILLA_SRC_DIR}/" "${MORCILLA_SYNC_DIR}/"
}

start_mutillidae_stack() {
  log "starting Mutillidae stack (database + directory + www)"
  docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" up -d --build database directory www
}

stop_mutillidae_stack() {
  log "stopping Mutillidae stack"
  docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" down --remove-orphans
}

reset_mutillidae_stack() {
  log "resetting Mutillidae stack"
  docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" down -v --remove-orphans
}

wait_for_http() {
  local url="$1"
  local timeout_secs="${2:-180}"
  local elapsed=0
  until curl -fsS "${url}" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    if [ "${elapsed}" -ge "${timeout_secs}" ]; then
      echo "timeout waiting for ${url}" >&2
      return 1
    fi
  done
}

bootstrap_database() {
  log "triggering Mutillidae database build"
  local output
  output="$(mktemp)"
  curl -fsS "http://127.0.0.1:18080/set-up-database.php" >"${output}"
  if ! grep -Eqi 'database|setup|success|table' "${output}"; then
    echo "database bootstrap did not return expected content" >&2
    tail -n 80 "${output}" >&2 || true
    rm -f "${output}"
    exit 1
  fi
  rm -f "${output}"

  docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" exec -T database \
    mariadb -uroot -pmutillidae -e "SELECT COUNT(*) AS table_count FROM information_schema.tables WHERE table_schema='mutillidae';" \
    | grep -Eq '[1-9][0-9]*'
}

seed_ldap_directory() {
  log "seeding LDAP directory"
  local search_output
  search_output="$(docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" exec -T directory \
    ldapsearch -x -H ldap://127.0.0.1:389 -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PASSWORD}" \
    -b "${LDAP_BASE_DN}" '(uid=fred)' dn 2>/dev/null || true)"
  if contains_text "${search_output}" 'dn: cn=fred'; then
    log "LDAP seed already present"
    return 0
  fi

  if ! docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" exec -T directory \
    ldapadd -c -x -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PASSWORD}" \
    -H ldap://127.0.0.1:389 -f /seed-ldif/mutillidae.ldif >/dev/null 2>&1; then
    log "ldapadd reported existing entries, verifying seed state"
  fi

  docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" exec -T directory \
    ldapsearch -x -H ldap://127.0.0.1:389 -D "${LDAP_BIND_DN}" -w "${LDAP_BIND_PASSWORD}" \
    -b "${LDAP_BASE_DN}" '(uid=fred)' dn | grep -Fq 'dn: cn=fred'
}

validate_mutillidae_home() {
  log "validating Mutillidae homepage"
  local body
  body="$(curl -fsS "http://127.0.0.1:18080/")"
  contains_text "${body}" 'OWASP Mutillidae'
}

validate_morcilla_runtime() {
  log "checking morcilla extension in www container"
  docker compose -f "${APP_COMPOSE_FILE}" --project-name "${APP_PROJECT}" exec -T www php -m | grep -qi '^morcilla$'

  log "checking morcilla telemetry headers"
  local headers
  headers="$(curl -fsS -D - -o /dev/null \
    -H 'Morcilla-Key: test-key' \
    -H 'Morcilla-Intercept: mysqli_query' \
    -H 'Morcilla-Correlation: smoke-1' \
    'http://127.0.0.1:18080/')"
  grep -qi '^X-Morcilla-Status:' <<<"${headers}"
}

ensure_scanner_image() {
  if [ "${PADV_FORCE_BUILD:-0}" = "1" ]; then
    log "building scanner image (forced)"
    docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" build padv
    return 0
  fi

  if docker image inspect "${SCANNER_IMAGE}" >/dev/null 2>&1; then
    log "scanner image already present, skipping rebuild"
    return 0
  fi

  log "building scanner image"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" build padv
}

run_scanner_tests() {
  log "starting scanner stack (joern)"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" up -d joern

  ensure_scanner_image

  log "running padv analyze"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" run --rm padv \
    analyze \
    --config /workspace/haxor/padv.mutillidae.strict.toml \
    --repo-root /workspace/targets/mutillidae \
    --mode variant

  log "running padv strict run"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" run --rm padv \
    run \
    --config /workspace/haxor/padv.mutillidae.strict.toml \
    --repo-root /workspace/targets/mutillidae \
    --mode variant

  log "listing generated bundles"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" run --rm padv \
    list \
    --config /workspace/haxor/padv.mutillidae.strict.toml \
    bundles
}

cmd_setup() {
  require_cmd git
  require_cmd docker
  require_cmd rsync
  require_cmd curl

  clone_or_update_repo https://github.com/webpwnized/mutillidae.git "${TARGET_REPO_DIR}"
  clone_or_update_repo https://github.com/webpwnized/mutillidae-docker.git "${TARGET_RUNTIME_DIR}"
  sync_morcilla_sources
  start_mutillidae_stack
  wait_for_http "http://127.0.0.1:18080/" 240
  bootstrap_database
  seed_ldap_directory
  validate_mutillidae_home
  validate_morcilla_runtime
  log "setup completed"
}

cmd_test() {
  require_cmd docker
  require_cmd curl

  wait_for_http "http://127.0.0.1:18080/" 120 || cmd_setup
  bootstrap_database
  seed_ldap_directory
  validate_mutillidae_home
  validate_morcilla_runtime
  run_scanner_tests
  log "strict padv test run completed"
}

usage() {
  cat <<'USAGE'
Usage: scripts/mutillidae_e2e.sh <command>

Commands:
  setup   Clone/update Mutillidae + runtime, sync Morcilla, start stack, bootstrap DB/LDAP, validate instrumentation
  test    Run strict padv analyze+run against Mutillidae (runs setup first when needed)
  assess  Run phased integration assessment and persist matrix + gap priorities
  reset   Tear down stack and named volumes for a clean bootstrap
  stop    Tear down stack without deleting volumes
USAGE
}

main() {
  local command="${1:-}"
  case "${command}" in
    setup)
      cmd_setup
      ;;
    test)
      cmd_test
      ;;
    assess)
      python3 "${ROOT_DIR}/scripts/mutillidae_integration_assess.py" --phase full
      ;;
    reset)
      reset_mutillidae_stack
      ;;
    stop)
      stop_mutillidae_stack
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
