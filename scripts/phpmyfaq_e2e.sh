#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_REPO_DIR="${ROOT_DIR}/targets/phpMyFAQ"
TARGET_APP_DIR="${TARGET_REPO_DIR}/phpmyfaq"
MORCILLA_SRC_DIR="/Users/johann/src/ml/php-src/ext/morcilla"
MORCILLA_SYNC_DIR="${TARGET_REPO_DIR}/.docker/morcilla/ext/morcilla"
PMF_COMPOSE_FILE="${ROOT_DIR}/docker-compose.phpmyfaq.yml"
SCANNER_COMPOSE_FILE="${ROOT_DIR}/docker-compose.yml"
STRICT_CONFIG_PATH="${ROOT_DIR}/padv.phpmyfaq.strict.toml"
PMF_PROJECT="phpmyfaq-e2e"
SCANNER_PROJECT="haxor-scan"
SETUP_COOKIE_JAR="${ROOT_DIR}/.padv/phpmyfaq-setup.cookies.txt"

log() {
  printf '[phpmyfaq-e2e] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

clone_or_update_repo() {
  mkdir -p "${ROOT_DIR}/targets"
  if [ ! -d "${TARGET_REPO_DIR}/.git" ]; then
    log "cloning phpMyFAQ into ${TARGET_REPO_DIR}"
    git clone --branch main git@github.com:johannhartmann/phpMyFAQ.git "${TARGET_REPO_DIR}"
  else
    log "updating phpMyFAQ checkout"
    git -C "${TARGET_REPO_DIR}" fetch --all --prune
    git -C "${TARGET_REPO_DIR}" checkout main
    git -C "${TARGET_REPO_DIR}" pull --ff-only origin main
  fi
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

ensure_phpmyfaq_dependencies() {
  if [ ! -f "${TARGET_REPO_DIR}/vendor/autoload.php" ]; then
    log "installing composer dependencies"
    docker run --rm \
      -u "$(id -u):$(id -g)" \
      -v "${TARGET_REPO_DIR}:/app" \
      -w /app \
      composer:latest \
      composer install --verbose --ignore-platform-reqs --no-interaction
  else
    log "composer dependencies already installed"
  fi
}

start_phpmyfaq_stack() {
  log "starting phpMyFAQ stack (MariaDB + Apache)"
  docker compose -f "${PMF_COMPOSE_FILE}" --project-name "${PMF_PROJECT}" up -d --build mariadb apache
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

bootstrap_phpmyfaq() {
  local db_config_file="${TARGET_APP_DIR}/content/core/config/database.php"

  if [ -f "${db_config_file}" ]; then
    log "bootstrap already completed (database.php exists), skipping install"
    return 0
  fi

  mkdir -p "${ROOT_DIR}/.padv"
  rm -f "${SETUP_COOKIE_JAR}"

  log "opening setup page"
  curl -fsS -c "${SETUP_COOKIE_JAR}" -b "${SETUP_COOKIE_JAR}" "http://127.0.0.1:18080/setup/" >/dev/null

  log "submitting installation form"
  local install_output
  install_output="$(mktemp)"

  curl -fsS -L \
    -c "${SETUP_COOKIE_JAR}" -b "${SETUP_COOKIE_JAR}" \
    -X POST "http://127.0.0.1:18080/setup/install" \
    --data-urlencode "sql_type=pdo_mysql" \
    --data-urlencode "sql_server=mariadb" \
    --data-urlencode "sql_port=3306" \
    --data-urlencode "sql_user=phpmyfaq" \
    --data-urlencode "sql_password=phpmyfaq" \
    --data-urlencode "sql_db=phpmyfaq" \
    --data-urlencode "sqltblpre=" \
    --data-urlencode "language=en" \
    --data-urlencode "permLevel=basic" \
    --data-urlencode "realname=Admin Local" \
    --data-urlencode "email=admin@local.test" \
    --data-urlencode "loginname=admin" \
    --data-urlencode "password=Admin123!" \
    --data-urlencode "password_retyped=Admin123!" \
    >"${install_output}"

  if grep -qi "installation worked like a charm" "${install_output}" || [ -f "${db_config_file}" ]; then
    log "phpMyFAQ bootstrap completed"
    rm -f "${install_output}"
    return 0
  fi

  echo "phpMyFAQ setup did not report success" >&2
  tail -n 80 "${install_output}" >&2 || true
  rm -f "${install_output}"
  exit 1
}

validate_morcilla_runtime() {
  log "checking morcilla extension in Apache container"
  docker compose -f "${PMF_COMPOSE_FILE}" --project-name "${PMF_PROJECT}" exec -T apache php -m | grep -qi '^morcilla$'

  log "checking morcilla telemetry headers"
  local headers
  headers="$(curl -fsSI \
    -H 'Morcilla-Key: test-key' \
    -H 'Morcilla-Intercept: mysqli_query' \
    -H 'Morcilla-Correlation: smoke-1' \
    'http://127.0.0.1:18080/index.php')"

  printf '%s\n' "${headers}" | grep -qi '^X-Morcilla-Status:'
}

ensure_phpmyfaq_runtime_config() {
  log "enforcing deterministic phpMyFAQ runtime config"
  docker compose -f "${PMF_COMPOSE_FILE}" --project-name "${PMF_PROJECT}" exec -T mariadb \
    mariadb -uroot -proot phpmyfaq \
    -e "INSERT INTO faqconfig (config_name, config_value) VALUES ('main.referenceURL', 'http://127.0.0.1:18080') ON DUPLICATE KEY UPDATE config_value=VALUES(config_value);"
}

run_scanner_tests() {
  log "starting scanner stack (joern)"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" up -d joern

  log "running padv analyze"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" run --rm padv \
    analyze \
    --config /workspace/haxor/padv.phpmyfaq.strict.toml \
    --repo-root /workspace/targets/phpMyFAQ \
    --mode variant

  log "running padv strict run"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" run --rm padv \
    run \
    --config /workspace/haxor/padv.phpmyfaq.strict.toml \
    --repo-root /workspace/targets/phpMyFAQ \
    --mode variant

  log "listing generated bundles"
  docker compose -f "${SCANNER_COMPOSE_FILE}" --project-name "${SCANNER_PROJECT}" run --rm padv \
    list \
    --config /workspace/haxor/padv.phpmyfaq.strict.toml \
    bundles
}

cmd_setup() {
  require_cmd git
  require_cmd docker
  require_cmd rsync
  require_cmd curl

  clone_or_update_repo
  sync_morcilla_sources
  ensure_phpmyfaq_dependencies
  start_phpmyfaq_stack
  log "waiting for setup endpoint"
  wait_for_http "http://127.0.0.1:18080/setup/" 240
  bootstrap_phpmyfaq
  ensure_phpmyfaq_runtime_config
  validate_morcilla_runtime
  log "setup completed"
}

cmd_test() {
  require_cmd docker
  require_cmd curl

  if [ ! -f "${TARGET_APP_DIR}/content/core/config/database.php" ]; then
    log "database.php missing -> running setup first"
    cmd_setup
  fi

  wait_for_http "http://127.0.0.1:18080/index.php" 120
  ensure_phpmyfaq_runtime_config
  validate_morcilla_runtime
  run_scanner_tests
  log "strict padv test run completed"
}

usage() {
  cat <<'USAGE'
Usage: scripts/phpmyfaq_e2e.sh <command>

Commands:
  setup   Clone/update phpMyFAQ, sync Morcilla, start stack, bootstrap install, validate instrumentation
  test    Run strict padv analyze+run against phpMyFAQ (runs setup first when needed)
  assess  Run phased integration assessment (A/B) and persist matrix + gap priorities
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
      python3 "${ROOT_DIR}/scripts/phpmyfaq_integration_assess.py" --phase full
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
