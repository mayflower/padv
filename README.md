# padv

`padv` is a Python CLI for discovery, detection, and deterministic validation of PHP security candidates using a LangGraph workflow with DeepAgents proposer/planner nodes plus Morcilla/Zend runtime oracle headers.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp padv.example.toml padv.toml
padv analyze --config padv.toml --repo-root /path/to/php/repo
```

`run/analyze/validate` remain stable CLI commands, but now execute through a graph pipeline:

- static discovery: source research + Joern + SCIP
- web discovery: browser-use (budgeted, with deterministic HTTP fallback)
- candidate synthesis/planning: DeepAgents (Anthropic-first, deterministic fallback)
- validation decision: deterministic gates only

## Docker Setup

This repo now ships a full Docker stack (`padv` + Joern server):

- [Dockerfile](/Users/johann/src/ml/haxor/Dockerfile)
- [docker-compose.yml](/Users/johann/src/ml/haxor/docker-compose.yml)
- [padv.docker.toml](/Users/johann/src/ml/haxor/padv.docker.toml)

Default target mount is `./targets -> /workspace/targets`.

```bash
mkdir -p targets
# example: ln -s ../morcilla targets/morcilla

docker compose up -d joern
docker compose run --rm padv analyze \
  --config /workspace/haxor/padv.docker.toml \
  --repo-root /workspace/targets/morcilla
```

If you want to mount a different host folder as `/workspace/targets`, set `PADV_TARGETS_DIR`:

```bash
PADV_TARGETS_DIR=../morcilla docker compose run --rm padv analyze \
  --config /workspace/haxor/padv.docker.toml \
  --repo-root /workspace/targets
```

## phpMyFAQ E2E Flow

Automated setup and strict scan workflow for `phpMyFAQ`:

- [scripts/phpmyfaq_e2e.sh](/Users/johann/src/ml/haxor/scripts/phpmyfaq_e2e.sh)
- [docker-compose.phpmyfaq.yml](/Users/johann/src/ml/haxor/docker-compose.phpmyfaq.yml)
- [docker/phpmyfaq/apache-morcilla.Dockerfile](/Users/johann/src/ml/haxor/docker/phpmyfaq/apache-morcilla.Dockerfile)
- [padv.phpmyfaq.strict.toml](/Users/johann/src/ml/haxor/padv.phpmyfaq.strict.toml)

Run full local setup (clone/update + bootstrap + Morcilla validation):

```bash
./scripts/phpmyfaq_e2e.sh setup
```

Run strict `padv` test pass (`analyze` + `run`) against the bootstrapped app:

```bash
./scripts/phpmyfaq_e2e.sh test
```

Run phased integration assessment (Phase A stabilization + Phase B requirement matrix):

```bash
./scripts/phpmyfaq_e2e.sh assess
```

## Joern Backend

`padv` supports two Joern execution modes:

- Script mode (default): run `joern --script` with `padv/static/joern/queries/owasp_php.sc`.
- HTTP mode: run `joern-parse` for PHP CPG generation, then execute queries via Joern HTTP `/query-sync`.

- Enable in `padv.toml`:
  - `[joern].enabled = true`
  - `[joern].command = "joern"` (or absolute binary path)
  - `[joern].parse_command = "joern-parse"`
  - `[joern].parse_language = "PHP"`
  - `[joern].use_http_api = false` (set true to use `server_url`)
  - `[joern].server_url = "http://127.0.0.1:8080"`
  - `[joern].script_path = ""` (empty uses built-in script)
- Joern fallback-to-regex is not supported. Joern execution errors are hard-fail.

## New Config Sections

The config requires explicit strict sections:

- `[llm]` provider/model/api-key env and generation limits
- `[agent]` DeepAgents and iteration controls
- `[scip]` generate+ingest settings (`hard_fail = true` by default)
- `[web]` browser-use budgets and fallback controls
- `[auth]` optional credentials/profile fields for authenticated web discovery
