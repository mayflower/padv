# padv

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/mayflower/padv/actions/workflows/test.yml/badge.svg)](https://github.com/mayflower/padv/actions/workflows/test.yml)

`padv` is a local CLI for discovery, detection, and deterministic validation of PHP security vulnerabilities.

It combines semantic static analysis ([SCIP](https://github.com/sourcegraph/scip), [Joern](https://github.com/joernio/joern)) with agentic runtime exploitation (LangGraph/DeepAgents) and strict gate-based validation via a [Morcilla](https://github.com/mayflower/morcilla)-instrumented PHP target.

Core philosophy: **agents propose and plan; gates decide deterministically based on runtime evidence.**

It is designed for local or sandbox targets only.
It does not scan external targets, generate advisories, or patch code.

## Architecture

```
CLI (padv analyze | run | validate)
  -> LangGraph state machine (discovery -> synthesis -> validation -> gates)

Discovery:        SCIP + Joern (semantic static analysis) + Playwright (web)
Agent stack:      DeepAgents (proposer, skeptic, scheduler, experiment)
Runtime oracle:   Morcilla instrumentation headers
Validation:       Deterministic gates V0-V6 (no LLM in the decision path)
```

A candidate is only **VALIDATED** if it passes all six gates (V0-V6). There are no exceptions or overrides.

## Requirements

- Python 3.11+ and [uv](https://docs.astral.sh/uv/)
- [Joern](https://github.com/joernio/joern) (`joern`, `joern-parse` on PATH)
- [scip-php](https://github.com/davidrjenni/scip-php) (`scip-php` on PATH)
- An LLM API key (e.g. `ANTHROPIC_API_KEY`) for agentic stages
- [Morcilla](https://github.com/mayflower/morcilla)-instrumented PHP target (only for `padv run` / `padv validate`, not needed for `padv analyze`)

## Install

```bash
uv sync
```

Run the CLI without activating a venv:

```bash
uv run padv --help
```

Alternative editable install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
padv --help
```

## Configure

Create a local config from the example:

```bash
cp padv.example.toml padv.toml
```

Important sections in `padv.toml`:

- `[target]`: target base URL and request timeout
- `[oracle]`: Morcilla request/response header contract and API key
- `[store]`: output directory, default `.padv`
- `[auth]`: optional login material for authenticated discovery
- `[joern]`: Joern execution settings
- `[scip]`: SCIP execution settings
- `[llm]`: provider/model/API key env
- `[agent]`: LangGraph/DeepAgents settings
- `[web]`: Playwright-based web discovery settings

Minimum practical setup:

1. point `[target].base_url` at your local app
2. set `[oracle].api_key`
3. ensure `[llm].api_key_env` exists in your shell
4. verify `joern`, `joern-parse`, `scip-php` are callable

Example:

```bash
export ANTHROPIC_API_KEY=...
uv run padv analyze --config padv.toml --repo-root /path/to/php/repo
```

## Core Commands

Top-level help:

```bash
uv run padv --help
```

Current commands:

- `padv analyze`
- `padv run`
- `padv analyze-failures`
- `padv validate`
- `padv sandbox`
- `padv list`
- `padv show`
- `padv export`

### `padv analyze`

Discovery and synthesis only. No runtime validation.

```bash
uv run padv analyze \
  --config padv.toml \
  --repo-root /path/to/php/repo
```

Useful flags:

- `--mode variant|delta|batch`
- `--no-progress`
- `--resume [RUN_ID|latest]`

Example:

```bash
uv run padv analyze \
  --config padv.toml \
  --repo-root ./targets/mutillidae \
  --mode variant
```

### `padv run`

Full flow: discovery, research, runtime validation, deterministic gates.

```bash
uv run padv run \
  --config padv.toml \
  --repo-root /path/to/php/repo
```

Example:

```bash
uv run padv run \
  --config padv.mutillidae.strict.toml \
  --repo-root ./targets/mutillidae \
  --mode variant
```

### `padv validate`

Validate existing candidates or analyze a repo and then validate.

Validate already persisted candidates:

```bash
uv run padv validate \
  --config padv.toml
```

Validate only selected candidates:

```bash
uv run padv validate \
  --config padv.toml \
  --candidate-id cand-00010 \
  --candidate-id cand-00024
```

Analyze and validate in one call:

```bash
uv run padv validate \
  --config padv.toml \
  --repo-root /path/to/php/repo
```

### `padv analyze-failures`

Aggregate historical failure patterns from the store.

```bash
uv run padv analyze-failures \
  --config padv.toml \
  --format table
```

JSON output:

```bash
uv run padv analyze-failures \
  --config padv.toml \
  --format json
```

### `padv sandbox`

Runs helper commands from `[sandbox]` in the config.

```bash
uv run padv sandbox --config padv.toml status
uv run padv sandbox --config padv.toml logs
uv run padv sandbox --config padv.toml deploy
uv run padv sandbox --config padv.toml reset
```

If your `[sandbox]` commands are empty, these are no-ops or fail accordingly.

### `padv list`

Inspect stored artifacts.

```bash
uv run padv list --config padv.toml candidates
uv run padv list --config padv.toml bundles
uv run padv list --config padv.toml runs
uv run padv list --config padv.toml resumes
```

### `padv show`

Show details for one stored object.

```bash
uv run padv show --config padv.toml --run-id run-1234abcd
uv run padv show --config padv.toml --bundle-id bundle-run-1234abcd-cand-00010
uv run padv show --config padv.toml --candidate-id cand-00010
```

### `padv export`

Export one bundle to a file.

```bash
uv run padv export \
  --config padv.toml \
  --bundle-id bundle-run-1234abcd-cand-00010 \
  --output /tmp/bundle.json
```

## Progress And Resume

`padv analyze`, `padv run`, and `padv validate` emit live progress by default.
Disable it with:

```bash
--no-progress
```

Interrupted runs can be resumed:

Resume the latest compatible run:

```bash
uv run padv run \
  --config padv.toml \
  --repo-root /path/to/php/repo \
  --resume
```

Resume a specific run:

```bash
uv run padv analyze \
  --config padv.toml \
  --repo-root /path/to/php/repo \
  --resume analyze-28062a3a11
```

List resumable metadata:

```bash
uv run padv list --config padv.toml resumes
```

## What Gets Written To Disk

By default, output goes to `.padv/`.

Important paths:

- `.padv/candidates.json`
- `.padv/static_evidence.json`
- `.padv/bundles/`
- `.padv/runs/`
- `.padv/artifacts/`
- `.padv/resume/`
- `.padv/langgraph/`

Useful things to inspect after a run:

- stage snapshots: `.padv/runs/<run-id>/stages/*.json`
- run-scoped agent workspace: `.padv/langgraph/<run-id>/workspace/`
- persisted summaries and findings: `.padv/artifacts/`

## What `analyze` vs `run` vs `validate` Actually Mean

- `analyze`
  - does semantic discovery, web discovery, auth setup, research, hypotheses, skeptic, frontier updates
  - does not run runtime validation or gates

- `run`
  - does everything in `analyze`
  - then builds validation plans, executes runtime requests, reduces evidence, and runs deterministic gates

- `validate`
  - works on existing candidates or freshly analyzed candidates
  - is useful when you want to focus on runtime validation without running the whole research loop again

## Docker

The repo ships a scanner container.

Files:

- `Dockerfile`
- `docker-compose.yml`
- `padv.docker.toml`

Example:

```bash
docker compose up -d joern

docker compose run --rm padv \
  analyze \
  --config /workspace/haxor/padv.docker.toml \
  --repo-root /workspace/targets/mutillidae
```

## Mutillidae Example

Strict local Mutillidae flow is already wired in this repo.

Relevant files:

- `scripts/mutillidae_e2e.sh`
- `docker-compose.mutillidae.yml`
- `padv.mutillidae.strict.toml`

Bring up and bootstrap the stack:

```bash
./scripts/mutillidae_e2e.sh setup
```

Run strict analyze + run against Mutillidae:

```bash
./scripts/mutillidae_e2e.sh test
```

## Expected Failure Modes

Common reasons a run fails early:

- `joern`, `joern-parse`, or `scip-php` missing
- LLM API key env var missing
- Morcilla target not instrumented, so runtime validation cannot produce oracle evidence
- target base URL wrong or app not reachable
- auth is disabled or unset for an auth-gated target

If discovery succeeds but validation quality is poor, inspect:

- `.padv/runs/<run-id>/stages/`
- `.padv/artifacts/`
- `.padv/bundles/`
- `.padv/resume/`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and contribution guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
