# Contributing to padv

## Development Setup

```bash
uv sync
uv run padv --help
```

## Running Tests

```bash
# Unit tests (no external services needed)
uv run pytest -m "not integration"

# All tests (requires Joern, SCIP, Morcilla, LLM API key)
uv run pytest

# Single test file
uv run pytest tests/test_gates.py

# With coverage
uv run pytest --cov=padv --cov-report=term-missing
```

## External Tool Dependencies

Some tests and CLI commands require external tools:

- **Joern** (`joern`, `joern-parse`): semantic code analysis
- **scip-php**: SCIP indexer for PHP
- **Morcilla**: runtime instrumentation oracle (only for `padv run` / `padv validate`)
- **LLM API key**: agentic stages need `ANTHROPIC_API_KEY` or equivalent

Tests that require these are marked with `@pytest.mark.integration`.

## Submitting Changes

1. Fork the repo and create a feature branch
2. Make your changes
3. Ensure `uv run pytest -m "not integration"` passes
4. Submit a pull request

## Code Style

- Python 3.11+ with type hints
- Keep deterministic gate logic in `padv/gates/engine.py`
- Keep Morcilla contract handling in `padv/oracle/morcilla.py`
- Tests go in `tests/` mirroring the source structure

## Design Principles

- Agents propose and plan; gates decide deterministically
- The Morcilla oracle is the single source of runtime truth
- A candidate is only VALIDATED if it passes all six gates (V0-V6)
- Non-semantic candidates are dropped during fusion
