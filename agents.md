# Agent Instructions

## Scope locks
- Never add reporting/advisory generation or patching automation.
- Do not call external targets; sandbox-only execution.

## Architecture rules
- Keep deterministic gate logic in `padv/gates/engine.py`.
- Keep Morcilla contract handling in `padv/oracle/morcilla.py`.
- Keep config schema changes backward-compatible where possible.

## Delivery protocol
1. Update/confirm spec assumptions.
2. Add or update tests.
3. Implement.
4. Run local unit/integration checks.
5. Summarize gate-impacting changes.
