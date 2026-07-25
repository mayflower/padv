"""A witness contract may only require flags the system can actually produce.

`csrf_invariant_missing` required `csrf_missing_token_acceptance` and
`idor_invariant_missing` required `idor_bypass`. Neither flag is emitted
anywhere, so both classes failed V3 on every candidate and were reported as
REFUTED — a confident negative result for an experiment that could not run.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from padv.config.schema import load_config
from padv.gates.engine import evaluate_candidate
from padv.models import Candidate, RuntimeCall, RuntimeEvidence, StaticEvidence, Witness, WitnessContract
from padv.taxonomy import KNOWN_WITNESS_FLAGS
from padv.validation.contracts import UNIMPLEMENTED_WITNESS_CLASSES, _WITNESS_CONTRACT_OVERRIDES
from padv.validation.preconditions import GatePreconditions

CONFIG_PATH = Path(__file__).resolve().parents[1] / "padv.toml"


def _unproducible_flags(vuln_class: str) -> list[str]:
    contract = _WITNESS_CONTRACT_OVERRIDES[vuln_class]
    referenced = list(contract.get("required_all", [])) + list(contract.get("required_any", []))
    return [flag for flag in referenced if flag not in KNOWN_WITNESS_FLAGS]


def test_only_documented_classes_require_a_flag_the_system_cannot_emit() -> None:
    unknown = {
        vuln_class: _unproducible_flags(vuln_class)
        for vuln_class in _WITNESS_CONTRACT_OVERRIDES
        if _unproducible_flags(vuln_class)
    }
    assert set(unknown) == set(UNIMPLEMENTED_WITNESS_CLASSES), (
        "witness contracts require flags that are never emitted and are not "
        f"declared in UNIMPLEMENTED_WITNESS_CLASSES: {unknown}"
    )


def test_documented_gaps_have_not_silently_been_closed() -> None:
    """Keeps the list from rotting once the missing detection is implemented."""
    for vuln_class in UNIMPLEMENTED_WITNESS_CLASSES:
        assert _unproducible_flags(vuln_class), (
            f"{vuln_class} is producible now; remove it from UNIMPLEMENTED_WITNESS_CLASSES"
        )


def test_known_flag_vocabulary_matches_the_derivers() -> None:
    """Guards the constant against drifting away from the code that emits flags."""
    import re

    source_root = Path(__file__).resolve().parents[1] / "padv"
    emitted: set[str] = set()
    for path in source_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        emitted.update(re.findall(r'flags\.add\(\s*"([a-z0-9_]+)"', text))
        emitted.update(re.findall(r'return \{"([a-z0-9_]+)"\}', text))

    from padv.taxonomy import CLASS_ORACLE_WITNESS_FLAGS

    emitted.update(CLASS_ORACLE_WITNESS_FLAGS.values())

    undeclared = sorted(emitted - set(KNOWN_WITNESS_FLAGS))
    assert not undeclared, f"flags emitted but not declared in KNOWN_WITNESS_FLAGS: {undeclared}"


# --- fail-closed behaviour ----------------------------------------------


def _runtime(request_id: str, negative: bool = False) -> RuntimeEvidence:
    return RuntimeEvidence(
        request_id=request_id,
        status="active_no_hits" if negative else "active_hits",
        call_count=1,
        overflow=False,
        arg_truncated=False,
        result_truncated=False,
        correlation=request_id,
        calls=[RuntimeCall(function="mysqli_query", file="app.php", line=10, args=['"x"'])],
        raw_headers={},
    )


def _static() -> list[StaticEvidence]:
    return [
        StaticEvidence(
            candidate_id="cand-1",
            query_profile="default",
            query_id="q1",
            file_path="app.php",
            line=10,
            snippet="x",
            hash="abc",
        )
    ]


def test_unproducible_contract_is_inconclusive_not_refuted() -> None:
    """An experiment that cannot run has not disproven anything."""
    result = evaluate_candidate(
        config=load_config(CONFIG_PATH),
        static_evidence=_static(),
        positive_runs=[_runtime("p1"), _runtime("p2")],
        negative_runs=[_runtime("n1", negative=True)],
        intercepts=["mysqli_query"],
        canary="padv-canary-123",
        preconditions=GatePreconditions(),
        evidence_signals=["joern", "web"],
        vuln_class="sql_injection_boundary",
        candidate=Candidate(
            candidate_id="cand-1",
            vuln_class="sql_injection_boundary",
            title="t",
            file_path="app.php",
            line=10,
            sink="mysqli_query",
            expected_intercepts=["mysqli_query"],
            canonical_class="sql_injection_boundary",
        ),
        witness=Witness(canonical_class="sql_injection_boundary", positive_flags=[], negative_flags=[]),
        witness_contract=WitnessContract(
            canonical_class="sql_injection_boundary",
            required_all=["a_flag_nothing_ever_emits"],
            required_any=[],
            negative_must_not_include=[],
            enforce_negative_clean=True,
        ),
    )
    assert result.decision == "INCONCLUSIVE"
    assert result.failed_gate == "V3"
    assert "cannot produce" in result.reason


@pytest.mark.parametrize(
    "vuln_class", sorted(set(_WITNESS_CONTRACT_OVERRIDES) - set(UNIMPLEMENTED_WITNESS_CLASSES))
)
def test_every_shipped_contract_is_producible(vuln_class: str) -> None:
    assert not _unproducible_flags(vuln_class)
