from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from padv.models import Candidate, EvidenceBundle, RunSummary, StaticEvidence


@dataclass(slots=True)
class EvidenceStore:
    root: Path

    @property
    def candidates_file(self) -> Path:
        return self.root / "candidates.json"

    @property
    def bundles_dir(self) -> Path:
        return self.root / "bundles"

    @property
    def runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def static_evidence_file(self) -> Path:
        return self.root / "static_evidence.json"

    @property
    def frontier_file(self) -> Path:
        return self.root / "frontier_state.json"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.bundles_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def save_candidates(self, candidates: list[Candidate]) -> None:
        self.ensure()
        payload = [c.to_dict() for c in candidates]
        self.candidates_file.write_text(json.dumps(payload, indent=2, ensure_ascii=True))

    def load_candidates(self) -> list[Candidate]:
        if not self.candidates_file.exists():
            return []
        data = json.loads(self.candidates_file.read_text())
        out: list[Candidate] = []
        for item in data:
            out.append(Candidate(**item))
        return out

    def save_static_evidence(self, static_evidence: list[StaticEvidence]) -> None:
        self.ensure()
        payload = [e.to_dict() for e in static_evidence]
        self.static_evidence_file.write_text(json.dumps(payload, indent=2, ensure_ascii=True))

    def load_static_evidence(self) -> list[StaticEvidence]:
        if not self.static_evidence_file.exists():
            return []
        data = json.loads(self.static_evidence_file.read_text())
        out: list[StaticEvidence] = []
        for item in data:
            out.append(StaticEvidence(**item))
        return out

    def save_bundle(self, bundle: EvidenceBundle) -> Path:
        self.ensure()
        path = self.bundles_dir / f"{bundle.bundle_id}.json"
        path.write_text(json.dumps(bundle.to_dict(), indent=2, ensure_ascii=True))
        return path

    def load_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        path = self.bundles_dir / f"{bundle_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def list_bundle_ids(self) -> list[str]:
        if not self.bundles_dir.exists():
            return []
        return sorted(p.stem for p in self.bundles_dir.glob("*.json"))

    def save_run_summary(self, summary: RunSummary) -> Path:
        self.ensure()
        path = self.runs_dir / f"{summary.run_id}.json"
        path.write_text(json.dumps(summary.to_dict(), indent=2, ensure_ascii=True))
        return path

    def load_run_summary(self, run_id: str) -> dict[str, Any] | None:
        path = self.runs_dir / f"{run_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def list_run_ids(self) -> list[str]:
        if not self.runs_dir.exists():
            return []
        return sorted(p.stem for p in self.runs_dir.glob("*.json"))

    def save_frontier_state(self, state: dict[str, Any]) -> Path:
        self.ensure()
        self.frontier_file.write_text(json.dumps(state, indent=2, ensure_ascii=True))
        return self.frontier_file

    def load_frontier_state(self) -> dict[str, Any] | None:
        if not self.frontier_file.exists():
            return None
        data = json.loads(self.frontier_file.read_text())
        if isinstance(data, dict):
            return data
        return None
