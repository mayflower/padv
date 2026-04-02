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
    def artifacts_dir(self) -> Path:
        return self.root / "artifacts"

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

    @property
    def langgraph_dir(self) -> Path:
        return self.root / "langgraph"

    @property
    def resume_dir(self) -> Path:
        return self.root / "resume"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.bundles_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.langgraph_dir.mkdir(parents=True, exist_ok=True)
        self.resume_dir.mkdir(parents=True, exist_ok=True)

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

    def save_json_artifact(self, relative_path: str, payload: dict[str, Any] | list[Any]) -> Path:
        self.ensure()
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True))
        return path

    def load_json_artifact(self, relative_path: str) -> dict[str, Any] | list[Any] | None:
        path = self.root / relative_path
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        if isinstance(data, (dict, list)):
            return data
        return None

    def save_resume_metadata(self, run_id: str, payload: dict[str, Any]) -> Path:
        self.ensure()
        path = self.resume_dir / f"{run_id}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=True))
        return path

    def load_resume_metadata(self, run_id: str) -> dict[str, Any] | None:
        path = self.resume_dir / f"{run_id}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            return data
        return None

    def list_resume_ids(self) -> list[str]:
        if not self.resume_dir.exists():
            return []
        return sorted(p.stem for p in self.resume_dir.glob("*.json"))

    def list_resume_metadata(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for run_id in self.list_resume_ids():
            item = self.load_resume_metadata(run_id)
            if isinstance(item, dict):
                out.append(item)
        return out

    def latest_resumable_run(
        self,
        *,
        mode: str | None = None,
        run_validation: bool | None = None,
        target_signature: str | None = None,
        config_signature: str | None = None,
    ) -> dict[str, Any] | None:
        items = self.list_resume_metadata()
        filtered: list[dict[str, Any]] = []
        for item in items:
            if str(item.get("status", "")).strip().lower() not in {"open", "failed", "yielded"}:
                continue
            if mode is not None and str(item.get("mode", "")).strip() != mode:
                continue
            if run_validation is not None and bool(item.get("run_validation")) != bool(run_validation):
                continue
            if target_signature is not None and str(item.get("target_signature", "")).strip() != target_signature:
                continue
            if config_signature is not None and str(item.get("config_signature", "")).strip() != config_signature:
                continue
            filtered.append(item)
        if not filtered:
            return None
        filtered.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
        return filtered[0]
