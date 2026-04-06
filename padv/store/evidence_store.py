from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from padv.models import Candidate, EvidenceBundle, RunSummary, StaticEvidence

_JSON_GLOB = "*.json"


class CorruptStoreArtifactError(RuntimeError):
    def __init__(self, path: Path, artifact_kind: str) -> None:
        self.path = path
        self.artifact_kind = str(artifact_kind)
        super().__init__(f"corrupt {self.artifact_kind} JSON at {self.path}")


class RunIdRequiredError(RuntimeError):
    def __init__(self, method: str, artifact_kind: str) -> None:
        self.method = str(method)
        self.artifact_kind = str(artifact_kind)
        super().__init__(f"{self.method} requires explicit run_id for {self.artifact_kind}")


class AmbiguousLegacyBundleLookupError(RuntimeError):
    def __init__(self, bundle_id: str, paths: list[Path]) -> None:
        self.bundle_id = str(bundle_id)
        self.paths = list(paths)
        joined = ", ".join(str(path) for path in self.paths)
        super().__init__(f"legacy bundle lookup matched multiple artifacts for {self.bundle_id}: {joined}")


@dataclass(slots=True)
class RunScopedEvidenceStore:
    store: "EvidenceStore"
    run_id: str

    @property
    def root(self) -> Path:
        return self.store.run_dir(self.run_id)

    def ensure(self) -> None:
        self.store.ensure_run(self.run_id)

    def save_candidates(self, candidates: list[Candidate]) -> None:
        self.store.save_candidates(candidates, run_id=self.run_id)

    def load_candidates(self) -> list[Candidate]:
        return self.store.load_candidates(run_id=self.run_id)

    def save_static_evidence(self, static_evidence: list[StaticEvidence]) -> None:
        self.store.save_static_evidence(static_evidence, run_id=self.run_id)

    def load_static_evidence(self) -> list[StaticEvidence]:
        return self.store.load_static_evidence(run_id=self.run_id)

    def save_bundle(self, bundle: EvidenceBundle) -> Path:
        return self.store.save_bundle(bundle, run_id=self.run_id)

    def load_bundle(self, bundle_id: str) -> dict[str, Any] | None:
        return self.store.load_bundle(bundle_id, run_id=self.run_id)

    def list_bundle_ids(self) -> list[str]:
        return self.store.list_bundle_ids(run_id=self.run_id)

    def save_json_artifact(self, relative_path: str, payload: dict[str, Any] | list[Any]) -> Path:
        return self.store.save_json_artifact(relative_path, payload, run_id=self.run_id)

    def load_json_artifact(self, relative_path: str) -> dict[str, Any] | list[Any] | None:
        return self.store.load_json_artifact(relative_path, run_id=self.run_id)


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

    def run_dir(self, run_id: str) -> Path:
        return self.runs_dir / run_id

    def for_run(self, run_id: str) -> RunScopedEvidenceStore:
        return RunScopedEvidenceStore(store=self, run_id=run_id)

    def ensure_run(self, run_id: str) -> Path:
        self.ensure()
        run_root = self.run_dir(run_id)
        run_root.mkdir(parents=True, exist_ok=True)
        (run_root / "bundles").mkdir(parents=True, exist_ok=True)
        return run_root

    @staticmethod
    def _write_json_atomic(path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(payload, indent=2, ensure_ascii=True).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, path)
            try:
                dir_fd = os.open(str(path.parent), os.O_RDONLY)
            except OSError:
                return
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    @staticmethod
    def _load_json(path: Path, *, artifact_kind: str, raise_on_corrupt: bool) -> Any | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            if raise_on_corrupt:
                raise CorruptStoreArtifactError(path, artifact_kind) from None
            return None

    def _candidates_file(self, run_id: str | None = None) -> Path:
        if run_id:
            return self.run_dir(run_id) / "candidates.json"
        return self.candidates_file

    def _static_evidence_file(self, run_id: str | None = None) -> Path:
        if run_id:
            return self.run_dir(run_id) / "static_evidence.json"
        return self.static_evidence_file

    def _bundles_dir(self, run_id: str | None = None) -> Path:
        if run_id:
            return self.run_dir(run_id) / "bundles"
        return self.bundles_dir

    def _bundle_paths_legacy_lookup(self, bundle_id: str | None = None) -> list[Path]:
        paths: list[Path] = []
        if bundle_id is None:
            if self.bundles_dir.exists():
                paths.extend(sorted(self.bundles_dir.glob(_JSON_GLOB)))
            if self.runs_dir.exists():
                for run_root in sorted(self.runs_dir.iterdir()):
                    if not run_root.is_dir():
                        continue
                    paths.extend(sorted((run_root / "bundles").glob(_JSON_GLOB)))
            return paths

        if self.bundles_dir.exists():
            root_path = self.bundles_dir / f"{bundle_id}.json"
            if root_path.exists():
                paths.append(root_path)
        if self.runs_dir.exists():
            for run_root in sorted(self.runs_dir.iterdir()):
                if not run_root.is_dir():
                    continue
                scoped = run_root / "bundles" / f"{bundle_id}.json"
                if scoped.exists():
                    paths.append(scoped)
        return paths

    def save_candidates(self, candidates: list[Candidate], *, run_id: str | None = None) -> None:
        if run_id:
            self.ensure_run(run_id)
        else:
            self.ensure()
        payload = [c.to_dict() for c in candidates]
        self._write_json_atomic(self._candidates_file(run_id), payload)

    def load_candidates(self, *, run_id: str | None = None) -> list[Candidate]:
        path = self._candidates_file(run_id)
        if not path.exists():
            return []
        data = self._load_json(path, artifact_kind="candidates", raise_on_corrupt=True)
        if not isinstance(data, list):
            return []
        out: list[Candidate] = []
        for item in data:
            out.append(Candidate(**item))
        return out

    def save_static_evidence(self, static_evidence: list[StaticEvidence], *, run_id: str | None = None) -> None:
        if run_id:
            self.ensure_run(run_id)
        else:
            self.ensure()
        payload = [e.to_dict() for e in static_evidence]
        self._write_json_atomic(self._static_evidence_file(run_id), payload)

    def load_static_evidence(self, *, run_id: str | None = None) -> list[StaticEvidence]:
        path = self._static_evidence_file(run_id)
        if not path.exists():
            return []
        data = self._load_json(path, artifact_kind="static_evidence", raise_on_corrupt=True)
        if not isinstance(data, list):
            return []
        out: list[StaticEvidence] = []
        for item in data:
            out.append(StaticEvidence(**item))
        return out

    def save_bundle(self, bundle: EvidenceBundle, *, run_id: str | None = None) -> Path:
        if run_id:
            self.ensure_run(run_id)
        else:
            self.ensure()
        path = self._bundles_dir(run_id) / f"{bundle.bundle_id}.json"
        self._write_json_atomic(path, bundle.to_dict())
        return path

    def load_bundle(self, bundle_id: str, *, run_id: str | None = None) -> dict[str, Any] | None:
        if run_id is None:
            raise RunIdRequiredError("load_bundle", "bundle")
        path = self._bundles_dir(run_id) / f"{bundle_id}.json"
        if not path.exists():
            return None
        payload = self._load_json(path, artifact_kind="bundle", raise_on_corrupt=True)
        if isinstance(payload, dict):
            return payload
        if payload is None:
            return None
        return None

    def load_bundle_legacy_lookup(self, bundle_id: str) -> dict[str, Any] | None:
        paths = self._bundle_paths_legacy_lookup(bundle_id)
        if not paths:
            return None
        if len(paths) > 1:
            raise AmbiguousLegacyBundleLookupError(bundle_id, paths)
        payload = self._load_json(paths[0], artifact_kind="bundle", raise_on_corrupt=True)
        if isinstance(payload, dict):
            return payload
        return None

    def list_bundle_ids(self, *, run_id: str | None = None) -> list[str]:
        if run_id is None:
            raise RunIdRequiredError("list_bundle_ids", "bundle")
        bundles_dir = self._bundles_dir(run_id)
        if not bundles_dir.exists():
            return []
        return sorted(p.stem for p in bundles_dir.glob(_JSON_GLOB))

    def list_bundle_ids_legacy_lookup(self) -> list[str]:
        return [path.stem for path in self._bundle_paths_legacy_lookup()]

    def load_all_bundles_legacy_lookup(self) -> list[dict[str, Any]]:
        bundles: list[dict[str, Any]] = []
        for path in self._bundle_paths_legacy_lookup():
            payload = self._load_json(path, artifact_kind="bundle", raise_on_corrupt=True)
            if isinstance(payload, dict):
                bundles.append(payload)
        return bundles

    def save_run_summary(self, summary: RunSummary) -> Path:
        self.ensure()
        path = self.runs_dir / f"{summary.run_id}.json"
        self._write_json_atomic(path, summary.to_dict())
        return path

    def load_run_summary(self, run_id: str) -> dict[str, Any] | None:
        path = self.runs_dir / f"{run_id}.json"
        if not path.exists():
            return None
        data = self._load_json(path, artifact_kind="run_summary", raise_on_corrupt=True)
        return data if isinstance(data, dict) else None

    def list_run_ids(self) -> list[str]:
        if not self.runs_dir.exists():
            return []
        return sorted(p.stem for p in self.runs_dir.glob(_JSON_GLOB))

    def save_frontier_state(self, state: dict[str, Any]) -> Path:
        self.ensure()
        self._write_json_atomic(self.frontier_file, state)
        return self.frontier_file

    def load_frontier_state(self) -> dict[str, Any] | None:
        if not self.frontier_file.exists():
            return None
        data = self._load_json(self.frontier_file, artifact_kind="frontier_state", raise_on_corrupt=True)
        if isinstance(data, dict):
            return data
        return None

    def save_json_artifact(
        self,
        relative_path: str,
        payload: dict[str, Any] | list[Any],
        *,
        run_id: str | None = None,
    ) -> Path:
        if run_id:
            base = self.ensure_run(run_id)
        else:
            self.ensure()
            base = self.root
        path = base / relative_path
        self._write_json_atomic(path, payload)
        return path

    def load_json_artifact(self, relative_path: str, *, run_id: str | None = None) -> dict[str, Any] | list[Any] | None:
        base = self.run_dir(run_id) if run_id else self.root
        path = base / relative_path
        if not path.exists():
            return None
        data = self._load_json(path, artifact_kind="json_artifact", raise_on_corrupt=True)
        if data is None:
            return None
        if isinstance(data, (dict, list)):
            return data
        return None

    def save_resume_metadata(self, run_id: str, payload: dict[str, Any]) -> Path:
        self.ensure()
        path = self.resume_dir / f"{run_id}.json"
        self._write_json_atomic(path, payload)
        return path

    def load_resume_metadata(self, run_id: str) -> dict[str, Any] | None:
        path = self.resume_dir / f"{run_id}.json"
        if not path.exists():
            return None
        data = self._load_json(path, artifact_kind="resume_metadata", raise_on_corrupt=True)
        if isinstance(data, dict):
            return data
        return None

    def list_resume_ids(self) -> list[str]:
        if not self.resume_dir.exists():
            return []
        return sorted(p.stem for p in self.resume_dir.glob(_JSON_GLOB))

    def list_resume_metadata(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for run_id in self.list_resume_ids():
            item = self.load_resume_metadata(run_id)
            if isinstance(item, dict):
                out.append(item)
        return out

    @staticmethod
    def _matches_resume_filters(
        item: dict[str, Any],
        *,
        mode: str | None,
        run_validation: bool | None,
        target_signature: str | None,
        config_signature: str | None,
    ) -> bool:
        if str(item.get("status", "")).strip().lower() not in {"open", "failed", "yielded"}:
            return False
        if mode is not None and str(item.get("mode", "")).strip() != mode:
            return False
        if run_validation is not None and bool(item.get("run_validation")) != bool(run_validation):
            return False
        if target_signature is not None and str(item.get("target_signature", "")).strip() != target_signature:
            return False
        if config_signature is not None and str(item.get("config_signature", "")).strip() != config_signature:
            return False
        return True

    def latest_resumable_run(
        self,
        *,
        mode: str | None = None,
        run_validation: bool | None = None,
        target_signature: str | None = None,
        config_signature: str | None = None,
    ) -> dict[str, Any] | None:
        filtered = [
            item for item in self.list_resume_metadata()
            if self._matches_resume_filters(
                item,
                mode=mode,
                run_validation=run_validation,
                target_signature=target_signature,
                config_signature=config_signature,
            )
        ]
        if not filtered:
            return None
        filtered.sort(key=lambda item: str(item.get("updated_at", "")), reverse=True)
        return filtered[0]
