from __future__ import annotations

import pickle
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from padv.config.schema import (
    AgentConfig,
    AuthConfig,
    BudgetConfig,
    CanaryConfig,
    DifferentialConfig,
    JoernConfig,
    LLMConfig,
    OracleConfig,
    PadvConfig,
    SandboxConfig,
    ScipConfig,
    StoreConfig,
    TargetConfig,
    WebConfig,
)
from padv.models import (
    Candidate,
    DifferentialPair,
    EnvironmentFacts,
    EvidenceBundle,
    ExperimentAttempt,
    FailureAnalysis,
    FailurePattern,
    GateResult,
    Hypothesis,
    ObjectiveScore,
    OracleEvidence,
    Refutation,
    RequestEvidence,
    ResearchFinding,
    ResearchTask,
    ResponseEvidence,
    RunSummary,
    RuntimeCall,
    RuntimeEvidence,
    StaticEvidence,
    ValidationContext,
    ValidationPlan,
    WitnessBundle,
    WitnessEvidence,
)
from padv.validation.preconditions import GatePreconditions
from padv.store.evidence_store import EvidenceStore


def _plain(value: Any) -> Any:
    if isinstance(value, defaultdict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def _nested_storage(raw: dict[str, Any]) -> defaultdict[str, defaultdict[str, dict[str, Any]]]:
    storage: defaultdict[str, defaultdict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(dict))
    for thread_id, namespaces in raw.items():
        ns_map = storage[thread_id]
        if not isinstance(namespaces, dict):
            continue
        for checkpoint_ns, checkpoints in namespaces.items():
            if isinstance(checkpoints, dict):
                ns_map[checkpoint_ns] = dict(checkpoints)
    return storage


def _dict_defaultdict(raw: dict[str, Any]) -> defaultdict[Any, dict[Any, Any]]:
    outer: defaultdict[Any, dict[Any, Any]] = defaultdict(dict)
    for key, value in raw.items():
        outer[key] = dict(value) if isinstance(value, dict) else {}
    return outer


_ALLOWED_MSGPACK_TYPES = (
    TargetConfig,
    OracleConfig,
    CanaryConfig,
    BudgetConfig,
    SandboxConfig,
    StoreConfig,
    AuthConfig,
    JoernConfig,
    LLMConfig,
    AgentConfig,
    ScipConfig,
    WebConfig,
    DifferentialConfig,
    PadvConfig,
    EvidenceStore,
    Candidate,
    StaticEvidence,
    RuntimeCall,
    RuntimeEvidence,
    DifferentialPair,
    GateResult,
    EvidenceBundle,
    RunSummary,
    FailurePattern,
    FailureAnalysis,
    ValidationPlan,
    ValidationContext,
    ObjectiveScore,
    ResearchTask,
    ResearchFinding,
    Hypothesis,
    Refutation,
    ExperimentAttempt,
    WitnessBundle,
    WitnessEvidence,
    RequestEvidence,
    ResponseEvidence,
    OracleEvidence,
    EnvironmentFacts,
    GatePreconditions,
)


class FileBackedMemorySaver(InMemorySaver):
    def __init__(self, path: str | Path) -> None:
        super().__init__(serde=JsonPlusSerializer(allowed_msgpack_modules=_ALLOWED_MSGPACK_TYPES))
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._restore()

    def _restore(self) -> None:
        if not self.path.exists():
            return
        with self._lock:
            payload = pickle.loads(self.path.read_bytes())
            if not isinstance(payload, dict):
                return
            storage = payload.get("storage", {})
            writes = payload.get("writes", {})
            blobs = payload.get("blobs", {})
            if isinstance(storage, dict):
                self.storage = _nested_storage(storage)
            if isinstance(writes, dict):
                self.writes = _dict_defaultdict(writes)
            if isinstance(blobs, dict):
                self.blobs = dict(blobs)

    def _flush(self) -> None:
        with self._lock:
            payload = {
                "storage": _plain(self.storage),
                "writes": _plain(self.writes),
                "blobs": _plain(self.blobs),
            }
            tmp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
            tmp_path.write_bytes(pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL))
            tmp_path.replace(self.path)

    def put(self, config, checkpoint, metadata, new_versions):
        with self._lock:
            result = super().put(config, checkpoint, metadata, new_versions)
            self._flush()
            return result

    def put_writes(self, config, writes, task_id, task_path: str = "") -> None:
        with self._lock:
            super().put_writes(config, writes, task_id, task_path)
            self._flush()

    def delete_thread(self, thread_id: str) -> None:
        with self._lock:
            super().delete_thread(thread_id)
            self._flush()

    async def aput(self, config, checkpoint, metadata, new_versions):
        with self._lock:
            result = await super().aput(config, checkpoint, metadata, new_versions)
            self._flush()
            return result

    async def aput_writes(self, config, writes, task_id, task_path: str = "") -> None:
        with self._lock:
            await super().aput_writes(config, writes, task_id, task_path)
            self._flush()

    async def adelete_thread(self, thread_id: str) -> None:
        with self._lock:
            await super().adelete_thread(thread_id)
            self._flush()
