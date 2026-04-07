from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from padv.config.schema import PadvConfig
from padv import __version__ as PADV_VERSION

_CODE_SIGNATURE_CACHE: tuple[tuple[tuple[str, int, int], ...], str] | None = None
_CODE_SIGNATURE_LOCK = threading.Lock()

def _code_signature_root() -> Path:
    return Path(__file__).resolve().parents[2]

def _code_signature() -> str:
    global _CODE_SIGNATURE_CACHE
    root = _code_signature_root()
    paths = [root / "padv.toml", *sorted((root / "padv").rglob("*.py"))]
    snapshot: list[tuple[str, int, int]] = []
    for path in paths:
        if not path.exists():
            continue
        stat = path.stat()
        snapshot.append((str(path.relative_to(root)), int(stat.st_mtime_ns), int(stat.st_size)))
    snapshot_key = tuple(snapshot)
    with _CODE_SIGNATURE_LOCK:
        cached = _CODE_SIGNATURE_CACHE
        if cached is not None and cached[0] == snapshot_key:
            return cached[1]
    hasher = hashlib.sha256()
    hasher.update(PADV_VERSION.encode("utf-8"))
    hasher.update(b"\0")
    for relative_path, _mtime_ns, _size in snapshot_key:
        hasher.update(relative_path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update((root / relative_path).read_bytes())
        hasher.update(b"\0")
    signature = hasher.hexdigest()[:16]
    with _CODE_SIGNATURE_LOCK:
        _CODE_SIGNATURE_CACHE = (snapshot_key, signature)
    return signature

from dataclasses import asdict

def _config_signature(config: PadvConfig) -> str:
    payload = asdict(config)
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]

def _get_cache_db_path(store_path: Path) -> Path:
    db_path = store_path / "agent_cache.sqlite"
    if not db_path.exists():
        store_path.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_cache (
                    cache_key TEXT PRIMARY KEY,
                    response_text TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()
    return db_path

def _cache_key(
    config: PadvConfig,
    prompt_version: str,
    stage: str,
    prompt: str,
    model_name: str
) -> str:
    payload = {
        "config_signature": _config_signature(config),
        "code_signature": _code_signature(),
        "prompt_version": prompt_version,
        "stage": stage,
        "prompt": prompt,
        "model_name": model_name,
    }
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

def with_agent_cache(
    stage: str,
    prompt_version: str,
    ttl_seconds: int = 3600
) -> Callable:
    """
    Decorator for caching LLM calls.
    The decorated function should have the signature: (llm: Any, config: PadvConfig, store_path: Path, prompt: str) -> str
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(llm: Any, config: PadvConfig, store_path: Path, prompt: str) -> str:
            if config.agent.deterministic_mode:
                return func(llm, config, store_path, prompt)

            model_name = getattr(llm, "model_name", "unknown_model")
            key = _cache_key(config, prompt_version, stage, prompt, model_name)
            db_path = _get_cache_db_path(store_path)

            with sqlite3.connect(db_path) as conn:
                row = conn.execute(
                    "SELECT response_text, created_at FROM agent_cache WHERE cache_key = ?",
                    (key,)
                ).fetchone()

                if row is not None:
                    response_text, created_at_str = row
                    created_at = datetime.fromisoformat(created_at_str)
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - created_at).total_seconds()
                    if age <= ttl_seconds:
                        return response_text
                    
                    conn.execute("DELETE FROM agent_cache WHERE cache_key = ?", (key,))
                    conn.commit()

            response_text = func(llm, config, store_path, prompt)

            with sqlite3.connect(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO agent_cache (cache_key, response_text, created_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        response_text = excluded.response_text,
                        created_at = excluded.created_at
                    """,
                    (
                        key,
                        response_text,
                        datetime.now(timezone.utc).isoformat()
                    )
                )
                conn.commit()

            return response_text
        return wrapper
    return decorator
