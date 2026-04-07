from __future__ import annotations

import os
import hashlib
import shutil
from pathlib import Path
from typing import Any

from padv.config.schema import PadvConfig
from padv.store.evidence_store import EvidenceStore

def joern_is_available() -> bool:
    return shutil.which("joern") is not None

def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()

def _extract_php_symbols(content: str, path: str) -> list[dict[str, Any]]:
    symbols = []
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if "function " in line:
            parts = line.split("function ")
            if len(parts) > 1:
                name_part = parts[1].split("(")[0].strip()
                if name_part:
                    symbols.append({
                        "name": name_part,
                        "file": path,
                        "line_range": [i + 1, i + 1]
                    })
    return symbols

def build_repo_index(
    run_id: str,
    target_sha: str,
    config: PadvConfig,
    repo_root: str,
    store: EvidenceStore
) -> dict[str, Any]:
    root_path = Path(repo_root)
    files = []
    symbols = []
    
    for root, _, filenames in os.walk(root_path):
        for name in filenames:
            if name.startswith("."):
                continue
            path = Path(root) / name
            rel_path = path.relative_to(root_path).as_posix()
            
            if "node_modules" in rel_path or "vendor" in rel_path or ".git" in rel_path:
                continue
                
            files.append({
                "path": rel_path,
                "size": path.stat().st_size,
                "extension": path.suffix.lower(),
                "sha256": _hash_file(path)
            })
            
            if path.suffix.lower() in [".php", ".inc"]:
                try:
                    content = path.read_text(encoding="utf-8")
                    symbols.extend(_extract_php_symbols(content, rel_path))
                except UnicodeDecodeError:
                    pass

    files.sort(key=lambda x: str(x["path"]))
    symbols.sort(key=lambda x: (str(x["file"]), str(x["name"])))
    
    joern_avail = joern_is_available()
    
    index = {
        "target_sha": target_sha,
        "files": files,
        "symbols": symbols,
        "sink_callsites_available": joern_avail,
        "sink_callsites": [],
        "framework_hints": {}
    }
    
    run_store = store.for_run(run_id)
    run_store.save_json_artifact("repo_index.json", index)
    
    return index