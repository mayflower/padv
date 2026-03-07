#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from padv.store.compaction import compact_store


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compact a .padv store by keeping the latest clean bundle per candidate signature "
            "and validating run/bundle references."
        )
    )
    parser.add_argument(
        "store_root",
        type=Path,
        nargs="?",
        default=Path(".padv"),
        help="Source store root (default: .padv)",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=None,
        help="Destination directory. Defaults to sibling clean_store directory.",
    )
    args = parser.parse_args()

    source_root = args.store_root.expanduser().resolve()
    output_root = (
        args.output_root.expanduser().resolve()
        if args.output_root is not None
        else (source_root.parent / "clean_store").resolve()
    )

    result = compact_store(source_root=source_root, output_root=output_root)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
