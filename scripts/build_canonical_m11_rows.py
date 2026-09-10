#!/usr/bin/env python3
"""Project C bridge from frozen C2 rows to M11's minimal row contract.

The frozen split is deliberately not silently reused by M11's separate grouped
holdout evaluator.  It remains in the source artifact and its SHA-256 is
recorded in this bridge output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    source = json.loads(args.input.read_text(encoding="utf-8-sig"))
    rows = []
    for row in source.get("rows", []):
        if set(row) != {"id", "group_id", "split", "labels", "features"}:
            raise ValueError("expected frozen C2 rows")
        rows.append({key: row[key] for key in ("id", "group_id", "labels", "features")})
    result = {"schema_version": "0.1", "feature_definition_version": "0.1", "rows": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
