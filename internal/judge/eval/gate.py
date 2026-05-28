"""CI accuracy gate — parses promptfoo results.json and fails if accuracy <80%."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

THRESHOLD = 0.80


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--results", default="results.json")
    p.add_argument("--threshold", type=float, default=THRESHOLD)
    args = p.parse_args()

    path = Path(args.results)
    if not path.exists():
        print(f"GATE: results file not found at {path}", file=sys.stderr)
        return 2

    data = json.loads(path.read_text())
    # promptfoo result schema: results.results[*].success (bool)
    rows = (data.get("results") or {}).get("results") or data.get("results") or []
    if not rows:
        print("GATE: no rows in results.json", file=sys.stderr)
        return 2

    total = len(rows)
    passed = sum(1 for r in rows if r.get("success") or r.get("gradingResult", {}).get("pass"))
    accuracy = passed / total
    print(f"GATE: {passed}/{total} = {accuracy:.2%} (threshold {args.threshold:.0%})")
    if accuracy + 1e-9 < args.threshold:
        print("GATE: FAIL — accuracy below threshold", file=sys.stderr)
        return 1
    print("GATE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
