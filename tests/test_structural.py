"""L4 structural unit tests for non-binary components."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_scalibr_signatures_well_formed():
    """signatures.json parses + every entry has required keys."""
    p = ROOT / "internal" / "structural" / "signatures.json"
    sigs = json.loads(p.read_text())
    assert isinstance(sigs, list) and sigs
    for s in sigs:
        assert s["project"]
        assert isinstance(s.get("strings", []), list)
        assert isinstance(s.get("symbols", []), list)
        assert isinstance(s.get("min_hits", 1), int)


def test_scalibr_binary_builds_and_detects(tmp_path):
    """Build lw-scalibr-fp and verify it detects a planted signature."""
    if subprocess.call(["which", "go"], stdout=subprocess.DEVNULL) != 0:
        pytest.skip("go not available")

    binp = tmp_path / "lw-scalibr-fp"
    subprocess.run(
        ["go", "build", "-o", str(binp),
         "./internal/structural/cmd/lw-scalibr-fp"],
        check=True, cwd=ROOT,
    )

    sample = tmp_path / "candidate"
    sample.mkdir()
    (sample / "README.md").write_text(
        "Hello world\nNative Linux GUI + CLI for Intel AMT\nuses imrsdk-linux\n"
    )

    proc = subprocess.run(
        [str(binp),
         "--signatures", str(ROOT / "internal" / "structural" / "signatures.json"),
         "--root", str(sample)],
        capture_output=True, text=True, check=True,
    )
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    assert lines, f"no findings: stderr={proc.stderr}"
    finding = json.loads(lines[0])
    assert finding["project"] == "intel-amt-linux"
    assert finding["hit_count"] >= 2
