"""TLSH (Trend Micro Locality-Sensitive Hash) per-file fuzzy hashing.

TLSH needs ≥50 bytes of input and reasonable entropy; smaller inputs return None.
Distance: lower is more similar. ≤30 is the de-facto malware/clone threshold.
Reference: https://github.com/trendmicro/tlsh
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import tlsh as _tlsh

MIN_BYTES = 50
DISTANCE_MATCH = 30


def hash_bytes(data: bytes) -> Optional[str]:
    """Return TLSH hex digest for `data`, or None if data too small/low-entropy."""
    if len(data) < MIN_BYTES:
        return None
    h = _tlsh.hash(data)
    # tlsh returns "TNULL" or "" for unhashable input
    if not h or h == "TNULL":
        return None
    return h


def hash_file(path: Path) -> Optional[str]:
    return hash_bytes(path.read_bytes())


def distance(a: str, b: str) -> int:
    """TLSH diff; lower is more similar. 0 is identical."""
    return _tlsh.diff(a, b)


def matches(a: str, b: str, threshold: int = DISTANCE_MATCH) -> bool:
    return distance(a, b) <= threshold
