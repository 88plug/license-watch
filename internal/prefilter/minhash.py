"""MinHash over k-shingles for file/document similarity (Jaccard estimate).

Algorithm: k=50 char shingles → MinHash(num_perm=128) → Jaccard estimate.
Reference: Broder 1997, datasketch docs.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from datasketch import MinHash, LeanMinHash

SHINGLE_K = 50
NUM_PERM = 128


def shingles(text: str, k: int = SHINGLE_K) -> Iterable[bytes]:
    """Yield overlapping k-char shingles as utf-8 bytes."""
    if len(text) < k:
        # short text → single shingle of the whole content
        yield text.encode("utf-8", errors="replace")
        return
    for i in range(len(text) - k + 1):
        yield text[i : i + k].encode("utf-8", errors="replace")


def build_minhash(text: str, k: int = SHINGLE_K, num_perm: int = NUM_PERM) -> LeanMinHash:
    """Build a LeanMinHash for `text`. LeanMinHash is small + fast to serialize."""
    mh = MinHash(num_perm=num_perm, seed=42)
    for sh in shingles(text, k=k):
        mh.update(sh)
    return LeanMinHash(mh)


def jaccard(a: LeanMinHash, b: LeanMinHash) -> float:
    """MinHash Jaccard estimate in [0, 1]."""
    return a.jaccard(b)


def to_dict(mh: LeanMinHash) -> dict:
    return {
        "seed": int(mh.seed),
        "hashvalues": [int(x) for x in mh.hashvalues],
        "num_perm": len(mh.hashvalues),
    }


def from_dict(d: dict) -> LeanMinHash:
    mh = MinHash(num_perm=d["num_perm"], seed=d["seed"])
    # restore hashvalues
    import numpy as np

    mh.hashvalues = np.array(d["hashvalues"], dtype=np.uint64)
    return LeanMinHash(mh)


def dump_json(path: Path, mh: LeanMinHash) -> None:
    path.write_text(json.dumps(to_dict(mh), sort_keys=True))


def load_json(path: Path) -> LeanMinHash:
    return from_dict(json.loads(path.read_text()))
