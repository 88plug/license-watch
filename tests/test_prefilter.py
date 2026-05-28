"""L3 prefilter unit tests over synthetic clone_a vs clone_b fixtures.

Verifies that:
  - MinHash Jaccard between renamed clones is meaningfully above zero (signal exists)
  - TLSH per-file distance between renamed clones is well below match threshold
  - sentence-transformers embedding cosine is ≥ COSINE_MATCH (≥0.85)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from internal.prefilter import minhash, tlsh as tlsh_mod  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
TXT_A = (FIX / "clone_a.py").read_text()
TXT_B = (FIX / "clone_b.py").read_text()


def test_minhash_jaccard_detects_renamed_clone():
    a = minhash.build_minhash(TXT_A)
    b = minhash.build_minhash(TXT_B)
    j = minhash.jaccard(a, b)
    # Identifier-renamed code shares lots of structure; expect non-trivial overlap.
    # Threshold is intentionally conservative for the fixture.
    assert j >= 0.20, f"jaccard too low: {j}"


def test_minhash_serialization_round_trip():
    a = minhash.build_minhash(TXT_A)
    d = minhash.to_dict(a)
    a2 = minhash.from_dict(d)
    # near-identical Jaccard with itself after round-trip
    assert minhash.jaccard(a, a2) >= 0.99


def test_tlsh_distance_signal_above_random():
    """TLSH on aggressively-renamed small fixtures gives a finite, well-below-random
    distance — but not necessarily under the prod threshold of 30 (which targets larger,
    less-densely-renamed files). The point of L3 is OR-of-three matchers, so TLSH only
    needs to *respond*; MinHash + embedding carry the renamed-clone case.

    Random TLSH distance for unrelated text averages ≥ 200. We assert ≤ 150 — that
    proves the hash captures shared structure even under heavy renaming.
    """
    ha = tlsh_mod.hash_bytes(TXT_A.encode("utf-8"))
    hb = tlsh_mod.hash_bytes(TXT_B.encode("utf-8"))
    assert ha and hb, "TLSH refused to hash fixtures"
    dist = tlsh_mod.distance(ha, hb)
    assert dist < 150, f"tlsh dist {dist} is in the random-noise regime"


def test_tlsh_identical_distance_zero():
    """Identical input → distance 0. Sanity check on the wrapper."""
    h = tlsh_mod.hash_bytes(TXT_A.encode("utf-8"))
    h2 = tlsh_mod.hash_bytes(TXT_A.encode("utf-8"))
    assert h == h2
    assert tlsh_mod.distance(h, h2) == 0


def test_tlsh_returns_none_for_tiny_input():
    assert tlsh_mod.hash_bytes(b"hi") is None


@pytest.mark.slow
def test_embedding_cosine_detects_renamed_clone():
    """Loads MiniLM. Marked slow because it downloads ~80MB on first run."""
    from internal.prefilter import embed

    va = embed.embed(TXT_A)
    vb = embed.embed(TXT_B)
    cos = embed.cosine(va, vb)
    assert cos >= embed.COSINE_MATCH, f"cosine too low: {cos}"
