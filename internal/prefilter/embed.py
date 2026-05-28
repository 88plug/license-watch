"""Sentence-transformers MiniLM embedding for README + script text.

Model: sentence-transformers/all-MiniLM-L6-v2 (CPU friendly, 384-dim, ~80MB).
Pinned model revision for reproducibility.

Embeddings cached to disk by sha256(text) → .npy file under cache_dir.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Iterable

import numpy as np

# Pinned model revision (commit on HF). All-MiniLM-L6-v2 is small + stable.
# When updating, pin the new revision SHA explicitly — never `main`.
MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "8b3219a92973c328a8e22fadcfa821b5dc75636a"  # pinned
EMBEDDING_DIM = 384
COSINE_MATCH = 0.85

# Lazy singleton — first call loads model.
_MODEL = None


def _load_model():
    global _MODEL
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer

        _MODEL = SentenceTransformer(
            MODEL_NAME,
            revision=MODEL_REVISION,
            device="cpu",
        )
    return _MODEL


def _cache_path(cache_dir: Path, text: str) -> Path:
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return cache_dir / f"{h}.npy"


def embed(text: str, cache_dir: Path | None = None) -> np.ndarray:
    """Embed `text` → (EMBEDDING_DIM,) float32. Caches when cache_dir given."""
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        p = _cache_path(cache_dir, text)
        if p.exists():
            return np.load(p)
    model = _load_model()
    vec = model.encode(text, convert_to_numpy=True, normalize_embeddings=True)
    vec = vec.astype(np.float32)
    if cache_dir is not None:
        np.save(_cache_path(cache_dir, text), vec)
    return vec


def embed_batch(texts: Iterable[str], cache_dir: Path | None = None) -> np.ndarray:
    """Batch encode. Returns (N, EMBEDDING_DIM)."""
    texts = list(texts)
    model = _load_model()
    vecs = model.encode(texts, convert_to_numpy=True, normalize_embeddings=True, batch_size=32)
    vecs = vecs.astype(np.float32)
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        for t, v in zip(texts, vecs):
            np.save(_cache_path(cache_dir, t), v)
    return vecs


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine on unit-normalized vectors == dot product. Returns [-1, 1]."""
    if a.shape != b.shape:
        raise ValueError(f"shape mismatch {a.shape} vs {b.shape}")
    # vectors already L2-normalized by encode(normalize_embeddings=True)
    return float(np.dot(a, b))


def save(path: Path, vec: np.ndarray) -> None:
    np.save(path, vec)


def load(path: Path) -> np.ndarray:
    return np.load(path)
