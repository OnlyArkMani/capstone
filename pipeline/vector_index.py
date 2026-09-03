"""
Vector storage and search.

FAISS `IndexFlatIP` is the default. Embeddings are L2-normalised, so inner
product is cosine similarity.

Flat, not IVF or HNSW: the corpus is under a hundred documents, where an
approximate index is slower to build, no faster to query, and introduces recall
error into a benchmark whose entire purpose is measuring what gets retrieved.
Approximate indexing becomes worth revisiting somewhere above ~100k vectors.

`NumpyIndex` is an exact brute-force fallback with identical results, so the
pipeline runs without FAISS installed. At this corpus size that is not a
compromise -- it computes precisely the same thing.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

import numpy as np

from .config import PipelineConfig, DEFAULT_CONFIG


class VectorIndex(ABC):
    backend: str
    dim: int

    @abstractmethod
    def add(self, vectors: np.ndarray) -> None: ...

    @abstractmethod
    def search(self, query: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        """Return (scores, indices), both shape (k,), sorted descending."""

    @abstractmethod
    def save(self, path: Path) -> None: ...

    @property
    @abstractmethod
    def size(self) -> int: ...


class FaissIndex(VectorIndex):
    backend = "faiss"

    def __init__(self, dim: int) -> None:
        import faiss  # noqa: PLC0415

        self._faiss = faiss
        self.dim = dim
        self._index = faiss.IndexFlatIP(dim)

    def add(self, vectors: np.ndarray) -> None:
        self._index.add(np.ascontiguousarray(vectors, dtype="float32"))

    def search(self, query: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        q = np.ascontiguousarray(query.reshape(1, -1), dtype="float32")
        scores, idx = self._index.search(q, min(k, self.size))
        return scores[0], idx[0]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._faiss.write_index(self._index, str(path))

    @classmethod
    def load(cls, path: Path) -> "FaissIndex":
        import faiss  # noqa: PLC0415

        idx = faiss.read_index(str(path))
        obj = cls.__new__(cls)
        obj._faiss = faiss
        obj._index = idx
        obj.dim = idx.d
        return obj

    @property
    def size(self) -> int:
        return int(self._index.ntotal)


class NumpyIndex(VectorIndex):
    backend = "numpy"

    def __init__(self, dim: int) -> None:
        self.dim = dim
        self._vectors = np.zeros((0, dim), dtype="float32")

    def add(self, vectors: np.ndarray) -> None:
        self._vectors = np.vstack([self._vectors, np.asarray(vectors, dtype="float32")])

    def search(self, query: np.ndarray, k: int) -> tuple[np.ndarray, np.ndarray]:
        scores = self._vectors @ np.asarray(query, dtype="float32").ravel()
        k = min(k, self.size)
        top = np.argpartition(-scores, k - 1)[:k] if k < self.size else np.arange(self.size)
        top = top[np.argsort(-scores[top])]
        return scores[top], top

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        np.save(path.with_suffix(".npy"), self._vectors)

    @classmethod
    def load(cls, path: Path) -> "NumpyIndex":
        vectors = np.load(path.with_suffix(".npy"))
        obj = cls(vectors.shape[1])
        obj._vectors = vectors.astype("float32")
        return obj

    @property
    def size(self) -> int:
        return int(self._vectors.shape[0])


def make_index(dim: int, config: PipelineConfig | None = None) -> VectorIndex:
    cfg = config or DEFAULT_CONFIG
    choice = cfg.index_backend
    if choice in ("auto", "faiss"):
        try:
            return FaissIndex(dim)
        except Exception as exc:
            if choice == "faiss":
                raise RuntimeError(
                    f"FAISS was requested but is unavailable: {exc}. Install with: pip install faiss-cpu"
                ) from exc
            print(
                "[pipeline] NOTE: faiss unavailable; using exact numpy search. At this corpus "
                "size the results are identical -- both are exact inner-product search.",
                flush=True,
            )
    if choice in ("auto", "numpy"):
        return NumpyIndex(dim)
    raise ValueError(f"unknown index_backend '{choice}'")


def load_index(config: PipelineConfig | None = None) -> tuple[VectorIndex, dict[str, Any]]:
    """Load a persisted index and its metadata sidecar."""
    cfg = config or DEFAULT_CONFIG
    if not cfg.meta_path.exists():
        raise FileNotFoundError(
            f"No index metadata at {cfg.meta_path}. Build the index first:\n"
            f"    python -m pipeline.build_index"
        )
    with cfg.meta_path.open(encoding="utf-8") as fh:
        meta = json.load(fh)

    backend = meta.get("index_backend", "numpy")
    if backend == "faiss":
        try:
            return FaissIndex.load(cfg.index_path), meta
        except Exception as exc:
            raise RuntimeError(
                f"index was built with FAISS but FAISS cannot load it here ({exc}). "
                f"Rebuild with: python -m pipeline.build_index"
            ) from exc
    return NumpyIndex.load(cfg.index_path), meta
