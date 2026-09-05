"""
Embedding backends.

`SentenceTransformerEmbedder` is the real one and the default. `HashingEmbedder`
is a deterministic, dependency-free fallback so the pipeline's structure, record
shapes and logging can be exercised in an environment without torch or model
weights -- CI, an air-gapped build, or a first run before anyone has downloaded
anything.

The fallback is NOT a substitute for the real model. It has no semantics: it
matches on character n-grams, so it behaves like a fuzzy lexical matcher. Any
retrieval quality number produced with it is meaningless and the pipeline says
so, loudly, wherever the backend is recorded.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod

import numpy as np

from .config import PipelineConfig, DEFAULT_CONFIG

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class Embedder(ABC):
    """Common interface. `name` is recorded in the index metadata and in every
    log line, so a set of results can always be traced to the model that made it."""

    name: str
    dim: int
    is_semantic: bool

    @abstractmethod
    def encode(self, texts: list[str], is_query: bool = False) -> np.ndarray:
        """Return L2-normalised embeddings, shape (len(texts), dim)."""

    def encode_one(self, text: str, is_query: bool = False) -> np.ndarray:
        return self.encode([text], is_query=is_query)[0]


def _l2_normalise(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


# Upper bound on cached document vectors. The corpus is 84 documents; this is
# generous enough that a cache clear should never happen in normal use, and small
# enough that a pathological caller cannot grow it without limit.
_DOC_CACHE_MAX = 4096


class SentenceTransformerEmbedder(Embedder):
    """Real embeddings via sentence-transformers.

    Default model is BAAI/bge-small-en-v1.5 (384-dim). bge models expect an
    instruction prefix on the QUERY side only; applying it to documents as well
    degrades retrieval, which is why the prefix is applied conditionally here
    rather than in the caller.
    """

    is_semantic = True

    def __init__(self, config: PipelineConfig | None = None) -> None:
        from sentence_transformers import SentenceTransformer  # noqa: PLC0415

        cfg = config or DEFAULT_CONFIG
        self._cfg = cfg
        self.name = cfg.embedding_model
        self._model = SentenceTransformer(cfg.embedding_model)
        self.dim = int(self._model.get_sentence_embedding_dimension())
        self._uses_query_prefix = "bge" in cfg.embedding_model.lower()
        self._doc_cache: dict[str, np.ndarray] = {}

    def encode(self, texts: list[str], is_query: bool = False) -> np.ndarray:
        """Encode texts, reusing cached DOCUMENT vectors where possible.

        The corpus is fixed and small, and the same documents are retrieved over
        and over: the anomaly detector re-embedded every retrieved document on
        every query, which during training meant 470 encodes of 84 documents
        whose vectors were already in the FAISS index. `embedding_anomaly_score`
        even documents the hazard -- "re-embedding for the detector would double
        the cost and, worse, risk using a different model than the index" -- but
        its `vectors` argument was never supplied by any caller.

        Caching here rather than at the call sites fixes it for all of them at
        once, and removes the divergence risk outright: a cached vector is by
        construction the one this embedder produced, so detector distances and
        index distances cannot drift apart.

        QUERIES are deliberately not cached. bge models take an instruction
        prefix on the query side only, so a query and a document with identical
        text are different inputs, and queries rarely repeat anyway.
        """
        if is_query:
            return self._encode_raw(texts, is_query=True)

        missing = [t for t in dict.fromkeys(texts) if t not in self._doc_cache]
        if missing:
            fresh = self._encode_raw(missing, is_query=False)
            for text, vec in zip(missing, fresh):
                if len(self._doc_cache) >= _DOC_CACHE_MAX:
                    self._doc_cache.clear()   # simple bound; the corpus fits many times over
                self._doc_cache[text] = vec
        if not texts:
            return np.zeros((0, self.dim), dtype="float32")
        return np.stack([self._doc_cache[t] for t in texts]).astype("float32")

    def _encode_raw(self, texts: list[str], is_query: bool) -> np.ndarray:
        payload = texts
        if is_query and self._uses_query_prefix and self._cfg.query_prefix:
            payload = [self._cfg.query_prefix + t for t in texts]
        vecs = self._model.encode(
            payload,
            batch_size=32,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )
        return np.asarray(vecs, dtype="float32")


class HashingEmbedder(Embedder):
    """Deterministic offline fallback. Character-n-gram hashing, no semantics.

    Present so that index construction, retrieval record shape, logging and the
    end-to-end path can be verified without network access or model weights.
    Retrieval quality measured with this backend is not a result.
    """

    is_semantic = False

    def __init__(self, dim: int = 384) -> None:
        self.name = f"hashing-fallback-{dim}d"
        self.dim = dim

    def _features(self, text: str) -> list[str]:
        toks = _TOKEN_RE.findall(text.lower())
        feats = list(toks)
        for tok in toks:
            padded = f"#{tok}#"
            feats.extend(padded[i:i + 3] for i in range(len(padded) - 2))
        feats.extend(f"{a}_{b}" for a, b in zip(toks, toks[1:]))
        return feats

    def encode(self, texts: list[str], is_query: bool = False) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype="float32")
        for row, text in enumerate(texts):
            for feat in self._features(text):
                h = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
                idx = int.from_bytes(h[:4], "big") % self.dim
                sign = 1.0 if h[4] % 2 else -1.0
                out[row, idx] += sign
        return _l2_normalise(out)


# Resolved embedders, keyed by the configuration that produced them.
#
# Without this cache every caller that omits an explicit embedder loads
# BAAI/bge-small-en-v1.5 from disk again. That is not hypothetical: the
# evaluation harness constructed its FusionScorer without one, the anomaly
# detector fell through to `get_embedder()` on every query, and a 40-query run
# loaded the model 40 times. `Retriever` carries the comment "construct once and
# reuse ... loading a transformer model on every query would dominate latency
# and make timing figures meaningless" -- correct, and defeated one layer down
# by a factory that rebuilt on each call. `detectors/injection.py` already
# caches its backend for exactly this reason; embeddings now match it.
#
# Keyed on the fields that change what gets built, so two different configs
# still get two different embedders. A GPU would not have helped here: the cost
# was loading weights, not computing with them.
_EMBEDDER_CACHE: dict[tuple[str, str, int], Embedder] = {}


def clear_embedder_cache() -> None:
    """Drop cached embedders. For tests that switch backends within one process."""
    _EMBEDDER_CACHE.clear()


def get_embedder(config: PipelineConfig | None = None, use_cache: bool = True) -> Embedder:
    """Resolve the configured backend, falling back with a visible warning.

    Cached by configuration. Pass use_cache=False for a genuinely independent
    instance; the fallback warning is printed only when one is actually built,
    so a cached hit stays silent rather than repeating a warning 40 times.
    """
    cfg = config or DEFAULT_CONFIG
    key = (cfg.embedding_backend, cfg.embedding_model, cfg.embedding_dim_fallback)
    if use_cache and key in _EMBEDDER_CACHE:
        return _EMBEDDER_CACHE[key]

    embedder = _build_embedder(cfg)
    if use_cache:
        _EMBEDDER_CACHE[key] = embedder
    return embedder


def _build_embedder(cfg: PipelineConfig) -> Embedder:
    choice = cfg.embedding_backend

    if choice in ("auto", "sentence_transformers"):
        try:
            return SentenceTransformerEmbedder(cfg)
        except Exception as exc:
            if choice == "sentence_transformers":
                raise RuntimeError(
                    f"sentence-transformers backend was requested but is unavailable: {exc}. "
                    f"Install it with: pip install sentence-transformers"
                ) from exc
            print(
                f"[pipeline] WARNING: sentence-transformers unavailable ({type(exc).__name__}); "
                f"falling back to the hashing embedder. Retrieval quality figures from this run "
                f"are NOT meaningful. Install sentence-transformers for real results.",
                flush=True,
            )
    if choice == "hashing" or choice == "auto":
        return HashingEmbedder(cfg.embedding_dim_fallback)
    raise ValueError(f"unknown embedding_backend '{choice}'")
