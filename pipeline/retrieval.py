"""
Retrieval, with Level 1 provenance and score logging built in.

`retrieve_top_k()` returns structured `RetrievedRecord` objects -- never bare
strings. Each carries its similarity to the query and the full provenance of its
source alongside the text. The report generator, the audit log and the Level 2
detectors all read those fields, so the shape is a contract (see records.py).
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import numpy as np

from .config import PipelineConfig, DEFAULT_CONFIG
from .corpus_loader import load_corpus, embedding_text
from .embeddings import Embedder, get_embedder
from .records import Provenance, RetrievedRecord, RetrievalResult
from .vector_index import VectorIndex, make_index, load_index


def query_hash(query: str) -> str:
    return hashlib.sha256(query.strip().encode("utf-8")).hexdigest()


def _provenance_from(doc: dict[str, Any]) -> Provenance:
    return Provenance(
        source_id=doc["source_id"],
        source_name=doc["source_name"],
        source_tier=int(doc["source_tier"]),
        source_tier_label=doc.get("source_tier_label", ""),
        source_type=doc.get("source_type", ""),
        publisher=doc.get("publisher"),
        published_date=doc.get("published_date"),
        ingestion_date=doc.get("ingestion_date"),
        reference_url=doc.get("reference_url"),
        reference_verified=bool(doc.get("reference_verified", False)),
        attestation=doc.get("attestation"),
        content_sha256=doc.get("content_sha256"),
    )


class Retriever:
    """Holds the embedder, the index and the document payloads.

    Construct once and reuse: building the index or loading a transformer model
    on every query would dominate latency and make timing figures meaningless.
    """

    def __init__(
        self,
        config: PipelineConfig | None = None,
        embedder: Embedder | None = None,
        index: VectorIndex | None = None,
        documents: list[dict[str, Any]] | None = None,
        index_id: str = "in-memory",
    ) -> None:
        self.config = config or DEFAULT_CONFIG
        self.embedder = embedder or get_embedder(self.config)
        self.documents = documents if documents is not None else []
        self.index = index
        self.index_id = index_id

    # ---------------- construction ----------------

    @classmethod
    def build(cls, config: PipelineConfig | None = None, verbose: bool = True) -> "Retriever":
        """Build an in-memory index over the whole corpus."""
        cfg = config or DEFAULT_CONFIG
        embedder = get_embedder(cfg)
        docs = load_corpus(cfg)
        texts = [embedding_text(d) for d in docs]
        if verbose:
            print(f"[pipeline] embedding {len(texts)} documents with {embedder.name} ...", flush=True)
        vectors = embedder.encode(texts, is_query=False)
        index = make_index(embedder.dim, cfg)
        index.add(vectors)
        index_id = hashlib.sha256(
            (embedder.name + "|" + "|".join(d["doc_id"] for d in docs)).encode("utf-8")
        ).hexdigest()[:16]
        if verbose:
            print(f"[pipeline] index ready: {index.size} vectors, {index.backend} backend, "
                  f"dim={embedder.dim}, index_id={index_id}", flush=True)
        return cls(cfg, embedder, index, docs, index_id)

    @classmethod
    def from_disk(cls, config: PipelineConfig | None = None) -> "Retriever":
        """Load a persisted index built by `python -m pipeline.build_index`."""
        cfg = config or DEFAULT_CONFIG
        index, meta = load_index(cfg)
        embedder = get_embedder(cfg)
        if meta.get("embedding_model") != embedder.name:
            raise RuntimeError(
                f"index was built with embedding model '{meta.get('embedding_model')}' but the "
                f"active embedder is '{embedder.name}'. Query and document vectors would live in "
                f"different spaces and every similarity would be meaningless. Rebuild the index."
            )
        docs = load_corpus(cfg)
        by_id = {d["doc_id"]: d for d in docs}
        ordered = [by_id[i] for i in meta["doc_ids"]]
        return cls(cfg, embedder, index, ordered, meta.get("index_id", "on-disk"))

    # ---------------- public API ----------------

    def embed_query(self, query: str) -> np.ndarray:
        """Return the L2-normalised query embedding."""
        if not query or not query.strip():
            raise ValueError("query is empty")
        return self.embedder.encode_one(query.strip(), is_query=True)

    def retrieve_top_k(self, query: str, k: int | None = None) -> RetrievalResult:
        """Retrieve the k nearest documents as structured records.

        Returns a RetrievalResult; `.records` is the list of RetrievedRecord.
        Each record carries similarity, full provenance and the document text.
        """
        if self.index is None or self.index.size == 0:
            raise RuntimeError("retriever has no index; call Retriever.build() or .from_disk()")
        k = k or self.config.default_k
        if k < 1:
            raise ValueError("k must be >= 1")

        started = time.perf_counter()
        qvec = self.embed_query(query)
        scores, indices = self.index.search(qvec, k)

        records: list[RetrievedRecord] = []
        for rank, (score, pos) in enumerate(zip(scores, indices), start=1):
            if pos < 0:
                continue
            doc = self.documents[int(pos)]
            records.append(RetrievedRecord(
                rank=rank,
                doc_id=doc["doc_id"],
                similarity=float(score),
                raw_score=float(score),
                title=doc.get("title", ""),
                summary=doc.get("summary", ""),
                content=doc.get("content", ""),
                provenance=_provenance_from(doc),
                tags=list(doc.get("tags", [])),
                cve_ids=list(doc.get("cve_ids", [])),
                attack_techniques=list(doc.get("attack_techniques", [])),
                healthcare_relevance=doc.get("healthcare_relevance"),
                vendor=doc.get("vendor"),
                product=doc.get("product"),
                content_word_count=doc.get("content_word_count"),
            ))

        return RetrievalResult(
            query=query,
            query_hash=query_hash(query),
            k=k,
            records=records,
            embedding_model=self.embedder.name,
            index_id=self.index_id,
            latency_ms=(time.perf_counter() - started) * 1000.0,
        )

    # ---------------- persistence ----------------

    def save(self, config: PipelineConfig | None = None) -> None:
        cfg = config or self.config
        cfg.index_dir.mkdir(parents=True, exist_ok=True)
        self.index.save(cfg.index_path)
        meta = {
            "index_id": self.index_id,
            "index_backend": self.index.backend,
            "embedding_model": self.embedder.name,
            "embedding_is_semantic": self.embedder.is_semantic,
            "dim": self.embedder.dim,
            "document_count": len(self.documents),
            # Order matters: index position i corresponds to doc_ids[i].
            "doc_ids": [d["doc_id"] for d in self.documents],
            "note": (
                "Partition of origin (clean/poisoned) is deliberately absent. The pipeline is "
                "partition-blind; ground truth is joined by doc_id at evaluation time only."
            ),
        }
        with cfg.meta_path.open("w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
            fh.write("\n")
