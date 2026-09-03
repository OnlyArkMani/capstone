"""
Structured records returned by the retrieval layer.

These shapes are a contract, not a convenience. The report generator and the
audit log both consume them, and the Level 2 detectors read their fields
directly, so a change here is a change to three downstream components.

Design references are to docs/design/TRUST_RISK_DESIGN.md.

What is deliberately absent
---------------------------
* **The clean/poisoned label.** Nothing in this module carries it, and the
  corpus loader discards which directory a document came from. Ground truth
  lives in corpus/ground_truth/ and is joined by `doc_id` at evaluation time
  only. See corpus/schema.py, "Ground truth separation".
* **Perplexity.** Not computed anywhere in this pipeline. This is a scoped-out
  decision from the literature review, not an omission: clean and adversarial
  text overlap in perplexity (design references P1 and P5), and no perplexity
  term appears in the composite score of design section 3.2. Do not add one.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(frozen=True)
class Provenance:
    """Where a retrieved document came from.

    Level 1 of the architecture requires provenance to travel with every
    retrieved document rather than being looked up later. `source_tier` in
    particular is the foundation of the case taxonomy (design section 1) and is
    a property of the source, never of the content.
    """

    source_id: str
    source_name: str
    source_tier: int
    source_tier_label: str
    source_type: str
    publisher: str | None = None
    published_date: str | None = None
    ingestion_date: str | None = None
    reference_url: str | None = None
    reference_verified: bool = False
    attestation: str | None = None
    content_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RetrievedRecord:
    """One retrieved document, with its score and its provenance.

    `similarity` is cosine similarity in [-1, 1] against the query embedding.
    Embeddings are L2-normalised at index time, so inner product and cosine are
    the same quantity here; `raw_score` preserves whatever the index returned so
    that a future change of metric stays auditable.
    """

    rank: int
    doc_id: str
    similarity: float
    raw_score: float
    title: str
    summary: str
    content: str
    provenance: Provenance
    tags: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    healthcare_relevance: str | None = None
    vendor: str | None = None
    product: str | None = None
    content_word_count: int | None = None

    # Convenience accessors used constantly downstream.
    @property
    def source_tier(self) -> int:
        return self.provenance.source_tier

    @property
    def source_id(self) -> str:
        return self.provenance.source_id

    def to_dict(self, include_content: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if not include_content:
            d.pop("content", None)
        return d


@dataclass(frozen=True)
class RetrievalResult:
    """The full result of one retrieval call.

    Carries the set-level quantities the detectors need. `n_retrieved` and the
    similarity spread feed the confidence measure (design section 4.2) and the
    per-query anomaly normalisation (design section 3.2), both of which are
    computed against the retrieval set rather than against the corpus.
    """

    query: str
    query_hash: str
    k: int
    records: list[RetrievedRecord]
    embedding_model: str
    index_id: str
    latency_ms: float

    @property
    def n_retrieved(self) -> int:
        return len(self.records)

    @property
    def similarities(self) -> list[float]:
        return [r.similarity for r in self.records]

    @property
    def tiers(self) -> list[int]:
        return [r.provenance.source_tier for r in self.records]

    @property
    def tier_min(self) -> int | None:
        """Worst (numerically highest) tier present. Design section 2.2."""
        return max(self.tiers) if self.records else None

    @property
    def top_tier(self) -> int | None:
        """Tier of the highest-similarity document.

        NOT the same as the design's `tier_governing`, which is the tier of the
        highest-*attribution* cited document (design section 2.2). Attribution
        needs the generation step, so this is the retrieval-time approximation
        and the fusion layer should recompute it properly.
        """
        return self.records[0].provenance.source_tier if self.records else None

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        return {
            "query": self.query,
            "query_hash": self.query_hash,
            "k": self.k,
            "n_retrieved": self.n_retrieved,
            "embedding_model": self.embedding_model,
            "index_id": self.index_id,
            "latency_ms": round(self.latency_ms, 2),
            "tier_min": self.tier_min,
            "top_tier": self.top_tier,
            "records": [r.to_dict(include_content=include_content) for r in self.records],
        }


@dataclass(frozen=True)
class GenerationResult:
    """The generated answer plus what it was generated from."""

    query: str
    answer: str
    model: str
    backend: str
    cited_doc_ids: list[str]
    prompt_chars: int
    latency_ms: float
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
