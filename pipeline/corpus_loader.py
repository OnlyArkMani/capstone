"""
Load the corpus for indexing.

Both partitions are loaded into one flat list and the partition each document
came from is DISCARDED. That is the whole point of this module.

The pipeline is the system under test. If it can tell which directory a
document came from, it can separate clean from poisoned without doing any
detection, and every metric downstream becomes meaningless. Ground truth lives
in corpus/ground_truth/ and is joined by `doc_id` by the evaluation harness --
which is the only component permitted to read it.

Three things enforce that here:
  1. `load_corpus()` never records the source directory on a document.
  2. `_assert_no_ground_truth()` raises if a document file carries an answer-key
     field, so a regression in the corpus builders fails loudly at index time
     rather than silently inflating a score.
  3. Nothing in this package imports from corpus/ground_truth/, and a test
     asserts that.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterator

from .config import PipelineConfig, DEFAULT_CONFIG, PROJECT_ROOT

# Single source of truth for the forbidden fields; falls back to a local copy if
# the corpus package is not importable (e.g. pipeline vendored elsewhere).
try:
    sys.path.insert(0, str(PROJECT_ROOT / "corpus"))
    from schema import FORBIDDEN_DOC_FIELDS  # type: ignore  # noqa: E402
except Exception:  # pragma: no cover
    FORBIDDEN_DOC_FIELDS = (
        "label", "ground_truth", "is_poisoned", "poison_family_id",
        "target_query_id", "intended_false_claim", "attacker_target_answer",
        "injection_payload", "corruption",
    )

# Fields the index and the retrieval records are allowed to see. An allowlist
# rather than a denylist: a new answer-key field added to the corpus in future
# is excluded by default instead of leaking until someone remembers to ban it.
ALLOWED_DOC_FIELDS = (
    "doc_id", "source_id", "source_name", "source_tier", "source_tier_label",
    "source_type", "publisher", "title", "summary", "content",
    "content_sha256", "content_word_count", "ingestion_date", "published_date",
    "reference_url", "reference_verified", "tags", "cve_ids",
    "attack_techniques", "healthcare_relevance", "vendor", "product",
    "attestation",
)


class GroundTruthLeakError(RuntimeError):
    """Raised when a document file carries an evaluation-only field."""


def _assert_no_ground_truth(doc: dict[str, Any], path: Path) -> None:
    leaked = [f for f in FORBIDDEN_DOC_FIELDS if f in doc]
    if leaked:
        raise GroundTruthLeakError(
            f"{path.name} carries evaluation-only field(s) {leaked}. The pipeline must never "
            f"see the clean/poisoned label. Fix the corpus builder; do not filter it here."
        )


def _iter_doc_paths(dirs: list[Path]) -> Iterator[Path]:
    for d in dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.json")):
            if path.name == "index.json":
                continue
            yield path


def load_corpus(config: PipelineConfig | None = None) -> list[dict[str, Any]]:
    """Return every indexable document, partition-blind, deduplicated by doc_id."""
    cfg = config or DEFAULT_CONFIG
    docs: dict[str, dict[str, Any]] = {}
    for path in _iter_doc_paths(cfg.corpus_dirs):
        with path.open(encoding="utf-8") as fh:
            raw = json.load(fh)
        _assert_no_ground_truth(raw, path)
        doc_id = raw.get("doc_id")
        if not doc_id:
            raise ValueError(f"{path} has no doc_id")
        if doc_id in docs:
            raise ValueError(f"duplicate doc_id '{doc_id}' across partitions")
        docs[doc_id] = {k: raw[k] for k in ALLOWED_DOC_FIELDS if k in raw}
    if not docs:
        raise FileNotFoundError(
            f"No documents found under {[str(d) for d in cfg.corpus_dirs]}. "
            f"Build the corpus first: python corpus/build_clean_corpus.py"
        )
    # Sorted by doc_id so index positions are deterministic across builds.
    return [docs[k] for k in sorted(docs)]


def embedding_text(doc: dict[str, Any]) -> str:
    """The text actually embedded for a document.

    Title and summary are included alongside the body because both carry
    retrieval signal a bare body does not -- and, relevant here, because the
    PoisonedRAG retrieval segment is woven into the summary of an adversarial
    document. Embedding the body alone would make the benchmark easier than the
    attack it models.
    """
    parts = [doc.get("title", ""), doc.get("summary", ""), doc.get("content", "")]
    return "\n\n".join(p for p in parts if p).strip()
