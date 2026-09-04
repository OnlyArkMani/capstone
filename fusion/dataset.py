"""
Build the labelled training set for the composite score.

For each query: retrieve, run the three detectors over the retrieved set, and
join the ground-truth label by `doc_id`. One row per (query, retrieved document).

Three things worth knowing about how this set is constructed
------------------------------------------------------------

**Ground truth is joined here and nowhere else.** This module is training and
evaluation code, which is the boundary: the detectors and the pipeline never see
the answer key, and an AST check enforces that. Labels never enter a feature.

**Grouping prevents the obvious leak.** Poisoned documents come from a handful of
attack templates. The group key is `poison_family_id` for poisoned rows and
`doc_id` for clean ones, so a template's instances never straddle a split. Without
this, the model memorises template surface statistics and every metric inflates.

**The entailment hypothesis is a stand-in until generation is wired in.**
Design section 3.1 defines the target against a *generated* answer. With no
generation step in the loop, `build_dataset` uses the query itself as the
hypothesis, which measures whether a document supports the question rather than
whether it supports the answer. That is a weaker but non-leaking proxy, it is
recorded per row in `hypothesis_source`, and it should be replaced with the real
generated claim before any headline figure is quoted.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detectors import (  # noqa: E402
    embedding_anomaly_score, injection_probabilities, entailment_scores,
    pairwise_conflict, d_conflict_max, tier1_conflict_max,
)
from fusion.bands import SignalSet  # noqa: E402

GT_DIR = PROJECT_ROOT / "corpus" / "ground_truth"


@dataclass
class InstanceRow:
    query_id: str
    query: str
    doc_id: str
    source_tier: int
    source_id: str
    similarity: float
    rank: int
    signals: SignalSet
    anomaly_z: float
    label: int                 # 1 = poisoned, 0 = clean
    group: str                 # split key
    poison_family_id: str | None
    hypothesis_source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id, "doc_id": self.doc_id,
            "source_tier": self.source_tier, "source_id": self.source_id,
            "similarity": round(self.similarity, 6), "rank": self.rank,
            "signals": self.signals.to_dict(), "anomaly_z": round(self.anomaly_z, 6),
            "label": self.label, "group": self.group,
            "poison_family_id": self.poison_family_id,
            "hypothesis_source": self.hypothesis_source,
        }


def load_ground_truth() -> dict[str, dict[str, Any]]:
    """doc_id -> {ground_truth, poison_family_id, ...}. Evaluation code only."""
    out: dict[str, dict[str, Any]] = {}
    for name in ("clean.json", "poisoned.json"):
        path = GT_DIR / name
        if path.exists():
            out.update(json.loads(path.read_text(encoding="utf-8"))["labels"])
    return out


def build_query_set(retriever: Any, include_generated: bool = True) -> list[tuple[str, str]]:
    """(query_id, query_text) pairs.

    The ten target queries are the ones the adversarial documents were built to
    intercept. Titles of clean documents are added as further queries so the set
    contains enough clean retrieval contexts to fit anything at all -- ten queries
    would give roughly fifty rows in total.
    """
    queries: list[tuple[str, str]] = []
    gt_path = GT_DIR / "poisoned.json"
    if gt_path.exists():
        for qid, q in json.loads(gt_path.read_text(encoding="utf-8"))["target_queries"].items():
            queries.append((qid, q["query_text"]))
    if include_generated:
        for doc in retriever.documents:
            title = (doc.get("title") or "").strip()
            if title:
                queries.append((f"gen_{doc['doc_id']}", title))
    return queries


def build_dataset(
    retriever: Any,
    k: int = 5,
    include_generated: bool = True,
    verbose: bool = True,
) -> tuple[list[InstanceRow], dict[str, Any]]:
    """Run every query through retrieval + detectors and label the results."""
    gt = load_ground_truth()
    if not gt:
        raise FileNotFoundError(
            f"No ground-truth manifests under {GT_DIR}. Build the corpus first.")

    queries = build_query_set(retriever, include_generated)
    rows: list[InstanceRow] = []
    backends: dict[str, Any] = {}

    for i, (qid, qtext) in enumerate(queries, 1):
        if verbose and i % 20 == 0:
            print(f"[fusion] {i}/{len(queries)} queries, {len(rows)} rows so far", flush=True)

        result = retriever.retrieve_top_k(qtext, k=k)
        if not result.records:
            continue

        anomaly = {s.doc_id: s for s in
                   embedding_anomaly_score(result.records, embedder=retriever.embedder)}
        injection = {s.doc_id: s for s in injection_probabilities(result.records)}
        # Hypothesis stand-in: see the module docstring.
        entail = {s.doc_id: s for s in entailment_scores(qtext, result.records)}

        backends.setdefault("anomaly", next(iter(anomaly.values())).backend.to_dict())
        backends.setdefault("injection", next(iter(injection.values())).backend.to_dict())
        backends.setdefault("entailment", next(iter(entail.values())).backend.to_dict())

        for rec in result.records:
            meta = gt.get(rec.doc_id)
            if meta is None:
                continue                      # not in the manifest: unlabelled, skip
            label = 1 if meta["ground_truth"] == "poisoned" else 0
            family = meta.get("poison_family_id")
            rows.append(InstanceRow(
                query_id=qid, query=qtext, doc_id=rec.doc_id,
                source_tier=rec.provenance.source_tier,
                source_id=rec.provenance.source_id,
                similarity=rec.similarity, rank=rec.rank,
                signals=SignalSet(
                    unsupport=entail[rec.doc_id].score,       # already risk-oriented
                    anomaly=anomaly[rec.doc_id].score,
                    injection=injection[rec.doc_id].score,
                    conflict=None,                            # detector not built yet
                ),
                anomaly_z=float(anomaly[rec.doc_id].detail.get("robust_z", 0.0)),
                label=label,
                # Group by attack family for poisoned rows so a template never
                # straddles a split; by doc_id for clean rows.
                group=(f"family:{family}" if label == 1 and family else f"doc:{rec.doc_id}"),
                poison_family_id=family,
                hypothesis_source="query_text_proxy",
            ))

    meta = {
        "n_queries": len(queries),
        "n_rows": len(rows),
        "n_pos": sum(r.label for r in rows),
        "n_neg": sum(1 - r.label for r in rows),
        "k": k,
        "n_groups": len({r.group for r in rows}),
        "detector_backends": backends,
        "signals_available": ["unsupport", "anomaly", "injection"],
        "signals_missing": ["conflict"],
        "hypothesis_source": "query_text_proxy",
        "caveats": [
            "The conflict detector (evidence vs. parametric knowledge) is not built; "
            "that signal is absent rather than zero-filled.",
            "Entailment uses the query as the hypothesis because generation is not in "
            "the loop. Replace with the generated claim before quoting headline figures.",
        ],
    }
    if verbose:
        print(f"[fusion] dataset: {meta['n_rows']} rows "
              f"({meta['n_pos']} poisoned / {meta['n_neg']} clean) "
              f"across {meta['n_groups']} groups from {meta['n_queries']} queries")
    return rows, meta


def rows_to_arrays(rows: Sequence[InstanceRow], spec) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    from .features import encode_many  # noqa: PLC0415

    X = encode_many([{"signals": r.signals, "source_tier": r.source_tier,
                      "anomaly_z": r.anomaly_z} for r in rows], spec)
    y = np.asarray([r.label for r in rows], dtype=int)
    groups = np.asarray([r.group for r in rows])
    return X, y, groups
