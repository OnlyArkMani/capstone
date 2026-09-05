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

**The entailment hypothesis is now the generated answer, per design 3.1.**
This used to substitute the query text, and that substitution did measurable
harm: PoisonedRAG documents restate the target query in order to be retrieved,
so measured against the QUERY they look better supported than genuine documents.
Training saw `unsupport` at AUC 0.248 -- inverted, worse than chance -- and
dropped the strongest detector in the system as anti-correlated. With a real
generator available the hypothesis is the generated answer, cached on disk so
refits are reproducible and need no network. Fallback to the query proxy is
per-QUERY, not per-run, and every row records which was used in
`hypothesis_source`; the run summary prints the split.

**`conflict` carries intra-evidence conflict, which is not the designed signal.**
Design 2.1 defines `conflict` as retrieved evidence versus the model's
PARAMETRIC KNOWLEDGE, which needs a probe this system does not have. What is
wired is design 0.4's derived quantity: retrieved documents contradicting each
other, per document, via the NLI cross-encoder. It is a real measurement and it
fills a signal that was previously absent, but it answers a different question
than the design specifies. Recorded as `conflict_source` in the dataset
metadata; it must be written into docs/design/ before any figure depending on it
is quoted.
"""

from __future__ import annotations

import hashlib

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
    pairwise_conflict, per_document_conflict, d_conflict_max, tier1_conflict_max,
)
from fusion.bands import SignalSet  # noqa: E402

GT_DIR = PROJECT_ROOT / "corpus" / "ground_truth"
# Defined here rather than imported from fusion.scorer: dataset is imported by
# train before scorer is needed, and a module-level import would couple the two
# for the sake of one path.
ARTIFACTS = PROJECT_ROOT / "fusion" / "artifacts"


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


# ---------------------------------------------------------------------------
# Generated answers, and why they are cached on disk
# ---------------------------------------------------------------------------
#
# Design section 3.1 defines entailment against the GENERATED ANSWER. Until a
# generator existed this module substituted the query text, and that substitution
# inverted the signal: PoisonedRAG documents restate the target query in order to
# be retrieved, so measured against the query they look BETTER supported than
# genuine documents. Training saw unsupport at AUC 0.248 -- worse than chance --
# and dropped the strongest detector in the system as anti-correlated.
#
# Generation is now available, so the real hypothesis can be used. Two practical
# problems come with it, and the cache solves both:
#
#   Cost. The Groq free tier's binding limit is 6,000 tokens per MINUTE, which at
#   RAG prompt sizes is roughly three queries a minute. Ninety-odd queries is
#   half an hour of wall clock. Paying that once per experiment iteration would
#   make iterating impossible.
#
#   Reproducibility. A language model is not a pure function. Refitting the model
#   tomorrow against freshly generated answers would silently change the training
#   set, and every comparison across runs would be confounded.
#
# So answers are cached by (query, retrieved doc ids) and the cache is a tracked
# JSON file. The first run pays for generation; every later run is instant, gets
# byte-identical hypotheses, and needs no network at all -- which also means the
# demonstration machine does not depend on Groq being reachable.

ANSWER_CACHE_PATH = ARTIFACTS / "generated_answers.json"


def _answer_cache_key(query: str, doc_ids: Sequence[str]) -> str:
    """Keyed on the doc ids as well as the query: the same question over a
    different retrieval set is a different generation, and reusing the answer
    across them would quietly mix experiments."""
    payload = query + "\u0000" + "\u0000".join(doc_ids)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def load_answer_cache() -> dict[str, str]:
    if not ANSWER_CACHE_PATH.exists():
        return {}
    try:
        with ANSWER_CACHE_PATH.open(encoding="utf-8") as fh:
            return dict(json.load(fh).get("answers", {}))
    except Exception:
        return {}


def save_answer_cache(cache: dict[str, str], backend: str) -> None:
    ANSWER_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ANSWER_CACHE_PATH.open("w", encoding="utf-8") as fh:
        json.dump({
            "_note": "Generated answers used as entailment hypotheses. Keyed by "
                     "sha256(query + retrieved doc ids). Tracked so refits are "
                     "reproducible and offline. Delete to regenerate.",
            "backend": backend,
            "n": len(cache),
            "answers": cache,
        }, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _resolve_generator(cfg: Any) -> Any | None:
    """A REAL generator, or None. The extractive stub is refused deliberately.

    The stub returns the leading sentences of the top retrieved documents. Used
    as an entailment hypothesis that is viciously circular -- the evidence would
    be scored on whether it entails a quotation of itself, and every document
    would look perfectly supported. That is worse than the query proxy, not
    better, so when no real model is configured this returns None and the caller
    falls back to the query with the substitution recorded.
    """
    try:
        from pipeline.generation import get_generator  # noqa: PLC0415
        gen = get_generator(cfg)
    except Exception as exc:
        print(f"[fusion] no generator available ({type(exc).__name__}); "
              f"entailment will use the query-text proxy.", flush=True)
        return None
    if getattr(gen, "backend", "extractive") == "extractive":
        print("[fusion] only the extractive stub is available. Refusing to use it as an "
              "entailment hypothesis (it quotes the evidence back at itself); "
              "falling back to the query-text proxy.", flush=True)
        return None
    return gen


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

    cfg = getattr(retriever, "config", None)
    generator = _resolve_generator(cfg)
    answer_cache = load_answer_cache()
    cache_at_start = len(answer_cache)
    gen_backend = getattr(generator, "backend", "none") if generator else "none"
    hypothesis_counts = {"generated_answer": 0, "query_text_proxy": 0}
    if verbose:
        print(f"[fusion] entailment hypothesis: "
              f"{'generated answers (' + gen_backend + ')' if generator else 'query-text proxy'}"
              f"; {cache_at_start} answer(s) already cached", flush=True)

    for i, (qid, qtext) in enumerate(queries, 1):
        if verbose and i % 20 == 0:
            print(f"[fusion] {i}/{len(queries)} queries, {len(rows)} rows so far", flush=True)

        result = retriever.retrieve_top_k(qtext, k=k)
        if not result.records:
            continue

        # ---- the entailment hypothesis -----------------------------------
        # Design 3.1 wants the generated answer. Fall back per QUERY rather than
        # per RUN: one Groq failure should cost one row's fidelity, not turn the
        # whole dataset back into proxies without saying so. Whichever was used
        # is recorded on every row.
        doc_ids = [r.doc_id for r in result.records]
        hypothesis, hyp_source = qtext, "query_text_proxy"
        if generator is not None:
            key = _answer_cache_key(qtext, doc_ids)
            answer = answer_cache.get(key)
            if answer is None:
                try:
                    answer = generator.generate_answer(qtext, result.records, cfg).answer
                    answer_cache[key] = answer
                except Exception as exc:
                    if verbose:
                        print(f"[fusion] generation failed on {qid} "
                              f"({type(exc).__name__}); using the query proxy for it.",
                              flush=True)
                    answer = None
            if answer and answer.strip():
                hypothesis, hyp_source = answer, "generated_answer"
        hypothesis_counts[hyp_source] += 1

        anomaly = {s.doc_id: s for s in
                   embedding_anomaly_score(result.records, embedder=retriever.embedder)}
        injection = {s.doc_id: s for s in injection_probabilities(result.records)}
        entail = {s.doc_id: s for s in entailment_scores(hypothesis, result.records)}

        # ---- intra-evidence conflict, per document ------------------------
        # Design 0.4's derived quantity, standing in for design 2.1's parametric
        # conflict signal. Recorded as conflict_source, never silently conflated.
        conflicts = pairwise_conflict(result.records)
        conflict_by_doc = per_document_conflict(conflicts)
        conflict_measurable = len(result.records) >= 2

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
                    conflict=(conflict_by_doc.get(rec.doc_id, 0.0)
                              if conflict_measurable else None),
                ),
                anomaly_z=float(anomaly[rec.doc_id].detail.get("robust_z", 0.0)),
                label=label,
                # Group by attack family for poisoned rows so a template never
                # straddles a split; by doc_id for clean rows.
                group=(f"family:{family}" if label == 1 and family else f"doc:{rec.doc_id}"),
                poison_family_id=family,
                hypothesis_source=hyp_source,
            ))

    if generator is not None and len(answer_cache) > cache_at_start:
        save_answer_cache(answer_cache, gen_backend)
        if verbose:
            print(f"[fusion] cached {len(answer_cache) - cache_at_start} new generated "
                  f"answer(s) to {ANSWER_CACHE_PATH.name}; later runs reuse them offline.",
                  flush=True)

    n_generated = hypothesis_counts["generated_answer"]
    caveats = [
        "`conflict` is INTRA-EVIDENCE conflict (retrieved documents against each "
        "other, design 0.4), standing in for design 2.1's parametric-knowledge "
        "signal, which needs a probe this system does not have. Recorded per row "
        "as conflict_source. Do not read it as the designed signal.",
    ]
    if n_generated < len(queries):
        caveats.append(
            f"{len(queries) - n_generated} of {len(queries)} queries fell back to the "
            f"query-text proxy as the entailment hypothesis. That proxy INVERTS the "
            f"unsupport signal on PoisonedRAG documents, which restate the query to be "
            f"retrieved; rows carrying it are marked hypothesis_source=query_text_proxy.")
    if n_generated:
        caveats.append(
            f"{n_generated} of {len(queries)} queries used a generated answer as the "
            f"hypothesis, per design 3.1. Answers are cached in "
            f"{ANSWER_CACHE_PATH.name} so refits are reproducible and offline.")

    meta = {
        "n_queries": len(queries),
        "n_rows": len(rows),
        "n_pos": sum(r.label for r in rows),
        "n_neg": sum(1 - r.label for r in rows),
        "k": k,
        "n_groups": len({r.group for r in rows}),
        "detector_backends": backends,
        "signals_available": ["unsupport", "anomaly", "injection", "conflict"],
        "signals_missing": [],
        "hypothesis_source": ("generated_answer" if n_generated == len(queries)
                              else "mixed" if n_generated else "query_text_proxy"),
        "hypothesis_counts": hypothesis_counts,
        "generation_backend": gen_backend,
        "conflict_source": "intra_evidence_pairwise_nli",
        "caveats": caveats,
    }
    if verbose:
        print(f"[fusion] dataset: {meta['n_rows']} rows "
              f"({meta['n_pos']} poisoned / {meta['n_neg']} clean) "
              f"across {meta['n_groups']} groups from {meta['n_queries']} queries")
        print(f"[fusion] hypothesis: {n_generated} generated / "
              f"{hypothesis_counts['query_text_proxy']} proxy   "
              f"conflict signal: now populated (intra-evidence)")
    return rows, meta


def rows_to_arrays(rows: Sequence[InstanceRow], spec) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    from .features import encode_many  # noqa: PLC0415

    X = encode_many([{"signals": r.signals, "source_tier": r.source_tier,
                      "anomaly_z": r.anomaly_z} for r in rows], spec)
    y = np.asarray([r.label for r in rows], dtype=int)
    groups = np.asarray([r.group for r in rows])
    return X, y, groups
