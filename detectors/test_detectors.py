#!/usr/bin/env python3
"""
Sanity check: do the three detectors point the right way on known documents?

    python -m detectors.test_detectors
    python -m detectors.test_detectors --verbose

This is NOT a performance evaluation. It answers one question before we build
fusion on top of these signals: given documents we already know the answer for,
does each detector move in the direction it is supposed to move? A detector
wired backwards produces confident, plausible, wrong numbers, and it is far
cheaper to catch that here than after it has been fused with two others.

Ground truth
------------
This script READS corpus/ground_truth/. That is correct and is the boundary: the
detectors are the system under test and never see the answer key; test and
evaluation code do. A check below asserts that no module in the detectors package
reads it.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detectors import (  # noqa: E402
    embedding_anomaly_score, injection_probabilities, entailment_scores,
    pairwise_conflict, d_conflict_max, tier1_conflict_max,
)
from detectors.base import doc_text  # noqa: E402

GT_DIR = PROJECT_ROOT / "corpus" / "ground_truth"
FAILURES: list[str] = []
WARNINGS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def load_docs() -> tuple[dict[str, dict], dict[str, dict], dict[str, Any]]:
    clean_gt = json.loads((GT_DIR / "clean.json").read_text(encoding="utf-8"))
    pois_gt = json.loads((GT_DIR / "poisoned.json").read_text(encoding="utf-8"))

    def read(partition: str, ids) -> dict[str, dict]:
        out = {}
        for doc_id in ids:
            path = PROJECT_ROOT / "corpus" / partition / f"{doc_id}.json"
            if path.exists():
                out[doc_id] = json.loads(path.read_text(encoding="utf-8"))
        return out

    return read("clean", clean_gt["labels"]), read("poisoned", pois_gt["labels"]), pois_gt


def bar(value: float, width: int = 20) -> str:
    filled = int(round(value * width))
    return "#" * filled + "." * (width - filled)


# ---------------------------------------------------------------------------

def test_isolation() -> None:
    """The detectors are the system under test; only eval code sees the answer key."""
    print("\n== detector isolation ==")
    from detectors.isolation_check import check_package  # noqa: PLC0415

    offenders = check_package(PROJECT_ROOT / "detectors",
                              skip=("test_detectors.py", "isolation_check.py"))
    check("no detector module reads ground truth", not offenders, f"offenders: {offenders}")

    pipe = check_package(PROJECT_ROOT / "pipeline",
                         skip=("test_pipeline.py",))
    check("no pipeline module reads ground truth", not pipe, f"offenders: {pipe}")


def test_structure(clean: dict, poisoned: dict) -> None:
    print("\n== output contract ==")
    sample = list(clean.values())[:5]
    a = embedding_anomaly_score(sample)
    check("anomaly returns one score per document", len(a) == len(sample))
    check("anomaly scores are in [0,1]", all(0.0 <= s.score <= 1.0 for s in a))
    check("anomaly reports robust_z for fusion", all("robust_z" in s.detail for s in a))
    check("anomaly on singleton returns 0", embedding_anomaly_score(sample[:1])[0].score == 0.0)
    check("anomaly on empty input returns []", embedding_anomaly_score([]) == [])

    i = injection_probabilities(sample)
    check("injection returns one score per document", len(i) == len(sample))
    check("injection scores are in [0,1]", all(0.0 <= s.score <= 1.0 for s in i))

    e = entailment_scores("The device is safe to use.", sample)
    check("entailment returns one score per document", len(e) == len(sample))
    check("entailment scores are in [0,1]", all(0.0 <= s.score <= 1.0 for s in e))
    check("entailment exposes both directions",
          all(abs((s.entailment + s.score) - 1.0) < 1e-6 for s in e))

    ids = {s.doc_id for s in a} | {s.doc_id for s in i} | {s.doc_id for s in e}
    check("all three detectors agree on doc_ids", ids == {d["doc_id"] for d in sample})


def test_injection(clean: dict, poisoned: dict, pois_gt: dict, verbose: bool) -> None:
    """Per-PAYLOAD reporting, deliberately, not one aggregate number.

    Which phrasings the detector catches and which it misses is the finding.
    An aggregate pass/fail would hide exactly the thing worth showing: the
    detector is a set of hand-written patterns, so it catches payloads whose
    wording it anticipates and misses payloads whose wording it does not. Every
    injection-bearing document is listed with its score, its band and the
    patterns that fired, so a reader can see the shape of the gap rather than
    take our word for its size.
    """
    print("\n== detector 2: prompt injection ==")
    docs = list(clean.values()) + list(poisoned.values())
    scores = {s.doc_id: s for s in injection_probabilities(docs)}
    backend = next(iter(scores.values())).backend
    # Inverted deliberately in September 2026. This used to warn when the
    # transformer was ABSENT. Probe 4 measured the transformer on this corpus and
    # it does not separate it at any aggregation tried, so the pattern backend is
    # now the primary and its use is not a degraded mode. What warrants a warning
    # is the transformer being primary, since its numbers are not trustworthy here.
    if backend.is_model:
        WARNINGS.append("injection ran on the transformer backend, measured as "
                        "non-separating on this corpus (see detectors/injection.py)")

    labels = pois_gt.get("labels", {})
    targets = [d for d, m in labels.items()
               if m.get("poison_family_id") == "direct_prompt_injection" and d in scores]
    if not targets:
        check("at least one injection-bearing document present", False)
        return

    # Band cut points come from fusion.bands, not from a number typed here, so
    # this table cannot drift away from what the system actually does.
    try:
        from fusion.bands import FIXED_THRESHOLD_SIGNALS  # noqa: PLC0415
        sus, mal = FIXED_THRESHOLD_SIGNALS["injection"]
    except Exception:
        sus, mal = 0.60, 0.90

    def band(v: float) -> str:
        return "MALICIOUS" if v >= mal else "SUSPICIOUS" if v >= sus else "MISSED"

    others = [t.score for d, t in scores.items() if d not in targets]
    loudest_other = max(others) if others else 0.0

    print(f"  backend: {backend.name} (transformer: {backend.is_model})")
    print(f"  bands:   SUSPICIOUS >= {sus:.2f}   MALICIOUS >= {mal:.2f}")
    print(f"\n  {'injection-bearing document':44s} {'score':>7s}  {'band':11s} patterns fired")
    print("  " + "-" * 104)

    caught, missed = 0, []
    for doc_id in sorted(targets, key=lambda d: -scores[d].score):
        sc = scores[doc_id].score
        pats = [h["pattern"] for h in scores[doc_id].detail.get("pattern_hits", [])]
        b = band(sc)
        if b == "MISSED":
            missed.append(doc_id)
        else:
            caught += 1
        print(f"  {doc_id:44s} {sc:7.4f}  {b:11s} {pats if pats else '-- nothing fired --'}")

    print(f"\n  reached at least SUSPICIOUS: {caught}/{len(targets)}")
    print(f"  loudest NON-injection document in the whole corpus: {loudest_other:.4f}")

    check("no clean or non-injection document reaches the suspicious band",
          loudest_other < sus, f"loudest other scored {loudest_other:.4f}")
    check("at least one injection payload reaches MALICIOUS",
          any(scores[d].score >= mal for d in targets))

    if missed:
        print("\n  MISSED, and this is the point of reporting per payload:")
        for doc_id in missed:
            variant = labels[doc_id].get("injection_variant", "unrecorded")
            print(f"    {doc_id}  (variant: {variant})")
        print("  These payloads carry no vocabulary the pattern set anticipates. They are")
        print("  the honest limit of a rule detector and they are in the corpus on purpose:")
        print("  a benchmark on which we score perfectly is a benchmark that measures nothing.")

    print("\n  NOTE: this team wrote both the payloads and the patterns. The table above")
    print("        shows which phrasings are anticipated, not how the detector would fare")
    print("        against an adversary who has not seen the pattern list.")


def test_entailment(clean: dict, poisoned: dict, pois_gt: dict, verbose: bool) -> None:
    print("\n== detector 3: claim-evidence entailment ==")
    queries = pois_gt["target_queries"]
    labels = pois_gt["labels"]

    rows, backend = [], None
    for doc_id, meta in labels.items():
        qid = meta["target_query_id"]
        q = queries[qid]
        pdoc = poisoned.get(doc_id)
        if not pdoc:
            continue
        anchors = [clean[a] for a in q["clean_anchor_doc_ids"] if a in clean]
        if not anchors:
            continue

        # The claim the attacker wants believed, against the poisoned document
        # and against the genuine one.
        s_att_pois = entailment_scores(q["attacker_target_answer"], [pdoc])[0]
        s_att_clean = entailment_scores(q["attacker_target_answer"], anchors)
        s_true_clean = entailment_scores(q["ground_truth_answer"], anchors)
        backend = backend or s_att_pois.backend

        rows.append({
            "doc_id": doc_id,
            "family": meta["poison_family_id"],
            "attacker_claim_vs_poisoned": s_att_pois.entailment,
            "attacker_claim_vs_clean": max(s.entailment for s in s_att_clean),
            "true_claim_vs_clean": max(s.entailment for s in s_true_clean),
        })

    if not rows:
        check("entailment pairs constructed", False)
        return

    print(f"  backend: {backend.name} (real model: {backend.is_model})")
    if not backend.is_model:
        WARNINGS.append("entailment ran on lexical overlap, which cannot detect contradiction")

    a_p = statistics.mean(r["attacker_claim_vs_poisoned"] for r in rows)
    a_c = statistics.mean(r["attacker_claim_vs_clean"] for r in rows)
    t_c = statistics.mean(r["true_claim_vs_clean"] for r in rows)

    print(f"  attacker's claim, supported by the POISONED doc : {a_p:.3f}  |{bar(a_p)}|")
    print(f"  attacker's claim, supported by the CLEAN anchor : {a_c:.3f}  |{bar(a_c)}|")
    print(f"  true answer,      supported by the CLEAN anchor : {t_c:.3f}  |{bar(t_c)}|")

    # The directional claim: a poisoned document supports the attacker's answer
    # more than the genuine document does. That gap is the signal the verifier
    # exists to expose.
    ok = a_p > a_c
    check("poisoned docs support the attacker's claim more than clean docs do", ok,
          f"{a_p:.3f} vs {a_c:.3f}")
    check("clean anchors support the true answer", t_c > 0.0, f"{t_c:.3f}")

    if verbose:
        print(f"    {'poisoned doc':<44}{'family':<26}{'att|pois':>9}{'att|clean':>11}")
        for r in sorted(rows, key=lambda x: -x["attacker_claim_vs_poisoned"]):
            print(f"    {r['doc_id'][:43]:<44}{r['family']:<26}"
                  f"{r['attacker_claim_vs_poisoned']:>9.3f}{r['attacker_claim_vs_clean']:>11.3f}")


def test_anomaly(clean: dict, poisoned: dict, pois_gt: dict, verbose: bool) -> None:
    print("\n== detector 1: embedding anomaly ==")
    from pipeline.embeddings import get_embedder  # noqa: PLC0415

    embedder = get_embedder()
    if not embedder.is_semantic:
        WARNINGS.append("anomaly ran on the non-semantic fallback embedder")

    # Realistic retrieval sets: four clean documents plus one poisoned document,
    # which is the shape the attack actually takes.
    clean_list = list(clean.values())
    ranks, backend = [], None
    for idx, (doc_id, pdoc) in enumerate(poisoned.items()):
        window = clean_list[(idx * 4) % (len(clean_list) - 4):][:4]
        retrieval_set = window + [pdoc]
        scores = embedding_anomaly_score(retrieval_set, embedder=embedder)
        backend = backend or scores[0].backend
        pois_score = next(s.score for s in scores if s.doc_id == doc_id)
        rank = 1 + sum(1 for s in scores if s.score > pois_score)
        ranks.append({"doc_id": doc_id, "score": pois_score, "rank": rank,
                      "z": scores[-1].detail["robust_z"]})

    print(f"  backend: {backend.name} (semantic embedder: {backend.is_model})")
    top1 = sum(1 for r in ranks if r["rank"] == 1)
    mean_score = statistics.mean(r["score"] for r in ranks)
    print(f"  poisoned document ranked most anomalous in its set: {top1}/{len(ranks)}")
    print(f"  mean anomaly score of poisoned documents          : {mean_score:.3f}  |{bar(mean_score)}|")

    if verbose:
        for r in sorted(ranks, key=lambda x: x["rank"]):
            print(f"    rank {r['rank']}  score {r['score']:.3f}  z {r['z']:+.2f}  {r['doc_id']}")

    check("anomaly produced a score for every poisoned document", len(ranks) == len(poisoned))
    if top1 < len(ranks) / 2:
        print("  EXPECTED: PoisonedRAG documents are constructed to sit NEAR the query in")
        print("  embedding space -- that is the attack. A document engineered for retrieval")
        print("  proximity can land inside the cluster it was aimed at, so this detector is")
        print("  expected to be the weakest of the three here. Low scores are an observation")
        print("  about the attack, not a defect.")


def test_pairwise_conflict(clean: dict, poisoned: dict) -> None:
    print("\n== derived: intra-evidence conflict (design 0.4) ==")
    # The Tier-1 spoofed advisory alongside the genuine one it contradicts.
    pair_ids = ["cisa-icsma-25-030-01", "poison-authority-contec-t1-cisa"]
    docs = [clean.get(pair_ids[0]), poisoned.get(pair_ids[1])]
    if not all(docs):
        check("Tier-1 conflict pair available", False)
        return
    conflicts = pairwise_conflict(docs)
    check("pairwise conflict returns one entry per pair", len(conflicts) == 1)
    print(f"  genuine vs spoofed Tier-1 advisory: contradiction "
          f"{conflicts[0].contradiction:.3f}  |{bar(conflicts[0].contradiction)}|")
    print(f"  d_conflict_max = {d_conflict_max(conflicts):.3f}   "
          f"tier1_conflict_max = {tier1_conflict_max(conflicts):.3f}")
    check("d_conflict_max is in [0,1]", 0.0 <= d_conflict_max(conflicts) <= 1.0)


def main() -> int:
    ap = argparse.ArgumentParser(description="Sanity-check the three Level 2 detectors.")
    ap.add_argument("--verbose", "-v", action="store_true", help="per-document tables")
    args = ap.parse_args()

    if not GT_DIR.exists():
        print(f"ERROR: {GT_DIR} not found. Build the corpus first.", file=sys.stderr)
        return 2

    clean, poisoned, pois_gt = load_docs()
    print(f"Loaded {len(clean)} clean and {len(poisoned)} poisoned documents.")

    test_isolation()
    test_structure(clean, poisoned)
    test_anomaly(clean, poisoned, pois_gt, args.verbose)
    test_injection(clean, poisoned, pois_gt, args.verbose)
    test_entailment(clean, poisoned, pois_gt, args.verbose)
    test_pairwise_conflict(clean, poisoned)

    print("\n" + "=" * 78)
    if WARNINGS:
        print("RUN IS NOT CONCLUSIVE — one or more detectors used a fallback backend:")
        for w in WARNINGS:
            print(f"  - {w}")
        print("  Directional results above are structural evidence only. Install the real")
        print("  models (pip install -r detectors/requirements.txt) before drawing any")
        print("  conclusion about detector performance.")
        print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} structural check(s): {FAILURES}")
        return 1
    print("All structural checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
