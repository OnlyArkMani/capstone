#!/usr/bin/env python3
"""
What the detectors say about documents we KNOW are clean.

    python -m eval.clean_calibration
    python -m eval.clean_calibration --no-generation     # faster, less faithful

The question
------------

The system auto-accepts nothing: every clean control query is sent to a human.
Two explanations produce that same number and they call for opposite responses.

  CALIBRATION FAULT   Clean documents cannot clear the GREEN thresholds even when
                      nothing is wrong with them. The thresholds describe a
                      distribution the clean corpus does not actually have, so
                      "suspicious" is being reported about ordinary traffic.

  CORRECTLY STRICT    Clean documents CAN clear the thresholds, and the reason
                      they do not reach GREEN lies elsewhere -- in the tier rule,
                      the confidence floor, or the score track's operating point.
                      Then relaxing the bands would buy false negatives and no
                      workload relief at all.

This script separates them by measuring, on the known-clean partition only:

  1. each detector's score distribution, against the band thresholds in force;
  2. the share of clean documents each threshold would admit;
  3. for every clean query, WHICH gate actually stood between it and GREEN --
     the tier rule, the case taxonomy, the score track, or the confidence floor.

Point 3 is the one that decides it. A threshold cannot be the cause of anything
if a different gate closes first, and four gates can each close on their own.

It changes nothing. The poisoned partition is not scored here, not read, and not
consulted: this is a study of what "normal" looks like, and mixing the attack
back in is how a calibration study turns into a fitting exercise.
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

from eval.run_evaluation import load_ground_truth, load_queries  # noqa: E402
from fusion.cases import ACCEPT, GREEN  # noqa: E402
from fusion.confidence import REVIEW_FLOOR  # noqa: E402
from fusion.scorer import FusionScorer  # noqa: E402
from pipeline.hypothesis import GENERATED, resolve as resolve_hypothesis  # noqa: E402
from pipeline.rag import BaselineRAG  # noqa: E402

OUT_DIR = PROJECT_ROOT / "eval" / "results"
SIGNALS = ("unsupport", "anomaly", "injection", "conflict")

# One hue for the bars: every panel shows a single series, so identity is carried
# by the panel title and a legend would be noise. The two threshold lines are
# STATUS colours, reserved for exactly this, and each is labelled -- never colour
# alone.
BAR = "#5B8DEF"
SUSPICIOUS_LINE = "#D08B2C"
MALICIOUS_LINE = "#C6444C"
INK = "#1B1F27"
MUTED = "#6B7280"
GRID = "#E5E7EB"


def percentiles(values: list[float]) -> dict[str, float]:
    if not values:
        return {}
    ordered = sorted(values)

    def q(p: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        idx = p * (len(ordered) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(ordered) - 1)
        return ordered[lo] + (ordered[hi] - ordered[lo]) * (idx - lo)

    return {"min": ordered[0], "p50": q(0.50), "p90": q(0.90), "p95": q(0.95),
            "p99": q(0.99), "max": ordered[-1],
            "mean": statistics.fmean(ordered), "n": len(ordered)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Detector behaviour on known-clean documents.")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--no-generation", action="store_true",
                    help="score against the query proxy; faster, but not what the "
                         "system does (design 9A.7)")
    ap.add_argument("--out", type=Path, default=OUT_DIR / "clean_calibration.json")
    args = ap.parse_args()

    poisoned_gt, _clean_gt, _manifest = load_ground_truth()
    rag = BaselineRAG.from_disk()
    scorer = FusionScorer.load(embedder=rag.retriever.embedder, verbose=False)
    scorer.warm_documents(rag.retriever.documents)

    queries = [(qid, text) for qid, text, is_target in load_queries() if not is_target]
    print("=" * 92)
    print("DETECTOR BEHAVIOUR ON KNOWN-CLEAN DOCUMENTS")
    print("=" * 92)
    print(f"  {len(queries)} clean control queries, k={args.k}. The poisoned partition is "
          f"not scored here.")

    by_signal: dict[str, list[float]] = {s: [] for s in SIGNALS}
    by_signal_tier: dict[int, dict[str, list[float]]] = {}
    rows: list[dict[str, Any]] = []
    gate_counts = {"tier_rule": 0, "taxonomy": 0, "score_track": 0,
                   "confidence_floor": 0, "reached_green": 0}

    for i, (qid, text) in enumerate(queries, start=1):
        result = rag.retrieve_top_k(text, k=args.k)
        records = result.records
        hyp = ({"source": "query_proxy", "hypothesis": text}
               if args.no_generation else resolve_hypothesis(rag, text, records))
        score = scorer.score_query(
            text, records,
            generated_answer=hyp["hypothesis"] if hyp["source"] == GENERATED else None)

        for doc in score.documents:
            if doc.doc_id in poisoned_gt:
                continue                      # known-poisoned: out of scope here
            for name in SIGNALS:
                value = doc.signals.get(name)
                if value is None:
                    continue
                by_signal[name].append(float(value))
                tier = int(doc.source_tier)
                by_signal_tier.setdefault(tier, {s: [] for s in SIGNALS})
                by_signal_tier[tier][name].append(float(value))

        # ---- which gate stood between this query and GREEN ----
        detail = score.detail
        gates = []
        if score.tier_governing != 1:
            gates.append("tier_rule")
        if detail.get("taxonomy_action") != ACCEPT:
            gates.append("taxonomy")
        if detail.get("score_action") != ACCEPT:
            gates.append("score_track")
        if detail.get("confidence_forced_review"):
            gates.append("confidence_floor")
        if not gates and score.headline == GREEN and score.action == ACCEPT:
            gate_counts["reached_green"] += 1
        for g in gates:
            gate_counts[g] += 1

        rows.append({
            "query_id": qid, "tier_governing": score.tier_governing,
            "headline": score.headline, "action": score.action,
            "case_id": score.case_id, "confidence": score.confidence,
            "risk_upper": score.risk_interval[1], "gates": gates,
            "hypothesis_source": hyp["source"],
        })
        if i % 10 == 0:
            print(f"      {i}/{len(queries)} clean queries scored")

    bands = scorer.bands
    thresholds = {s: (bands.suspicious.get(s), bands.malicious.get(s)) for s in SIGNALS}

    print()
    print("SIGNAL DISTRIBUTIONS — known-clean documents only")
    print(f"  {'signal':11s} {'n':>4s} {'p50':>8s} {'p90':>8s} {'p95':>8s} {'p99':>8s} "
          f"{'max':>8s}   {'θ_sus':>8s} {'θ_mal':>8s}   {'% CLEAN band':>13s}")
    admitted: dict[str, float] = {}
    for name in SIGNALS:
        values = by_signal[name]
        if not values:
            print(f"  {name:11s}    0   (no measurements)")
            continue
        p = percentiles(values)
        sus, mal = thresholds[name]
        share = (sum(1 for v in values if sus is None or v < sus) / len(values)) * 100
        admitted[name] = round(share, 2)
        sus_s = f"{sus:.4f}" if sus is not None else "  n/a"
        mal_s = f"{mal:.4f}" if mal is not None else "  n/a"
        print(f"  {name:11s} {p['n']:4d} {p['p50']:8.4f} {p['p90']:8.4f} {p['p95']:8.4f} "
              f"{p['p99']:8.4f} {p['max']:8.4f}   {sus_s:>8s} {mal_s:>8s}   {share:12.1f}%")

    print()
    print("WHAT STOOD BETWEEN A CLEAN QUERY AND GREEN")
    print(f"  {'gate':22s} {'queries':>8s}   what it is")
    describe = {
        "tier_rule": "design 2.9: GREEN needs a Tier-1 governing source",
        "taxonomy": "the case taxonomy did not propose Accept",
        "score_track": "risk upper bound >= tau_review (the fitted score)",
        "confidence_floor": f"confidence < {REVIEW_FLOOR} forces at least Review",
    }
    for gate, text in describe.items():
        print(f"  {gate:22s} {gate_counts[gate]:8d}   {text}")
    print(f"  {'reached GREEN':22s} {gate_counts['reached_green']:8d}")

    # A gate that closes on EVERY query is the binding one; a threshold cannot be
    # the cause of anything while a different gate is shut on all of them.
    n = len(queries)
    binding = [g for g in describe if gate_counts[g] == n]
    print()
    print("READING")
    if binding:
        print(f"  Binding on all {n} clean queries: {', '.join(binding)}.")
    band_clean = all(v >= 90.0 for v in admitted.values()) if admitted else False
    if band_clean and "score_track" in binding:
        print("  The band thresholds are NOT the constraint. Clean documents sit inside")
        print("  the CLEAN band on every signal; what closes on every query is the score")
        print("  track's operating point. Relaxing the bands would buy false negatives")
        print("  and no workload relief, because a different gate shuts first.")
    elif not band_clean:
        print("  Some signals put clean documents outside the CLEAN band. Those bands")
        print("  describe a distribution the clean corpus does not have -- a calibration")
        print("  fault worth correcting on the labelled clean partition.")

    payload = {
        "n_clean_queries": n,
        "k": args.k,
        "hypothesis": ("query_proxy" if args.no_generation else "generated_answer"),
        "distributions": {s: percentiles(by_signal[s]) for s in SIGNALS},
        "distributions_by_tier": {
            str(t): {s: percentiles(v[s]) for s in SIGNALS}
            for t, v in sorted(by_signal_tier.items())},
        "band_thresholds": {s: {"suspicious": thresholds[s][0], "malicious": thresholds[s][1]}
                            for s in SIGNALS},
        "percent_in_clean_band": admitted,
        "gate_counts": gate_counts,
        "binding_gates": binding,
        "review_floor": REVIEW_FLOOR,
        "operating_thresholds": scorer.operating,
        "queries": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nwritten: {args.out}")

    chart = plot(by_signal, thresholds, args.out.with_suffix(".png"))
    if chart:
        print(f"         {chart}")
    return 0


def plot(by_signal: dict[str, list[float]], thresholds: dict[str, Any],
         path: Path) -> Path | None:
    """Small multiples: one panel per signal, because they are four different
    quantities on four different scales and one axis cannot serve them all."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        print(f"(no chart — matplotlib unavailable: {type(exc).__name__})")
        return None

    fig, axes = plt.subplots(2, 2, figsize=(11, 7))
    fig.suptitle("Detector scores on known-clean documents, against the bands in force",
                 fontsize=13, color=INK, y=0.98)

    for ax, name in zip(axes.flat, SIGNALS):
        values = by_signal[name]
        ax.set_title(name, fontsize=11, color=INK, loc="left")
        ax.set_facecolor("white")
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        for spine in ("left", "bottom"):
            ax.spines[spine].set_color(GRID)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        ax.tick_params(colors=MUTED, labelsize=9)

        if not values:
            ax.text(0.5, 0.5, "no measurements", ha="center", va="center",
                    color=MUTED, transform=ax.transAxes)
            continue

        ax.hist(values, bins=30, color=BAR, edgecolor="white", linewidth=0.5)
        sus, mal = thresholds[name]
        for value, colour, label in ((sus, SUSPICIOUS_LINE, "suspicious"),
                                     (mal, MALICIOUS_LINE, "malicious")):
            if value is None:
                continue
            ax.axvline(value, color=colour, linewidth=2, linestyle="--")
            ax.annotate(f"{label} {value:.3f}", xy=(value, ax.get_ylim()[1]),
                        xytext=(3, -10), textcoords="offset points",
                        fontsize=8, color=colour, rotation=90, va="top")
        share = sum(1 for v in values if sus is None or v < sus) / len(values) * 100
        ax.set_xlabel(f"{share:.1f}% inside the CLEAN band", fontsize=9, color=MUTED)

    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(path, dpi=150, facecolor="white")
    plt.close(fig)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
