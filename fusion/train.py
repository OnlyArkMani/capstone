#!/usr/bin/env python3
"""
Fit the fusion layer: calibrate bands, train the composite score, report performance.

    python -m fusion.train
    python -m fusion.train --k 5 --no-generated-queries

Steps, in order:
  1. Build the labelled instance set (retrieval + detectors + ground-truth join).
  2. Split by GROUP -- attack family for poisoned rows, doc_id for clean ones --
     into a locked test set and a training set. Random splitting would let a
     poison template straddle both and inflate every metric.
  3. Calibrate the band thresholds on CLEAN TRAINING rows only.
  4. Choose the feature-ladder rung the corpus can support, then fit.
  5. Derive the operating thresholds from held-out predictions.
  6. Evaluate, including Attack Success Rate against the naive baseline.
  7. Persist everything to fusion/artifacts/.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fusion.bands import BandThresholds, SignalSet  # noqa: E402
from fusion.cases import REJECT, ESCALATE, classify_document  # noqa: E402
from fusion.dataset import build_dataset, rows_to_arrays  # noqa: E402
from fusion.evaluate import (  # noqa: E402
    NAIVE_THRESHOLD, attack_success_rate, compute_metrics, derive_thresholds,
    naive_baseline_scores,
)
from fusion.features import choose_feature_spec  # noqa: E402
from fusion.model import RANDOM_SEED, TrustModel  # noqa: E402
from fusion.scorer import ARTIFACTS, MODEL_PATH, OPERATING_PATH, THRESHOLDS_PATH  # noqa: E402


def signal_separation(rows, signal_names):
    """Per-signal mean difference and AUC between poisoned and clean TRAINING rows.

    Run before fitting, because a signal that points the wrong way produces a
    model that is confidently backwards, and the metrics alone will not tell you
    which signal did it.

    One inversion is known and expected here. PoisonedRAG documents carry a
    retrieval-optimising segment that RESTATES THE TARGET QUERY -- that is how they
    get retrieved. So when the query stands in as the entailment hypothesis (which
    it must, until generation is in the loop), a poisoned document appears MORE
    supported than a genuine one. The signal is not merely weak in that
    configuration, it is anti-correlated, and including it lets the model exploit
    an inversion that will vanish the moment a real generated claim is used.
    """
    import statistics as st

    out = {}
    for name in signal_names:
        pos = [v for r in rows if r.label == 1 and (v := getattr(r.signals, name)) is not None]
        neg = [v for r in rows if r.label == 0 and (v := getattr(r.signals, name)) is not None]
        if not pos or not neg:
            out[name] = {"usable": False, "reason": "one class has no values"}
            continue
        diff = st.mean(pos) - st.mean(neg)
        try:
            from sklearn.metrics import roc_auc_score  # noqa: PLC0415
            y = [1] * len(pos) + [0] * len(neg)
            auc = float(roc_auc_score(y, pos + neg))
        except Exception:
            auc = float("nan")
        out[name] = {
            "mean_poisoned": round(st.mean(pos), 4),
            "mean_clean": round(st.mean(neg), 4),
            "mean_difference": round(diff, 4),
            "auc": round(auc, 4),
            "inverted": diff < 0,
            "usable": diff > 0,
        }
    return out


def grouped_split(y, groups, test_fraction=0.20, seed=RANDOM_SEED):
    """Hold out whole groups, keeping both classes present on each side.

    Falls back to a simple group split when the corpus is too small for the
    stratified splitter -- and says so, rather than silently producing a split
    with no positives in test.
    """
    try:
        from sklearn.model_selection import StratifiedGroupKFold  # noqa: PLC0415

        n_splits = max(2, int(round(1 / test_fraction)))
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        for train_idx, test_idx in sgkf.split(np.zeros(len(y)), y, groups):
            if y[test_idx].sum() > 0 and y[train_idx].sum() > 0:
                return train_idx, test_idx, "StratifiedGroupKFold"
    except Exception:
        pass

    rng = np.random.default_rng(seed)
    uniq = np.array(sorted(set(groups)))
    rng.shuffle(uniq)
    n_test = max(1, int(len(uniq) * test_fraction))
    test_groups = set(uniq[:n_test])
    test_idx = np.array([i for i, g in enumerate(groups) if g in test_groups])
    train_idx = np.array([i for i, g in enumerate(groups) if g not in test_groups])
    return train_idx, test_idx, "group_shuffle_fallback"


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the Level 3 fusion layer.")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--no-generated-queries", action="store_true",
                    help="use only the 10 target queries (produces very few rows)")
    ap.add_argument("--test-fraction", type=float, default=0.20)
    ap.add_argument("--out", type=Path, default=ARTIFACTS)
    args = ap.parse_args()

    print("=" * 78)
    print("LEVEL 3 FUSION — TRAINING")
    print("=" * 78)

    # ---- 1. dataset ----
    from pipeline.retrieval import Retriever  # noqa: PLC0415

    print("\n[1/7] Building retrieval index ...")
    retriever = Retriever.build(verbose=True)

    print("\n[2/7] Building labelled instance set ...")
    rows, ds_meta = build_dataset(retriever, k=args.k,
                                  include_generated=not args.no_generated_queries)
    if not rows:
        print("ERROR: no labelled rows produced.", file=sys.stderr)
        return 1
    if ds_meta["n_pos"] == 0:
        print("ERROR: no poisoned instances retrieved. Nothing to learn from.", file=sys.stderr)
        return 1

    y_all = np.asarray([r.label for r in rows], dtype=int)
    groups_all = np.asarray([r.group for r in rows])

    # ---- 2. split ----
    print("\n[3/7] Splitting by group (attack family / document) ...")
    train_idx, test_idx, split_method = grouped_split(y_all, groups_all, args.test_fraction)
    train_rows = [rows[i] for i in train_idx]
    test_rows = [rows[i] for i in test_idx]
    print(f"      method={split_method}  train={len(train_rows)} "
          f"({int(y_all[train_idx].sum())} poisoned)  "
          f"test={len(test_rows)} ({int(y_all[test_idx].sum())} poisoned)")
    print("      Groups never straddle the split, so a poison template cannot be "
          "memorised then scored.")

    # ---- 3. band thresholds, clean training rows only ----
    print("\n[4/7] Calibrating band thresholds on CLEAN TRAINING rows ...")
    clean_train = [r.signals for r in train_rows if r.label == 0]
    bands = BandThresholds.fit(clean_train)
    print(f"      fitted on {len(clean_train)} clean rows — {bands.note}")
    for name in ("unsupport", "anomaly", "injection"):
        print(f"        {name:<11} suspicious {bands.suspicious.get(name, float('nan')):.4f}"
              f"   malicious {bands.malicious.get(name, float('nan')):.4f}")

    # ---- 4. signal diagnostics, then features + fit ----
    print("\n[5/7] Signal separation on TRAINING rows (before fitting) ...")
    sep = signal_separation(train_rows, ds_meta["signals_available"])
    for name, d in sep.items():
        if not d.get("usable") and "reason" in d:
            print(f"      {name:<11} unusable: {d['reason']}")
            continue
        flag = "  <-- INVERTED" if d["inverted"] else ""
        print(f"      {name:<11} poisoned {d['mean_poisoned']:.4f}  clean {d['mean_clean']:.4f}"
              f"  diff {d['mean_difference']:+.4f}  AUC {d['auc']:.3f}{flag}")

    inverted = [n for n, d in sep.items() if d.get("inverted")]
    usable_signals = [n for n in ds_meta["signals_available"] if n not in inverted]
    if inverted:
        print(f"\n      DROPPING {len(inverted)} inverted signal(s): {', '.join(inverted)}")
        print("      An anti-correlated signal does not merely add noise — the model would")
        print("      learn to read it backwards, and that inversion is an artefact of this")
        print("      configuration rather than a property of the attack.")
        if "unsupport" in inverted:
            print("      For `unsupport` specifically the cause is known: PoisonedRAG documents")
            print("      restate the target query to get retrieved, so with the query standing")
            print("      in as the entailment hypothesis they look BETTER supported than genuine")
            print("      ones. This should reverse once a real generated claim is used.")
    if not usable_signals:
        print("\nERROR: every signal is inverted or unusable. Nothing to fit.", file=sys.stderr)
        print("       The fusion mechanics are fine; the detector inputs are not.",
              file=sys.stderr)
        return 1

    n_pos_train = int(y_all[train_idx].sum())
    spec = choose_feature_spec(usable_signals, n_pos_train)
    print(f"      Feature ladder: rung={spec.rung}, {len(spec.names)} features")
    print(f"      {spec.note}")
    print(f"      features: {', '.join(spec.names)}")

    X_train, y_train, g_train = rows_to_arrays(train_rows, spec)
    X_test, y_test, _ = rows_to_arrays(test_rows, spec)

    model = TrustModel(spec)
    report = model.fit(X_train, y_train, g_train)
    print(f"      backend={report.backend}  C={report.chosen_C}  "
          f"calibrated={report.calibrated}")
    print("      coefficients:")
    for name, coef in sorted(report.coefficients.items(), key=lambda kv: -abs(kv[1])):
        print(f"        {name:<24}{coef:+.4f}")

    # Every base signal is risk-oriented, so every coefficient should be POSITIVE.
    # A negative one means the model reads that signal backwards, which produces
    # confident wrong answers rather than obviously broken ones.
    wrong_sign = [n for n in spec.base_signals
                  if report.coefficients.get(f"x_{n}", 0.0) < 0]
    if wrong_sign:
        print(f"\n      SIGN CHECK FAILED for: {', '.join(wrong_sign)}")
        print("      These signals are risk-oriented, so their coefficients should be")
        print("      positive. A negative coefficient means the fitted model reads the")
        print("      signal backwards. With fallback detector backends this is expected;")
        print("      with the production models it would be a defect to investigate.")
    else:
        print("\n      Sign check: all base-signal coefficients are positive, as expected.")

    # Design section 3.2 calls for this one explicitly: anomaly should be penalised
    # MORE steeply for Tier-1 sources, not less.
    inter = report.coefficients.get("is_tier1_x_anomaly")
    if inter is not None:
        verdict = "as designed" if inter > 0 else "AGAINST the taxonomy — investigate"
        print(f"\n      is_tier1_x_anomaly = {inter:+.4f} ({verdict})")
        if inter <= 0:
            print("      The taxonomy asserts a Tier-1 anomaly is MORE serious. A negative "
                  "coefficient means either the corpus lacks Tier-1 compromise instances "
                  "or the labelling is wrong. Do not ship without understanding why.")

    # ---- 5. operating thresholds ----
    print("\n[6/7] Deriving operating thresholds from held-out predictions ...")
    test_scores = model.predict_risk(X_test)
    operating = derive_thresholds(y_test, test_scores)
    print(f"      tau_review={operating['tau_review']:.4f}  "
          f"tau_reject={operating['tau_reject']:.4f}  regime={operating['regime']}")
    if not operating["bands_consistent"]:
        print(f"      {operating['note']}")

    # ---- 6. evaluation ----
    print("\n[7/7] Evaluating on the held-out set ...")
    metrics = compute_metrics(y_test, test_scores, threshold=operating["tau_review"])
    print(f"      precision {metrics.precision:.3f}   recall {metrics.recall:.3f}   "
          f"F1 {metrics.f1:.3f}   F3 {metrics.f_beta:.3f}")
    print(f"      PR-AUC {metrics.pr_auc:.3f}   ROC-AUC {metrics.roc_auc:.3f}   "
          f"Brier {metrics.brier:.3f}")
    print(f"      recall @ FPR<=0.10: {metrics.recall_at_budget:.3f}")
    print(f"      confusion: TP {metrics.tp}  FP {metrics.fp}  "
          f"TN {metrics.tn}  FN {metrics.fn}")
    print(f"      precision corrected to realistic prevalence: "
          f"5% -> {metrics.precision_at_prevalence['0.05']:.3f}, "
          f"1% -> {metrics.precision_at_prevalence['0.01']:.3f}")

    # ---- ASR: fusion vs the naive single-signal baseline ----
    naive = naive_baseline_scores(test_rows)
    baseline_blocked = naive >= NAIVE_THRESHOLD
    fusion_blocked = []
    for row, score in zip(test_rows, test_scores):
        case = classify_document(row.source_tier, row.signals, bands)
        blocked_by_rule = case.action in (REJECT, ESCALATE)
        blocked_by_score = score >= operating["tau_reject"] if operating["bands_consistent"] \
            else False
        fusion_blocked.append(bool(blocked_by_rule or blocked_by_score))
    asr = attack_success_rate(y_test, fusion_blocked, baseline_blocked,
                              fusion_scores=test_scores)

    print("\n      ATTACK SUCCESS RATE (retrieval containment)")
    print(f"        naive baseline ({asr.baseline_description}): {asr.asr_baseline:.3f}")
    print(f"        fusion layer:                                 {asr.asr_fusion:.3f}")
    print(f"        absolute reduction: {asr.absolute_reduction:+.3f}   "
          f"relative: {asr.relative_reduction:+.1%}")
    print(f"        false blocks on clean docs — baseline {asr.baseline_false_blocks}"
          f"/{asr.n_clean_retrieved} ({asr.baseline_false_block_rate:.1%}), "
          f"fusion {asr.fusion_false_blocks}/{asr.n_clean_retrieved} "
          f"({asr.fusion_false_block_rate:.1%})")
    if asr.matched_comparison_note:
        print(f"\n        MATCHED-RATE COMPARISON (the fair one)")
        print(f"        {asr.matched_comparison_note}")
        print("        ASR alone is not a fair comparison: a baseline that blocks")
        print("        everything scores ASR 0 while being useless in practice.")

    # ---- 7. persist ----
    args.out.mkdir(parents=True, exist_ok=True)
    bands.save(THRESHOLDS_PATH)
    model.save(MODEL_PATH)
    with OPERATING_PATH.open("w", encoding="utf-8") as fh:
        json.dump(operating, fh, indent=2)
        fh.write("\n")

    caveats = list(ds_meta["caveats"])
    non_model = [k for k, v in (ds_meta["detector_backends"] or {}).items()
                 if v and not v.get("is_model")]
    if non_model:
        caveats.append(
            f"Detectors running on FALLBACK backends: {', '.join(non_model)}. Every figure "
            f"above is structural evidence that the fusion layer works, not a measurement "
            f"of detection performance. Install the production models and refit.")
    if inverted:
        caveats.append(
            f"Signals dropped for being anti-correlated with the label on training data: "
            f"{', '.join(inverted)}. See signal_separation in this file for the figures.")
    if wrong_sign:
        caveats.append(f"Fitted coefficients have the wrong sign for: {', '.join(wrong_sign)}.")
    if spec.underpowered:
        caveats.append("Feature ladder is at the underpowered rung; coefficients are "
                       "indicative and the case taxonomy remains the primary control.")

    metrics_payload = {
        "dataset": ds_meta, "split": {"method": split_method,
                                      "n_train": len(train_rows), "n_test": len(test_rows),
                                      "n_pos_train": n_pos_train,
                                      "n_pos_test": int(y_test.sum())},
        "signal_separation": sep, "dropped_inverted_signals": inverted,
        "feature_spec": spec.to_dict(), "fit_report": report.to_dict(),
        "band_thresholds": {"suspicious": bands.suspicious, "malicious": bands.malicious,
                            "n_clean_calibration": bands.n_clean_calibration},
        "operating_thresholds": operating,
        "metrics": metrics.to_dict(), "attack_success_rate": asr.to_dict(),
        "caveats": caveats,
    }
    metrics_path = PROJECT_ROOT / "eval" / "fusion_metrics.json"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics_payload, fh, indent=2)
        fh.write("\n")

    print(f"\nSaved:")
    print(f"  {THRESHOLDS_PATH}")
    print(f"  {MODEL_PATH}  (+ .json sidecar)")
    print(f"  {OPERATING_PATH}")
    print(f"  {metrics_path}")

    weak = [n for n, d in sep.items() if d.get("auc") and abs(d["auc"] - 0.5) < 0.10]
    if len(weak) == len(sep):
        print("\n" + "=" * 78)
        print("VERDICT: the fusion layer is wired correctly and every stage runs, but NO")
        print("detector signal separates poisoned from clean in this configuration (all")
        print("AUCs within 0.10 of chance). The mechanics are validated; the inputs are")
        print("not yet real. Install the production detector models and refit before")
        print("drawing any conclusion about detection performance.")
        print("=" * 78)

    if caveats:
        print("\n" + "=" * 78)
        print("CAVEATS — read before quoting any figure above")
        for c in caveats:
            print(f"  - {c}")
        print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
