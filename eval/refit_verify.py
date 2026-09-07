#!/usr/bin/env python3
"""
Guarded refit-and-verify for the design 9A.10 composite-score restriction.

    python -m eval.refit_verify              # refit into a sandbox, verify, DO NOT ship
    python -m eval.refit_verify --adopt      # additionally ship, ONLY if every gate passes

WHY THIS SCRIPT EXISTS
----------------------
`python -m fusion.train` overwrites `fusion/artifacts/` and `eval/fusion_metrics.json`
in place. Its `--out` flag is accepted but NOT honoured: the persist block calls
`bands.save(THRESHOLDS_PATH)` / `model.save(MODEL_PATH)` against fixed module-level
paths, so `--out` only creates an empty directory while the real artifacts are
replaced regardless. Running the refit directly the night before a demo therefore
destroys the shipped model with no way back. This script takes a full backup first,
runs the refit, compares everything against that backup field by field, and restores
the shipped state unless every gate passes and --adopt was given.

THE TWO QUESTIONS THIS SCRIPT KEEPS SEPARATE
--------------------------------------------
They are different questions and conflating them is how a "nothing changed" claim
gets made falsely.

  1. Is the RULE TRACK unchanged?  (C1-C11 case assignment, band thresholds)
     This SHOULD be unchanged, and the change is designed so it cannot be otherwise:
     `fusion/cases.py` imports only from `fusion/bands.py`; neither imports
     `fusion/features.py` or `fusion/model.py`; case assignment reads raw detector
     scores against band thresholds and never consults a regression coefficient.
     Band thresholds are fitted on clean training rows independently of the feature
     spec. If anything here moves, the change was not what it claimed to be.

  2. Is the FINAL DISPOSITION unchanged?  (Accept/Review/Reject/Escalate, FPR,
     exposure, the 0%-vouched-for guarantee)
     This is NOT guaranteed, and expecting it is a mistake. The final action is the
     escalation-dominance reconciliation of the rule track with the SCORE track, and
     the score track's `tau_review` is derived from held-out predictions of the model
     being refitted. Today `tau_review` is 0.0 because no cut point on an ROC-AUC
     0.179 score reaches the 0.95 recall target, which is precisely why the Accept
     disposition is unreachable and the 0%-vouched-for guarantee is structural
     (design 9A.9). If the reduced model discriminates better, `tau_review` may leave
     0.0 -- and the disposition mix WILL move, auto-accept may reopen, and attacks may
     become vouched-for.

     That is a NEW OPERATING POINT. Design roadmap P5 gates recalibration on fixing
     entailment (P1) first. So this script treats a moved `tau_review` as a REPORTABLE
     FINDING and a blocker to adoption -- not as a success and not as a failure.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKUP = ROOT / "eval" / "results" / "refit_baseline"

TRACKED = [
    ("fusion/artifacts/band_thresholds.json", True),
    ("fusion/artifacts/operating_thresholds.json", True),
    ("fusion/artifacts/trust_model.json", True),
    ("fusion/artifacts/trust_model.joblib", False),
    ("eval/fusion_metrics.json", True),
    ("eval/results/evaluation.json", True),
    ("eval/results/comparison_table.txt", False),
    ("eval/results/clean_calibration.json", True),
]

PASS, FAIL, INFO = "PASS", "FAIL", "----"


def load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def backup(tag: str) -> None:
    dest = BACKUP / tag
    dest.mkdir(parents=True, exist_ok=True)
    for rel, _ in TRACKED:
        src = ROOT / rel
        if src.exists():
            out = dest / rel.replace("/", "__")
            shutil.copy2(src, out)


def restore(tag: str) -> None:
    src_dir = BACKUP / tag
    for rel, _ in TRACKED:
        src = src_dir / rel.replace("/", "__")
        if src.exists():
            shutil.copy2(src, ROOT / rel)


def run(cmd: list[str], label: str) -> bool:
    print(f"\n>>> {label}: {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        print(f"    {label} FAILED with exit code {r.returncode}")
        return False
    return True


def check(results: list, name: str, ok: bool, detail: str = "") -> None:
    results.append((PASS if ok else FAIL, name, detail))


def note(results: list, name: str, detail: str) -> None:
    results.append((INFO, name, detail))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adopt", action="store_true",
                    help="ship the refit ONLY if every gate passes and the operating "
                         "point did not move")
    ap.add_argument("--skip-eval", action="store_true",
                    help="refit and compare fit metrics only; skip the 40-query harness")
    args = ap.parse_args()

    print("=" * 78)
    print("REFIT AND VERIFY — design 9A.10 composite-score restriction")
    print("=" * 78)

    for rel, _ in TRACKED:
        if not (ROOT / rel).exists():
            print(f"ERROR: missing baseline file {rel}. Refusing to run.", file=sys.stderr)
            return 2

    print("\n[1/5] Backing up the shipped state ...")
    backup("shipped")
    print(f"      -> {BACKUP / 'shipped'}")

    before_fusion = load(ROOT / "eval/fusion_metrics.json")
    before_bands = load(ROOT / "fusion/artifacts/band_thresholds.json")
    before_oper = load(ROOT / "fusion/artifacts/operating_thresholds.json")
    before_eval = load(ROOT / "eval/results/evaluation.json")
    before_clean = load(ROOT / "eval/results/clean_calibration.json")

    print("\n[2/5] Refitting the composite score ...")
    if not run([sys.executable, "-m", "fusion.train"], "fusion.train"):
        print("\nRefit failed. Restoring shipped state.")
        restore("shipped")
        return 1

    after_fusion = load(ROOT / "eval/fusion_metrics.json")
    after_bands = load(ROOT / "fusion/artifacts/band_thresholds.json")
    after_oper = load(ROOT / "fusion/artifacts/operating_thresholds.json")

    results: list = []

    # ---- Gate A: the run itself must be real -------------------------------
    ds = after_fusion["dataset"]
    backends = ds.get("detector_backends") or {}
    degraded = [k for k, v in backends.items() if v and v.get("is_fallback")]
    check(results, "No detector on a fallback backend", not degraded,
          f"degraded: {', '.join(degraded)}" if degraded else "")
    hyp = ds.get("hypothesis_counts", {})
    check(results, "All rows used a generated answer as hypothesis",
          hyp.get("query_text_proxy", 1) == 0,
          f"generated={hyp.get('generated_answer')} proxy={hyp.get('query_text_proxy')}")
    check(results, "Fit backend is sklearn (Platt calibration available)",
          after_fusion["fit_report"].get("backend") == "sklearn",
          f"backend={after_fusion['fit_report'].get('backend')}")
    check(results, "Model is calibrated",
          bool(after_fusion["fit_report"].get("calibrated")))

    # ---- Gate B: the feature set is the intended one ------------------------
    names = after_fusion["feature_spec"]["names"]
    expected = ["x_conflict", "is_tier1", "is_tier3"]
    check(results, "Feature set is exactly x_conflict + tier dummies",
          names == expected, f"got {names}")
    for gone in ("x_unsupport", "x_injection", "x_anomaly", "is_tier1_x_conflict"):
        check(results, f"{gone} absent from the regression", gone not in names)

    # ---- Gate C: the rule track did not move --------------------------------
    check(results, "Band thresholds byte-identical", before_bands == after_bands,
          "band thresholds moved — the change was NOT statistical-layer only")
    check(results, "Split unchanged (same rows, same groups)",
          before_fusion["split"] == after_fusion["split"],
          f"before={before_fusion['split']} after={after_fusion['split']}")
    check(results, "Detector backends unchanged",
          (before_fusion["dataset"].get("detector_backends")
           == after_fusion["dataset"].get("detector_backends")))
    check(results, "Raw signal separation unchanged (detectors untouched)",
          before_fusion["signal_separation"] == after_fusion["signal_separation"],
          "a detector's raw output changed — this must not happen")

    # ---- The finding: did the composite score improve? ----------------------
    b_roc = before_fusion["metrics"]["roc_auc"]
    a_roc = after_fusion["metrics"]["roc_auc"]
    b_pr = before_fusion["metrics"]["pr_auc"]
    a_pr = after_fusion["metrics"]["pr_auc"]
    note(results, "Held-out ROC-AUC", f"{b_roc:.3f} -> {a_roc:.3f}")
    note(results, "Held-out PR-AUC", f"{b_pr:.4f} -> {a_pr:.4f}")
    positive_rate = (after_fusion["metrics"]["n_pos"] / after_fusion["metrics"]["n"])
    note(results, "Held-out positive rate (PR-AUC floor)", f"{positive_rate:.4f}")
    verdict = ("DISCRIMINATIVE (meaningfully above chance)" if a_roc >= 0.60 else
               "MARGINAL (0.55-0.60, not meaningfully above chance at this n)"
               if a_roc >= 0.55 else
               "NOT DISCRIMINATIVE (at or below chance)")
    note(results, "Verdict on the reduced composite score", f"ROC-AUC {a_roc:.3f} — {verdict}")

    # ---- Gate D: has the OPERATING POINT moved? -----------------------------
    tau_moved = (abs(float(before_oper["tau_review"]) - float(after_oper["tau_review"])) > 1e-9
                 or abs(float(before_oper["tau_reject"])
                        - float(after_oper["tau_reject"])) > 1e-9)
    note(results, "tau_review",
         f"{before_oper['tau_review']} -> {after_oper['tau_review']}")
    note(results, "tau_reject",
         f"{before_oper['tau_reject']} -> {after_oper['tau_reject']}")
    if tau_moved:
        note(results, "OPERATING POINT MOVED",
             "This is a NEW operating point. Roadmap P5 gates recalibration on "
             "fixing entailment (P1) first. Report it; do not adopt it tonight.")

    # ---- Gate E: the evaluation harness -------------------------------------
    if not args.skip_eval:
        print("\n[3/5] Re-running the evaluation harness ...")
        if not run([sys.executable, "-m", "eval.run_evaluation"], "eval.run_evaluation"):
            print("\nEvaluation failed. Restoring shipped state.")
            restore("shipped")
            return 1
        after_eval = load(ROOT / "eval/results/evaluation.json")

        def full(d):
            for c in d["configurations"]:
                if c["config"] == "full_system":
                    return c
            raise KeyError("full_system configuration missing")

        b, a = full(before_eval), full(after_eval)
        fields = [
            ("Attacks vouched for (the guarantee)",
             b["attack_success_rate"]["high_confidence"], a["attack_success_rate"]["high_confidence"]),
            ("Attack exposure (reached the user)",
             b["attack_success_rate"]["exposure"], a["attack_success_rate"]["exposure"]),
            ("False positive rate",
             b["false_positive_rate"]["value"], a["false_positive_rate"]["value"]),
            ("Clean queries routed to a human",
             b["false_positive_rate"]["review_rate_on_clean_queries"],
             a["false_positive_rate"]["review_rate_on_clean_queries"]),
            ("Auto-accept rate",
             b["disposition_mix"]["auto_accept_rate"], a["disposition_mix"]["auto_accept_rate"]),
            ("Human review rate",
             b["disposition_mix"]["human_review_rate"], a["disposition_mix"]["human_review_rate"]),
            ("Blocked rate",
             b["disposition_mix"]["blocked_rate"], a["disposition_mix"]["blocked_rate"]),
            ("False negative — vouched for",
             b["false_negative_rate"]["value"], a["false_negative_rate"]["value"]),
            ("False negative — exposure",
             b["false_negative_rate"]["exposure"], a["false_negative_rate"]["exposure"]),
            ("Clean auto-accept, per document",
             b["clean_auto_accept_rate"]["per_document"], a["clean_auto_accept_rate"]["per_document"]),
            ("Clean auto-accept, per query",
             b["clean_auto_accept_rate"]["per_query"], a["clean_auto_accept_rate"]["per_query"]),
            ("GREEN-eligible query rate (structural ceiling)",
             b["clean_auto_accept_rate"]["green_eligible_query_rate"],
             a["clean_auto_accept_rate"]["green_eligible_query_rate"]),
        ]
        for label, bv, av in fields:
            check(results, f"UNCHANGED: {label}", bv == av, f"{bv} -> {av}")

        check(results, "UNCHANGED: detection breakdown by case (C1-C11)",
              before_eval["weakness_breakdown"]["by_case"]
              == after_eval["weakness_breakdown"]["by_case"])
        check(results, "UNCHANGED: detection breakdown by attack family",
              before_eval["weakness_breakdown"]["by_poison_family"]
              == after_eval["weakness_breakdown"]["by_poison_family"])
        check(results, "UNCHANGED: detection breakdown by source tier",
              before_eval["weakness_breakdown"]["by_source_tier"]
              == after_eval["weakness_breakdown"]["by_source_tier"])
        check(results, "UNCHANGED: attack reachability",
              before_eval["attack_reachability"] == after_eval["attack_reachability"])

        print("\n[4/5] Re-running clean calibration (per-query case assignment) ...")
        if run([sys.executable, "-m", "eval.clean_calibration"], "eval.clean_calibration"):
            after_clean = load(ROOT / "eval/results/clean_calibration.json")

            def keyed(d):
                return {q["query_id"]: (q["case_id"], q["action"], q["headline"])
                        for q in d["queries"]}

            kb, ka = keyed(before_clean), keyed(after_clean)
            same_cases = all(kb.get(q, (None,))[0] == ka.get(q, (None,))[0] for q in kb)
            check(results, "UNCHANGED: per-query C1-C11 case id, all 30 clean queries",
                  same_cases)
            same_actions = kb == ka
            check(results, "UNCHANGED: per-query action and headline, all 30 clean queries",
                  same_actions)
            if not same_actions and same_cases:
                note(results, "Cases held, dispositions moved",
                     "Exactly the signature of an operating-point change: the rule "
                     "track is intact and the score track moved underneath it.")
                for q in kb:
                    if kb[q] != ka.get(q):
                        note(results, f"  {q}", f"{kb[q]} -> {ka.get(q)}")
            check(results, "UNCHANGED: band thresholds in calibration record",
                  before_clean["band_thresholds"] == after_clean["band_thresholds"])
            note(results, "Binding gates",
                 f"{before_clean['binding_gates']} -> {after_clean['binding_gates']}")
            note(results, "Gate counts",
                 f"{before_clean['gate_counts']} -> {after_clean['gate_counts']}")

    # ---- Report -------------------------------------------------------------
    print("\n[5/5] Results")
    print("=" * 78)
    width = max(len(n) for _, n, _ in results)
    for status, name, detail in results:
        line = f"  [{status}] {name.ljust(width)}"
        if detail:
            line += f"   {detail}"
        print(line)
    print("=" * 78)

    failures = [n for s, n, _ in results if s == FAIL]
    print(f"\n  {len(failures)} failed gate(s), "
          f"{sum(1 for s, _, _ in results if s == PASS)} passed.")

    if failures:
        print("\n  FAILED GATES:")
        for n in failures:
            print(f"    - {n}")

    should_adopt = args.adopt and not failures and not tau_moved
    if should_adopt:
        print("\n  ADOPTED. The refit is now the shipped model.")
        backup("adopted")
    else:
        reasons = []
        if failures:
            reasons.append(f"{len(failures)} gate(s) failed")
        if tau_moved:
            reasons.append("the operating point moved (roadmap P5, gated on P1)")
        if not args.adopt:
            reasons.append("--adopt was not given")
        print(f"\n  NOT ADOPTED ({'; '.join(reasons)}).")
        print("  Refit output preserved under eval/results/refit_baseline/refit_result/")
        backup("refit_result")
        restore("shipped")
        print("  Shipped state restored. The demo is unaffected.")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
