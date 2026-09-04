"""
Evaluation for the composite score, including Attack Success Rate reduction.

Metric choices all follow from ONE stated assumption (design section 3.7): a
missed attack costs roughly ten times a false alarm. Everything below is a
consequence of that rather than a preference.

* **PR-AUC, not ROC-AUC, for model selection.** ROC-AUC normalises its
  false-positive axis by the large negative class and therefore flatters under
  imbalance. Precision-recall keeps the minority class in the denominator.
* **F-beta with beta = 3**, since beta = sqrt(C_FN / C_FP) = sqrt(10) ~= 3.16.
  The headline scalar is then a consequence of the cost assumption.
* **Recall at a fixed alert budget** as the operating metric. Maximising recall
  alone is degenerate -- flag everything, recall 1.0. The operationally
  meaningful question is how much can be caught within the alert volume a SOC can
  absorb.
* **Accuracy is not reported** except inside a confusion matrix. With a skewed
  corpus, predicting "clean" for everything scores well and is worthless.

Attack Success Rate
-------------------
ASR here is measured at the **retrieval-containment** stage, not end to end: the
generation step is not yet wired into this loop, so we measure whether a poisoned
document reaches the analyst, not whether it changed the final answer. That is a
narrower claim than the design's eventual one and is labelled as such in the
output. Once generation is in the loop, ASR should be recomputed against whether
the generated answer matches the attacker's intended answer.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Sequence

import numpy as np

ALERT_BUDGET_FPR = 0.10
BETA = 3.0
COST_FN, COST_FP = 10.0, 1.0
NAIVE_THRESHOLD = 0.5      # the "any single signal over a half" baseline


@dataclass
class Metrics:
    n: int
    n_pos: int
    n_neg: int
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    f_beta: float
    pr_auc: float
    roc_auc: float
    recall_at_budget: float
    threshold_at_budget: float
    brier: float
    expected_cost: float
    precision_at_prevalence: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _confusion(y: np.ndarray, pred: np.ndarray) -> tuple[int, int, int, int]:
    tp = int(np.sum((pred == 1) & (y == 1)))
    fp = int(np.sum((pred == 1) & (y == 0)))
    tn = int(np.sum((pred == 0) & (y == 0)))
    fn = int(np.sum((pred == 0) & (y == 1)))
    return tp, fp, tn, fn


def _safe_div(a: float, b: float) -> float:
    return float(a / b) if b else 0.0


def precision_at_prevalence(tpr: float, fpr: float, prevalence: float) -> float:
    """Prevalence-corrected precision.

    The corpus is far more poisoned than real traffic would be. A detector with
    90% precision at 25% prevalence can fall well below 20% at 2% -- the base-rate
    problem that makes real alerting systems unusable. Reporting the corrected
    figure is what stops the headline number being an overstatement.
    """
    num = tpr * prevalence
    den = num + fpr * (1.0 - prevalence)
    return _safe_div(num, den)


def compute_metrics(y: Sequence[int], scores: Sequence[float], threshold: float = 0.5) -> Metrics:
    """`scores` are P(poisoned). Higher = riskier."""
    y = np.asarray(y, dtype=int)
    s = np.asarray(scores, dtype=float)
    pred = (s >= threshold).astype(int)
    tp, fp, tn, fn = _confusion(y, pred)

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    b2 = BETA ** 2
    f_beta = _safe_div((1 + b2) * precision * recall, b2 * precision + recall)

    try:
        from sklearn.metrics import average_precision_score, roc_auc_score  # noqa: PLC0415
        pr_auc = float(average_precision_score(y, s)) if len(set(y)) > 1 else 0.0
        roc_auc = float(roc_auc_score(y, s)) if len(set(y)) > 1 else 0.0
    except Exception:
        pr_auc = roc_auc = 0.0

    # Recall at the alert budget: best recall achievable while FPR stays under it.
    best_recall, best_thr = 0.0, 1.0
    for thr in np.unique(np.concatenate([s, [0.0, 1.0]])):
        p = (s >= thr).astype(int)
        t_p, f_p, t_n, f_n = _confusion(y, p)
        fpr = _safe_div(f_p, f_p + t_n)
        rec = _safe_div(t_p, t_p + f_n)
        if fpr <= ALERT_BUDGET_FPR and rec > best_recall:
            best_recall, best_thr = rec, float(thr)

    brier = float(np.mean((s - y) ** 2))
    tpr = recall
    fpr_at_thr = _safe_div(fp, fp + tn)

    return Metrics(
        n=len(y), n_pos=int(y.sum()), n_neg=int((1 - y).sum()), threshold=threshold,
        tp=tp, fp=fp, tn=tn, fn=fn,
        precision=round(precision, 6), recall=round(recall, 6),
        f1=round(f1, 6), f_beta=round(f_beta, 6),
        pr_auc=round(pr_auc, 6), roc_auc=round(roc_auc, 6),
        recall_at_budget=round(best_recall, 6), threshold_at_budget=round(best_thr, 6),
        brier=round(brier, 6),
        expected_cost=round(COST_FN * fn + COST_FP * fp, 2),
        precision_at_prevalence={
            "0.05": round(precision_at_prevalence(tpr, fpr_at_thr, 0.05), 6),
            "0.01": round(precision_at_prevalence(tpr, fpr_at_thr, 0.01), 6),
        },
    )


# ---------------------------------------------------------------------------
# Operating thresholds
# ---------------------------------------------------------------------------

def derive_thresholds(y: Sequence[int], scores: Sequence[float],
                      recall_target: float = 0.95,
                      precision_target: float = 0.90) -> dict[str, Any]:
    """tau_review and tau_reject, derived rather than chosen (design section 3.9).

    tau_review  lowest threshold reaching the recall target — catch nearly
                everything; the cost is human review, which is what Review means.
    tau_reject  lowest threshold reaching the precision target — only suppress an
                answer automatically when we are confident.

    If tau_review >= tau_reject the bands are inconsistent, meaning the model is
    too weak to support automated rejection at these tolerances. The correct
    response is to DISABLE the auto-Reject band and route everything above
    tau_review to Review — not to loosen the precision requirement.
    """
    y = np.asarray(y, dtype=int)
    s = np.asarray(scores, dtype=float)
    candidates = np.unique(np.concatenate([s, [0.0, 1.0]]))

    tau_review = 1.0
    for thr in sorted(candidates):
        pred = (s >= thr).astype(int)
        tp, fp, tn, fn = _confusion(y, pred)
        if _safe_div(tp, tp + fn) >= recall_target:
            tau_review = float(thr)
    tau_reject, reject_reachable = 1.0, False
    for thr in sorted(candidates):
        pred = (s >= thr).astype(int)
        tp, fp, tn, fn = _confusion(y, pred)
        if tp > 0 and _safe_div(tp, tp + fp) >= precision_target:
            tau_reject, reject_reachable = float(thr), True
            break

    # tau_reject == 1.0 with nothing reaching the precision target is NOT a
    # consistent three-band configuration -- it is a band that can never fire.
    # Treating it as consistent would report an auto-Reject capability the model
    # does not have.
    consistent = reject_reachable and tau_review < tau_reject
    return {
        "tau_review": round(tau_review, 6),
        "tau_reject": round(tau_reject, 6),
        "recall_target": recall_target,
        "precision_target": precision_target,
        "bands_consistent": consistent,
        "reject_reachable": reject_reachable,
        "regime": "three_band" if consistent else "review_only",
        "note": ("Bands consistent: Accept / Review / Reject." if consistent else
                 "No threshold reaches the precision target, so auto-Reject can never "
                 "fire. Everything above tau_review routes to Review." if not reject_reachable else
                 "tau_review >= tau_reject: the model cannot support automated rejection "
                 "at these tolerances. Auto-Reject is DISABLED and everything above "
                 "tau_review routes to Review. Loosening the precision target instead "
                 "would be the wrong fix."),
    }


# ---------------------------------------------------------------------------
# Attack Success Rate
# ---------------------------------------------------------------------------

@dataclass
class ASRResult:
    asr_baseline: float
    asr_fusion: float
    absolute_reduction: float
    relative_reduction: float
    n_poisoned_retrieved: int
    baseline_blocked: int
    fusion_blocked: int
    baseline_false_blocks: int
    fusion_false_blocks: int
    n_clean_retrieved: int
    baseline_description: str
    scope_note: str
    # Matched-FPR comparison. ASR on its own is not a fair comparison: a baseline
    # that blocks everything scores ASR 0 while being useless. These fields answer
    # "at the same false-block rate, which catches more attacks?"
    baseline_false_block_rate: float = 0.0
    fusion_false_block_rate: float = 0.0
    matched_fpr: float | None = None
    asr_fusion_at_matched_fpr: float | None = None
    matched_comparison_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def naive_baseline_scores(rows: Sequence[Any]) -> np.ndarray:
    """The comparison baseline: flag if ANY single detector signal exceeds a fixed 0.5.

    This is the obvious thing a team would do without a fusion layer, and it is the
    honest thing to compare against -- not a strawman, and not something tuned to
    lose.
    """
    out = []
    for r in rows:
        vals = [v for v in (r.signals.unsupport, r.signals.anomaly,
                            r.signals.injection, r.signals.conflict) if v is not None]
        out.append(max(vals) if vals else 0.0)
    return np.asarray(out, dtype=float)


def attack_success_rate(
    y: Sequence[int],
    fusion_blocked: Sequence[bool],
    baseline_blocked: Sequence[bool],
    fusion_scores: Sequence[float] | None = None,
) -> ASRResult:
    """ASR = fraction of retrieved poisoned documents that reach the analyst.

    "Blocked" means the disposition was Reject or Escalate. Accept and Review both
    return the document to the analyst, so both count as reaching them -- Review
    marks it unverified but does not withhold it.
    """
    y = np.asarray(y, dtype=int)
    fb = np.asarray(fusion_blocked, dtype=bool)
    bb = np.asarray(baseline_blocked, dtype=bool)

    pos, neg = y == 1, y == 0
    n_pos, n_neg = int(pos.sum()), int(neg.sum())

    asr_base = _safe_div(int((pos & ~bb).sum()), n_pos)
    asr_fuse = _safe_div(int((pos & ~fb).sum()), n_pos)

    base_fpr = _safe_div(int((neg & bb).sum()), n_neg)
    fuse_fpr = _safe_div(int((neg & fb).sum()), n_neg)

    # At the baseline's own false-block rate, how much would the fusion score
    # catch? Without this, a baseline that blocks 80% of clean documents "wins"
    # on ASR while being unusable in practice.
    matched_asr, matched_note = None, ""
    if fusion_scores is not None and n_pos and n_neg:
        fs = np.asarray(fusion_scores, dtype=float)
        best = None
        for thr in np.unique(np.concatenate([fs, [0.0, 1.0]])):
            blocked = fs >= thr
            if _safe_div(int((neg & blocked).sum()), n_neg) <= base_fpr:
                asr = _safe_div(int((pos & ~blocked).sum()), n_pos)
                if best is None or asr < best:
                    best = asr
        matched_asr = round(best, 6) if best is not None else None
        matched_note = (
            f"At the baseline's own false-block rate ({base_fpr:.1%} of clean documents), "
            f"the fusion score reaches ASR {matched_asr:.3f} versus the baseline's "
            f"{asr_base:.3f}. This is the fair comparison; the operating-point figures "
            f"above are not, because the two block at very different rates."
        ) if matched_asr is not None else ""

    return ASRResult(
        asr_baseline=round(asr_base, 6),
        asr_fusion=round(asr_fuse, 6),
        absolute_reduction=round(asr_base - asr_fuse, 6),
        relative_reduction=round(_safe_div(asr_base - asr_fuse, asr_base), 6),
        n_poisoned_retrieved=n_pos,
        baseline_blocked=int((pos & bb).sum()),
        fusion_blocked=int((pos & fb).sum()),
        baseline_false_blocks=int((neg & bb).sum()),
        fusion_false_blocks=int((neg & fb).sum()),
        n_clean_retrieved=n_neg,
        baseline_false_block_rate=round(base_fpr, 6),
        fusion_false_block_rate=round(fuse_fpr, 6),
        matched_fpr=round(base_fpr, 6) if matched_asr is not None else None,
        asr_fusion_at_matched_fpr=matched_asr,
        matched_comparison_note=matched_note,
        baseline_description=f"any single detector signal >= {NAIVE_THRESHOLD}",
        scope_note=("Measured at the RETRIEVAL-CONTAINMENT stage: whether a poisoned "
                    "document reaches the analyst, not whether it changed the generated "
                    "answer. Generation is not yet in this loop. Recompute end to end "
                    "against the attacker's intended answer once it is."),
    )
