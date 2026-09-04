"""
Part C — the confidence measure. Design section 4.

Risk and confidence answer different questions and are kept as separate outputs:

    RISK        how likely is it that this response is attacker-influenced?
    CONFIDENCE  how much should we trust that risk estimate?

A risk of 0.85 from five agreeing documents across three independent sources is a
finding. The same 0.85 from one document, with the detectors contradicting each
other, is a guess. Reporting them as one number would hide the difference from
the analyst, so we do not.

Five components, combined by GEOMETRIC mean
-------------------------------------------
Confidence is conjunctive: we are confident only if there is enough evidence AND
it agrees AND it is independent AND the detectors concur AND the model is stable.
An arithmetic mean lets four strong components mask one fatal weakness, which is
precisely the behaviour we cannot afford. Any component at zero drives the
composite to zero, which is correct.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, asdict
from typing import Any, Sequence

import numpy as np

KAPPA = 2.0                # evidence-volume saturation constant
AGREEMENT_EXPONENT = 1.5   # the one component weighted above 1.0
SINGLETON_CAP = 0.30
N_EFF_ONE_CAP = 0.40
REVIEW_FLOOR = 0.35        # below this, minimum disposition is Review
NEAR_DUPLICATE_COSINE = 0.95


@dataclass
class ConfidenceResult:
    confidence: float
    components: dict[str, float]
    n_eff: float
    caps_applied: list[str]
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Effective sample size
# ---------------------------------------------------------------------------

def effective_sample_size(weights: Sequence[float], n_distinct_sources: int | None = None) -> float:
    """Kish effective sample size, capped by the number of independent sources.

    The inverse-Simpson form means one document carrying 90% of the attribution
    weight yields n_eff ~= 1.2 even when five documents were retrieved -- correctly,
    because the answer really rested on one. The independence cap then stops five
    near-duplicates from one feed inflating it again.
    """
    w = np.asarray([max(float(x), 0.0) for x in weights], dtype=float)
    if w.size == 0:
        return 0.0
    total = w.sum()
    if total <= 0:
        return float(w.size)
    w = w / total
    n_eff = float(1.0 / np.sum(w ** 2))
    if n_distinct_sources is not None:
        n_eff = min(n_eff, float(n_distinct_sources))
    return n_eff


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

def c_volume(n_eff: float, kappa: float = KAPPA) -> float:
    """Evidence volume, saturating. n_eff=1 -> 0.39, 3 -> 0.78, 5 -> 0.92.

    Saturating rather than linear because the tenth corroborating document adds
    far less than the second, and a linear form would let volume dominate.
    """
    return float(1.0 - math.exp(-max(n_eff, 0.0) / kappa))


def c_agreement(d_conflict_max: float) -> float:
    """Evidence agreement. Volume without agreement is not confidence.

    Five documents that contradict each other are less informative than two that
    agree, and this is the component that encodes it.
    """
    return float(min(1.0, max(0.0, 1.0 - d_conflict_max)))


def c_independence(n_distinct_sources: int, n_distinct_tiers: int) -> float:
    """Source independence. Five documents from one feed is one witness, quoted five times.

    Cross-tier corroboration is weighted in deliberately: an attacker who has
    poisoned one feed has not necessarily poisoned CISA *and* a community feed, so
    agreement spanning tiers is harder to manufacture than agreement within one.
    """
    return float(0.7 * min(n_distinct_sources / 3.0, 1.0)
                 + 0.3 * min(n_distinct_tiers / 2.0, 1.0))


def c_coherence(signal_votes: Sequence[float]) -> float:
    """Detector coherence. If the detectors disagree, the estimate rests on an
    unresolved internal contradiction.

    0.5 is the maximum standard deviation attainable by values on [0, 1] (half at
    each extreme), so the ratio is a proper normalisation rather than an arbitrary
    scale.
    """
    votes = [v for v in signal_votes if v is not None]
    if len(votes) < 2:
        return 1.0
    sd = statistics.pstdev(votes)
    return float(min(1.0, max(0.0, 1.0 - sd / 0.5)))


def c_model_stability(interval_width: float) -> float:
    """How stable the fitted model's output is for this particular input.

    Captures two problems at once: inputs in sparse regions of the training
    distribution give unstable coefficients and wide intervals, and predictions
    near p=0.5 are inherently uncertain. Both correctly lower confidence.
    """
    return float(min(1.0, max(0.0, 1.0 - interval_width)))


# ---------------------------------------------------------------------------
# Composition
# ---------------------------------------------------------------------------

def compute_confidence(
    *,
    n_eff: float,
    d_conflict_max: float,
    n_distinct_sources: int,
    n_distinct_tiers: int,
    signal_votes: Sequence[float],
    risk_interval_width: float,
    is_singleton: bool = False,
) -> ConfidenceResult:
    comps = {
        "volume": c_volume(n_eff),
        "agreement": c_agreement(d_conflict_max),
        "independence": c_independence(n_distinct_sources, n_distinct_tiers),
        "coherence": c_coherence(signal_votes),
        "model_stability": c_model_stability(risk_interval_width),
    }
    weights = {"volume": 1.0, "agreement": AGREEMENT_EXPONENT, "independence": 1.0,
               "coherence": 1.0, "model_stability": 1.0}

    total_w = sum(weights.values())
    if any(v <= 0.0 for v in comps.values()):
        confidence = 0.0
    else:
        log_sum = sum(weights[k] * math.log(v) for k, v in comps.items())
        confidence = math.exp(log_sum / total_w)

    caps: list[str] = []
    if n_eff <= 1.0 and confidence > N_EFF_ONE_CAP:
        confidence, _ = N_EFF_ONE_CAP, caps.append("n_eff<=1 cap 0.40")
    if is_singleton and confidence > SINGLETON_CAP:
        confidence, _ = SINGLETON_CAP, caps.append("singleton cap 0.30")

    return ConfidenceResult(
        confidence=round(float(confidence), 6),
        components={k: round(v, 6) for k, v in comps.items()},
        n_eff=round(float(n_eff), 4),
        caps_applied=caps,
        detail={
            "weights": weights,
            "note": ("Geometric mean: confidence is conjunctive, so one weak component "
                     "drags the composite down. A single-document answer can never be "
                     "high confidence regardless of how clean it looks."),
        },
    )


def forces_review(confidence: float) -> bool:
    """Below the floor, a human looks at it whatever the score says.

    Low confidence may only make a disposition MORE conservative, never less: a
    wide interval is not a reason to relax.
    """
    return confidence < REVIEW_FLOOR
