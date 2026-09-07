"""
Feature encoding for the composite score. Design section 3.2.

Four decisions here carry the design's weight.

**Bounded signals get a logit transform.** Unsupport, injection and conflict are
probabilities concentrated near the endpoints -- an injection classifier outputs
0.001 or 0.98, rarely 0.5. A linear model on raw probabilities spends almost all
its resolution on a region containing no data.

**The anomaly signal is already a within-set robust z-score.** It arrives from the
detector normalised against its own retrieval set (median/MAD), which makes it
scale-free across embedding models and corpus sizes. It is used as-is rather than
re-transformed.

**Source tier is dummy-coded, never ordinal.** This is the single most important
encoding decision in the project. Encoding tier as 1/2/3 would force the model to
assume risk moves monotonically with tier -- the exact opposite of the C4/C9
inversion the taxonomy asserts. An ordinal encoding makes that relationship
*structurally unrepresentable*: the model would be incapable of learning the thing
it was built to learn. Tier 2 is the reference level, being the middle and modal
category.

**Tier x signal interactions are what carry the inversion.** Dummies alone shift
the intercept per tier; they cannot change a signal's slope per tier. Without
interactions the model can say "Tier 1 is safer overall" but never "an anomaly
means more when it comes from Tier 1".
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

from .bands import SignalSet

EPS = 1e-3          # logit clipping; bounds each transformed feature to +/- 6.9
LOGIT_SIGNALS = ("unsupport", "injection", "conflict")   # anomaly arrives pre-normalised

# ---------------------------------------------------------------------------
# Which signals the COMPOSITE STATISTICAL SCORE is allowed to use as regression
# features. Design section 9A.10 (design-v1.7).
#
# This is NOT a list of active detectors. Every detector keeps running and keeps
# feeding the rule track (fusion/bands.py -> fusion/cases.py), which compares each
# detector's RAW score against its own band thresholds and never consults a
# regression coefficient. Removing a signal from this tuple removes it from the
# logistic regression ONLY.
#
# Three signals were removed here, each for a diagnosed and separate reason:
#   unsupport  - chance-level (AUC 0.488). The NLI cross-encoder is a sentence-pair
#                model and is being handed whole-document premise and whole-answer
#                hypothesis text; it cannot score support at that granularity, so it
#                saturates. Fixing the granularity is P1 on the roadmap; until then
#                the feature contributes no information to the fit.
#   anomaly    - anti-correlated (AUC 0.410). PoisonedRAG documents are built to sit
#                CLOSE to the target query in embedding space, so they are less
#                outlier-like than an unusual genuine document. Wrong instrument for
#                this attack class, not a broken implementation. Already dropped
#                automatically by the inversion guard in fusion/train.py; naming it
#                here makes the exclusion declared rather than incidental.
#   injection  - zero variance across all 490 rows of THIS training sample (AUC
#                exactly 0.500), so its coefficient can only be noise. The detector
#                itself separates: measured per payload it scores 1.0000, 0.9925 and
#                0.9840 MALICIOUS, 0.8000 SUSPICIOUS, and 0.0000 on the fifth. This
#                is corpus coverage, not detector failure, and s_inj is a rule-track
#                signal by design (section 2.1 grants it the only single-signal
#                MALICIOUS rule, on declared thresholds).
#
# Restoring a signal here is a design change and needs a version bump in section 10.
COMPOSITE_SIGNALS: tuple[str, ...] = ("conflict",)

# Interactions are disabled while COMPOSITE_SIGNALS holds a single signal: with one
# base signal the tier interactions are collinear enough with the tier dummies that
# they buy nothing, and the C4/C9 inversion they were there to carry is asserted by
# the rule track (cases C4 vs C9) rather than learned. Section 3.2's argument for
# interactions applies to the multi-signal rungs and is unchanged for them.
COMPOSITE_INTERACTIONS_ENABLED = False


def logit(p: float, eps: float = EPS) -> float:
    p = min(1.0 - eps, max(eps, float(p)))
    return math.log(p / (1.0 - p))


@dataclass
class FeatureSpec:
    """Which features this model uses, and why that rung of the ladder was chosen.

    The events-per-variable rule (design section 3.3) is applied automatically:
    logistic regression wants roughly 10-15 minority-class events per predictor,
    so the feature set shrinks when the corpus cannot support the full one. The
    reduced rung keeps `is_tier1 x anomaly` and `is_tier1 x conflict` because
    those two carry the C4/C9 inversion; the rest are refinements we can afford
    to lose.
    """

    names: list[str]
    base_signals: list[str]
    interactions: list[tuple[str, str]]
    rung: str
    n_pos_at_fit: int
    underpowered: bool
    note: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "names": self.names, "base_signals": self.base_signals,
            "interactions": [list(i) for i in self.interactions],
            "rung": self.rung, "n_pos_at_fit": self.n_pos_at_fit,
            "underpowered": self.underpowered, "note": self.note,
        }


def choose_feature_spec(available_signals: Sequence[str], n_pos: int) -> FeatureSpec:
    """Pick the feature-ladder rung the corpus can actually support.

    Two filters apply, in order. `COMPOSITE_SIGNALS` (design 9A.10) restricts which
    signals may enter the regression at all, on measured discrimination. The
    events-per-variable ladder then chooses how many interaction terms the corpus
    can support among whatever survived.
    """
    sigs = [s for s in ("unsupport", "anomaly", "injection", "conflict") if s in available_signals]
    excluded = [s for s in sigs if s not in COMPOSITE_SIGNALS]
    sigs = [s for s in sigs if s in COMPOSITE_SIGNALS]
    dummies = ["is_tier1", "is_tier3"]

    if n_pos >= 150:
        rung, inter = "full", [(d, s) for d in dummies for s in sigs]
        note = "Full feature set; events-per-variable satisfied."
        under = False
    elif n_pos >= 60:
        rung = "reduced"
        inter = [("is_tier1", s) for s in sigs if s in ("anomaly", "conflict")]
        note = ("Reduced interactions: only the two that carry the Tier-1 inversion. "
                "Events-per-variable does not support the full set.")
        under = False
    else:
        rung, inter = "base_only", []
        note = ("UNDERPOWERED: fewer than 60 positive instances. Base signals and tier "
                "dummies only, no interactions. Coefficients are indicative; the case "
                "taxonomy is the primary control at this corpus size.")
        under = True

    if not COMPOSITE_INTERACTIONS_ENABLED:
        inter = []

    if excluded:
        # `rung` names the events-per-variable ladder step and is left alone: it is a
        # statement about corpus size, not about the allowlist. The restriction is
        # recorded in `note`, which keeps FeatureSpec's field set identical to the one
        # pickled into already-shipped artifacts.
        note = (f"{note} COMPOSITE RESTRICTION (design 9A.10): "
                f"{', '.join(excluded)} excluded from the regression on measured "
                f"discrimination; still active in the rule track."
                + ("" if COMPOSITE_INTERACTIONS_ENABLED
                   else " Tier interactions disabled at single-signal width."))

    names = [f"x_{s}" for s in sigs] + dummies + [f"{d}_x_{s}" for d, s in inter]
    return FeatureSpec(names=names, base_signals=sigs, interactions=inter,
                       rung=rung, n_pos_at_fit=n_pos, underpowered=under, note=note)


def encode(signals: SignalSet, source_tier: int, spec: FeatureSpec,
           anomaly_z: float | None = None) -> np.ndarray:
    """Encode one document into the model's feature vector.

    `anomaly_z` is the detector's within-set robust z-score. When it is not
    supplied the squashed [0, 1] anomaly score is used as a stand-in and the
    result is a little less informative -- prefer passing the z.
    """
    values: list[float] = []
    base: dict[str, float] = {}

    for name in spec.base_signals:
        raw = getattr(signals, name)
        if raw is None:
            v = 0.0
        elif name == "anomaly":
            v = float(anomaly_z) if anomaly_z is not None else float(raw)
        else:
            v = logit(raw)
        base[name] = v
        values.append(v)

    is_tier1 = 1.0 if source_tier == 1 else 0.0
    is_tier3 = 1.0 if source_tier == 3 else 0.0
    values.extend([is_tier1, is_tier3])
    dummies = {"is_tier1": is_tier1, "is_tier3": is_tier3}

    for d, s in spec.interactions:
        values.append(dummies[d] * base.get(s, 0.0))

    return np.asarray(values, dtype=float)


def encode_many(rows: Sequence[dict[str, Any]], spec: FeatureSpec) -> np.ndarray:
    """Encode a dataset. Each row needs `signals`, `source_tier`, optional `anomaly_z`."""
    return np.vstack([
        encode(r["signals"], r["source_tier"], spec, r.get("anomaly_z"))
        for r in rows
    ]) if rows else np.zeros((0, len(spec.names)))
