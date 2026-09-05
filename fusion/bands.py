"""
Signal bands: turning four detector scores into Clean / Suspicious / Malicious.

Per design section 2.1, band thresholds are **not hand-picked**. For each signal
they are quantiles of that signal's distribution over CLEAN documents:

    theta_sus = Q_0.95(clean)   the strangest 5% of normal behaviour
    theta_mal = Q_0.99(clean)   the strangest 1% of normal behaviour

This makes a false-positive rate a design input rather than something discovered
after deployment, and it keeps the bands meaningful when a detector is swapped
for a better one -- the thresholds move with it.

Signal conventions (design section 0.3): every value here is RISK-oriented,
higher = riskier. Entailment runs the other way and is converted once, at the
detector boundary, into `unsupport = 1 - entailment`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

SIGNAL_NAMES = ("unsupport", "anomaly", "injection", "conflict")
SUSPICIOUS_Q = 0.95
MALICIOUS_Q = 0.99

# Signals whose cut points are DECLARED rather than fitted, with the reasoning
# for each. Everything else is fitted from the clean distribution as above.
#
# injection -- the detector is a noisy-OR over hand-specified patterns with
#   hand-assigned weights, not an empirical score with a distribution. Its clean
#   distribution is 83 zeros and nothing else, because no pattern fires on a
#   clean document; that is the detector working, not a calibration sample.
#   Fitting quantiles on it would put Q0.95 at exactly 0.0, the degeneracy guard
#   below would correctly refuse that as an always-fire threshold and mark the
#   signal unusable, and `assign_band` excludes unusable signals -- so the
#   `injection_alone` rule, the one rule design section 2.1 allows to act on a
#   single signal, would become unreachable code while every suite still passed.
#   Quantiles cannot calibrate a rule detector. The cut points come from the
#   pattern weights instead:
#
#     0.60 (suspicious) is the weakest single pattern in the set, so any one
#          pattern firing is at least worth an analyst's attention.
#     0.90 (malicious) is reached by one pattern only if that pattern is
#          `addressed_to_model` (0.90) or `override_instruction` (0.95), the two
#          with no benign reading, or by any two mid-weight patterns together.
#          `system_impersonation` (0.85) alone lands SUSPICIOUS, not MALICIOUS,
#          because a legitimate advisory can carry the words "system note".
#
#   These are judgement, openly, and are revisited when the corpus carries more
#   than one document of family direct_prompt_injection. See detectors/injection.py.
FIXED_THRESHOLD_SIGNALS: dict[str, tuple[float, float]] = {
    "injection": (0.60, 0.90),
}

# A clean distribution flatter than this carries no threshold information.
DEGENERATE_SPREAD = 1e-6
FLOOR, CEILING = 1e-6, 1.0 - 1e-6

CLEAN, SUSPICIOUS, MALICIOUS = "CLEAN", "SUSPICIOUS", "MALICIOUS"
BANDS = (CLEAN, SUSPICIOUS, MALICIOUS)


@dataclass
class SignalSet:
    """The four detector signals for one document, all risk-oriented [0, 1].

    `conflict` is Optional because the evidence-conflict detector (retrieved
    evidence vs. the model's parametric knowledge) is designed but not yet
    implemented. A missing signal is EXCLUDED from the band logic rather than
    treated as zero: a zero is an assertion of "no conflict", which is a claim we
    have no evidence for, and it would bias every band toward CLEAN.
    """

    unsupport: float | None = None
    anomaly: float | None = None
    injection: float | None = None
    conflict: float | None = None

    def available(self) -> dict[str, float]:
        return {n: v for n in SIGNAL_NAMES if (v := getattr(self, n)) is not None}

    def missing(self) -> list[str]:
        return [n for n in SIGNAL_NAMES if getattr(self, n) is None]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BandThresholds:
    """Per-signal suspicious/malicious cut points, fitted on clean documents."""

    suspicious: dict[str, float] = field(default_factory=dict)
    malicious: dict[str, float] = field(default_factory=dict)
    n_clean_calibration: int = 0
    fitted: bool = False
    note: str = ""
    # Signals whose clean distribution was too degenerate to threshold. These are
    # EXCLUDED from band logic rather than given a nonsense cut point.
    unusable: dict[str, str] = field(default_factory=dict)

    # ---------------- fitting ----------------

    @classmethod
    def fit(cls, clean_signals: Sequence[SignalSet]) -> "BandThresholds":
        """Fit from the clean calibration split only.

        Fitting on anything but clean data would let poisoned documents raise the
        thresholds that are supposed to detect them.
        """
        sus, mal, unusable = {}, {}, {}
        for name in SIGNAL_NAMES:
            if name in FIXED_THRESHOLD_SIGNALS:
                sus[name], mal[name] = FIXED_THRESHOLD_SIGNALS[name]
                continue
            values = [v for s in clean_signals if (v := getattr(s, name)) is not None]
            if not values:
                unusable[name] = "signal absent from every calibration row"
                continue
            if len(values) < 20:
                # Too few points for a stable 99th percentile. Fall back to a
                # conservative fixed pair and say so, rather than fitting noise.
                sus[name], mal[name] = 0.60, 0.85
                continue
            arr = np.asarray(values, dtype=float)
            q_sus = float(np.quantile(arr, SUSPICIOUS_Q))
            q_mal = float(np.quantile(arr, MALICIOUS_Q))

            # Degeneracy guard. If the clean distribution has almost no spread --
            # a detector returning a constant, which the fallback backends do --
            # its quantiles are not thresholds, they are that constant. Two ways
            # this goes badly wrong if left alone:
            #
            #   q_sus at 0.0  ->  EVERY document is above threshold, so the whole
            #                     corpus reads as malicious.
            #   q_sus at 1.0  ->  NOTHING can ever exceed it, so the signal is dead.
            #
            # Either is worse than having no threshold for that signal, so the
            # signal is marked unusable and excluded from band logic entirely.
            spread = float(np.max(arr) - np.min(arr))
            if spread < DEGENERATE_SPREAD or q_sus <= FLOOR or q_sus >= CEILING:
                unusable[name] = (
                    f"clean distribution is degenerate (spread {spread:.4f}, "
                    f"Q{SUSPICIOUS_Q:.2f}={q_sus:.4f}); thresholds would be "
                    f"{'always-fire' if q_sus <= FLOOR else 'never-fire'}")
                continue

            sus[name], mal[name] = q_sus, q_mal
            if mal[name] <= sus[name]:
                mal[name] = sus[name] + 1e-6
        return cls(
            suspicious=sus, malicious=mal, unusable=unusable,
            n_clean_calibration=len(clean_signals), fitted=True,
            note=f"Q{SUSPICIOUS_Q:.2f}/Q{MALICIOUS_Q:.2f} of the clean calibration distribution"
                 + (f"; {', '.join(sorted(FIXED_THRESHOLD_SIGNALS))} declared, not fitted"
                    if FIXED_THRESHOLD_SIGNALS else "")
                 + (f"; {len(unusable)} signal(s) unusable" if unusable else ""),
        )

    @classmethod
    def provisional(cls) -> "BandThresholds":
        """Placeholders for use before any corpus exists. Clearly marked unfitted."""
        return cls(
            suspicious={n: 0.60 for n in SIGNAL_NAMES},
            malicious={n: 0.85 for n in SIGNAL_NAMES},
            fitted=False,
            note="PROVISIONAL — not fitted to any corpus. Run fusion.train to calibrate.",
        )

    # ---------------- persistence ----------------

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2)
            fh.write("\n")

    @classmethod
    def load(cls, path: Path) -> "BandThresholds":
        with path.open(encoding="utf-8") as fh:
            return cls(**json.load(fh))


# ---------------------------------------------------------------------------
# Band assignment
# ---------------------------------------------------------------------------

def assign_band(signals: SignalSet, thresholds: BandThresholds) -> tuple[str, dict[str, Any]]:
    """Classify one document's signals into a band. Design section 2.1.

    MALICIOUS if  injection alone is above its malicious threshold
              or  two or more signals are above theirs
              or  one is, and two others are above their suspicious threshold
    SUSPICIOUS if at least one signal is above its suspicious threshold
    CLEAN      otherwise

    **Injection alone is sufficient; the others are not.** Anomalous embeddings,
    unsupported claims and knowledge conflicts all have benign explanations -- a
    genuinely novel advisory, a badly written one, a model whose training predates
    the CVE. Instruction text aimed at a language model inside a threat-intel
    document has none. Its presence is evidence of intent, not of unusual
    statistics.
    """
    # A signal with no usable threshold contributes nothing, rather than being
    # compared against a cut point we know to be meaningless.
    avail = {n: v for n, v in signals.available().items() if n not in thresholds.unusable}
    over_mal = [n for n, v in avail.items() if v >= thresholds.malicious.get(n, 1.0)]
    over_sus = [n for n, v in avail.items() if v >= thresholds.suspicious.get(n, 1.0)]

    detail = {
        "over_malicious": over_mal,
        "over_suspicious": over_sus,
        "missing_signals": signals.missing(),
        "unusable_signals": sorted(thresholds.unusable),
        "rule": None,
    }

    if "injection" in over_mal:
        detail["rule"] = "injection_alone"
        return MALICIOUS, detail
    if len(over_mal) >= 2:
        detail["rule"] = "two_signals_malicious"
        return MALICIOUS, detail
    if len(over_mal) >= 1 and len([n for n in over_sus if n not in over_mal]) >= 2:
        detail["rule"] = "one_malicious_two_suspicious"
        return MALICIOUS, detail
    if over_sus:
        detail["rule"] = "one_suspicious"
        return SUSPICIOUS, detail
    detail["rule"] = "none_over_threshold"
    return CLEAN, detail
