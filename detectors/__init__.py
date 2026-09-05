"""
Level 2 — independent detectors.

Three detectors, deliberately independent: no detector sees another's output, and
fusion happens later. Design references P1, P4 and P6 all reach the same
conclusion, that no single detector should be trusted alone, and independence is
what makes the combination worth more than its parts.

    from detectors import (
        embedding_anomaly_score,   # per-document cluster-distance outlier score
        injection_probability,     # per-document prompt-injection probability
        entailment_score,          # claim support, HIGHER = SAFER
    )

Every score is in [0, 1] and every detector returns per-document values, never
only an aggregate. Aggregation belongs to fusion, which takes the **max** over
cited documents rather than the mean (design section 0.5) -- one crafted document
among four clean ones is the entire attack, and averaging it away is how the
attack survives.

Direction: `entailment_score` is the one signal where higher is safer. Its
risk-oriented complement `unsupport = 1 - entailment` is what the fusion layer
consumes (design section 0.3), and `entailment_scores()` returns it directly in
`.score` so the convention is not something anyone has to remember.

Backends: each detector resolves a real pretrained model and falls back to a
heuristic when one is unavailable. `BackendInfo.is_model` travels with every
result, and the test harness refuses to call a run conclusive without it.

Nothing in this package reads corpus/ground_truth/. The detectors are the system
under test; the evaluation harness is the only component permitted the answer key.
"""

from .base import BackendInfo, DetectorScore, robust_z, squash
from .anomaly import AnomalyScore, embedding_anomaly_score, anomaly_score_max
from .injection import (
    InjectionScore, injection_probability, injection_probabilities,
    injection_probability_max,
)
from .entailment import (
    EntailmentScore, PairwiseConflict, entailment_score, entailment_scores,
    unsupport_max, best_entailment, pairwise_conflict, per_document_conflict, d_conflict_max,
    tier1_conflict_max,
)

__all__ = [
    "embedding_anomaly_score", "anomaly_score_max", "AnomalyScore",
    "injection_probability", "injection_probabilities", "injection_probability_max",
    "InjectionScore",
    "entailment_score", "entailment_scores", "unsupport_max", "best_entailment",
    "EntailmentScore",
    "pairwise_conflict", "per_document_conflict", "d_conflict_max", "tier1_conflict_max", "PairwiseConflict",
    "BackendInfo", "DetectorScore", "robust_z", "squash",
]

__version__ = "0.1.0"
