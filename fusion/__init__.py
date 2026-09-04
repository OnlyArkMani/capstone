"""
Level 3 — fusion, confidence and adaptive response.

    from fusion import score_query
    result = score_query(query, retrieval.records)
    print(result.summary())

Three parts, wired into one call:

  A  Case classifier      C1..C11 from source tier x signal band, under a fixed
                          precedence order, each carrying a priority and an action.
                          The analyst-facing headline -- GREEN / ORANGE / RED, with RED
                          sub-typed -- is derived from the reconciled action and the
                          governing tier (design 2.9). GREEN requires an affirmative
                          Accept from Tier 1; everything else falls to ORANGE or RED.
  B  Composite score      Fitted logistic regression over the detector signals plus
                          dummy-coded source tier, returning a calibrated
                          trustworthiness percentage.
  C  Confidence           Five components combined by geometric mean, reported
                          separately from risk because they answer different
                          questions.

The rule track and the statistical track run over the same signals and the more
conservative disposition wins. That guarantees adding the fitted model can never
make the system less safe than the taxonomy alone -- worth having when the model
is fitted on a corpus we built ourselves.

Nothing in this package reads corpus/ground_truth/ at inference time. `dataset.py`
and `train.py` do, because they are training and evaluation code, which is the
boundary.
"""

from .bands import (
    BANDS, CLEAN, SUSPICIOUS, MALICIOUS, BandThresholds, SignalSet, assign_band,
)
from .cases import (
    ACCEPT, REVIEW, REJECT, ESCALATE, ACTION_MEANING, CASES, CASES_BY_ID,
    CaseAssignment, CaseDefinition, classify_document, classify_response,
    escalation_dominance,
    GREEN, ORANGE, RED, HEADLINE_BANDS, HEADLINE_LABEL,
    ATTACK_DETECTED, TRUSTED_SOURCE_COMPROMISE, SUBTYPE_LABEL,
    Headline, headline_band,
)
from .confidence import (
    ConfidenceResult, compute_confidence, effective_sample_size, forces_review,
)
from .evaluate import (
    ASRResult, Metrics, attack_success_rate, compute_metrics, derive_thresholds,
    naive_baseline_scores,
)
from .features import FeatureSpec, choose_feature_spec, encode, encode_many
from .model import TrustModel
from .scorer import DocumentScore, FusionScorer, QueryScore, score_query

__all__ = [
    "score_query", "FusionScorer", "QueryScore", "DocumentScore",
    "classify_document", "classify_response", "escalation_dominance",
    "CaseAssignment", "CaseDefinition", "CASES", "CASES_BY_ID", "ACTION_MEANING",
    "ACCEPT", "REVIEW", "REJECT", "ESCALATE",
    "headline_band", "Headline", "GREEN", "ORANGE", "RED", "HEADLINE_BANDS",
    "HEADLINE_LABEL", "ATTACK_DETECTED", "TRUSTED_SOURCE_COMPROMISE", "SUBTYPE_LABEL",
    "SignalSet", "BandThresholds", "assign_band",
    "BANDS", "CLEAN", "SUSPICIOUS", "MALICIOUS",
    "TrustModel", "FeatureSpec", "choose_feature_spec", "encode", "encode_many",
    "compute_confidence", "effective_sample_size", "forces_review", "ConfidenceResult",
    "compute_metrics", "derive_thresholds", "attack_success_rate",
    "naive_baseline_scores", "Metrics", "ASRResult",
]

__version__ = "0.1.0"
