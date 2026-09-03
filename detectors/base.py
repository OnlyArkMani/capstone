"""
Shared machinery for the Level 2 detectors.

Every detector in this package obeys the same three rules:

1. **Per-document scores, never only an aggregate.** Aggregation is the fusion
   layer's job, and it needs the individual values -- design section 0.5 takes
   the *max* over cited documents rather than the mean, precisely because
   PoisonedRAG's mechanism is one crafted document among several clean ones.
   Averaging it against four clean neighbours is how the attack evades
   detection.

2. **Every score is in [0, 1], higher = riskier.** `entailment_score` is the one
   quantity that runs the other way (higher = better supported), so it is
   returned as-is and the risk-oriented `unsupport = 1 - entailment` is provided
   alongside, matching design section 0.3.

3. **The backend is always reported.** Each detector resolves a real model and
   falls back to a heuristic when the model is unavailable. A fallback score is
   structurally valid and analytically worthless, so `BackendInfo.is_model`
   travels with every result and the test harness refuses to call a run
   conclusive without it.

Nothing in this package reads corpus/ground_truth/. The detectors are the system
under test.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np


@dataclass(frozen=True)
class BackendInfo:
    """Which implementation produced a score, and whether it is the real one."""

    name: str
    is_model: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "is_model": self.is_model, "detail": self.detail}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

MAD_SCALE = 1.4826  # makes MAD a consistent estimator of sigma under normality
SQUASH_TAU = 2.0


def robust_z(values: Sequence[float]) -> np.ndarray:
    """Median/MAD z-scores, per design section 3.2.

    Median and MAD rather than mean and standard deviation because the quantity
    being detected *is* the outlier: a mean-based normaliser is dragged by the
    very document it is meant to expose.

    Returns zeros when the set has no dispersion (n < 2, or every value
    identical). A set with no spread carries no outlier evidence, and inventing
    some by dividing by epsilon would manufacture a signal that is not there.
    """
    arr = np.asarray(values, dtype=float)
    if arr.size < 2:
        return np.zeros_like(arr)
    median = float(np.median(arr))
    mad = float(np.median(np.abs(arr - median)))
    if mad <= 0.0:
        return np.zeros_like(arr)
    return (arr - median) / (MAD_SCALE * mad)


def squash(z: float, tau: float = SQUASH_TAU) -> float:
    """Map a one-sided robust z-score onto [0, 1].

    `1 - exp(-max(z, 0) / tau)`: z=0 -> 0.00, z=2 -> 0.63, z=4 -> 0.86,
    z=6 -> 0.95. Saturating, never quite reaching 1.

    **Deliberately not min-max normalisation.** Min-max over a retrieval set
    always assigns exactly one document 1.0 and one 0.0, whether or not anything
    is anomalous -- so it would manufacture a maximum-severity outlier in every
    clean set the system ever sees. Scaling by dispersion instead means a set
    with no outlier scores near zero throughout, which is the correct answer.
    """
    return float(1.0 - math.exp(-max(z, 0.0) / tau))


def softmax(logits: Sequence[float]) -> np.ndarray:
    arr = np.asarray(logits, dtype=float)
    arr = arr - arr.max()
    exp = np.exp(arr)
    return exp / exp.sum()


def clip01(x: float) -> float:
    return float(min(1.0, max(0.0, x)))


# ---------------------------------------------------------------------------
# Result base
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectorScore:
    """One document's score from one detector."""

    doc_id: str
    score: float                      # [0, 1], higher = riskier
    backend: BackendInfo
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "score": round(self.score, 6),
            "backend": self.backend.to_dict(),
            "detail": self.detail,
        }


def as_records(retrieved_docs: Sequence[Any]) -> list[Any]:
    """Accept RetrievedRecord objects, plain dicts, or raw strings.

    The detectors are called from the pipeline (records), from the evaluation
    harness (dicts loaded from the log), and from tests (whatever is to hand).
    Normalising the input here keeps that flexibility out of three separate
    modules.
    """
    out = []
    for i, d in enumerate(retrieved_docs):
        if isinstance(d, str):
            out.append({"doc_id": f"doc_{i}", "content": d, "title": "", "summary": ""})
        elif isinstance(d, dict):
            out.append(d)
        else:
            out.append({
                "doc_id": getattr(d, "doc_id", f"doc_{i}"),
                "content": getattr(d, "content", ""),
                "title": getattr(d, "title", ""),
                "summary": getattr(d, "summary", ""),
            })
    return out


def doc_text(doc: dict[str, Any]) -> str:
    parts = [doc.get("title", ""), doc.get("summary", ""), doc.get("content", "")]
    return "\n\n".join(p for p in parts if p).strip()
