"""
Parts A, B and C wired into one call: `score_query`.

    from fusion import score_query
    result = score_query(query, retrieval.records)

    result.trust_percent        # 0-100, the analyst-facing number
    result.confidence_interval  # (low, high) on trustworthiness
    result.case_id / case_name  # C1..C11
    result.action               # ACCEPT | REVIEW | REJECT | ESCALATE

How the final action is reached
-------------------------------
Two tracks run over the same signals and the more conservative wins
(design section 3.9):

    RULE TRACK         the case taxonomy -- semantics a model fitted on a few
                       hundred instances cannot learn, notably the Tier-1
                       inversion and the treatment of authoritative divergence
                       as *not* an attack.
    STATISTICAL TRACK  the fitted score against derived thresholds -- better than
                       hand-written rules on patterns present in training, but
                       opaque during an incident and silent on unseen attacks.

Escalation dominance guarantees that adding the statistical track can never make
the system less safe than the rules alone. Only the rule track can produce
ESCALATE, because escalation is a claim about the *system* and needs the semantic
structure of a case, not a scalar.

Two further constraints, both one-directional:
* Confidence below the floor forces at least REVIEW.
* Thresholds apply to the UPPER bound of the risk interval, not the point
  estimate, so low confidence pushes borderline cases toward Review automatically.
Neither can make a disposition *less* conservative.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Sequence

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from detectors import (  # noqa: E402
    embedding_anomaly_score, injection_probabilities, entailment_scores,
    pairwise_conflict, per_document_conflict, d_conflict_max, tier1_conflict_max,
)
from detectors.base import doc_text  # noqa: E402
from .bands import SignalSet, BandThresholds  # noqa: E402
from .cases import (  # noqa: E402
    ACCEPT, REVIEW, REJECT, ESCALATE, ACTION_MEANING,
    GREEN, ORANGE, RED, ATTACK_DETECTED, TRUSTED_SOURCE_COMPROMISE,
    Headline, classify_document, classify_response, escalation_dominance, headline_band,
)
from .confidence import compute_confidence, effective_sample_size, forces_review  # noqa: E402
from .features import FeatureSpec, choose_feature_spec, encode  # noqa: E402
from .model import TrustModel  # noqa: E402

ARTIFACTS = Path(__file__).resolve().parent / "artifacts"
MODEL_PATH = ARTIFACTS / "trust_model.joblib"
THRESHOLDS_PATH = ARTIFACTS / "band_thresholds.json"
OPERATING_PATH = ARTIFACTS / "operating_thresholds.json"


@dataclass
class DocumentScore:
    doc_id: str
    source_tier: int
    source_id: str
    similarity: float
    signals: dict[str, float | None]
    trust_percent: float
    risk: float
    case_id: str
    case_name: str
    action: str
    priority: str
    headline: str = ORANGE
    headline_subtype: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class QueryScore:
    """What `score_query` returns."""

    query: str
    # --- the headline an analyst reads first (design 2.9) ---
    headline: str                            # GREEN | ORANGE | RED
    headline_label: str                      # "Good to Go" | "Mid-Suspicious, ..." | "Reject / Escalate"
    headline_subtype: str | None             # RED only: ATTACK_DETECTED | TRUSTED_SOURCE_COMPROMISE
    headline_subtype_label: str | None
    headline_meaning: str
    # --- the quantities behind it ---
    trust_percent: float                     # 0-100
    confidence: float                        # 0-1, how much to trust that figure
    confidence_interval: tuple[float, float]  # on trust_percent
    risk: float                              # P(poisoned), the audit-log quantity
    risk_interval: tuple[float, float]
    case_id: str
    case_name: str
    priority: str
    action: str
    action_meaning: str
    band: str
    tier_governing: int
    n_retrieved: int
    n_eff: float
    documents: list[DocumentScore] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["documents"] = [x.to_dict() if hasattr(x, "to_dict") else x for x in self.documents]
        return d

    def summary(self) -> str:
        lo, hi = self.confidence_interval
        head = self.headline + (f" / {self.headline_subtype_label}"
                                if self.headline_subtype_label else "")
        return (f"{head} — {self.trust_percent:.1f}% trustworthy "
                f"(CI {lo:.1f}-{hi:.1f}, confidence {self.confidence:.2f}) | "
                f"{self.case_id} {self.case_name} | {self.action}")


class FusionScorer:
    """Holds the fitted model, the thresholds and the detector backends.

    Construct once and reuse. Loading a model and resolving detector backends per
    query would dominate latency and make timing figures meaningless.
    """

    def __init__(
        self,
        model: TrustModel | None = None,
        band_thresholds: BandThresholds | None = None,
        operating: dict[str, Any] | None = None,
        embedder: Any | None = None,
    ) -> None:
        self.model = model
        self.bands = band_thresholds or BandThresholds.provisional()
        self.operating = operating or {"tau_review": 0.30, "tau_reject": 0.70,
                                       "bands_consistent": True, "regime": "provisional"}
        self.embedder = embedder
        self.fitted = model is not None

    # ---------------- construction ----------------

    @classmethod
    def load(cls, embedder: Any | None = None, verbose: bool = True) -> "FusionScorer":
        """Load persisted artefacts, degrading gracefully if training has not run."""
        import json  # noqa: PLC0415

        model = None
        if MODEL_PATH.exists():
            try:
                model = TrustModel.load(MODEL_PATH)
            except Exception as exc:
                if verbose:
                    print(f"[fusion] WARNING: could not load model ({type(exc).__name__}); "
                          f"the rule track will run alone.")
        elif verbose:
            print("[fusion] NOTE: no trained model found. The case taxonomy will run alone "
                  "— which is a valid configuration, not a broken one. Run "
                  "`python -m fusion.train` to fit the statistical track.")

        bands = (BandThresholds.load(THRESHOLDS_PATH) if THRESHOLDS_PATH.exists()
                 else BandThresholds.provisional())
        operating = (json.loads(OPERATING_PATH.read_text(encoding="utf-8"))
                     if OPERATING_PATH.exists() else None)
        return cls(model, bands, operating, embedder)

    # ---------------- warm start ----------------

    def warm_documents(self, documents: Sequence[Any]) -> int:
        """Pre-encode the corpus into the embedder's document cache.

        The anomaly detector embeds the text of every retrieved document, and
        that text is `title + summary + content` -- not the `embedding_text`
        form the index was built from, so the index's vectors cannot stand in
        for it and the encode genuinely has to happen. It just does not have to
        happen while an analyst is waiting: the corpus is fixed, so every vector
        this produces is one the detector would otherwise compute on the query
        path, and it computes them once at startup instead.

        The values are identical by construction -- same embedder, same texts,
        the same cache the detector reads from. This moves work in time; it does
        not change what is computed. Returns how many documents were warmed.
        """
        if self.embedder is None or not documents:
            return 0
        if getattr(self.embedder, "_doc_cache", None) is None:
            return 0        # a backend with no cache to fill; nothing to warm
        texts = [doc_text(d) if isinstance(d, dict) else doc_text(vars(d)) for d in documents]
        texts = [t for t in texts if t.strip()]
        if texts:
            self.embedder.encode(texts, is_query=False)
        return len(texts)

    # ---------------- signals ----------------

    def _signals(self, retrieved_docs: Sequence[Any], hypothesis: str) -> dict[str, Any]:
        anomaly = {s.doc_id: s for s in
                   embedding_anomaly_score(retrieved_docs, embedder=self.embedder)}
        injection = {s.doc_id: s for s in injection_probabilities(retrieved_docs)}
        entail = {s.doc_id: s for s in entailment_scores(hypothesis, retrieved_docs)}
        conflicts = pairwise_conflict(retrieved_docs)
        return {
            "anomaly": anomaly, "injection": injection, "entail": entail,
            "conflicts": conflicts,
            "d_conflict_max": d_conflict_max(conflicts),
            "tier1_conflict": tier1_conflict_max(conflicts),
            "backends": {
                "anomaly": next(iter(anomaly.values())).backend.to_dict() if anomaly else None,
                "injection": next(iter(injection.values())).backend.to_dict() if injection else None,
                "entailment": next(iter(entail.values())).backend.to_dict() if entail else None,
            },
        }

    # ---------------- the public call ----------------

    def score_query(
        self,
        query: str,
        retrieved_docs: Sequence[Any],
        generated_answer: str | None = None,
    ) -> QueryScore:
        """Score one query and its retrieval set.

        `generated_answer`, when supplied, is used as the entailment hypothesis --
        which is what design section 3.1 actually specifies. Without it the query
        stands in, measuring whether the evidence supports the *question* rather
        than the *answer*. That substitution is recorded in the result.
        """
        if not retrieved_docs:
            raise ValueError("no retrieved documents to score")

        hypothesis = generated_answer or query
        sig = self._signals(retrieved_docs, hypothesis)

        signals_by_doc: dict[str, SignalSet] = {}
        tiers_by_doc: dict[str, int] = {}
        anomaly_z_by_doc: dict[str, float] = {}
        doc_scores: list[DocumentScore] = []

        # Intra-evidence conflict, per document. See per_document_conflict: this
        # is design 0.4's derived quantity standing in for design 2.1's
        # parametric-knowledge signal, and the substitution is reported rather
        # than hidden. A document in a singleton retrieval has no pair to be
        # compared against, so it gets None (absent) rather than 0.0 (measured
        # and found not to disagree) -- the SignalSet contract treats those
        # differently on purpose.
        conflict_by_doc = per_document_conflict(sig["conflicts"])
        conflict_measurable = len(retrieved_docs) >= 2

        for rec in retrieved_docs:
            did = rec.doc_id
            s = SignalSet(
                unsupport=sig["entail"][did].score,
                anomaly=sig["anomaly"][did].score,
                injection=sig["injection"][did].score,
                conflict=(conflict_by_doc.get(did, 0.0) if conflict_measurable else None),
            )
            signals_by_doc[did] = s
            tiers_by_doc[did] = rec.provenance.source_tier
            anomaly_z_by_doc[did] = float(sig["anomaly"][did].detail.get("robust_z", 0.0))

        # ---- Part A: cases ----
        similarities = {r.doc_id: r.similarity for r in retrieved_docs}
        weights = [max(s, 0.0) for s in similarities.values()]
        n_sources = len({r.provenance.source_id for r in retrieved_docs})
        n_tiers = len({r.provenance.source_tier for r in retrieved_docs})
        n_eff = effective_sample_size(weights, n_sources)

        # Corroboration: does more than one document support the hypothesis?
        supporting = sum(1 for did in signals_by_doc
                         if sig["entail"][did].entailment >= 0.5)
        tier_governing = retrieved_docs[0].provenance.source_tier

        response_case = classify_response(
            tier_governing=tier_governing,
            signals_by_doc=signals_by_doc,
            tiers_by_doc=tiers_by_doc,
            thresholds=self.bands,
            tier1_conflict=sig["tier1_conflict"],
            similarities=similarities,
            n_eff=n_eff,
            corroborated=supporting >= 2,
        )

        # ---- Part B: composite score ----
        risk = risk_lo = risk_hi = None
        if self.model is not None:
            per_doc_risk = []
            for rec in retrieved_docs:
                x = encode(signals_by_doc[rec.doc_id], rec.provenance.source_tier,
                           self.model.spec, anomaly_z_by_doc[rec.doc_id])
                lo, pt, hi = self.model.risk_interval(x)
                per_doc_risk.append((rec, pt, lo, hi))
            # Response-level risk is the MAX over documents, never the mean
            # (design 0.5): one crafted document among four clean ones is the
            # entire attack, and averaging it away is how the attack survives.
            rec_max, risk, risk_lo, risk_hi = max(per_doc_risk, key=lambda t: t[1])

            for rec, pt, lo, hi in per_doc_risk:
                dcase = classify_document(rec.provenance.source_tier,
                                          signals_by_doc[rec.doc_id], self.bands)
                dhead = headline_band(dcase.action, rec.provenance.source_tier)
                doc_scores.append(DocumentScore(
                    doc_id=rec.doc_id, source_tier=rec.provenance.source_tier,
                    source_id=rec.provenance.source_id, similarity=round(rec.similarity, 6),
                    signals=signals_by_doc[rec.doc_id].to_dict(),
                    trust_percent=round(100.0 * (1.0 - pt), 2), risk=round(pt, 6),
                    case_id=dcase.case_id, case_name=dcase.case_name,
                    action=dcase.action, priority=dcase.priority,
                    headline=dhead.band, headline_subtype=dhead.subtype,
                ))
        else:
            for rec in retrieved_docs:
                dcase = classify_document(rec.provenance.source_tier,
                                          signals_by_doc[rec.doc_id], self.bands)
                dhead = headline_band(dcase.action, rec.provenance.source_tier)
                doc_scores.append(DocumentScore(
                    doc_id=rec.doc_id, source_tier=rec.provenance.source_tier,
                    source_id=rec.provenance.source_id, similarity=round(rec.similarity, 6),
                    signals=signals_by_doc[rec.doc_id].to_dict(),
                    trust_percent=float("nan"), risk=float("nan"),
                    case_id=dcase.case_id, case_name=dcase.case_name,
                    action=dcase.action, priority=dcase.priority,
                    headline=dhead.band, headline_subtype=dhead.subtype,
                ))

        # ---- Part C: confidence ----
        votes = [v for v in (
            max((s.unsupport or 0.0) for s in signals_by_doc.values()),
            max((s.anomaly or 0.0) for s in signals_by_doc.values()),
            max((s.injection or 0.0) for s in signals_by_doc.values()),
        )]
        interval_width = (risk_hi - risk_lo) if risk is not None else 0.5
        conf = compute_confidence(
            n_eff=n_eff, d_conflict_max=sig["d_conflict_max"],
            n_distinct_sources=n_sources, n_distinct_tiers=n_tiers,
            signal_votes=votes, risk_interval_width=interval_width,
            is_singleton=(len(retrieved_docs) == 1),
        )

        # ---- reconcile ----
        score_action = ACCEPT
        if risk is not None:
            # Threshold the UPPER bound, so low confidence tightens the outcome.
            p_upper = risk_hi
            tau_r, tau_x = self.operating["tau_review"], self.operating["tau_reject"]
            if not self.operating.get("bands_consistent", True):
                score_action = REVIEW if p_upper >= tau_r else ACCEPT
            elif p_upper >= tau_x:
                score_action = REJECT
            elif p_upper >= tau_r:
                score_action = REVIEW

        final_action = escalation_dominance(response_case.action, score_action)
        if forces_review(conf.confidence):
            final_action = escalation_dominance(final_action, REVIEW)

        # The headline is derived LAST, from the reconciled action -- never from the
        # taxonomy action or the score action alone. Deriving it earlier would let it
        # disagree with the disposition the system actually took (design 2.9).
        head = headline_band(final_action, tier_governing)

        trust = 100.0 * (1.0 - risk) if risk is not None else float("nan")
        trust_lo = 100.0 * (1.0 - risk_hi) if risk is not None else float("nan")
        trust_hi = 100.0 * (1.0 - risk_lo) if risk is not None else float("nan")

        return QueryScore(
            query=query,
            headline=head.band, headline_label=head.label,
            headline_subtype=head.subtype, headline_subtype_label=head.subtype_label,
            headline_meaning=head.meaning,
            trust_percent=round(trust, 2) if risk is not None else float("nan"),
            confidence=conf.confidence,
            confidence_interval=(round(trust_lo, 2), round(trust_hi, 2))
            if risk is not None else (float("nan"), float("nan")),
            risk=round(risk, 6) if risk is not None else float("nan"),
            risk_interval=(round(risk_lo, 6), round(risk_hi, 6))
            if risk is not None else (float("nan"), float("nan")),
            case_id=response_case.case_id, case_name=response_case.case_name,
            priority=response_case.priority, action=final_action,
            action_meaning=ACTION_MEANING[final_action],
            band=response_case.band, tier_governing=tier_governing,
            n_retrieved=len(retrieved_docs), n_eff=round(n_eff, 4),
            documents=doc_scores,
            detail={
                "taxonomy_action": response_case.action,
                "score_action": score_action,
                "reconciliation": "escalation_dominance",
                "headline_rule": head.rule,
                "confidence_forced_review": forces_review(conf.confidence),
                "confidence_components": conf.components,
                "confidence_caps": conf.caps_applied,
                "all_matched_cases": response_case.all_matched_cases,
                "case_rationale": response_case.rationale,
                "d_conflict_max": round(sig["d_conflict_max"], 6),
                "tier1_conflict": round(sig["tier1_conflict"], 6),
                "hypothesis_source": "generated_answer" if generated_answer else "query_proxy",
                "model_fitted": self.model is not None,
                "bands_fitted": self.bands.fitted,
                "detector_backends": sig["backends"],
                "operating_regime": self.operating.get("regime"),
            },
        )


_DEFAULT: FusionScorer | None = None


def score_query(query: str, retrieved_docs: Sequence[Any],
                generated_answer: str | None = None,
                embedder: Any | None = None) -> QueryScore:
    """Module-level convenience. Loads artefacts once and caches the scorer."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = FusionScorer.load(embedder=embedder)
    return _DEFAULT.score_query(query, retrieved_docs, generated_answer)
