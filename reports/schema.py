"""
The report's shape, and the pending analyst-decision block.

Design references: §2.6 actions, §2.9 headline band, §5.3 `analyst_decisions`,
§5.5 the override vocabulary, §5.8 the never-auto-populated invariant.

Risk tier
---------
Derived from the case priority (P0..P5), which the taxonomy already computes.
It is a coarse severity label for sorting a queue, and it is *derived* rather than
being a fresh judgement — a second independent severity scale would be one more
thing that can disagree with the first.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

REPORT_SCHEMA_VERSION = "report-v1.0"

# ---------------------------------------------------------------------------
# Risk tier — derived from case priority
# ---------------------------------------------------------------------------

RISK_TIER_BY_PRIORITY: dict[str, str] = {
    "P0": "CRITICAL",
    "P1": "HIGH",
    "P2": "HIGH",
    "P3": "MEDIUM",
    "P4": "LOW",
    "P5": "INFORMATIONAL",
}

RISK_TIER_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
_SEVERITY = {name: i for i, name in enumerate(reversed(RISK_TIER_ORDER))}

# The floor each final action puts under the risk tier. Derived from §2.6: an
# action is what the system decided to do, so the queue label may not sit below it.
RISK_TIER_FLOOR_BY_ACTION: dict[str, str] = {
    "ACCEPT": "INFORMATIONAL",
    "REVIEW": "MEDIUM",
    "REJECT": "HIGH",
    "ESCALATE": "CRITICAL",
}


def risk_tier_for(priority: str, action: str | None = None) -> str:
    """Queue-sortable severity, from the case priority and the final action.

    Priority alone is not enough. The two tracks are reconciled by escalation
    dominance (§3.9), so the statistical track can raise the final action above
    what the case priority implies — a C2 (P4, "low") whose fitted score pushed it
    to Review is not a low-severity item in a queue, and labelling it LOW is how it
    ends up at the bottom of a sorted list and never gets read.

    So the label is the MORE SEVERE of the two, which is the same commitment as
    escalation dominance itself: the queue label tracks what the system actually
    decided, not the more comfortable of two available numbers. Unknown priorities
    and unknown actions both map to HIGH, never to LOW.
    """
    tier = RISK_TIER_BY_PRIORITY.get(priority, "HIGH")
    if action is None:
        return tier
    floor = RISK_TIER_FLOOR_BY_ACTION.get(action, "HIGH")
    return tier if _SEVERITY[tier] >= _SEVERITY[floor] else floor


# ---------------------------------------------------------------------------
# analyst_decision — the pending block
# ---------------------------------------------------------------------------

ANALYST_DECISION_VALUES = ("ACCEPT", "REJECT", "OVERRIDE")
OVERRIDE_ACTIONS = ("ACCEPT", "REVIEW", "REJECT", "ESCALATE")
PER_DOCUMENT_VERDICTS = ("CLEAN", "POISONED", "UNCERTAIN")

# Design §5.5. Free text cannot be used as a future training label; a closed
# vocabulary can, and each code maps to a specific corrective action.
OVERRIDE_REASON_CODES: dict[str, str] = {
    "FALSE_POSITIVE_BENIGN_ANOMALY": "Anomalous but legitimately so (novel advisory, unusual formatting)",
    "SOURCE_STALE_NOT_MALICIOUS": "Content outdated, not adversarial",
    "LEGITIMATE_TIER1_DISAGREEMENT": "C10 fired and the divergence is genuine and expected",
    "TIER_MISLABELLED": "Provenance tagger assigned the wrong tier",
    "MISSED_ATTACK_SYSTEM_UNDERSCORED": "Analyst identified poisoning the system scored as low risk",
    "INSUFFICIENT_EVIDENCE_TO_JUDGE": "Analyst cannot determine either way",
    "DETECTOR_ERROR_INJECTION": "Injection classifier plainly wrong",
    "DETECTOR_ERROR_ENTAILMENT": "NLI verdict plainly wrong",
    "CONFIDENCE_TOO_LOW_TO_ACT": "Score plausible but confidence too low to rely on",
    "POLICY_OVERRIDE": "Organisational policy overrides the technical verdict",
    "OTHER": "Anything else — override_reason_text then mandatory",
}

STATUS_AWAITING_REVIEW = "AWAITING_REVIEW"


@dataclass
class AnalystDecisionBlock:
    """The pending decision slot the dashboard renders. **Not a database row.**

    Design §5.8 is unambiguous: an unreviewed event has *no row* in
    `analyst_decisions` — not a NULL, and specifically not a `PENDING` sentinel,
    because a sentinel sitting in the same column as real verdicts means every
    future aggregate has to remember to exclude it, and the first query that
    forgets is silently wrong rather than an error.

    This block does not contradict that. It is a **form specification** carried
    inside a rendering artefact: it tells the dashboard which values are legal and
    what the analyst must supply. `status` describes the *report*, not a stored
    decision. Nothing here is ever written to `analyst_decisions`; a row comes into
    existence only when a human submits the form, and it is written by the
    dashboard's decision handler, which is the only component holding that grant.

    The distinction matters enough to encode: `decision` is `None`, the field names
    mirror §5.3 exactly so a handler can map them without a translation layer, and
    `is_database_row` is `False` so that anything tempted to persist this object
    has to override an explicit flag to do it.
    """

    status: str = STATUS_AWAITING_REVIEW
    decision: str | None = None
    is_database_row: bool = False

    # Mirrors §5.3 field names so the dashboard handler needs no translation.
    analyst_id: str | None = None
    analyst_role: str | None = None
    override_action: str | None = None
    override_reason_code: str | None = None
    override_reason_text: str | None = None
    per_document_verdicts: list[dict[str, Any]] = field(default_factory=list)
    analyst_confidence: int | None = None
    time_to_decision_ms: int | None = None
    decided_at: str | None = None
    review_started_at: str | None = None

    # What the system said, snapshotted so a submitted row stands alone (§5.3).
    system_recommended_action: str | None = None
    system_case_id: str | None = None
    system_risk_score: float | None = None
    system_confidence: float | None = None
    system_headline: str | None = None

    form_spec: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def pending(
        cls,
        *,
        system_recommended_action: str,
        system_case_id: str,
        system_risk_score: float | None,
        system_confidence: float,
        system_headline: str,
        doc_ids: list[str],
    ) -> "AnalystDecisionBlock":
        return cls(
            system_recommended_action=system_recommended_action,
            system_case_id=system_case_id,
            system_risk_score=system_risk_score,
            system_confidence=system_confidence,
            system_headline=system_headline,
            form_spec={
                "decision": {"required": True, "values": list(ANALYST_DECISION_VALUES)},
                "override_action": {
                    "required_if": "decision == 'OVERRIDE'",
                    "values": list(OVERRIDE_ACTIONS)},
                "override_reason_code": {
                    "required_if": "decision == 'OVERRIDE'",
                    "values": list(OVERRIDE_REASON_CODES),
                    # Carried rather than computed at render time. A renderer that
                    # derives its own figures is a second implementation of the
                    # logic, and the two drift; the grounding test enforces this by
                    # rejecting any number in the output that the report does not
                    # hold, which is how this field came to exist.
                    "n_codes": len(OVERRIDE_REASON_CODES)},
                "override_reason_text": {
                    "required_if": "override_reason_code == 'OTHER'", "type": "text"},
                "per_document_verdicts": {
                    "required": False, "values": list(PER_DOCUMENT_VERDICTS),
                    "doc_ids": doc_ids,
                    "note": ("Document-level verdicts are the highest-value field in the "
                             "table: response-level labels are weak supervision, but the "
                             "detectors operate on documents.")},
                "analyst_confidence": {"required": False, "range": [1, 5]},
            },
        )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["_invariant"] = (
            "NEVER AUTO-POPULATED (design §5.8). This block is a form specification "
            "inside a rendering artefact, not a row in analyst_decisions. No row exists "
            "for this event until a human submits a decision in the dashboard; an "
            "unreviewed event is represented by the ABSENCE of a row, never by this "
            "status value. Do not persist this object as a decision.")
        return d


# ---------------------------------------------------------------------------
# Report parts
# ---------------------------------------------------------------------------

@dataclass
class SignalReading:
    """One detector's score on one document, next to the threshold it was judged against."""

    signal: str
    value: float | None
    suspicious_threshold: float | None
    malicious_threshold: float | None
    # BOTH margins are stored. The narrative cites whichever threshold the signal
    # actually crossed, and its Fact must point at the matching field — citing a
    # malicious-threshold margin against `margin_to_suspicious` produces a sentence
    # whose number is right and whose provenance is wrong, which is precisely the
    # failure the grounding test exists to catch. It did catch it.
    margin_to_suspicious: float | None
    margin_to_malicious: float | None
    status: str          # over_malicious | over_suspicious | below | unusable | missing
    backend: str | None = None
    is_model_backend: bool | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DocumentSection:
    """Per-source breakdown: provenance, tier, and every detector's individual score."""

    rank: int
    doc_id: str
    title: str
    source_id: str
    source_name: str
    source_tier: int
    source_tier_label: str
    similarity: float
    case_id: str
    case_name: str
    headline: str
    headline_subtype: str | None
    action: str
    priority: str
    trust_percent: float | None
    risk: float | None
    signals: dict[str, float | None]
    readings: list[SignalReading] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    entities: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["readings"] = [r.to_dict() if hasattr(r, "to_dict") else r for r in self.readings]
        return d
