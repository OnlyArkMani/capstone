"""
Part A — the case classifier.

Eleven cases (design section 2.3), assigned deterministically under a fixed
precedence order (section 2.7). Nine come from crossing three source trust tiers
with three content bands; two are cross-cutting cases defined on the structure of
the retrieval set rather than on the grid.

Why named cases instead of only a score
---------------------------------------
A number tells an analyst how worried to be. A case tells them *what kind of
thing this is*, which is what determines the response. "Two authorities disagree"
and "an unverified source is lying" can carry the same risk score and require
completely different actions.

The two decisions worth understanding before reading the table
--------------------------------------------------------------

**C4 outranks C9.** A merely *suspicious* Tier-1 document is priority P1; an
outright *malicious* Tier-3 document is P2. This looks backwards and is
deliberate. The tier is a prior: because anomalous behaviour is improbable for a
Tier-1 source by construction, observing it carries far more information than the
same observation from Tier 3, where we already assumed it. Tier-1 sources are
also trusted by everything downstream, so the blast radius is larger. And every
plausible explanation -- source compromise, an intercepted fetch path, a
provenance mislabel, an insider edit -- is a finding about *our own system*
rather than about this query. That is precisely why the action is Escalate.

**C10 is not poisoning.** Two Tier-1 sources contradicting each other is
characterised by high inter-document contradiction with *quiet* attack
indicators, and is usually an advisory revision, a scope difference, or genuine
analytic disagreement. The system is bound never to silently pick a winner: there
is no principled basis for choosing between two authorities, and doing so would
conceal from the analyst the single most decision-relevant fact available.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Sequence

from .bands import CLEAN, SUSPICIOUS, MALICIOUS, SignalSet, BandThresholds, assign_band

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

ACCEPT, REVIEW, REJECT, ESCALATE = "ACCEPT", "REVIEW", "REJECT", "ESCALATE"

# Ordering used by escalation dominance (design section 3.9).
ACTION_SEVERITY = {ACCEPT: 0, REVIEW: 1, REJECT: 2, ESCALATE: 3}

ACTION_MEANING = {
    ACCEPT: "Return the answer automatically, with the provenance panel attached.",
    REVIEW: "Return the answer marked unverified and queue it for an analyst. It may be "
            "fine, but must not be relied on for a downstream action until confirmed.",
    REJECT: "Suppress the answer, return the evidence trail instead, quarantine the "
            "document. PROTECTS THIS ANSWER — the query is the unit of concern.",
    ESCALATE: "Raise a security event to the threat-intelligence owner. PROTECTS THE "
              "SYSTEM — a source or the pipeline is the unit of concern; this query is "
              "merely how we noticed.",
}


# ---------------------------------------------------------------------------
# Headline classification — design section 2.9
# ---------------------------------------------------------------------------

GREEN, ORANGE, RED = "GREEN", "ORANGE", "RED"
HEADLINE_BANDS = (GREEN, ORANGE, RED)

ATTACK_DETECTED = "ATTACK_DETECTED"
TRUSTED_SOURCE_COMPROMISE = "TRUSTED_SOURCE_COMPROMISE"

HEADLINE_LABEL = {
    GREEN: "Good to Go",
    ORANGE: "Mid-Suspicious, Review Recommended",
    RED: "Reject / Escalate",
}

SUBTYPE_LABEL = {
    ATTACK_DETECTED: "Attack Detected",
    TRUSTED_SOURCE_COMPROMISE: "Trusted Source Compromise Suspected",
}

SUBTYPE_MEANING = {
    ATTACK_DETECTED:
        "Malicious or irregular content from a source we had not already vouched for. "
        "THE DOCUMENT IS THE UNIT OF CONCERN — quarantining it largely closes the matter.",
    TRUSTED_SOURCE_COMPROMISE:
        "A source we had already verified is behaving anomalously. THE SOURCE IS THE UNIT "
        "OF CONCERN — the finding is about our own trust infrastructure and outlives this "
        "query, so it goes to the threat-intelligence owner rather than into the answer queue.",
}

# The one tier that can carry a GREEN headline (design 2.9.3). Tier 2 is excluded as a
# policy choice about review capacity; Tier 3 as a property of unverified provenance.
GREEN_TIER = 1


@dataclass(frozen=True)
class Headline:
    """The analyst-facing three-state band. Design section 2.9.

    DERIVED, never stored as an independent judgement: it is a function of the final action
    and the governing tier, so it cannot disagree with the action it came from.
    """

    band: str                    # GREEN | ORANGE | RED
    label: str                   # the human-readable name
    subtype: str | None          # RED only
    subtype_label: str | None
    meaning: str
    rule: str                    # which clause of 2.9.1 fired, for the audit log

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:
        return f"{self.band}" + (f" / {self.subtype_label}" if self.subtype_label else "")


def headline_band(action: str, tier_governing: int | None) -> Headline:
    """Derive the headline band from the final action and the governing tier.

    Clause order is design section 2.9.1, first match wins. Read the structure, not just the
    conditions: **GREEN is the last clause and requires an affirmative conjunction**, and the
    function returns ORANGE for everything it does not positively recognise. There is
    deliberately no `else: GREEN` branch -- an unknown action, an absent tier or a tier this
    function has never heard of all terminate at ORANGE.

    That asymmetry is the fail-safe (2.9.4), and it is the same commitment as escalation
    dominance: a degraded input may cost precision, never safety.
    """
    # RED — Reject or Escalate, sub-typed by whose problem this is.
    if action in (REJECT, ESCALATE):
        if tier_governing == GREEN_TIER:
            sub = TRUSTED_SOURCE_COMPROMISE
            rule = "reject_or_escalate_tier1"
        else:
            sub = ATTACK_DETECTED
            rule = "reject_or_escalate"
        return Headline(RED, HEADLINE_LABEL[RED], sub, SUBTYPE_LABEL[sub],
                        SUBTYPE_MEANING[sub], rule)

    # ORANGE — an explicit Review, or any source we have not verified ourselves.
    if action == REVIEW:
        return Headline(ORANGE, HEADLINE_LABEL[ORANGE], None, None,
                        ACTION_MEANING[REVIEW], "review_action")
    if tier_governing != GREEN_TIER:
        return Headline(
            ORANGE, HEADLINE_LABEL[ORANGE], None, None,
            "Quiet signals from a source we did not verify ourselves. The absence of "
            "evidence against a document is not evidence for it, so it is returned marked "
            "unverified rather than passed automatically.",
            f"tier_not_{GREEN_TIER}")

    # GREEN — reachable only here, and only by an affirmative Accept from Tier 1.
    if action == ACCEPT:
        return Headline(GREEN, HEADLINE_LABEL[GREEN], None, None,
                        ACTION_MEANING[ACCEPT], "accept_tier1")

    # Fail-safe. An action this function does not recognise is not a reason to relax.
    return Headline(ORANGE, HEADLINE_LABEL[ORANGE], None, None,
                    f"Unrecognised action {action!r}; defaulting to review rather than "
                    f"passing an unclassifiable response.", "failsafe_default")


@dataclass(frozen=True)
class CaseDefinition:
    case_id: str
    name: str
    tier: str
    outcome: str
    priority: str          # P0 highest .. P5 lowest
    action: str
    rationale: str


# Order here IS the precedence order (design section 2.7): first match wins.
CASES: tuple[CaseDefinition, ...] = (
    CaseDefinition("C5", "Authoritative Channel Compromise", "1", MALICIOUS, "P0", ESCALATE,
                   "A Tier-1 channel carrying malicious content implies compromise, spoofing "
                   "or a provenance failure — all findings about the system itself."),
    CaseDefinition("C4", "Trusted-Source Anomaly", "1", SUSPICIOUS, "P1", ESCALATE,
                   "An anomaly is improbable from Tier 1 by construction, so it carries more "
                   "information and a wider blast radius than the same anomaly from Tier 3."),
    CaseDefinition("C11", "Isolated Retrieval Outlier", "any", "—", "P1", ESCALATE,
                   "A single high-similarity document that is also an embedding outlier with "
                   "no corroboration is the canonical corpus-insertion signature."),
    CaseDefinition("C10", "Authoritative Divergence", "1 vs 1", "—", "P2", REVIEW,
                   "Two Tier-1 sources contradicting each other with quiet attack indicators "
                   "is advisory revision or genuine disagreement, not an attack. Never "
                   "adjudicate; present both."),
    CaseDefinition("C7", "Open-Feed Poisoning", "2", MALICIOUS, "P2", REJECT,
                   "Malicious content in a trusted-but-open feed; reject the answer and "
                   "escalate at source level."),
    CaseDefinition("C9", "Expected-Path Poisoning", "3", MALICIOUS, "P2", REJECT,
                   "The anticipated attack path. Contained: rejecting the answer and "
                   "quarantining the document largely resolves it."),
    CaseDefinition("C6", "Open-Feed Irregularity", "2", SUSPICIOUS, "P3", REVIEW,
                   "Irregular content from a moderated but community-writable source."),
    CaseDefinition("C8", "Unverified Irregularity", "3", SUSPICIOUS, "P3", REJECT,
                   "Irregular content with no provenance to fall back on."),
    CaseDefinition("C3", "Unverified but Unremarkable", "3", CLEAN, "P3", REVIEW,
                   "Low source trust is not malicious content. Unremarkable, but cannot be "
                   "authoritative on its own."),
    CaseDefinition("C2", "Community Corroboration", "2", CLEAN, "P4", ACCEPT,
                   "Clean content from a reputable open source."),
    CaseDefinition("C1", "Authoritative Confirmation", "1", CLEAN, "P5", ACCEPT,
                   "Clean content from a verified authoritative source. Normal operation."),
)

CASES_BY_ID = {c.case_id: c for c in CASES}


@dataclass
class CaseAssignment:
    case_id: str
    case_name: str
    priority: str
    action: str
    band: str
    source_tier: int | None
    all_matched_cases: list[str]
    rationale: str
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Grid lookup
# ---------------------------------------------------------------------------

def _grid_case(tier: int, band: str) -> CaseDefinition:
    for c in CASES:
        if c.tier == str(tier) and c.outcome == band:
            return c
    raise ValueError(f"no grid case for tier={tier} band={band}")


# ---------------------------------------------------------------------------
# Document-level classification
# ---------------------------------------------------------------------------

def classify_document(
    source_tier: int,
    signals: SignalSet,
    thresholds: BandThresholds,
) -> CaseAssignment:
    """Classify one document from its source tier and its detector scores.

    Returns the grid case (C1–C9). The two cross-cutting cases, C10 and C11, are
    properties of a retrieval SET rather than of a single document and are
    assigned by `classify_response`.
    """
    if source_tier not in (1, 2, 3):
        raise ValueError(f"source_tier must be 1, 2 or 3; got {source_tier!r}")
    band, band_detail = assign_band(signals, thresholds)
    case = _grid_case(source_tier, band)
    return CaseAssignment(
        case_id=case.case_id, case_name=case.name, priority=case.priority,
        action=case.action, band=band, source_tier=source_tier,
        all_matched_cases=[case.case_id], rationale=case.rationale,
        detail={"signals": signals.to_dict(), **band_detail, "level": "document"},
    )


# ---------------------------------------------------------------------------
# Response-level classification, including the two cross-cutting cases
# ---------------------------------------------------------------------------

def classify_response(
    tier_governing: int,
    signals_by_doc: dict[str, SignalSet],
    tiers_by_doc: dict[str, int],
    thresholds: BandThresholds,
    *,
    tier1_conflict: float = 0.0,
    similarities: dict[str, float] | None = None,
    n_eff: float | None = None,
    corroborated: bool = True,
) -> CaseAssignment:
    """Classify the response as a whole, applying the full precedence order.

    Set-level signals use the MAX over documents, not the mean (design section
    0.5). PoisonedRAG's mechanism is one crafted document among several clean
    ones; averaging it against four clean neighbours is exactly how the attack
    evades detection.
    """
    if not signals_by_doc:
        raise ValueError("no documents to classify")

    set_signals = SignalSet(**{
        name: (max(vals) if (vals := [v for s in signals_by_doc.values()
                                      if (v := getattr(s, name)) is not None]) else None)
        for name in ("unsupport", "anomaly", "injection", "conflict")
    })
    band, band_detail = assign_band(set_signals, thresholds)

    matched: list[str] = []
    detail: dict[str, Any] = {
        "level": "response",
        "set_signals": set_signals.to_dict(),
        "tier_governing": tier_governing,
        "tier_min": max(tiers_by_doc.values()) if tiers_by_doc else None,
        "tier1_conflict": round(tier1_conflict, 6),
        "n_eff": n_eff,
        **band_detail,
    }

    # ---- precedence, first match wins ----

    # C5 / C4: Tier-1 malicious or suspicious.
    if tier_governing == 1 and band == MALICIOUS:
        matched.append("C5")
    if tier_governing == 1 and band == SUSPICIOUS:
        matched.append("C4")

    # C11: isolated retrieval outlier. A single document that is both an
    # embedding outlier and uncorroborated, in a set with almost no effective
    # independent evidence.
    inj_quiet = (set_signals.injection or 0.0) < thresholds.suspicious.get("injection", 1.0)
    outliers = [d for d, s in signals_by_doc.items()
                if (s.anomaly or 0.0) >= thresholds.malicious.get("anomaly", 1.0)]
    if (len(outliers) == 1 and (n_eff is None or n_eff <= 2.0) and not corroborated):
        matched.append("C11")
        detail["isolated_outlier_doc"] = outliers[0]

    # C10: two Tier-1 documents contradicting each other, with attack indicators
    # quiet. The quiet clause matters -- a contradiction accompanied by an anomaly
    # is a possible compromise wearing the costume of a disagreement, and C4/C5
    # should catch it instead.
    ano_quiet = (set_signals.anomaly or 0.0) < thresholds.suspicious.get("anomaly", 1.0)
    n_tier1 = sum(1 for t in tiers_by_doc.values() if t == 1)
    if (n_tier1 >= 2 and tier1_conflict >= thresholds.malicious.get("unsupport", 0.85)
            and inj_quiet and ano_quiet):
        matched.append("C10")

    # Grid cases for the governing tier.
    matched.append(_grid_case(tier_governing, band).case_id)

    # Resolve by the canonical precedence order.
    ordered = [c.case_id for c in CASES if c.case_id in matched]
    winner = CASES_BY_ID[ordered[0]]
    detail["precedence_applied"] = ordered

    return CaseAssignment(
        case_id=winner.case_id, case_name=winner.name, priority=winner.priority,
        action=winner.action, band=band, source_tier=tier_governing,
        all_matched_cases=ordered, rationale=winner.rationale, detail=detail,
    )


def escalation_dominance(*actions: str) -> str:
    """The more conservative action wins (design section 3.9).

    This is what guarantees that adding the statistical track can never make the
    system less safe than the rule track alone -- a property worth having when
    the statistical track is fitted on a corpus we built ourselves.
    """
    valid = [a for a in actions if a in ACTION_SEVERITY]
    if not valid:
        raise ValueError(f"no valid action among {actions!r}")
    return max(valid, key=lambda a: ACTION_SEVERITY[a])
