"""
The presentation vocabulary: what every internal token is called in front of a
SOC analyst, and what a number on the screen actually licenses them to do.

Why this module exists
----------------------
The results view carries five severity encodings at once -- the verdict band, the
recommended action, the case id, the case priority and the risk tier -- and they
are consistent by construction: the band is derived from the action and the tier,
the risk tier from the priority and the action, the priority from the case. An
analyst does not know that. Five tokens with no stated relationship read as five
independent judgements, and the first question they provoke is "which of these is
the answer", which is the one question the page should never leave open.

So the tokens are not removed -- the audit trail, the evaluation harness and the
override vocabulary all key on them and an interface that renamed them would put
a translation layer between what a reviewer sees and what the database stores.
They are demoted. One sentence in plain English carries the verdict, and the
tokens sit underneath it as classification detail, each with the explanation that
was previously only in a source file.

What this module is allowed to contain, and why that matters
------------------------------------------------------------
Strings, and lookups keyed on strings. No thresholds, no arithmetic on a score,
no decision about what an action should be. Every fact stated here is either a
restatement of something `fusion/cases.py` already defines or a wording choice.

That boundary is the same one `components.py` and `style.py` already hold -- the
console displays figures, it never derives them -- and here it is load-bearing in
a second way. The case definitions in `fusion.cases` are imported rather than
copied, so a case whose priority or action changes upstream cannot end up
described one way by the scorer and another way by the screen. The *only* thing
this module adds is English.

The grade bands
---------------
`trust_grade` and `confidence_grade` map a number to a word and a sentence. These
are REPORTING bands for reading a figure aloud, in the same sense as the zones on
the trust dial, and they are deliberately not decision thresholds: the action
comes from the case taxonomy, which is rule-based, and nothing on this screen may
imply that a percentage decided it. The wording says so explicitly, because a
panel audience shown a number and a colour will otherwise assume the number was
the mechanism -- and on this system it is not.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fusion.cases import CASES_BY_ID  # noqa: E402

# ---------------------------------------------------------------------------
# The verdict, in one sentence
# ---------------------------------------------------------------------------

#: What the band means for the analyst in front of it. Second person, imperative
#: where there is something to do. These sit *alongside* `BAND_STYLE`'s formal
#: dispositions rather than replacing them: the formal label is what the system
#: has authorised and is the sentence somebody would have to defend afterwards,
#: and it stays in the banner. This is the reading of it.
BAND_SENTENCE: dict[str, str] = {
    "GREEN": "You can use this answer. The evidence behind it came from a source "
             "we verify ourselves, and no detector found anything irregular in it.",
    "ORANGE": "Check this before you use it. Nothing here is proven malicious, but "
              "at least one part of the evidence could not be vouched for — so the "
              "answer is returned unverified rather than passed automatically.",
    "RED": "Do not act on this answer. The security layer found evidence that the "
           "retrieved material was manipulated, and has suppressed the answer in "
           "favour of the evidence trail.",
}

#: The RED sub-type answers a different question: *whose problem is this*. An
#: ordinary attack is closed by quarantining a document; a trusted-source
#: compromise is a finding about our own trust infrastructure and outlives the
#: query. An analyst triaging a red queue needs to tell them apart without
#: opening anything, which is why this is a sentence and not a code.
SUBTYPE_SENTENCE: dict[str, str] = {
    "ATTACK_DETECTED":
        "This is an attack on this answer. The bad material came from a source we "
        "had never vouched for, so the document is the thing to deal with — "
        "quarantine it and the matter is largely closed.",
    "TRUSTED_SOURCE_COMPROMISE":
        "This is a problem with one of our own trusted sources, not just with this "
        "answer. A feed we had already verified is behaving anomalously, so the "
        "source is the thing to deal with — and that finding outlives this query.",
}

#: Read out loud, with the consequence attached. `fusion.cases.ACTION_MEANING`
#: states the mechanism; this states what it means for the person reading it.
ACTION_SENTENCE: dict[str, str] = {
    "ACCEPT": "Return the answer automatically, with its provenance attached.",
    "REVIEW": "Return the answer marked unverified and put it in the analyst queue. "
              "It may well be fine — it must not drive a downstream action until "
              "somebody confirms it.",
    "REJECT": "Suppress the answer, hand back the evidence trail instead, and "
              "quarantine the document. This protects the answer.",
    "ESCALATE": "Raise a security event to the threat-intelligence owner. This "
                "protects the system — a source or the pipeline is the problem, and "
                "this query is merely how we noticed.",
}

#: Four to six words. Used where the full sentence will not fit — the banner side
#: figures, the quick-decision rail, a chip.
ACTION_SHORT: dict[str, str] = {
    "ACCEPT": "Use it",
    "REVIEW": "Verify before use",
    "REJECT": "Do not use it",
    "ESCALATE": "Report to threat intel",
}


# ---------------------------------------------------------------------------
# The eleven cases, in English
# ---------------------------------------------------------------------------

#: `title` is what replaces the formal case name on screen; `plain` is what the
#: situation is; `distinct` is what separates this case from the one next to it,
#: which is the part a taxonomy of eleven cases most needs and least often says.
#:
#: The formal name and the rationale are NOT duplicated here — they are read off
#: `CASES_BY_ID` by `case_view` below, so a change to the taxonomy cannot leave
#: this file describing a case that no longer exists in those terms.
CASE_COPY: dict[str, dict[str, str]] = {
    "C1": {
        "title": "Clean answer from a verified source",
        "plain": "Everything retrieved came from a source we verify ourselves, and "
                 "no detector found anything irregular. This is normal operation.",
        "distinct": "The only case that can be returned automatically without a "
                    "reviewer seeing it first.",
    },
    "C2": {
        "title": "Clean answer from a reputable open source",
        "plain": "The evidence looks clean, but it came from an open feed we "
                 "moderate rather than one we verify end to end.",
        "distinct": "Clean, like C1 — but the source cannot be authoritative on "
                    "its own, so the answer carries an unverified mark.",
    },
    "C3": {
        "title": "Nothing wrong found, but the source is unverified",
        "plain": "No detector fired, and we also have no provenance to fall back "
                 "on. Low source trust is not the same thing as bad content.",
        "distinct": "Absence of evidence against a document is not evidence for "
                    "it. That is the whole reason this is a review and not a pass.",
    },
    "C4": {
        "title": "A source we trust is behaving strangely",
        "plain": "A Tier 1 feed — one we verify ourselves — produced content our "
                 "detectors found irregular. That should be very unlikely.",
        "distinct": "Ranked above an outright malicious Tier 3 document on "
                    "purpose. An anomaly from a source we vouched for carries far "
                    "more information and a far wider blast radius.",
    },
    "C5": {
        "title": "A source we trust is carrying malicious content",
        "plain": "A Tier 1 feed is delivering material the detectors judged "
                 "malicious. That implies the source is compromised, spoofed, or "
                 "mislabelled in our own provenance records.",
        "distinct": "The most serious case in the taxonomy, because the failure is "
                    "inside our trust infrastructure rather than outside it.",
    },
    "C6": {
        "title": "Irregular content from an open feed",
        "plain": "Something in the evidence looks off, and it came from a "
                 "moderated but community-writable source.",
        "distinct": "Irregular, not malicious — and from a source where irregular "
                    "content is a normal enough occurrence to warrant a look "
                    "rather than a rejection.",
    },
    "C7": {
        "title": "An open feed has been poisoned",
        "plain": "Malicious content arrived through a feed we treat as trusted but "
                 "which anyone can write to.",
        "distinct": "The answer is rejected and the problem is also raised at the "
                    "level of the source, because an open feed that carried one "
                    "poisoned document will carry others.",
    },
    "C8": {
        "title": "Irregular content with no provenance behind it",
        "plain": "Something looks off and there is no source history to weigh it "
                 "against.",
        "distinct": "Rejected rather than reviewed, unlike the equivalent case on "
                    "an open feed, because there is nothing to fall back on.",
    },
    "C9": {
        "title": "Poisoning on the expected attack path",
        "plain": "An unverified source delivered malicious content. This is the "
                 "attack this system was built to catch.",
        "distinct": "The most contained of the serious cases: rejecting the answer "
                    "and quarantining the document largely resolves it.",
    },
    "C10": {
        "title": "Two trusted sources disagree",
        "plain": "Two sources we both verify are contradicting each other, and the "
                 "attack indicators are quiet. This is usually an advisory "
                 "revision, a scope difference, or real analytic disagreement.",
        "distinct": "Not poisoning. The system will never pick a winner between "
                    "two authorities — there is no principled basis for it, and "
                    "doing so would hide the single most useful fact available.",
    },
    "C11": {
        "title": "One document stands alone, unlike anything else",
        "plain": "A single document matched the query closely, sits far away from "
                 "everything else in the corpus, and nothing corroborates it.",
        "distinct": "The signature of a document inserted into the corpus rather "
                    "than one that was already there.",
    },
}


def case_view(case_id: str | None) -> dict[str, str]:
    """Everything the screen needs about one case, formal and plain together.

    The formal name, priority, action and rationale are read off `CASES_BY_ID`
    rather than restated, so this cannot drift from the taxonomy. An unknown id
    returns a view that says so instead of an empty one -- a blank case panel in
    a demo reads as a rendering fault, and "we do not recognise this" is the
    honest message.
    """
    definition = CASES_BY_ID.get(case_id or "")
    copy = CASE_COPY.get(case_id or "", {})
    if definition is None:
        return {
            "case_id": case_id or "—",
            "title": "Unrecognised classification",
            "formal_name": "",
            "plain": "The report carries a case id this console does not have "
                     "wording for. Treat the recommended action as authoritative.",
            "distinct": "",
            "rationale": "",
            "priority": "",
            "action": "",
        }
    return {
        "case_id": definition.case_id,
        "title": copy.get("title", definition.name),
        "formal_name": definition.name,
        "plain": copy.get("plain", definition.rationale),
        "distinct": copy.get("distinct", ""),
        "rationale": definition.rationale,
        "priority": definition.priority,
        "action": definition.action,
    }


# ---------------------------------------------------------------------------
# Priority and risk tier
# ---------------------------------------------------------------------------

#: P0..P5 is a queue-ordering device. What an analyst wants from it is "how soon",
#: which the letter and digit do not say.
PRIORITY_MEANING: dict[str, str] = {
    "P0": "Highest priority — work this before anything else in the queue.",
    "P1": "High priority — work this in the current shift.",
    "P2": "High priority — work this in the current shift, after any P0 or P1.",
    "P3": "Medium priority — work this when the shift's urgent items are clear.",
    "P4": "Low priority — routine, no time pressure.",
    "P5": "Informational — recorded for the trail, no action expected.",
}

#: The queue label. It is the more severe of the case priority and the floor the
#: final action puts under it, so it can sit above what the priority alone
#: implies -- which is deliberate and worth saying on screen, because a reader
#: who spots the mismatch will otherwise read it as a bug.
RISK_TIER_MEANING: dict[str, str] = {
    "CRITICAL": "Sorts to the top of the queue. Something about our own system, "
                "not only this answer, needs attention.",
    "HIGH": "Sorts high in the queue. This answer was withheld or escalated.",
    "MEDIUM": "Sorts mid-queue. Needs a human to confirm before the answer is "
              "relied on.",
    "LOW": "Sorts low in the queue. Routine.",
    "INFORMATIONAL": "Recorded for the audit trail. No queue action expected.",
}


# ---------------------------------------------------------------------------
# The four detectors
# ---------------------------------------------------------------------------

#: The internal signal key, the report's field name, and what the detector is
#: actually looking for. The field name is kept and still shown in the numeric
#: table under each document, because that is the string somebody quoting a score
#: in a write-up needs; the plain name is what carries the meter and the chart.
DETECTOR: dict[str, dict[str, str]] = {
    "injection": {
        "name": "Hidden instructions in the document",
        "field": "injection_probability",
        "what": "Looks for text planted to give orders to the language model "
                "rather than to inform a reader — “ignore previous "
                "instructions”, a fake system prompt, an invisible directive.",
        "high": "A high reading means the document is trying to steer the answer.",
    },
    "anomaly": {
        "name": "Content unlike anything else in the corpus",
        "field": "embedding_anomaly_score",
        "what": "Measures how far this document sits from the rest of the corpus "
                "in meaning-space. Genuine advisories cluster; inserted ones "
                "usually do not.",
        "high": "A high reading means the document does not belong with its "
                "neighbours.",
    },
    "unsupport": {
        "name": "Answer not backed by its own sources",
        "field": "claim_unsupport_score",
        "what": "Checks each claim in the drafted answer against the evidence it "
                "was supposedly drawn from.",
        "high": "A high reading means the answer is asserting things its own "
                "evidence does not support.",
    },
    "conflict": {
        "name": "Sources contradicting each other",
        "field": "evidence_conflict_score",
        "what": "Compares the retrieved documents against one another, pair by "
                "pair, looking for direct contradiction.",
        "high": "A high reading means the evidence set disagrees with itself — one "
                "of these documents is wrong.",
    },
}


def detector_name(signal: str) -> str:
    return DETECTOR.get(signal, {}).get("name", signal)


def detector_field(signal: str) -> str:
    return DETECTOR.get(signal, {}).get("field", signal)


#: Every detector points the same way, and it is the opposite way to the trust
#: score. Saying so once, on screen, removes the most common misreading of this
#: page: that a big number is a good number.
DETECTOR_DIRECTION = ("For all four detectors a HIGHER reading is worse. This is "
                      "the opposite direction to the trust score above, where "
                      "higher is better.")

#: What each detector status licenses. `below` is not "clean": it is a
#: measurement that came in under the line, which is a narrower claim.
STATUS_SENTENCE: dict[str, str] = {
    "over_malicious": "Over the malicious line — this detector is confident.",
    "over_suspicious": "Over the suspicious line — enough to warrant a look.",
    "below": "Measured, and came in under the line. Not the same as proven clean.",
    "unusable": "Could not be calibrated. This is not a clean result — the system "
                "does not know.",
    "missing": "Did not run. This is not a clean result — the system does not know.",
}


# ---------------------------------------------------------------------------
# Reading the two numbers
# ---------------------------------------------------------------------------

#: (floor, word, what the figure licenses). Read top-down; first floor the value
#: clears wins. REPORTING bands for saying a number out loud -- not thresholds,
#: and the copy says so where it is shown.
_TRUST_GRADES: tuple[tuple[float, str, str], ...] = (
    (85.0, "High", "Consistent with an answer that was not tampered with."),
    (70.0, "Moderate", "Probably sound, but worth confirming against the evidence."),
    (40.0, "Low", "Enough doubt that the answer should not be relied on alone."),
    (0.0, "Very low", "Consistent with an answer built on manipulated evidence."),
)

_CONFIDENCE_GRADES: tuple[tuple[float, str, str], ...] = (
    (75.0, "Strong", "Several independent sources, and the detectors agree."),
    (50.0, "Moderate", "Usable, but resting on less evidence than we would like."),
    (35.0, "Weak", "Thin or conflicting evidence. Read the trust score with care."),
    (0.0, "Very weak", "Too little agreeing evidence to lean on the score at all."),
)


def _grade(percent: Any, table: tuple[tuple[float, str, str], ...]
           ) -> tuple[str, str]:
    if percent is None:
        return "", ""
    try:
        value = float(percent)
    except (TypeError, ValueError):
        return "", ""
    for floor, word, meaning in table:
        if value >= floor:
            return word, meaning
    return "", ""


def trust_grade(trust_percent: Any) -> tuple[str, str]:
    """(word, sentence) for a 0-100 trust figure. ("", "") if there is none."""
    return _grade(trust_percent, _TRUST_GRADES)


def confidence_grade(confidence_percent: Any) -> tuple[str, str]:
    """(word, sentence) for a 0-100 confidence figure. Takes PERCENT, not the
    0-1 fraction the report stores -- the caller converts, so that the single
    place a fraction becomes a percentage is visible at the call site."""
    return _grade(confidence_percent, _CONFIDENCE_GRADES)


TRUST_SCALE_NOTE = (
    "Higher is better. This is the calibrated probability that the answer was "
    "not shaped by an attacker. It is a **reported figure, not the decision** — "
    "the action above came from the rule-based case taxonomy, which is what "
    "guarantees the safety property."
)

CONFIDENCE_SCALE_NOTE = (
    "Higher is better. This says how much weight the trust score can carry, not "
    "how safe the answer is. A high score from one lone document and the same "
    "score from five agreeing sources are different claims, so they are reported "
    "as two numbers rather than averaged into one."
)

INTERVAL_NOTE = (
    "The bar is the 95% interval. A wide one means the score itself is uncertain, "
    "which changes what you should do with it."
)

#: The five components of the confidence figure. It is a geometric mean, so any
#: one component near zero drags the whole thing down -- which is the point, and
#: is why naming the weak one is more useful than the composite.
CONFIDENCE_COMPONENT: dict[str, str] = {
    "volume": "How much evidence there was.",
    "agreement": "How well the documents agreed with each other.",
    "independence": "Whether the documents came from genuinely separate sources.",
    "detector_concurrence": "Whether the four detectors agreed with each other.",
    "model_stability": "How steady the scoring model was on this input.",
}


# ---------------------------------------------------------------------------
# What to do next
# ---------------------------------------------------------------------------

#: Keyed on the final action. Each entry is an ordered checklist. Nothing here is
#: computed -- the document-specific steps are appended by the caller from fields
#: already in the report, and no step is invented for a fact the report does not
#: carry.
ACTION_STEPS: dict[str, list[str]] = {
    "ACCEPT": [
        "Use the answer, with its provenance panel attached.",
        "Record your decision below so the trail is complete.",
    ],
    "REVIEW": [
        "Open the evidence below and read the documents that fired a detector.",
        "Confirm the claim against a source outside this corpus before you act on "
        "it.",
        "Do not let this answer drive a change to a clinical system until it is "
        "confirmed.",
        "Record Accept, Reject or Override below.",
    ],
    "REJECT": [
        "Do not use this answer, and do not forward it.",
        "Quarantine the flagged document so it stops being retrieved.",
        "Answer the original question from a source outside this corpus.",
        "Record Accept, Reject or Override below.",
    ],
    "ESCALATE": [
        "Do not use this answer.",
        "Raise a security event with the threat-intelligence owner — the finding "
        "is about a source, not only about this query.",
        "Treat every recent answer that drew on the same source as suspect until "
        "the source is cleared.",
        "Record Accept, Reject or Override below.",
    ],
}


def next_steps(report: dict[str, Any]) -> list[str]:
    """The checklist for this report. Formatting and selection only.

    Document-specific lines name documents the report already flagged; the tier
    line is added only when the report itself says the governing tier is 1. No
    step here is derived from a score.
    """
    action = str(report.get("recommended_action") or "")
    steps = list(ACTION_STEPS.get(action, ACTION_STEPS["REVIEW"]))

    flagged = [
        str(doc.get("doc_id"))
        for doc in (report.get("documents") or [])
        if any(r.get("status") in ("over_malicious", "over_suspicious")
               for r in (doc.get("readings") or []))
    ]
    if flagged and action in ("REJECT", "ESCALATE"):
        steps.insert(1, "The document(s) to quarantine: "
                        + ", ".join(f"`{d}`" for d in flagged) + ".")
    elif flagged:
        steps.insert(0, "Start with the flagged document(s): "
                        + ", ".join(f"`{d}`" for d in flagged) + ".")

    unknown = [
        glossary_field
        for doc in (report.get("documents") or [])
        for r in (doc.get("readings") or [])
        if r.get("status") in ("unusable", "missing")
        and (glossary_field := detector_name(str(r.get("signal"))))
    ]
    if unknown:
        steps.append("Note that " + str(len(set(unknown))) + " detector(s) "
                     "produced no usable reading on this query, so part of the "
                     "evidence is unmeasured rather than clean.")
    return steps


# ---------------------------------------------------------------------------
# Why this verdict — the traceable ladder
# ---------------------------------------------------------------------------

def verdict_ladder(report: dict[str, Any]) -> list[dict[str, str]]:
    """Four to five steps from query to verdict, each one traceable to a field.

    This is the single most useful thing on the page for somebody being shown
    the system rather than using it: it walks the architecture without a slide,
    and every step names the report field it came from so nothing in it can be
    an assertion the console invented.
    """
    docs = report.get("documents") or []
    tier = report.get("tier_governing")
    case = case_view(report.get("case_id"))
    steps: list[dict[str, str]] = []

    steps.append({
        "step": "Retrieved the evidence",
        "detail": f"{report.get('n_retrieved', len(docs))} document(s) came back "
                  f"for this query, ranked by similarity alone. Retrieval knows "
                  f"nothing about which sources are trustworthy.",
    })

    fired: list[str] = []
    for doc in docs:
        for r in doc.get("readings") or []:
            if r.get("status") in ("over_malicious", "over_suspicious"):
                fired.append(f"{detector_name(str(r.get('signal')))} on "
                             f"`{doc.get('doc_id')}`")
    if fired:
        steps.append({
            "step": "Ran the detectors",
            "detail": f"{len(fired)} reading(s) came in over a threshold: "
                      + "; ".join(fired[:4])
                      + ("; and others." if len(fired) > 4 else "."),
        })
    else:
        steps.append({
            "step": "Ran the detectors",
            "detail": "Every reading came in under its threshold. That is a "
                      "measurement below the line, not a proof of cleanliness.",
        })

    if tier is not None:
        steps.append({
            "step": "Weighed who the evidence came from",
            "detail": f"The governing source is Tier {tier}. "
                      + ("Tier 1 is a source we verify ourselves, so irregular "
                         "behaviour from it is treated far more seriously than the "
                         "same behaviour from an unverified feed."
                         if tier == 1 else
                         "That is not a source we verify end to end, so the answer "
                         "cannot be passed automatically however quiet the "
                         "detectors are."),
        })

    steps.append({
        "step": "Classified the situation",
        "detail": f"Detector outcome plus source tier resolves to "
                  f"**{case['case_id']} — {case['title']}**, under a fixed "
                  f"precedence order. {case['plain']}",
    })

    steps.append({
        "step": "Decided what to do",
        "detail": f"That case carries the action "
                  f"**{report.get('recommended_action', '—')}**. "
                  + ACTION_SENTENCE.get(str(report.get("recommended_action")), ""),
    })
    return steps


# ---------------------------------------------------------------------------
# The landing page
# ---------------------------------------------------------------------------

WHAT_THIS_IS_TITLE = "A security layer between retrieval and the answer"

WHAT_THIS_IS = (
    "This console is a **reference client**. The product is the trust layer "
    "behind it: a pipeline-agnostic gateway that sits between a healthcare RAG "
    "system's retrieval step and the answer it delivers, in the same position a "
    "web application firewall occupies in front of a web app. It is not tied to "
    "this corpus, this retriever or this console."
)

HOW_IT_WORKS: list[tuple[str, str]] = [
    ("The corpus is deliberately poisoned",
     "Genuine healthcare threat intelligence sits alongside adversarial documents "
     "covering six attack families. Retrieval is partition-blind — it ranks by "
     "similarity and knows nothing about which documents are hostile."),
    ("Four detectors read the retrieved evidence",
     "Hidden instructions, content unlike the rest of the corpus, claims the "
     "evidence does not support, and sources contradicting each other."),
    ("A rule-based taxonomy classifies the situation",
     "Detector outcome crossed with source trust tier resolves to one of eleven "
     "named cases under a fixed precedence order. The case carries the action."),
    ("The analyst gets a verdict, the reasoning, and a decision to make",
     "Every query and every decision is written to a tamper-evident audit trail, "
     "and the console never fills a decision in on the analyst's behalf."),
]

SAFETY_CLAIM = (
    "The safety property the layer is built around: **no attack is ever vouched "
    "for.** A manipulated answer may be withheld or escalated, but it is never "
    "returned to the analyst as cleared."
)

GROUND_TRUTH_NOTE = (
    "Nothing in this console reads the answer key. The demonstration questions "
    "below are query text and a label — the system reaches its verdict knowing "
    "only what an analyst would have typed."
)


__all__ = [
    "BAND_SENTENCE", "SUBTYPE_SENTENCE", "ACTION_SENTENCE", "ACTION_SHORT",
    "CASE_COPY", "case_view", "PRIORITY_MEANING", "RISK_TIER_MEANING",
    "DETECTOR", "detector_name", "detector_field", "DETECTOR_DIRECTION",
    "STATUS_SENTENCE", "trust_grade", "confidence_grade", "TRUST_SCALE_NOTE",
    "CONFIDENCE_SCALE_NOTE", "INTERVAL_NOTE", "CONFIDENCE_COMPONENT",
    "ACTION_STEPS", "next_steps", "verdict_ladder",
    "WHAT_THIS_IS_TITLE", "WHAT_THIS_IS", "HOW_IT_WORKS", "SAFETY_CLAIM",
    "GROUND_TRUTH_NOTE",
]
