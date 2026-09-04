"""
Template-grounded reasoning. The one module where "never invent a number" is
enforced structurally rather than promised in a comment.

The problem
-----------
The reasoning narrative is the part of the report an analyst actually reads, and
it is the part most tempting to generate freely. A language model asked to
"explain why this was flagged" produces fluent, confident prose that is right most
of the time — and the times it is wrong, it is wrong in the most damaging possible
way: a plausible number attached to a real detector, in a document that looks
identical to a correct one. An analyst has no way to tell them apart.

It is also worth noticing that the input to that generation step would be a
document we may already believe is adversarial. Handing poisoned text to a model
and asking it to describe itself is the attack surface, not the defence.

The mechanism
-------------
Every number that reaches the narrative arrives as a `Fact`, and a `Fact` carries
three things: the value, a JSON pointer to where that value lives in the report
object, and how it should be formatted. Templates contain slots, never literals.
Rendering substitutes facts and records which pointers were used.

The consequence is that grounding becomes *checkable* rather than *asserted*:
`test_reports.py` pulls every number out of the rendered narrative and requires
each one to resolve to a real value at a real path in the report. A sentence that
cannot do that fails the build. That test is the actual deliverable here; this
module is the thing that makes it possible to pass honestly.

What this costs
---------------
The prose is more rigid than a model's would be. Sentences are assembled from a
fixed inventory of clauses, so the writing is repetitive across reports. That is
an acceptable price — an analyst reading twenty reports a day benefits from
sentences that always mean exactly the same thing, and predictability is a feature
in an audit trail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Sequence

# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------

# Formats. Each renders a value deterministically so that the same number always
# appears the same way -- which is what makes the grounding check exact rather
# than fuzzy.
FMT_SCORE = "score"          # 0.8231  -> "0.823"
FMT_PERCENT = "percent"      # 87.42   -> "87.4%"
FMT_PLAIN = "plain"          # 3       -> "3"
FMT_TEXT = "text"            # passthrough for non-numeric slots
FMT_DELTA = "delta"          # 0.223   -> "+0.223"

SCORE_DP = 3
PERCENT_DP = 1


@dataclass(frozen=True)
class Fact:
    """One value that may appear in narrative text, with its provenance.

    `path` is a JSON pointer into the report dict (e.g.
    `/documents/2/signals/injection`). It is not decoration: the grounding test
    resolves it and compares the result against the rendered text, so a fact whose
    path is wrong fails the build rather than shipping a plausible sentence.
    """

    key: str
    value: Any
    path: str
    fmt: str = FMT_SCORE

    def render(self) -> str:
        if self.fmt == FMT_TEXT or isinstance(self.value, str):
            return str(self.value)
        if self.value is None:
            return "n/a"
        if self.fmt == FMT_SCORE:
            return f"{float(self.value):.{SCORE_DP}f}"
        if self.fmt == FMT_PERCENT:
            return f"{float(self.value):.{PERCENT_DP}f}%"
        if self.fmt == FMT_DELTA:
            return f"{float(self.value):+.{SCORE_DP}f}"
        if self.fmt == FMT_PLAIN:
            v = float(self.value)
            return str(int(v)) if v.is_integer() else f"{v:g}"
        return str(self.value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Sentence:
    """One rendered clause plus the facts it consumed.

    Keeping the fact list attached to the sentence — rather than to the narrative
    as a whole — means a failing grounding check names the exact sentence, which is
    the difference between a useful test failure and an annoying one.
    """

    template_id: str
    text: str
    facts: list[Fact] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"template_id": self.template_id, "text": self.text,
                "facts": [f.to_dict() for f in self.facts]}


@dataclass
class Narrative:
    """The assembled reasoning text and its full provenance."""

    sentences: list[Sentence] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(s.text for s in self.sentences)

    def paragraphs(self) -> list[str]:
        return [s.text for s in self.sentences]

    def all_facts(self) -> list[Fact]:
        return [f for s in self.sentences for f in s.facts]

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "sentences": [s.to_dict() for s in self.sentences],
            "grounding": {
                "method": "template_substitution",
                "generated_by_model": False,
                "note": ("Every numeric value in this narrative was substituted from a "
                         "Fact carrying a JSON pointer into this report. No text here was "
                         "produced by a language model."),
                "fact_count": len(self.all_facts()),
                "paths_used": sorted({f.path for f in self.all_facts()}),
            },
        }


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

# Slots are {name} and are filled ONLY from Facts. A template containing a bare
# number would defeat the whole mechanism, so `check_templates_have_no_literals`
# below asserts that none does, and the test suite calls it.
TEMPLATES: dict[str, str] = {
    # --- headline ---
    "headline_green":
        "Classified {headline} ({headline_label}): the governing source is Tier "
        "{tier} and no detector signal exceeded its threshold.",
    "headline_orange_review":
        "Classified {headline} ({headline_label}): the system's recommended action is "
        "{action}, so the answer is returned marked unverified pending analyst review.",
    "headline_orange_tier":
        "Classified {headline} ({headline_label}): the governing source is Tier {tier}, "
        "which cannot be auto-accepted regardless of signal outcome — quiet signals from "
        "a source we have not verified mean nothing stood out, not that the content is "
        "trustworthy.",
    "headline_red_attack":
        "Classified {headline} — Attack Detected ({case_id} {case_name}): malicious or "
        "irregular content on a Tier {tier} source. The document is the unit of concern.",
    "headline_red_compromise":
        "Classified {headline} — Trusted Source Compromise Suspected ({case_id} "
        "{case_name}): a Tier {tier} source we had already verified is behaving "
        "anomalously. The source, not the document, is the unit of concern.",

    # --- detector citations ---
    "signal_over_malicious":
        "Flagged because {signal} = {value} on document {doc_id}, exceeding the "
        "malicious threshold of {threshold} by {margin}, on a Tier {tier} source.",
    "signal_over_suspicious":
        "Flagged because {signal} = {value} on document {doc_id}, exceeding the "
        "suspicious threshold of {threshold} by {margin}, on a Tier {tier} source.",
    "signal_below":
        "{signal} peaked at {value} on document {doc_id}, below its suspicious "
        "threshold of {threshold}.",
    "signal_unusable":
        "{signal} was excluded from the decision: its distribution over clean "
        "documents was too degenerate to threshold, so any cut point would be "
        "meaningless rather than merely imprecise.",
    "signal_missing":
        "{signal} was not computed for this query and is treated as absent rather "
        "than as zero — a zero would assert an absence of evidence we do not have.",
    "no_signal_fired":
        "No detector signal reached its suspicious threshold on any of the "
        "{n_docs} retrieved documents.",

    # --- score and confidence ---
    "composite_score":
        "The fitted model puts composite trustworthiness at {trust}, with a 95% "
        "interval of {trust_low} to {trust_high}.",
    "composite_absent":
        "No fitted model was available for this query, so no composite score is "
        "reported. The case taxonomy ran alone, which is a valid configuration.",
    "confidence_high":
        "Confidence in that estimate is {confidence}, drawn from {n_eff} effective "
        "independent documents across {n_sources} distinct sources.",
    "confidence_low":
        "Confidence in that estimate is only {confidence} — below the {floor} floor "
        "— so the disposition was raised to at least Review regardless of the score.",
    "confidence_singleton":
        "The answer rests on a single document, which caps confidence at {cap} "
        "however clean the signals look.",

    # --- reconciliation ---
    "reconciliation_agree":
        "The rule track and the statistical track both proposed {action}.",
    "reconciliation_differ":
        "The case taxonomy proposed {taxonomy_action} and the fitted score proposed "
        "{score_action}; the more conservative of the two, {action}, was taken.",

    # --- provenance and caveats ---
    "backend_fallback":
        "CAVEAT: {n_fallback} of the detectors ran on fallback backends "
        "({fallback_list}). The scores above are structural indicators, not "
        "measurements, and must not be quoted as detector performance.",
    "model_unfitted":
        "CAVEAT: band thresholds are provisional rather than fitted to a corpus.",
    "entities_found":
        "Extracted {n_entities} indicators from the retrieved documents by pattern "
        "matching: {entity_summary}.",
    "entities_none":
        "No IP addresses, domains, file hashes or CVE identifiers were extracted "
        "from the retrieved documents.",
}

_SLOT = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_BARE_NUMBER = re.compile(r"(?<![\w{/.-])\d+(?:\.\d+)?(?![\w}/-])")


def check_templates_have_no_literals() -> list[str]:
    """Assert that no template hard-codes a number.

    A literal in a template is the exact failure this module exists to prevent: it
    would render as a real-looking figure that no `Fact` backs, and the grounding
    test would then have to either fail on valid reports or be weakened to let it
    through. Catching it here keeps the test strict.

    "95%" in the composite-score template is the one deliberate exception -- it
    names the interval's coverage level, which is a fixed property of the method
    rather than a computed value -- and it is listed explicitly so it cannot be
    used to smuggle others in.
    """
    allowed = {"composite_score": {"95"}}
    offenders = []
    for tid, template in TEMPLATES.items():
        for m in _BARE_NUMBER.finditer(template):
            if m.group(0) in allowed.get(tid, set()):
                continue
            offenders.append(f"{tid}: literal {m.group(0)!r}")
    return offenders


def render_template(template_id: str, facts: Sequence[Fact]) -> Sentence:
    """Fill one template from facts. Raises if a slot has no fact.

    The strictness is the point. A missing fact is a bug in the caller, and the
    alternative -- leaving the slot in place, or substituting an empty string --
    ships a sentence that reads as complete and is not.
    """
    template = TEMPLATES[template_id]
    by_key = {f.key: f for f in facts}
    slots = set(_SLOT.findall(template))
    missing = slots - set(by_key)
    if missing:
        raise ValueError(
            f"template {template_id!r} needs facts {sorted(missing)}; "
            f"got {sorted(by_key)}")

    text = template
    used: list[Fact] = []
    for slot in slots:
        fact = by_key[slot]
        text = text.replace("{" + slot + "}", fact.render())
        used.append(fact)
    return Sentence(template_id=template_id, text=text, facts=used)


class NarrativeBuilder:
    """Accumulates sentences, refusing anything that is not template-grounded."""

    def __init__(self) -> None:
        self.narrative = Narrative()

    def add(self, template_id: str, *facts: Fact) -> "NarrativeBuilder":
        self.narrative.sentences.append(render_template(template_id, facts))
        return self

    def build(self) -> Narrative:
        return self.narrative
