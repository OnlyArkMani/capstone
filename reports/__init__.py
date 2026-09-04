"""
Level 3 output — the SOC-analyst report.

    from fusion import score_query
    from reports import build_report, render_markdown

    score  = score_query(query, records)
    report = build_report(query, score, records)
    print(render_markdown(report))

The headline (GREEN / ORANGE / RED, with RED sub-typed) is first and alone, per
design section 2.9. Everything else is the supporting detail an analyst opens when
the case is not GREEN, or when they want to verify one that is.

Two properties this package exists to guarantee:

**The reasoning narrative is template-grounded.** Every number in it is substituted
from a `Fact` carrying a JSON pointer into the report object. No language model
writes any part of it, and `test_reports.py` resolves every figure in the rendered
text back to a real value at a real path -- a sentence that cannot be traced fails
the build.

**Indicators are extracted by regex, never by a model.** An analyst pivots on these
values, and a model reading a document we may already believe is adversarial is the
attack surface rather than the defence.
"""

from .entities import Entity, extract_entities, extract_from_documents, group_by_kind
from .generator import Report, build_report
from .narrative import (
    Fact, Narrative, NarrativeBuilder, Sentence, TEMPLATES,
    check_templates_have_no_literals, render_template,
)
from .render import render_markdown, render_text
from .schema import (
    ANALYST_DECISION_VALUES, OVERRIDE_REASON_CODES, PER_DOCUMENT_VERDICTS,
    REPORT_SCHEMA_VERSION, RISK_TIER_ORDER, AnalystDecisionBlock, DocumentSection,
    SignalReading, risk_tier_for,
)

__all__ = [
    "build_report", "Report", "render_markdown", "render_text",
    "extract_entities", "extract_from_documents", "group_by_kind", "Entity",
    "Fact", "Narrative", "NarrativeBuilder", "Sentence", "TEMPLATES",
    "render_template", "check_templates_have_no_literals",
    "AnalystDecisionBlock", "DocumentSection", "SignalReading", "risk_tier_for",
    "ANALYST_DECISION_VALUES", "OVERRIDE_REASON_CODES", "PER_DOCUMENT_VERDICTS",
    "REPORT_SCHEMA_VERSION", "RISK_TIER_ORDER",
]

__version__ = "0.1.0"
