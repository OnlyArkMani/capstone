"""
Human-readable renderings of a `Report`.

Both renderers read the same `Report` object and neither computes anything. That
is the point: a renderer that derives its own figures is a second implementation
of the scoring logic, and the two drift. Every number printed here was already in
the report, which is also what lets the grounding test check the rendered text
rather than only the JSON.

Layout follows design §2.9: **the headline is first, alone, and unmissable.** An
analyst working a queue reads the band and stops there when it is GREEN. Score,
case, evidence and reasoning are the detail they open when it is not — or when
they want to verify a GREEN, which is the other reason the detail must always be
present rather than hidden behind the happy path.
"""

from __future__ import annotations

from typing import Any

from .generator import Report, SIGNAL_DISPLAY, STATUS_OVER_MAL, STATUS_OVER_SUS

BAR = "=" * 78
RULE = "-" * 78

# Text markers rather than colour: reports are read in terminals, pasted into
# tickets, and printed. A marker survives all three; an ANSI escape does not.
BAND_MARKER = {"GREEN": "[ GREEN ]", "ORANGE": "[ ORANGE ]", "RED": "[ RED ]"}


def _fmt(value: Any, dp: int = 3, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    if isinstance(value, str):
        return value
    return f"{value:.{dp}f}{suffix}"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_markdown(report: Report | dict[str, Any]) -> str:
    r = report.to_dict() if hasattr(report, "to_dict") else report
    out: list[str] = []

    # --- headline, above everything ---
    out.append(f"# {r['headline_display']}")
    out.append("")
    out.append(f"**{r['headline_label']}**")
    out.append("")
    out.append(f"> {r['headline_meaning']}")
    out.append("")
    out.append(f"*Recommended action: **{r['recommended_action']}** · "
               f"Risk tier: **{r['risk_tier']}** ({r['priority']}) · "
               f"Case {r['case_id']} {r['case_name']}*")
    out.append("")
    out.append(RULE)
    out.append("")

    # --- identification ---
    out.append("## Query")
    out.append("")
    out.append(f"> {r['query']}")
    out.append("")
    out.append(f"| | |\n|---|---|\n"
               f"| Report ID | `{r['report_id']}` |\n"
               f"| Generated | {r['generated_at']} |\n"
               f"| Schema | `{r['schema_version']}` |\n"
               f"| Documents retrieved | {r['n_retrieved']} "
               f"(effective independent: {_fmt(r['n_eff'], 2)}) |\n"
               f"| Governing source tier | {r['tier_governing']} |")
    out.append("")

    # --- scores ---
    out.append("## Trust assessment")
    out.append("")
    lo, hi = r["trust_interval"]
    trust = (f"**{_fmt(r['trust_percent'], 1, '%')}** "
             f"(95% interval {_fmt(lo, 1, '%')} – {_fmt(hi, 1, '%')})"
             if r["trust_percent"] is not None else "*not computed — no fitted model*")
    out.append(f"| Measure | Value |\n|---|---|\n"
               f"| Composite trust score | {trust} |\n"
               f"| Confidence in that score | {_fmt(r['confidence'], 3)} |\n"
               f"| Signal band | {r['band']} |\n"
               f"| Risk tier | {r['risk_tier']} |")
    out.append("")
    if r["confidence_components"]:
        parts = " · ".join(f"{k} {_fmt(v, 2)}"
                           for k, v in sorted(r["confidence_components"].items()))
        out.append(f"Confidence components: {parts}")
        if r["confidence_caps"]:
            out.append(f"Caps applied: {', '.join(r['confidence_caps'])}")
        out.append("")

    # --- reasoning ---
    out.append("## Reasoning")
    out.append("")
    for sentence in r["reasoning"]["sentences"]:
        out.append(f"- {sentence['text']}")
    out.append("")
    g = r["reasoning"]["grounding"]
    out.append(f"*{g['fact_count']} values in the text above are substituted from computed "
               f"fields of this report; none is model-generated.*")
    out.append("")

    # --- evidence ---
    out.append("## Evidence — retrieved documents")
    out.append("")
    for doc in r["documents"]:
        marker = BAND_MARKER.get(doc["headline"], doc["headline"])
        out.append(f"### {doc['rank']}. {marker} `{doc['doc_id']}`")
        out.append("")
        out.append(f"{doc['title']}" if doc["title"] else "")
        out.append("")
        out.append(f"| Field | Value |\n|---|---|\n"
                   f"| Source | {doc['source_name']} (`{doc['source_id']}`) |\n"
                   f"| Trust tier | {doc['source_tier']} — {doc['source_tier_label']} |\n"
                   f"| Similarity to query | {_fmt(doc['similarity'], 4)} |\n"
                   f"| Case | {doc['case_id']} {doc['case_name']} |\n"
                   f"| Action | {doc['action']} ({doc['priority']}) |")
        out.append("")
        out.append("| Detector | Score | Suspicious @ | Malicious @ | Status |")
        out.append("|---|---|---|---|---|")
        for reading in doc["readings"]:
            flag = "**FIRED**" if reading["status"] in (STATUS_OVER_MAL, STATUS_OVER_SUS) \
                else reading["status"]
            out.append(f"| `{SIGNAL_DISPLAY.get(reading['signal'], reading['signal'])}` "
                       f"| {_fmt(reading['value'])} "
                       f"| {_fmt(reading['suspicious_threshold'])} "
                       f"| {_fmt(reading['malicious_threshold'])} | {flag} |")
        out.append("")
        prov = doc.get("provenance") or {}
        if prov.get("reference_url") or prov.get("published_date"):
            out.append(f"Provenance: published {prov.get('published_date', 'unknown')}"
                       f" · ingested {prov.get('ingestion_date', 'unknown')}"
                       f" · reference verified: {prov.get('reference_verified')}")
            out.append("")

    # --- indicators ---
    out.append("## Extracted indicators")
    out.append("")
    if r["entity_count"]:
        for kind, items in sorted(r["entities"].items()):
            values = ", ".join(f"`{e['value']}`" for e in items)
            out.append(f"- **{kind}** ({len(items)}): {values}")
        out.append("")
        out.append("*Extracted by pattern matching only. No language model was involved, "
                   "so no indicator here can have been invented.*")
    else:
        out.append("None found.")
    out.append("")

    # --- caveats ---
    if r["caveats"]:
        out.append("## Caveats")
        out.append("")
        for c in r["caveats"]:
            out.append(f"- {c}")
        out.append("")

    # --- analyst decision ---
    ad = r["analyst_decision"]
    out.append("## Analyst decision")
    out.append("")
    out.append(f"**Status: {ad['status']}** — awaiting human review.")
    out.append("")
    out.append("This field is never populated by the system. It is filled in only when an "
               "analyst acts on this case in the dashboard.")
    out.append("")
    out.append(f"- Decision: one of {', '.join(ad['form_spec']['decision']['values'])}")
    out.append(f"- If OVERRIDE: an override action and a reason code from the "
               f"{ad['form_spec']['override_reason_code']['n_codes']}-code "
               f"controlled vocabulary are both required")
    out.append(f"- Per-document verdicts "
               f"({', '.join(ad['form_spec']['per_document_verdicts']['values'])}) "
               f"for: {', '.join(f'`{d}`' for d in ad['form_spec']['per_document_verdicts']['doc_ids'])}")
    out.append("")

    return "\n".join(out).replace("\n\n\n", "\n\n")


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

def render_text(report: Report | dict[str, Any], width: int = 78) -> str:
    """Compact fixed-width rendering, for a terminal or a ticket paste."""
    r = report.to_dict() if hasattr(report, "to_dict") else report
    out: list[str] = [BAR]

    marker = BAND_MARKER.get(r["headline"], r["headline"])
    out.append(f"{marker}  {r['headline_label'].upper()}")
    if r["headline_subtype_label"]:
        out.append(f"          {r['headline_subtype_label']}")
    out.append(BAR)
    out.append(f"Action: {r['recommended_action']:9} Risk tier: {r['risk_tier']:14} "
               f"Case: {r['case_id']} {r['case_name']}")
    out.append(f"Query:  {r['query'][:width - 8]}")
    out.append(f"Report: {r['report_id']}   {r['generated_at']}")
    out.append(RULE)

    lo, hi = r["trust_interval"]
    trust = (f"{_fmt(r['trust_percent'], 1)}%  [{_fmt(lo, 1)}% - {_fmt(hi, 1)}%]"
             if r["trust_percent"] is not None else "not computed")
    out.append(f"Trust score : {trust}")
    out.append(f"Confidence  : {_fmt(r['confidence'])}"
               + (f"   caps: {', '.join(r['confidence_caps'])}"
                  if r["confidence_caps"] else ""))
    out.append(f"Evidence    : {r['n_retrieved']} documents, "
               f"{_fmt(r['n_eff'], 2)} effective independent, "
               f"governing tier {r['tier_governing']}")
    out.append(RULE)

    out.append("REASONING")
    for s in r["reasoning"]["sentences"]:
        out.append(f"  - {s['text']}")
    out.append(RULE)

    out.append("EVIDENCE")
    for doc in r["documents"]:
        m = BAND_MARKER.get(doc["headline"], doc["headline"])
        out.append(f"  {doc['rank']}. {m:10} {doc['doc_id']}  "
                   f"(tier {doc['source_tier']}, sim {_fmt(doc['similarity'], 3)})")
        for reading in doc["readings"]:
            fired = reading["status"] in (STATUS_OVER_MAL, STATUS_OVER_SUS)
            name = SIGNAL_DISPLAY.get(reading["signal"], reading["signal"])
            out.append(f"       {'>>' if fired else '  '} {name:26} "
                       f"{_fmt(reading['value']):>7}  "
                       f"(sus {_fmt(reading['suspicious_threshold']):>7}, "
                       f"mal {_fmt(reading['malicious_threshold']):>7})  "
                       f"{reading['status']}")
    out.append(RULE)

    out.append(f"INDICATORS ({r['entity_count']})")
    if r["entity_count"]:
        for kind, items in sorted(r["entities"].items()):
            out.append(f"  {kind:8} {', '.join(e['value'] for e in items)}")
    else:
        out.append("  none")

    if r["caveats"]:
        out.append(RULE)
        out.append("CAVEATS")
        for c in r["caveats"]:
            out.append(f"  ! {c}")

    out.append(RULE)
    out.append(f"ANALYST DECISION: {r['analyst_decision']['status']} "
               f"(never set by the system; a human fills this in)")
    out.append(BAR)
    return "\n".join(out)
