"""
Rendering pieces for the dashboard, kept out of the page files.

Why these are separate functions rather than inline Streamlit calls
------------------------------------------------------------------
Two reasons, and the second is the important one.

The banner has a hard requirement: it must be **the first thing rendered**, above
everything else, visible without scrolling or clicking. That is a property of the
call order, and a property is testable only if the thing that has it is a function
somebody can call. `test_dashboard.py` runs these against a recording stub and
asserts the banner is call number one.

And nothing here computes. Every figure comes from the report object assembled in
`reports/`. A dashboard that derives its own numbers is a second implementation of
the scoring logic, and the two drift — which the report generator's own tests
already caught once.

Presentation
------------
Colours, spacing and the HTML builders live in `dashboard/style.py`; this module
decides *what* is shown and in what order, and asks that module for the markup.
The stylesheet is injected once by the page file, never from here — a stylesheet
emitted from `render_banner` would become the banner's first recorded call and
the ordering requirement above would stop being tested.

Two properties of the visual language are load-bearing rather than decorative:

*State is never colour alone.* Every band, every fired detector and every tier
carries an icon or a word beside its colour, because a colourblind reviewer, a
washed-out projector and a greyscale printout each delete the colour channel and
the verdict still has to arrive.

*Absence is not zero.* A detector that did not run, or could not be calibrated,
is drawn as text rather than as an empty bar. A bar at zero says "we measured
this and it was clean"; that is the opposite of what an uncalibrated detector
means, and the distinction is the whole point of the `unusable` status.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dashboard import style  # noqa: E402

# Kept as a module-level mapping because the audit-log page and the tests both
# import it. `bg` is the banner fill; the accent step for lines, dots and bars
# against the dark surface lives beside it in `style.BAND`.
BAND_STYLE: dict[str, dict[str, str]] = {
    "GREEN": {"bg": style.BAND["GREEN"]["bg"], "fg": "#FFFFFF", "icon": "✓",
              "label": "GOOD TO GO"},
    "ORANGE": {"bg": style.BAND["ORANGE"]["bg"], "fg": "#FFFFFF", "icon": "!",
               "label": "MID-SUSPICIOUS — REVIEW RECOMMENDED"},
    "RED": {"bg": style.BAND["RED"]["bg"], "fg": "#FFFFFF", "icon": "✕",
            "label": "REJECT / ESCALATE"},
}

SUBTYPE_LABEL = {
    "ATTACK_DETECTED": "Attack Detected",
    "TRUSTED_SOURCE_COMPROMISE": "Trusted Source Compromise Suspected",
}

SUBTYPE_HINT = {
    "ATTACK_DETECTED":
        "Malicious or irregular content from a source we had not vouched for. "
        "The document is the unit of concern — quarantining it largely closes this.",
    "TRUSTED_SOURCE_COMPROMISE":
        "A source we had already verified is behaving anomalously. The source is the "
        "unit of concern — this is a finding about our own trust infrastructure and "
        "it outlives this query.",
}

SIGNAL_DISPLAY = {
    "injection": "injection_probability",
    "anomaly": "embedding_anomaly_score",
    "unsupport": "claim_unsupport_score",
    "conflict": "evidence_conflict_score",
}


def _fmt(value: Any, dp: int = 3, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    if isinstance(value, str):
        return value
    return f"{value:.{dp}f}{suffix}"


def _md(st: Any, html: str) -> None:
    st.markdown(html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# The banner — always first
# ---------------------------------------------------------------------------

def render_banner(st: Any, report: dict[str, Any]) -> None:
    """The full-width colour banner. **Must be the first thing on the page.**

    Sized so that the band is legible from across a room and cannot be mistaken
    for a heading. When the band is RED the sub-type sits directly underneath,
    because an analyst scanning red flags needs to tell an ordinary attack from a
    suspected source compromise without opening anything.

    The geometry stays inline rather than moving into the stylesheet. The test
    reads this string and asserts the display size and the fill are present, and
    a banner whose loudness could be removed by a stylesheet that failed to load
    is exactly the failure the requirement exists to prevent.
    """
    band = report.get("headline", "ORANGE")
    style_ = BAND_STYLE.get(band, BAND_STYLE["ORANGE"])
    subtype = report.get("headline_subtype")

    sub_html = ""
    if band == "RED" and subtype:
        sub_html = (
            f'<div class="tz-banner-subtype" style="font-size:1.55rem;'
            f'font-weight:600;">{SUBTYPE_LABEL.get(subtype, subtype)}</div>')

    _md(st, f"""
        <div class="tz-banner" style="background:{style_['bg']};
                    color:{style_['fg']};border-radius:6px;">
          <div class="tz-banner-eyebrow">System verdict</div>
          <div style="font-size:3.5rem;font-weight:800;line-height:1.05;
                      letter-spacing:0.02em;">
            {style_['icon']}&nbsp;{band}
          </div>
          <div class="tz-banner-sub">{style_['label']}</div>
          {sub_html}
        </div>
        """)

    if band == "RED" and subtype:
        st.caption(SUBTYPE_HINT.get(subtype, ""))


def render_headline_metrics(st: Any, report: dict[str, Any]) -> None:
    """Composite trust score directly below the banner, then case and action.

    The 95% interval used to be a line of caption text. It is now drawn to scale
    under the figure, because how *wide* it is changes what an analyst should do
    with the number and a pair of decimals does not communicate width.
    """
    trust = report.get("trust_percent")
    lo, hi = (report.get("trust_interval") or [None, None])[:2]
    band = report.get("headline", "ORANGE")

    c1, c2, c3 = st.columns([1.35, 1, 1])
    with c1:
        st.metric(
            "Composite trust score",
            "not computed" if trust is None else f"{trust:.1f}%",
            help="Calibrated probability that this response is not attacker-influenced, "
                 "expressed as trustworthiness.")
        if trust is not None and lo is not None:
            _md(st, style.interval(trust, lo, hi))
    with c2:
        st.metric("Confidence in that score", _fmt(report.get("confidence"), 2),
                  help="How much to trust the figure on the left. Reported separately "
                       "because a high score from one document and a high score from "
                       "five agreeing sources are different things.")
    with c3:
        st.metric("Risk tier", report.get("risk_tier", "—"),
                  help="Queue severity, from the case priority and the final action, "
                       "whichever is more severe.")

    _md(st, f"<div style='height:2px;background:{style.band_accent(band)};"
            f"opacity:0.55;border-radius:1px;margin:0.55rem 0 0 0;'></div>")


def render_case_and_action(st: Any, report: dict[str, Any]) -> None:
    band = report.get("headline", "ORANGE")
    action = report.get("recommended_action", "—")
    _md(st, f"""
        <div class="tz-panel tz-panel-accent"
             style="border-left-color:{style.band_accent(band)};margin-top:0.55rem;">
          <div class="tz-eyebrow">Case classification</div>
          <div style="font-size:1rem;font-weight:600;margin:0.25rem 0 0.45rem 0;">
            {report.get('case_id', '—')} — {report.get('case_name', '')}
          </div>
          <div style="display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;">
            {style.chip(action, style.band_accent(band))}
            <span style="font-size:0.8rem;color:{style.INK_3};">
              recommended action · {report.get('priority', '')}</span>
          </div>
        </div>""")
    if report.get("action_meaning"):
        st.caption(report["action_meaning"])


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def render_documents(st: Any, report: dict[str, Any]) -> None:
    """One expander per retrieved document, with every detector's own score.

    Each reading is drawn twice on purpose: as a bar with the two thresholds
    ticked on the track, which answers "is this close to firing" without reading
    anything, and as the numeric table beneath it, which carries the exact values
    somebody will quote in a write-up. The bar is the glance; the table is the
    record.
    """
    docs = report.get("documents", []) or []
    st.subheader(f"Evidence — {len(docs)} retrieved documents")

    for doc in docs:
        band = doc.get("headline", "ORANGE")
        readings = doc.get("readings", []) or []
        fired = [r for r in readings
                 if r.get("status") in ("over_malicious", "over_suspicious")]
        flag = f" · {len(fired)} signal(s) fired" if fired else ""
        title = (f"{style.band_dot(band)}  {doc['rank']}. {doc['doc_id']}  ·  "
                 f"T{doc['source_tier']}  ·  sim {_fmt(doc.get('similarity'), 3)}{flag}")

        with st.expander(title, expanded=bool(fired)):
            _md(st, f"""
                <div style="display:flex;align-items:center;gap:0.55rem;
                            flex-wrap:wrap;margin:0.35rem 0 0.7rem 0;">
                  {style.band_chip(band)}
                  {style.tier_badge(doc.get('source_tier'),
                                    doc.get('source_tier_label', ''))}
                  {style.chip(str(doc.get('action', '')), style.INK_2)}
                </div>
                <div style="font-size:0.95rem;font-weight:600;margin-bottom:0.3rem;">
                  {doc.get('title', '')}</div>""")

            _md(st, style.kv([
                ("Source", f"{doc.get('source_name', '')} "
                           f"({doc.get('source_id', '')})"),
                ("Trust tier", f"{doc.get('source_tier')} — "
                               f"{doc.get('source_tier_label', '')}"),
                ("Case", f"{doc.get('case_id')} {doc.get('case_name', '')}"),
                ("Action", f"{doc.get('action')} ({doc.get('priority')})"),
            ]))

            _md(st, '<div class="tz-eyebrow" style="margin:1rem 0 0.55rem 0;">'
                    'Detector readings</div>')
            for r in readings:
                _md(st, style.meter(
                    SIGNAL_DISPLAY.get(r["signal"], r["signal"]),
                    r.get("value"), r.get("suspicious_threshold"),
                    r.get("malicious_threshold"), str(r.get("status", ""))))

            rows = []
            for r in readings:
                rows.append({
                    "Detector": SIGNAL_DISPLAY.get(r["signal"], r["signal"]),
                    "Score": _fmt(r.get("value")),
                    "Suspicious at": _fmt(r.get("suspicious_threshold")),
                    "Malicious at": _fmt(r.get("malicious_threshold")),
                    "Status": ("FIRED" if r.get("status") in
                               ("over_malicious", "over_suspicious") else r.get("status")),
                })
            st.table(rows)

            unusable = [r for r in readings if r.get("status") == "unusable"]
            missing = [r for r in readings if r.get("status") == "missing"]
            if unusable or missing:
                st.caption(
                    "`unusable` means the detector could not be calibrated at all; "
                    "`missing` means it never ran. Neither is a clean result — they mean "
                    "the system does not know.")

            prov = doc.get("provenance") or {}
            if prov:
                st.caption(
                    f"Published {prov.get('published_date', 'unknown')} · "
                    f"ingested {prov.get('ingestion_date', 'unknown')} · "
                    f"reference verified: {prov.get('reference_verified')}")


def render_entities(st: Any, report: dict[str, Any]) -> None:
    st.subheader(f"Extracted indicators ({report.get('entity_count', 0)})")
    entities = report.get("entities", {}) or {}
    if not entities:
        st.info("No IP addresses, domains, file hashes or CVE identifiers were found.")
        return
    for kind, items in sorted(entities.items()):
        values = "".join(
            f'<span class="tz-tier tz-tier-2" style="margin:0 0.3rem 0.3rem 0;'
            f'display:inline-block;">{e["value"]}</span>' for e in items)
        _md(st, f"""
            <div style="margin-bottom:0.55rem;">
              <span class="tz-eyebrow">{kind} ({len(items)})</span><br/>
              <div style="margin-top:0.3rem;">{values}</div>
            </div>""")
    st.caption("Extracted by pattern matching only. No language model was involved, so "
               "nothing here can have been invented.")


def render_reasoning(st: Any, report: dict[str, Any]) -> None:
    st.subheader("Reasoning")
    reasoning = report.get("reasoning", {}) or {}
    sentences = reasoning.get("sentences", []) or []
    if sentences:
        items = "".join(
            f'<li style="margin-bottom:0.4rem;">{s["text"]}</li>' for s in sentences)
        _md(st, f'<div class="tz-panel"><ul style="margin:0;padding-left:1.1rem;'
                f'font-size:0.9rem;line-height:1.55;">{items}</ul></div>')
    grounding = reasoning.get("grounding", {})
    if grounding:
        st.caption(
            f"{grounding.get('fact_count', 0)} values above are substituted from computed "
            f"fields of this report; none is model-generated.")


def render_caveats(st: Any, report: dict[str, Any]) -> None:
    """Shown prominently, not tucked away.

    Every detector in this build may be running on a fallback backend. A dashboard
    that displays those scores without saying so invites a demo audience to read
    them as measurements.
    """
    for caveat in report.get("caveats", []) or []:
        st.warning(caveat, icon="⚠️")


# ---------------------------------------------------------------------------
# Audit viewer
# ---------------------------------------------------------------------------

def event_rows_for_table(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten audit rows for display. Formatting only — no derivation."""
    out = []
    for e in events:
        band = e.get("headline", "")
        subtype = e.get("headline_subtype")
        display = band + (f" — {SUBTYPE_LABEL.get(subtype, subtype)}" if subtype else "")
        trust = e.get("trust_percent")
        out.append({
            "Class": display,
            "Case": f"{e.get('case_id', '')} {e.get('case_name', '') or ''}".strip(),
            "Trust %": "—" if trust is None else f"{trust:.1f}",
            "Confidence": _fmt(e.get("confidence"), 2),
            "Action": e.get("final_action", ""),
            "Analyst decision": e.get("analyst_decision") or "— not reviewed —",
            "Query": (e.get("query_text", "")[:60]
                      + ("…" if len(e.get("query_text", "")) > 60 else "")),
            "When": (e.get("created_at") or "")[:19],
            "Reference": e.get("event_id", ""),
        })
    return out
