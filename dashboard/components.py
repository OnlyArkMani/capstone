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
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Colours chosen for contrast against white text at large sizes rather than for
# brand fidelity. This is read across a room during a demo.
BAND_STYLE: dict[str, dict[str, str]] = {
    "GREEN": {"bg": "#1B7F4C", "fg": "#FFFFFF", "icon": "✓",
              "label": "GOOD TO GO"},
    "ORANGE": {"bg": "#C2610A", "fg": "#FFFFFF", "icon": "!",
               "label": "MID-SUSPICIOUS — REVIEW RECOMMENDED"},
    "RED": {"bg": "#B3261E", "fg": "#FFFFFF", "icon": "✕",
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


# ---------------------------------------------------------------------------
# The banner — always first
# ---------------------------------------------------------------------------

def render_banner(st: Any, report: dict[str, Any]) -> None:
    """The full-width colour banner. **Must be the first thing on the page.**

    Sized so that the band is legible from across a room and cannot be mistaken
    for a heading. When the band is RED the sub-type sits directly underneath,
    because an analyst scanning red flags needs to tell an ordinary attack from a
    suspected source compromise without opening anything.
    """
    band = report.get("headline", "ORANGE")
    style = BAND_STYLE.get(band, BAND_STYLE["ORANGE"])
    subtype = report.get("headline_subtype")

    sub_html = ""
    if band == "RED" and subtype:
        sub_html = (
            f'<div style="font-size:1.55rem;font-weight:600;margin-top:0.35rem;'
            f'letter-spacing:0.01em;">{SUBTYPE_LABEL.get(subtype, subtype)}</div>')

    st.markdown(
        f"""
        <div style="background:{style['bg']};color:{style['fg']};
                    padding:2.1rem 2.4rem;border-radius:14px;
                    margin:0 0 1.1rem 0;text-align:center;
                    box-shadow:0 2px 14px rgba(0,0,0,0.18);">
          <div style="font-size:3.5rem;font-weight:800;line-height:1.05;
                      letter-spacing:0.02em;">
            {style['icon']}&nbsp;{band}
          </div>
          <div style="font-size:1.5rem;font-weight:600;margin-top:0.3rem;
                      letter-spacing:0.03em;">{style['label']}</div>
          {sub_html}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if band == "RED" and subtype:
        st.caption(SUBTYPE_HINT.get(subtype, ""))


def render_headline_metrics(st: Any, report: dict[str, Any]) -> None:
    """Composite trust score directly below the banner, then case and action."""
    trust = report.get("trust_percent")
    lo, hi = (report.get("trust_interval") or [None, None])[:2]

    c1, c2, c3 = st.columns([1.2, 1, 1])
    with c1:
        st.metric(
            "Composite trust score",
            "not computed" if trust is None else f"{trust:.1f}%",
            help="Calibrated probability that this response is not attacker-influenced, "
                 "expressed as trustworthiness.")
        if trust is not None and lo is not None:
            st.caption(f"95% interval {lo:.1f}% – {hi:.1f}%")
    with c2:
        st.metric("Confidence in that score", _fmt(report.get("confidence"), 2),
                  help="How much to trust the figure on the left. Reported separately "
                       "because a high score from one document and a high score from "
                       "five agreeing sources are different things.")
    with c3:
        st.metric("Risk tier", report.get("risk_tier", "—"),
                  help="Queue severity, from the case priority and the final action, "
                       "whichever is more severe.")


def render_case_and_action(st: Any, report: dict[str, Any]) -> None:
    st.markdown(
        f"**Case {report.get('case_id', '—')} — {report.get('case_name', '')}**  \n"
        f"Recommended action: **{report.get('recommended_action', '—')}** "
        f"({report.get('priority', '')})")
    if report.get("action_meaning"):
        st.caption(report["action_meaning"])


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

def render_documents(st: Any, report: dict[str, Any]) -> None:
    """One expander per retrieved document, with every detector's own score."""
    docs = report.get("documents", []) or []
    st.subheader(f"Evidence — {len(docs)} retrieved documents")

    for doc in docs:
        band = doc.get("headline", "ORANGE")
        icon = BAND_STYLE.get(band, {}).get("icon", "")
        fired = [r for r in doc.get("readings", [])
                 if r.get("status") in ("over_malicious", "over_suspicious")]
        flag = f" — {len(fired)} signal(s) fired" if fired else ""
        title = (f"{icon} {doc['rank']}. {doc['doc_id']} · Tier {doc['source_tier']} · "
                 f"similarity {_fmt(doc.get('similarity'), 3)}{flag}")

        with st.expander(title, expanded=bool(fired)):
            st.markdown(
                f"**{doc.get('title', '')}**  \n"
                f"Source: {doc.get('source_name', '')} (`{doc.get('source_id', '')}`)  \n"
                f"Trust tier: {doc.get('source_tier')} — {doc.get('source_tier_label', '')}  \n"
                f"Case: {doc.get('case_id')} {doc.get('case_name', '')} · "
                f"Action: {doc.get('action')} ({doc.get('priority')})")

            rows = []
            for r in doc.get("readings", []):
                rows.append({
                    "Detector": SIGNAL_DISPLAY.get(r["signal"], r["signal"]),
                    "Score": _fmt(r.get("value")),
                    "Suspicious at": _fmt(r.get("suspicious_threshold")),
                    "Malicious at": _fmt(r.get("malicious_threshold")),
                    "Status": ("FIRED" if r.get("status") in
                               ("over_malicious", "over_suspicious") else r.get("status")),
                })
            st.table(rows)

            unusable = [r for r in doc.get("readings", []) if r.get("status") == "unusable"]
            missing = [r for r in doc.get("readings", []) if r.get("status") == "missing"]
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
        values = ", ".join(f"`{e['value']}`" for e in items)
        st.markdown(f"**{kind}** ({len(items)}) — {values}")
    st.caption("Extracted by pattern matching only. No language model was involved, so "
               "nothing here can have been invented.")


def render_reasoning(st: Any, report: dict[str, Any]) -> None:
    st.subheader("Reasoning")
    reasoning = report.get("reasoning", {}) or {}
    for sentence in reasoning.get("sentences", []):
        st.markdown(f"- {sentence['text']}")
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
