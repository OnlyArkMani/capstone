"""
Audit log viewer — every query the system has scored, and what happened to it.

Filters by headline class, case classification and analyst decision, which are
the three questions someone actually asks of this table: *what did we flag*,
*what kind of thing was it*, and *what did we conclude*.

"Not reviewed" is a filter option here but not a stored value. Design §5.8 keeps
undecided as the absence of a decision row rather than a `PENDING` sentinel, so
this page asks for a null join result instead of a status string.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st  # noqa: E402

from dashboard.components import BAND_STYLE, SUBTYPE_LABEL, event_rows_for_table  # noqa: E402
from dashboard.service import distinct_cases, get_audit_log, list_events  # noqa: E402

st.set_page_config(page_title="Audit Log — Trust & Risk Layer", page_icon="📋",
                   layout="wide")

st.markdown("### Audit log")
st.caption("Every scored query, with its class, case, scores and analyst decision.")

log = get_audit_log()
stats = log.stats()

# --- summary strip ---
cols = st.columns(5)
cols[0].metric("Queries logged", stats["total_events"])
for i, band in enumerate(("GREEN", "ORANGE", "RED"), start=1):
    cols[i].metric(band, stats["by_headline"].get(band, 0))
cols[4].metric("Awaiting review", stats["unreviewed"])

st.markdown("---")

# --- filters ---
f1, f2, f3, f4 = st.columns(4)
with f1:
    headline = st.selectbox("Class", ["All", "GREEN", "ORANGE", "RED"])
with f2:
    subtype = st.selectbox(
        "RED sub-type", ["All", "ATTACK_DETECTED", "TRUSTED_SOURCE_COMPROMISE"],
        format_func=lambda s: SUBTYPE_LABEL.get(s, s),
        disabled=(headline not in ("All", "RED")),
        help="An ordinary attack and a suspected compromise of a source we trusted "
             "are not equally urgent.")
with f3:
    cases = distinct_cases()
    case_id = st.selectbox("Case classification", ["All"] + cases)
with f4:
    decision = st.selectbox(
        "Analyst decision", ["All", "UNREVIEWED", "ACCEPT", "REJECT", "OVERRIDE"],
        format_func=lambda d: "— not reviewed —" if d == "UNREVIEWED" else d)

events = list_events(
    headline=None if headline == "All" else headline,
    subtype=None if subtype == "All" else subtype,
    case_id=None if case_id == "All" else case_id,
    decision=None if decision == "All" else decision,
    limit=500)

st.caption(f"{len(events)} matching {'query' if len(events) == 1 else 'queries'}")

if not events:
    st.info("No queries match these filters. Run one from the console page.")
else:
    st.dataframe(event_rows_for_table(events), use_container_width=True,
                 hide_index=True)

    st.markdown("---")
    chosen = st.selectbox(
        "Open a query", [e["event_id"] for e in events],
        format_func=lambda eid: next(
            (f"{e['headline']} · {e['case_id']} · {e['query_text'][:50]}"
             for e in events if e["event_id"] == eid), eid))
    if chosen:
        event = log.get_event(chosen)
        band = event["headline"]
        style = BAND_STYLE.get(band, BAND_STYLE["ORANGE"])
        sub = event.get("headline_subtype")
        st.markdown(
            f"""<div style="background:{style['bg']};color:{style['fg']};
                    padding:0.9rem 1.2rem;border-radius:10px;margin-bottom:0.8rem;">
                <span style="font-size:1.5rem;font-weight:700;">{band}</span>
                {'<span style="font-size:1.05rem;margin-left:0.8rem;">'
                 + SUBTYPE_LABEL.get(sub, sub) + '</span>' if sub else ''}
            </div>""", unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown(
                f"**Query:** {event['query_text']}  \n"
                f"**Reference:** `{event['event_id']}`  \n"
                f"**When:** {event['created_at']}  \n"
                f"**Case:** {event['case_id']} {event.get('case_name') or ''}  \n"
                f"**Action:** {event['final_action']} ({event['risk_priority']})")
        with c2:
            trust = event.get("trust_percent")
            st.markdown(
                f"**Trust score:** "
                f"{'not computed' if trust is None else f'{trust:.1f}%'}  \n"
                f"**Confidence:** {event['confidence']:.3f}  \n"
                f"**Rule track proposed:** {event['taxonomy_action']}  \n"
                f"**Score track proposed:** {event['score_action']}  \n"
                f"**Detectors were real models:** "
                f"{'yes' if event['backends_are_models'] else 'NO — fallback backends'}")

        decision_row = log.current_decision(chosen)
        if decision_row:
            st.success(
                f"Analyst decision: **{decision_row['analyst_decision']}**"
                + (f" → {decision_row['override_action']} "
                   f"({decision_row['override_reason_code']})"
                   if decision_row["analyst_decision"] == "OVERRIDE" else "")
                + f" · by {decision_row['analyst_id']} at {decision_row['decided_at']}")
            if decision_row.get("supersedes_decision_id"):
                st.caption(f"This supersedes `{decision_row['supersedes_decision_id']}`. "
                           f"The earlier decision is retained in the log.")
        else:
            st.info("Not yet reviewed — there is no decision record for this query. "
                    "Undecided is the absence of a row, never a stored value.")

st.markdown("---")
with st.expander("Integrity"):
    chain = log.verify_chain()
    if chain["ok"]:
        st.success(f"Decision hash chain verifies across {chain['n_rows']} row(s).")
        st.caption(f"Chain head: `{chain['head'][:32]}…`  \n"
                   "Each decision hashes its own content plus its predecessor's hash, so "
                   "editing any historical row breaks every hash after it.")
    else:
        st.error(f"Hash chain broken at row {chain['broken_at']} "
                 f"(`{chain['decision_id']}`): {chain['reason']}")
