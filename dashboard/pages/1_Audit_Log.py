"""
Audit log viewer — every query the system has scored, and what happened to it.

Filters by headline class, case classification and analyst decision, which are
the three questions someone actually asks of this table: *what did we flag*,
*what kind of thing was it*, and *what did we conclude*.

"Not reviewed" is a filter option here but not a stored value. Design 5.8 keeps
undecided as the absence of a decision row rather than a `PENDING` sentinel, so
this page asks for a null join result instead of a status string. The same holds
for the review chart: the unreviewed slice is a subtraction of two counts the log
reports, never a column read.

Presentation follows `dashboard/style.py` and `dashboard/charts.py`, the same two
layers the console page uses. The two pages are one product and a reviewer moving
between them should not have to re-learn where anything is.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st  # noqa: E402

from dashboard import charts, style  # noqa: E402
from dashboard.components import SUBTYPE_LABEL, event_rows_for_table  # noqa: E402
from dashboard.service import distinct_cases, get_audit_log, list_events  # noqa: E402

st.set_page_config(page_title="Audit Log — Trust and Risk Layer", layout="wide")
style.inject(st)

st.markdown(style.masthead(
    "Audit log",
    "Every scored query, with its class, case, scores and analyst decision",
    "TAMPER-EVIDENT · HASH-CHAINED"),
    unsafe_allow_html=True)

log = get_audit_log()
stats = log.stats()

# --- summary strip ---------------------------------------------------------
# Total and unreviewed are neutral counts. The three band counts wear their own
# state colour, and each keeps its band name as the label, so the row is still
# readable with the colour channel removed.
st.markdown(style.stat_cards([
    ("Queries logged", stats["total_events"], style.ACCENT),
    ("Green", stats["by_headline"].get("GREEN", 0), style.GOOD),
    ("Orange", stats["by_headline"].get("ORANGE", 0), style.WARN),
    ("Red", stats["by_headline"].get("RED", 0), style.CRIT),
    ("Awaiting review", stats["unreviewed"], style.NEUTRAL),
]), unsafe_allow_html=True)

# --- distribution charts ---------------------------------------------------
if stats["total_events"]:
    g1, g2, g3 = st.columns([1, 1.4, 1])
    with g1:
        st.markdown('<div class="tz-eyebrow" style="margin:1.5rem 0 0.4rem 0;">'
                    'Verdict bands</div>', unsafe_allow_html=True)
        spec = charts.band_split(stats["by_headline"])
        if spec:
            charts.render(g1, spec, height=150)
    with g2:
        st.markdown('<div class="tz-eyebrow" style="margin:1.5rem 0 0.4rem 0;">'
                    'Case classification</div>', unsafe_allow_html=True)
        spec = charts.case_split(stats["by_case"])
        if spec:
            charts.render(g2, spec, height=150)
    with g3:
        st.markdown('<div class="tz-eyebrow" style="margin:1.5rem 0 0.4rem 0;">'
                    'Analyst outcomes</div>', unsafe_allow_html=True)
        spec = charts.review_split(stats["total_events"], stats["decided"],
                                   stats["by_decision"])
        if spec:
            charts.render(g3, spec, height=150)

# --- filters ---------------------------------------------------------------
st.markdown('<div class="tz-eyebrow" style="margin:1.7rem 0 0.5rem 0;">Filters</div>',
            unsafe_allow_html=True)
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

    st.subheader("Open a query")
    chosen = st.selectbox(
        "Query", [e["event_id"] for e in events], label_visibility="collapsed",
        format_func=lambda eid: next(
            (f"{e['headline']} · {e['case_id']} · {e['query_text'][:50]}"
             for e in events if e["event_id"] == eid), eid))
    if chosen:
        event = log.get_event(chosen)
        band = event["headline"]
        spec = style.BAND.get(band, style.BAND["ORANGE"])
        sub = event.get("headline_subtype")
        sub_html = (f'<span style="font-size:0.9rem;margin-left:0.9rem;'
                    f'opacity:0.92;">{SUBTYPE_LABEL.get(sub, sub)}</span>'
                    if sub else "")
        st.markdown(
            f'<div style="background:{spec["bg"]};color:#FFFFFF;border-radius:3px;'
            f'padding:0.6rem 1.1rem;margin:0.3rem 0 0.8rem 0;">'
            f'<span style="font-size:1.25rem;font-weight:700;letter-spacing:0.02em;">'
            f'{spec["icon"]}&nbsp;{band}</span>{sub_html}</div>',
            unsafe_allow_html=True)

        trust = event.get("trust_percent")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(style.kv([
                ("Query", event["query_text"]),
                ("Reference", event["event_id"]),
                ("When", str(event["created_at"])),
                ("Case", f"{event['case_id']} {event.get('case_name') or ''}"),
                ("Action", f"{event['final_action']} ({event['risk_priority']})"),
            ]), unsafe_allow_html=True)
        with c2:
            backends_ok = bool(event["backends_are_models"])
            st.markdown(style.kv([
                ("Trust score",
                 "not computed" if trust is None else f"{trust:.1f}%"),
                ("Confidence", f"{event['confidence']:.3f}"),
                ("Rule track", event["taxonomy_action"]),
                ("Score track", event["score_action"]),
                ("Detectors",
                 "real models" if backends_ok else "NO — fallback backends"),
            ]), unsafe_allow_html=True)

        # The two tracks are the architecture's central claim — a rule-based
        # classification and a calibrated score, reconciled conservatively. When
        # they disagree, that is the most decision-relevant fact on this page, so
        # it is stated rather than left for the reader to spot in two adjacent
        # rows of a key-value block.
        if event["taxonomy_action"] != event["score_action"]:
            st.warning(
                f"The two assessments disagreed: the case taxonomy proposed "
                f"**{event['taxonomy_action']}** and the composite score proposed "
                f"**{event['score_action']}**. The final action "
                f"**{event['final_action']}** is the more conservative of the two.")

        if not backends_ok:
            st.warning("One or more detectors ran on a fallback backend for this "
                       "query. The scores above are not model measurements.")

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

st.subheader("Integrity")
chain = log.verify_chain()
if chain["ok"]:
    st.markdown(
        f'<div class="tz-panel tz-panel-accent" style="border-left-color:{style.GOOD};">'
        f'{style.chip("chain verified", style.GOOD, "✓")}'
        f'<div style="margin-top:0.55rem;font-size:0.84rem;color:{style.INK_2};">'
        f'Verifies across {chain["n_rows"]} row(s). Head '
        f'<code>{chain["head"][:32]}…</code></div>'
        f'<div style="margin-top:0.4rem;font-size:0.76rem;color:{style.INK_3};">'
        f'Each decision hashes its own content plus its predecessor\'s hash, so '
        f'editing any historical row breaks every hash after it.</div></div>',
        unsafe_allow_html=True)
else:
    st.error(f"Hash chain broken at row {chain['broken_at']} "
             f"(`{chain['decision_id']}`): {chain['reason']}")
