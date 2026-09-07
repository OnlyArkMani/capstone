"""
The SOC analyst console.

    streamlit run dashboard/app.py

Page one: ask a question, get a verdict, act on it. Page two: the audit log.

The banner is the first thing rendered on the results view, above everything
else, and that ordering is a requirement rather than a style choice (design
2.9). An analyst working a queue reads the band and stops there when it is
GREEN; the score, the case, the evidence and the reasoning are the detail they
open when it is not -- or when they want to verify a GREEN.

Writing a decision goes through `DecisionWriter`, which is the only class in the
project that may insert into `analyst_decisions`. This module never touches that
table directly, and `AuditLog` -- which the scoring path holds -- has no method
that could.

Presentation is in `dashboard/style.py`, charts in `dashboard/charts.py`. The
stylesheet is injected here, once, immediately after `set_page_config` and before
anything else renders -- never from a render function, because the first recorded
call on the results view has to be the banner and the tests check exactly that.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st  # noqa: E402

from dashboard import style  # noqa: E402
from dashboard.components import (  # noqa: E402
    render_banner, render_caveats, render_case_and_action, render_documents,
    render_entities, render_headline_metrics, render_performance, render_reasoning,
    render_score_analysis, render_signal_overview,
)
from dashboard.demo_queries import CUSTOM, DEMO_QUERIES  # noqa: E402
from dashboard.service import (  # noqa: E402
    OVERRIDE_REASON_CODES, ScoringUnavailable, get_audit_log, get_decision_writer,
    run_query,
    STAGES,
)

PAGE_TITLE = "Trust and Risk Layer — SOC Analyst Console"
SUBTITLE = ("Corpus poisoning detection for retrieval-augmented threat "
            "intelligence")
SYSTEM_MARK = "DESIGN-V1.7 · HEALTHCARE THREAT INTELLIGENCE"


def _init_state() -> None:
    st.session_state.setdefault("report", None)
    st.session_state.setdefault("event_id", None)
    st.session_state.setdefault("review_started_at", None)
    st.session_state.setdefault("decision_saved", None)
    st.session_state.setdefault("show_override", False)
    st.session_state.setdefault("_demo_choice", None)


def main() -> None:
    st.set_page_config(page_title=PAGE_TITLE, layout="wide")
    style.inject(st)
    _init_state()

    analyst_id, analyst_role = _render_sidebar()

    st.markdown(style.masthead(PAGE_TITLE, SUBTITLE, SYSTEM_MARK),
                unsafe_allow_html=True)

    query, run = _render_query_bar()

    if run and query and query.strip():
        if not _score(query.strip()):
            return

    report = st.session_state.report
    if report is None:
        _render_empty_state()
        return

    # ---- THE BANNER IS FIRST. Nothing renders above it. ----
    render_banner(st, report)
    render_headline_metrics(st, report)
    render_case_and_action(st, report)
    render_caveats(st, report)

    render_signal_overview(st, report)
    render_score_analysis(st, report)

    render_reasoning(st, report)
    render_documents(st, report)
    render_entities(st, report)
    render_performance(st, report)

    _render_decision_panel(st, report, analyst_id, analyst_role)

    with st.expander("Reference and provenance"):
        st.markdown(
            f"Audit reference: `{st.session_state.event_id}`  \n"
            f"Report ID: `{report.get('report_id')}`  \n"
            f"Generated: {report.get('generated_at')}  \n"
            f"Schema: `{report.get('schema_version')}`")
        st.json(report.get("provenance", {}))


# ---------------------------------------------------------------------------
# Chrome
# ---------------------------------------------------------------------------

def _render_sidebar() -> tuple[str, str]:
    with st.sidebar:
        st.markdown(
            '<div class="tz-side-brand">Trust and Risk Layer</div>'
            '<div class="tz-side-brand-sub">Healthcare threat-intelligence RAG'
            '<br/>Team Zetabyte</div>',
            unsafe_allow_html=True)
        st.markdown(f'<div style="height:1px;background:{style.LINE};'
                    f'margin:0.9rem 0 1rem 0;"></div>', unsafe_allow_html=True)

        st.markdown('<div class="tz-eyebrow">Analyst</div>',
                    unsafe_allow_html=True)
        analyst_id = st.text_input("Analyst ID", value="analyst-01",
                                   help="Pseudonymous and stable. Never a real name.")
        analyst_role = st.selectbox(
            "Role", ["tier1_soc", "tier2_soc", "threat_intel", "other"], index=1)

        st.markdown('<div class="tz-eyebrow" style="margin:1.3rem 0 0.4rem 0;">'
                    'Queue</div>', unsafe_allow_html=True)
        stats = get_audit_log().stats()
        st.markdown(
            style.side_stat("Queries logged", stats["total_events"])
            + style.side_stat("Awaiting review", stats["unreviewed"])
            + style.side_stat("Rejected or escalated",
                              stats["by_headline"].get("RED", 0)),
            unsafe_allow_html=True)
        st.page_link("pages/1_Audit_Log.py", label="Open the audit log")
    return analyst_id, analyst_role


def _render_query_bar() -> tuple[str, bool]:
    """The query input, with the demonstration set beside it.

    The picker writes into the text box rather than bypassing it, so what runs is
    always exactly what the analyst can see and edit. The labels name the attack
    class each question probes; only the text is passed to `run_query`, so the
    system reaches its verdict knowing what an analyst would have typed and
    nothing else.
    """
    st.markdown('<div class="tz-eyebrow">Security query</div>',
                unsafe_allow_html=True)

    c_input, c_pick = st.columns([2.6, 1])
    with c_pick:
        labels = [CUSTOM] + [f"{label}" for label, _ in DEMO_QUERIES]
        choice = st.selectbox(
            "Demonstration set", labels, label_visibility="collapsed",
            help="Ten benchmark questions covering all six poison families in the "
                 "corpus. Selecting one fills the box; it is still an ordinary "
                 "query and is scored like any other.")
        if choice != CUSTOM and choice != st.session_state.get("_demo_choice"):
            st.session_state["_demo_choice"] = choice
            for label, text in DEMO_QUERIES:
                if label == choice:
                    st.session_state["query_input"] = text
                    break

    with c_input:
        query = st.text_input(
            "Security query", label_visibility="collapsed",
            placeholder="Is CVE-2026-1234 being actively exploited against "
                        "imaging systems?",
            key="query_input")

    col_run, col_clear, _ = st.columns([1, 1, 5])
    with col_run:
        run = st.button("Run query", type="primary", use_container_width=True)
    with col_clear:
        if st.button("Clear", use_container_width=True):
            st.session_state.report = None
            st.session_state.event_id = None
            st.session_state.decision_saved = None
            st.rerun()
    return query, bool(run)


def _score(query: str) -> bool:
    """Run one query. Returns False if it could not be scored.

    Named stages rather than one anonymous spinner. The security layer is the
    slow part and it is slow because it is doing something -- three detectors and
    a pairwise contradiction check over the retrieved evidence -- so the wait
    should say that. An unlabelled wait of even a second or two reads as the
    system being slow; a labelled one reads as the system working, which is the
    truthful reading here.
    """
    with st.status(STAGES["security"], expanded=True) as status:
        try:
            def announce(key: str, label: str) -> None:
                status.update(label=label)
                st.write(label)
                if key == "security":
                    st.caption("Embedding anomaly · prompt injection · "
                               "claim–evidence entailment · pairwise contradiction")

            report, event_id = run_query(query, on_stage=announce)
            status.update(label=STAGES["done"], state="complete", expanded=False)
        except ScoringUnavailable as exc:
            status.update(label="Could not score this query", state="error",
                          expanded=True)
            st.error(f"Could not score this query: {exc}")
            return False

    st.session_state.report = report
    st.session_state.event_id = event_id
    st.session_state.review_started_at = time.time()
    st.session_state.decision_saved = None
    st.session_state.show_override = False
    return True


def _render_empty_state() -> None:
    st.info("No query scored yet. Enter a security query above, or pick one from "
            "the demonstration set, to score it against the corpus.")
    st.markdown(
        f"""
        <div class="tz-panel" style="margin-top:0.9rem;">
          <div class="tz-eyebrow">What this console does</div>
          <div style="font-size:0.85rem;line-height:1.65;color:{style.INK_2};
                      margin-top:0.5rem;">
            Every question is answered from a retrieval corpus that contains
            adversarial documents alongside genuine threat intelligence. Before the
            answer is shown, three detectors run over the retrieved evidence, the
            situation is classified into one of eleven named cases, and the detector
            signals are fused into a calibrated score with a separate confidence
            estimate. The two assessments are reconciled conservatively, and the
            decision is written to a tamper-evident audit trail.
          </div>
          <div style="font-size:0.85rem;line-height:1.65;color:{style.INK_2};
                      margin-top:0.7rem;">
            Retrieval is partition-blind: it ranks by similarity alone and knows
            nothing about which documents are adversarial. Nothing in this console
            reads the ground-truth manifest.
          </div>
        </div>
        """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

def _render_decision_panel(st_mod: Any, report: dict[str, Any],
                           analyst_id: str, analyst_role: str) -> None:
    """Accept / Reject / Override, written back to the audit log.

    Nothing is written until one of these is pressed. Until then the event has no
    row in `analyst_decisions` at all -- not a blank one and not a `PENDING` one --
    which is what makes the table usable as training data later.

    The judgement inputs are rendered **above** the buttons. Streamlit reruns the
    script top to bottom on every interaction, so a button placed above the
    widgets it consumes reads their values from the previous run. It happened to
    work here because the widgets carry session-state keys, but the layout taught
    the wrong order: an analyst saw the actions before the fields those actions
    submit. Inputs first, then the commit.
    """
    st_mod.subheader("Analyst decision")

    saved = st_mod.session_state.get("decision_saved")
    if saved:
        st_mod.success(f"Recorded: **{saved['decision']}** "
                       f"(reference `{saved['decision_id']}`)")
        if st_mod.button("Revise this decision"):
            st_mod.session_state.decision_saved = None
            st_mod.rerun()
        return

    st_mod.caption(
        "This is never filled in by the system. Until you choose, this query has no "
        "decision record at all.")

    verdicts = _per_document_verdicts(st_mod, report)
    confidence = st_mod.slider("Your confidence (optional)", 1, 5, 3)

    c1, c2, c3, _ = st_mod.columns([1, 1, 1, 2])
    with c1:
        accept = st_mod.button("Accept", use_container_width=True,
                               help="The system's recommendation is correct.")
    with c2:
        reject = st_mod.button("Reject", use_container_width=True,
                               help="The content is untrustworthy.")
    with c3:
        override = st_mod.button("Override", use_container_width=True,
                                 help="Disagree with the system's recommendation. "
                                      "Requires an action and a reason code.")

    if override:
        st_mod.session_state.show_override = True

    if accept or reject:
        _save(st_mod, "ACCEPT" if accept else "REJECT", analyst_id, analyst_role,
              verdicts, confidence)
        return

    if st_mod.session_state.get("show_override"):
        st_mod.markdown('<div class="tz-eyebrow" style="margin-top:1rem;">'
                        'Override details — both fields are required</div>',
                        unsafe_allow_html=True)
        action = st_mod.selectbox("What should the action have been?",
                                  ["ACCEPT", "REVIEW", "REJECT", "ESCALATE"])
        code = st_mod.selectbox(
            "Reason code", list(OVERRIDE_REASON_CODES),
            format_func=lambda c: f"{c} — {OVERRIDE_REASON_CODES[c]}")
        text = st_mod.text_area(
            "Notes" + (" (required for OTHER)" if code == "OTHER" else " (optional)"))
        if st_mod.button("Submit override", type="primary"):
            if code == "OTHER" and not text.strip():
                st_mod.error("Reason code OTHER requires a note.")
                return
            _save(st_mod, "OVERRIDE", analyst_id, analyst_role, verdicts, confidence,
                  override_action=action, override_reason_code=code,
                  override_reason_text=text.strip() or None)


def _per_document_verdicts(st_mod: Any, report: dict[str, Any]) -> list[dict[str, Any]]:
    """Optional per-document judgements — the highest-value field in the table.

    Response-level labels are weak supervision; the detectors operate on documents,
    so document-level judgement is what a future retraining pass actually needs.
    """
    with st_mod.expander("Per-document verdicts (optional, most valuable field)"):
        st_mod.caption(
            "Response-level decisions are weak supervision. The detectors work on "
            "documents, so a per-document verdict is what a future recalibration needs.")
        out = []
        for doc in report.get("documents", []) or []:
            verdict = st_mod.radio(
                f"`{doc['doc_id']}` (Tier {doc['source_tier']})",
                ["— skip —", "CLEAN", "POISONED", "UNCERTAIN"],
                horizontal=True, key=f"verdict_{doc['doc_id']}")
            if verdict != "— skip —":
                out.append({"doc_id": doc["doc_id"], "verdict": verdict, "note": ""})
        return out


def _save(st_mod: Any, decision: str, analyst_id: str, analyst_role: str,
          verdicts: list[dict[str, Any]], confidence: int, **kwargs: Any) -> None:
    from logs.audit import DecisionInput  # noqa: PLC0415

    started = st_mod.session_state.get("review_started_at")
    elapsed = int((time.time() - started) * 1000) if started else None
    try:
        decision_id = get_decision_writer().record_decision(
            st_mod.session_state.event_id,
            DecisionInput(
                decision=decision, analyst_id=analyst_id, analyst_role=analyst_role,
                per_document_verdicts=verdicts, analyst_confidence=confidence,
                time_to_decision_ms=elapsed, **kwargs))
    except ValueError as exc:
        st_mod.error(f"Decision refused: {exc}")
        return
    st_mod.session_state.decision_saved = {"decision": decision, "decision_id": decision_id}
    st_mod.rerun()


if __name__ == "__main__":
    main()
