"""
The SOC analyst console.

    streamlit run dashboard/app.py

Page one: ask a question, get a verdict, act on it. Page two: the audit log.

The banner is the first thing rendered on the results view, above everything
else, and that ordering is a requirement rather than a style choice (design
2.9). An analyst working a queue reads the band and stops there when it is
GREEN; the score, the case, the evidence and the reasoning are the detail they
open when it is not -- or when they want to verify a GREEN.

The reading order, and why the decision panel moved
---------------------------------------------------
The results view is now two halves with a rule between them.

The first half is the DECISION: the banner, the verdict in one sentence, the
classification detail, any caveats, what to do next, the case, the two scores,
and then the decision panel itself. An analyst who trusts the verdict can act
without scrolling, which is the normal case in a queue.

The second half is the VERIFICATION: how the layer reached the verdict, the
detector readings, the charts, the reasoning, the evidence document by document,
the indicators and the latency. This is what an analyst opens when they do not
trust the verdict, or when they are the person being shown the system.

The decision panel used to sit at the bottom, after all of that. The layout
therefore asked every analyst to read the verification before they were offered
the decision, which is the wrong default for the common case and, in a demo, put
eight screens between the verdict and the only interactive thing on the page.
There is still exactly ONE place a decision is committed -- a second set of
Accept and Reject buttons higher up would need its own widget keys and would
silently discard the optional per-document verdicts, which are the most valuable
field in the table.

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

from dashboard import glossary, style  # noqa: E402
from dashboard.components import (  # noqa: E402
    render_banner, render_caveats, render_case_and_action,
    render_classification_strip, render_documents, render_entities,
    render_headline_metrics, render_next_steps, render_performance,
    render_reasoning, render_score_analysis, render_signal_overview,
    render_verdict_ladder, render_verdict_sentence,
)
from dashboard import demo_queries  # noqa: E402
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
    _render_nav()

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

    # ---- half one: the decision ----
    render_verdict_sentence(st, report)
    render_classification_strip(st, report)
    # Caveats sit here rather than lower down because every detector in this
    # build may be running on a fallback backend, and an analyst who is about to
    # act on a score needs to know that before they act, not after.
    render_caveats(st, report)
    render_next_steps(st, report)
    render_case_and_action(st, report)
    render_headline_metrics(st, report)

    _render_decision_panel(st, report, analyst_id, analyst_role)

    # ---- half two: the verification ----
    _md(f'<div style="height:1px;background:{style.LINE};'
        f'margin:2.2rem 0 0 0;"></div>')
    st.markdown('<div class="tz-eyebrow" style="margin:1.1rem 0 0.2rem 0;">'
                'Verification — the evidence behind the verdict</div>',
                unsafe_allow_html=True)
    st.caption(
        "Everything below this line is the working. An analyst who accepts the "
        "verdict does not need it; an analyst who doubts it, or anyone being "
        "shown how the layer decides, starts here.")

    render_verdict_ladder(st, report)
    render_signal_overview(st, report)
    render_score_analysis(st, report)
    render_reasoning(st, report)
    render_documents(st, report)
    render_entities(st, report)
    render_performance(st, report)

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

def _md(html: str) -> None:
    st.markdown(html, unsafe_allow_html=True)


def _render_nav() -> None:
    """Page navigation in the body, not only in the sidebar.

    The sidebar can be collapsed, and when it is, anything reachable only from
    there is gone until the page is reloaded. The audit log is half of this
    product -- it is where a reviewer confirms that a decision was recorded and
    that the chain still verifies -- so it gets a route that does not depend on
    a panel being open.
    """
    c1, c2, _ = st.columns([1, 1, 5])
    with c1:
        st.page_link("app.py", label="Console")
    with c2:
        st.page_link("pages/1_Audit_Log.py", label="Audit log")


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
        st.markdown('<div class="tz-eyebrow" style="margin:1.3rem 0 0.4rem 0;">'
                    'Pages</div>', unsafe_allow_html=True)
        st.page_link("app.py", label="Console")
        st.page_link("pages/1_Audit_Log.py", label="Audit log")
    return analyst_id, analyst_role


def _render_query_bar() -> tuple[str, bool]:
    """The query input, with the demonstration set beside it.

    The picker writes into the text box rather than bypassing it, so what runs is
    always exactly what the analyst can see and edit. The labels name the attack
    class each question probes; only the text is passed to `run_query`, so the
    system reaches its verdict knowing what an analyst would have typed and
    nothing else.
    """
    st.markdown('<div class="tz-eyebrow">Ask a security question</div>',
                unsafe_allow_html=True)

    c_input, c_pick = st.columns([2.6, 1])
    with c_pick:
        # Grouped by attack family, with the family name carried in the option
        # label rather than in a section header. Streamlit's selectbox has no
        # option-group concept, and the two alternatives were both worse: a
        # second selectbox for the family costs a click on every demonstration,
        # and an expander here would render above the banner, which the ordering
        # requirement forbids and `test_dashboard.py` checks.
        labels = [CUSTOM]
        for _family, items in demo_queries.by_family():
            labels += [label for label, _ in items]

        def _label(option: str) -> str:
            if option == CUSTOM:
                return option
            family = demo_queries.family_of(option)
            return f"{family} · {option}" if family else option

        choice = st.selectbox(
            "Demonstration set", labels, label_visibility="collapsed",
            format_func=_label,
            help="Ten benchmark questions covering all six poison families in the "
                 "corpus, grouped by attack family. Selecting one fills the box; "
                 "it is still an ordinary query and is scored like any other.")
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

    # What the selected scenario is testing, stated before it runs. The line
    # describes the adversary's technique only -- never the verdict, never which
    # document is hostile. Those live in the ground-truth manifest, which no part
    # of this console may read.
    probes = demo_queries.probes(choice) if choice != CUSTOM else ""
    if probes:
        st.caption(f"**What this scenario probes:** {probes}")

    col_run, col_clear, _ = st.columns([1, 1, 5])
    with col_run:
        run = st.button("Run security check", type="primary",
                        use_container_width=True)
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
    """The landing page: what the product is, before any query has been run.

    This is the first screen a panel sees, and the old version of it opened by
    describing the console. That framing is wrong in a way that matters: the
    console is a REFERENCE CLIENT, and the deliverable is the layer behind it --
    a pipeline-agnostic gateway that sits between retrieval and answer delivery
    in any healthcare RAG system, in the position a web application firewall
    occupies in front of a web app. So the page now leads with the layer, states
    the safety property it is built around, walks the four stages, and only then
    offers the scenarios.

    Expanders are used freely here. They are forbidden above the banner on the
    results view, but there is no banner on this view -- `report is None` is
    exactly the branch that returns before one is rendered.
    """
    st.info("Nothing scored yet. Ask a question above, or pick one of the ten "
            "benchmark scenarios, to run it against the poisoned corpus.")

    _md(style.hero(glossary.WHAT_THIS_IS_TITLE, glossary.WHAT_THIS_IS,
                   glossary.SAFETY_CLAIM))

    st.markdown('<div class="tz-eyebrow" style="margin:1.5rem 0 0 0;">'
                'How a question becomes a verdict</div>', unsafe_allow_html=True)
    _md(style.flow(glossary.HOW_IT_WORKS))

    st.markdown('<div class="tz-eyebrow" style="margin:1.6rem 0 0.3rem 0;">'
                'What the four detectors look for</div>', unsafe_allow_html=True)
    _md(style.detector_legend([
        (spec["name"], spec["field"], spec["what"])
        for spec in glossary.DETECTOR.values()]))
    _md(f'<div style="margin-top:0.55rem;">'
        f'{style.note("<strong>Reading direction.</strong> " + glossary.DETECTOR_DIRECTION)}'
        f'</div>')

    st.markdown('<div class="tz-eyebrow" style="margin:1.7rem 0 0.3rem 0;">'
                'The benchmark scenarios</div>', unsafe_allow_html=True)
    st.caption(glossary.GROUND_TRUTH_NOTE)
    for family, items in demo_queries.by_family():
        with st.expander(f"{family} — {len(items)} scenario(s)"):
            note = demo_queries.FAMILY_NOTE.get(family, "")
            if note:
                st.caption(note)
            for label, text in items:
                _md(f'<div style="margin:0.55rem 0 0.75rem 0;padding-left:0.7rem;'
                    f'border-left:2px solid {style.LINE};">'
                    f'<div style="font-size:0.82rem;font-weight:650;'
                    f'color:{style.INK};">{label}</div>'
                    f'<div style="font-size:0.79rem;line-height:1.55;'
                    f'color:{style.INK_2};margin-top:0.22rem;">"{text}"</div>'
                    f'<div style="font-size:0.75rem;line-height:1.5;'
                    f'color:{style.INK_3};margin-top:0.25rem;">'
                    f'Probes: {demo_queries.probes(label)}</div></div>')

    st.markdown('<div class="tz-eyebrow" style="margin:1.7rem 0 0.3rem 0;">'
                'The eleven cases the layer can reach</div>',
                unsafe_allow_html=True)
    st.caption(
        "Detector outcome crossed with source trust tier, under a fixed "
        "precedence order. The case carries the action — which is what makes the "
        "safety property a rule rather than a threshold on a score.")
    with st.expander("Open the case reference"):
        for case_id, copy in glossary.CASE_COPY.items():
            view = glossary.case_view(case_id)
            _md(f'<div style="margin-bottom:0.85rem;padding-left:0.7rem;'
                f'border-left:2px solid {style.LINE};">'
                f'<div style="font-size:0.83rem;font-weight:650;color:{style.INK};">'
                f'{copy["title"]}</div>'
                f'<div style="font-family:{style.MONO};font-size:0.68rem;'
                f'color:{style.INK_3};margin-top:0.1rem;">{view["case_id"]} — '
                f'{view["formal_name"]} · {view["priority"]} · '
                f'{view["action"]}</div>'
                f'<div style="font-size:0.78rem;line-height:1.55;'
                f'color:{style.INK_2};margin-top:0.3rem;">{copy["plain"]}</div>'
                f'<div style="font-size:0.75rem;line-height:1.5;'
                f'color:{style.INK_3};margin-top:0.25rem;">'
                f'{copy["distinct"]}</div></div>')


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
    action = str(report.get("recommended_action", "—"))
    st_mod.subheader("Your decision")

    saved = st_mod.session_state.get("decision_saved")
    if saved:
        st_mod.success(f"Recorded: **{saved['decision']}** "
                       f"(reference `{saved['decision_id']}`)")
        if st_mod.button("Revise this decision"):
            st_mod.session_state.decision_saved = None
            st_mod.rerun()
        return

    # The recommendation is restated here, in the plain form, because this is the
    # moment the analyst is agreeing or disagreeing with it -- and by this point
    # the banner may have scrolled off the top of the screen.
    st_mod.markdown(style.band_panel(
        report.get("headline", "ORANGE"),
        f'<div style="font-size:0.86rem;line-height:1.6;color:{style.INK_2};">'
        f'The layer recommends <strong style="color:{style.INK};">{action}</strong>'
        f' — {glossary.ACTION_SHORT.get(action, "")}. '
        f'Agreeing records that; disagreeing records an override with a reason '
        f'code, which is what a future recalibration learns from.</div>'),
        unsafe_allow_html=True)

    st_mod.caption(
        "The system never fills this in. Until you choose, this query has no "
        "decision record at all — not a blank one and not a pending one.")

    verdicts = _per_document_verdicts(st_mod, report)
    confidence = st_mod.slider(
        "How sure are you? (optional — 1 is a guess, 5 is certain)", 1, 5, 3)

    c1, c2, c3, _ = st_mod.columns([1, 1, 1, 2])
    with c1:
        accept = st_mod.button(f"Agree — {action}", use_container_width=True,
                               help="The layer's recommendation is correct. "
                                    "Recorded as ACCEPT.")
    with c2:
        reject = st_mod.button("Reject the content", use_container_width=True,
                               help="The retrieved material is untrustworthy, "
                                    "whatever the layer recommended. Recorded as "
                                    "REJECT.")
    with c3:
        override = st_mod.button("Disagree — override", use_container_width=True,
                                 help="You would have taken a different action. "
                                      "Requires the action you would have taken "
                                      "and a reason code.")

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
        override_action = st_mod.selectbox(
            "What should the action have been?",
            ["ACCEPT", "REVIEW", "REJECT", "ESCALATE"],
            format_func=lambda a: f"{a} — {glossary.ACTION_SHORT.get(a, '')}")
        st_mod.caption(glossary.ACTION_SENTENCE.get(override_action, ""))
        code = st_mod.selectbox(
            "Why? (this is the field a future recalibration learns from)",
            list(OVERRIDE_REASON_CODES),
            format_func=lambda c: f"{c} — {OVERRIDE_REASON_CODES[c]}")
        text = st_mod.text_area(
            "Notes" + (" (required for OTHER)" if code == "OTHER" else " (optional)"))
        if st_mod.button("Submit override", type="primary"):
            if code == "OTHER" and not text.strip():
                st_mod.error("Reason code OTHER requires a note.")
                return
            _save(st_mod, "OVERRIDE", analyst_id, analyst_role, verdicts, confidence,
                  override_action=override_action, override_reason_code=code,
                  override_reason_text=text.strip() or None)


def _per_document_verdicts(st_mod: Any, report: dict[str, Any]) -> list[dict[str, Any]]:
    """Optional per-document judgements — the highest-value field in the table.

    Response-level labels are weak supervision; the detectors operate on documents,
    so document-level judgement is what a future retraining pass actually needs.
    """
    with st_mod.expander("Judge each document individually (optional — the most "
                         "valuable thing you can record here)"):
        st_mod.caption(
            "A single verdict on the whole answer is weak supervision. The "
            "detectors work document by document, so a per-document judgement is "
            "what a future recalibration can actually learn from. Skip any you "
            "are unsure about.")
        out = []
        for doc in report.get("documents", []) or []:
            verdict = st_mod.radio(
                f"`{doc['doc_id']}` — Tier {doc['source_tier']}, "
                f"rank {doc.get('rank', '?')}",
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
