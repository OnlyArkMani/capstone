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
the scoring logic, and the two drift -- which the report generator's own tests
already caught once.

Presentation
------------
Colours, spacing and the HTML builders live in `dashboard/style.py`; charts live
in `dashboard/charts.py`. This module decides *what* is shown and in what order,
and asks those two for the markup. The stylesheet is injected once by the page
file, never from here -- a stylesheet emitted from `render_banner` would become
the banner's first recorded call and the ordering requirement above would stop
being tested.

Three properties of the visual language are load-bearing rather than decorative:

*State is never colour alone.* Every band, every fired detector and every tier
carries a mark or a word beside its colour, because a colourblind reviewer, a
washed-out projector and a greyscale printout each delete the colour channel and
the verdict still has to arrive.

*Absence is not zero.* A detector that did not run, or could not be calibrated,
is drawn as text rather than as an empty bar. A bar at zero says "we measured
this and it was clean"; that is the opposite of what an uncalibrated detector
means, and the distinction is the whole point of the `unusable` status.

*Nothing is an emoji.* The marks in this interface are typographic or drawn in
CSS. Emoji render differently on every platform, carry a colour that the state
palette did not choose, and read as decoration in a tool whose entire job is to
be believed.

Plain language, and why the internal tokens survive underneath it
-----------------------------------------------------------------
The results view carries five severity encodings at once: the verdict band, the
recommended action, the case id, the case priority and the risk tier. They are
consistent by construction -- the band is derived from the action and the tier,
the risk tier from the priority and the action, the priority from the case -- but
an analyst does not know that, and five tokens with no stated relationship read
as five independent judgements.

None of them are removed. The audit trail, the evaluation harness and the
override vocabulary all key on those exact strings, and an interface that renamed
them would put a translation layer between what a reviewer sees on screen and
what the database stores. They are DEMOTED instead: `render_verdict_sentence`
carries the verdict in one line of English, and `render_classification_strip`
puts the tokens underneath it as labelled detail, each beside the explanation
that previously existed only in a source-file docstring.

All of that wording lives in `dashboard/glossary.py`, which imports the case
definitions from `fusion.cases` rather than restating them -- so a case whose
priority or action changes upstream cannot end up described one way by the scorer
and another way by the screen.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dashboard import charts, glossary, style  # noqa: E402

# Kept as a module-level mapping because the audit-log page and the tests both
# import it. `bg` is the banner fill; the accent step for lines, dots and bars
# against the dark surface lives beside it in `style.BAND`.
#
# The labels are dispositions, not encouragement. "GOOD TO GO" told an analyst
# how to feel about a result; "CLEARED FOR ANALYST USE" tells them what the
# system has actually authorised, which is the sentence they would have to
# defend afterwards.
BAND_STYLE: dict[str, dict[str, str]] = {
    "GREEN": {"bg": style.BAND["GREEN"]["bg"], "fg": "#FFFFFF", "icon": "✓",
              "label": "CLEARED FOR ANALYST USE"},
    "ORANGE": {"bg": style.BAND["ORANGE"]["bg"], "fg": "#FFFFFF", "icon": "!",
               "label": "REVIEW REQUIRED BEFORE USE"},
    "RED": {"bg": style.BAND["RED"]["bg"], "fg": "#FFFFFF", "icon": "✕",
            "label": "REJECTED — DO NOT ACT ON THIS ANSWER"},
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

#: The report's field name for each signal. Kept, and still shown in the numeric
#: table under every document, because it is the string somebody quoting a score
#: in a write-up has to be able to find. It is no longer what labels the meter:
#: `injection_probability` told an analyst which variable held the number, not
#: what the detector was looking for, and only one of those is useful at a
#: glance. The plain names come from `glossary.DETECTOR`.
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


def _eyebrow(st: Any, text: str, top: str = "1.5rem") -> None:
    """A section label. Used instead of `st.subheader` where the heading would
    otherwise be louder than the figure underneath it."""
    _md(st, f'<div class="tz-eyebrow" style="margin:{top} 0 0.5rem 0;">{text}</div>')


# ---------------------------------------------------------------------------
# The banner — always first
# ---------------------------------------------------------------------------

def render_banner(st: Any, report: dict[str, Any]) -> None:
    """The full-width verdict bar. **Must be the first thing on the page.**

    Sized so that the band is legible from across a room and cannot be mistaken
    for a heading. When the band is RED the sub-type sits directly underneath,
    because an analyst scanning red flags needs to tell an ordinary attack from a
    suspected source compromise without opening anything.

    The right-hand figures are here rather than only in the metric row below
    because the banner is what somebody photographs, and a verdict with no
    disposition beside it is the half of the answer that does not tell anyone
    what to do next.

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
            f'<div class="tz-banner-subtype" style="font-size:1.05rem;'
            f'font-weight:600;">{SUBTYPE_LABEL.get(subtype, subtype)}</div>')

    # The Action figure now carries the plain reading under the token rather than
    # the token alone. "ESCALATE" is what the system decided; "Report to threat
    # intel" is what it means for the person reading the banner, and the banner
    # is the part somebody photographs.
    action = str(report.get("recommended_action", "—"))
    figures = [
        ("Action", action, glossary.ACTION_SHORT.get(action, "")),
        ("Case", str(report.get("case_id", "—")),
         glossary.case_view(report.get("case_id")).get("title", "")),
        ("Priority", str(report.get("priority", "—")),
         str(report.get("risk_tier", ""))),
    ]
    figs_html = "".join(
        f'<div class="tz-banner-fig"><span class="k">{k}</span>'
        f'<span class="v">{v}</span>'
        + (f'<span class="k" style="text-transform:none;letter-spacing:0.01em;'
           f'font-size:0.63rem;opacity:0.82;max-width:11rem;margin-left:auto;">'
           f'{w}</span>' if w else "")
        + '</div>'
        for k, v, w in figures)

    _md(st, f"""
        <div class="tz-banner" style="background:{style_['bg']};
                    color:{style_['fg']};border-radius:4px;
                    box-shadow:0 0 0 1px {style.band_accent(band)}55,
                               0 6px 26px -8px {style.band_glow(band)};">
          <div>
            <div class="tz-banner-eyebrow">System verdict</div>
            <div style="font-size:3.5rem;font-weight:700;line-height:1.02;
                        letter-spacing:0.01em;">
              {style_['icon']}&nbsp;{band}
            </div>
            <div class="tz-banner-sub">{style_['label']}</div>
            {sub_html}
          </div>
          <div class="tz-banner-side">{figs_html}</div>
        </div>
        """)

    if band == "RED" and subtype:
        st.caption(SUBTYPE_HINT.get(subtype, ""))


def render_verdict_sentence(st: Any, report: dict[str, Any]) -> None:
    """The verdict in one line of English, directly under the banner.

    This is the sentence the page is built around. The band above it is a colour
    and a word; this says what it means for the person in front of it, in the
    second person, with the imperative where there is something to do. When the
    band is RED the sub-type sentence follows, because "quarantine a document"
    and "a source we trusted is compromised" are different jobs for different
    people and the distinction has to arrive without an expander being opened.
    """
    band = report.get("headline", "ORANGE")
    subtype = report.get("headline_subtype")
    sentence = glossary.BAND_SENTENCE.get(band, glossary.BAND_SENTENCE["ORANGE"])
    sub = glossary.SUBTYPE_SENTENCE.get(subtype or "", "") if band == "RED" else ""
    _md(st, style.verdict_sentence(band, sentence, sub))


def render_classification_strip(st: Any, report: dict[str, Any]) -> None:
    """The five internal tokens, demoted to labelled detail with explanations.

    Every cell is topped with the same band accent, so the strip reads as one
    object describing one verdict. That is the whole point: these five were
    previously scattered across the banner and two metric rows, and a reader who
    cannot see that they are derived from one another reasonably assumes they are
    five separate judgements that happen to agree.
    """
    band = report.get("headline", "ORANGE")
    case = glossary.case_view(report.get("case_id"))
    action = str(report.get("recommended_action", "—"))
    priority = str(report.get("priority", "—"))
    risk = str(report.get("risk_tier", "—"))

    cells = [
        ("Verdict band", str(band),
         "The three-state summary. Derived from the action and the source tier, "
         "so it can never disagree with them."),
        ("What the system did", action, glossary.ACTION_SENTENCE.get(action, "")),
        ("Case", case["case_id"], case["title"]),
        ("Queue priority", priority, glossary.PRIORITY_MEANING.get(priority, "")),
        ("Risk tier", risk, glossary.RISK_TIER_MEANING.get(risk, "")),
    ]
    _md(st, style.detail_strip(cells, style.band_accent(band)))
    st.caption(
        "These five are not five separate judgements. The case comes from the "
        "detector outcome crossed with the source tier; the action and the "
        "priority come from the case; the verdict band comes from the action and "
        "the tier; the risk tier is the more severe of the priority and the "
        "floor the action puts under it.")


def render_next_steps(st: Any, report: dict[str, Any]) -> None:
    """What to do about it, as an ordered checklist.

    Assembled in `glossary.next_steps` from the final action plus the documents
    this report already flagged. Nothing in it is derived from a score, and no
    step names a fact the report does not carry -- a checklist that invented a
    document id would be the most damaging possible failure on this page.
    """
    band = report.get("headline", "ORANGE")
    steps = glossary.next_steps(report)
    if not steps:
        return
    _md(st, style.band_panel(
        band,
        '<div class="tz-eyebrow">What to do next</div>'
        '<div style="margin-top:0.55rem;">' + style.steps_list(steps) + '</div>',
        extra="margin-top:0.6rem;"))


def render_verdict_ladder(st: Any, report: dict[str, Any]) -> None:
    """Query to verdict, one rung per decision the layer took.

    The most useful single block on the page for somebody being shown the system
    rather than using it: it walks retrieval, detection, provenance weighting,
    classification and action in order, and each rung names the report field it
    came from. Placed above the charts because it is the explanation the charts
    are evidence for, not the other way round.
    """
    rungs = glossary.verdict_ladder(report)
    if not rungs:
        return
    _eyebrow(st, "How the layer reached this verdict", top="1.5rem")
    _md(st, f'<div class="tz-panel" style="border-left:3px solid '
            f'{style.band_accent(report.get("headline", "ORANGE"))};">'
            + style.ladder(rungs) + '</div>')


def render_headline_metrics(st: Any, report: dict[str, Any]) -> None:
    """The two headline figures, each with its grade, direction and scale note.

    Three things changed here and each fixed a specific misreading.

    **Both figures are percentages.** The report stores confidence as a 0-1
    fraction, and the console used to print it as `0.62` in a tile next to
    `73.4%`. Two scales in adjacent tiles invited the reading that one of them
    was out of ten; worse, it made the two look like different kinds of quantity
    when they are both "how much of the way to certain".

    **Each figure carries a word.** `62%` does not tell a first-time reader
    whether that is a normal number for this system. "Moderate", with the
    sentence that follows it, does. The bands are REPORTING bands for saying the
    number out loud, in the same sense as the zones on the trust dial -- not
    decision thresholds, and the scale note says so, because an audience shown a
    number and a colour will otherwise assume the number was the mechanism. On
    this system it is not: the rule-based case taxonomy is.

    **The direction is on the card.** The trust score rises toward safe and the
    four detector readings rise toward dangerous. A reader who carries one
    convention onto the other inverts the whole page, so each card states which
    way it runs in 10px type rather than relying on a caption further down.

    The 95% interval stays drawn to scale inside the trust card -- how *wide* it
    is changes what an analyst should do with the number, and a pair of decimals
    does not communicate width.
    """
    trust = report.get("trust_percent")
    lo, hi = (report.get("trust_interval") or [None, None])[:2]
    band = report.get("headline", "ORANGE")

    confidence = report.get("confidence")
    # The single place a 0-1 fraction becomes a percentage, kept at the call site
    # so it is visible rather than buried in a formatter.
    conf_pct = None if confidence is None else float(confidence) * 100.0

    trust_word, trust_meaning = glossary.trust_grade(trust)
    conf_word, conf_meaning = glossary.confidence_grade(conf_pct)

    c1, c2, c3 = st.columns([1.4, 1.25, 1])
    with c1:
        _md(c1, style.score_card(
            "Trust in this answer",
            "not computed" if trust is None else f"{trust:.1f}%",
            trust_word, trust_meaning,
            style.band_accent(band),
            direction="higher is safer",
            scale_note=glossary.TRUST_SCALE_NOTE,
            extra_html=(style.interval(trust, lo, hi)
                        + (f'<div class="tz-score-scale" style="border:0;'
                           f'padding-top:0.25rem;">{glossary.INTERVAL_NOTE}</div>'
                           if trust is not None and lo is not None else ""))))
    with c2:
        _md(c2, style.score_card(
            "How much that score is worth",
            "n/a" if conf_pct is None else f"{conf_pct:.0f}%",
            conf_word, conf_meaning,
            style.INFO,
            direction="higher is firmer",
            scale_note=glossary.CONFIDENCE_SCALE_NOTE))
    with c3:
        # Kept as an `st.metric` rather than a third card. It is a queue label
        # rather than a measurement -- it has no scale, no interval and no
        # direction to explain -- and giving it the same furniture as the two
        # figures beside it would have implied it was one.
        st.metric("Queue severity", report.get("risk_tier", "—"),
                  help="Where this sorts in the analyst queue. The more severe of "
                       "the case priority and the floor the final action puts "
                       "under it — never the more comfortable of the two.")
        st.caption(glossary.RISK_TIER_MEANING.get(
            str(report.get("risk_tier", "")), ""))

    _md(st, f"<div style='height:2px;background:{style.band_accent(band)};"
            f"opacity:0.5;border-radius:1px;margin:0.55rem 0 0 0;'></div>")


def render_case_and_action(st: Any, report: dict[str, Any]) -> None:
    """The case, led by what it means rather than by what it is called.

    The plain title is the heading and the formal name sits underneath it as the
    record. That inversion is the point: `C6 — Open-Feed Irregularity` is precise
    and tells a first-time reader nothing, while "Irregular content from an open
    feed" tells them the situation and costs the same space.

    The `distinct` line is the part a taxonomy of eleven cases most needs and
    least often states -- what separates this case from the one beside it. It is
    what answers the question a panel always asks about C4: why a *suspicious*
    Tier-1 document outranks an outright *malicious* Tier-3 one.
    """
    band = report.get("headline", "ORANGE")
    action = str(report.get("recommended_action", "—"))
    case = glossary.case_view(report.get("case_id"))
    accent = style.band_accent(band)

    distinct = (f'<div style="font-size:0.8rem;line-height:1.6;'
                f'color:{style.INK_3};margin-top:0.45rem;padding-top:0.45rem;'
                f'border-top:1px solid {style.LINE_SOFT};">'
                f'<strong style="color:{style.INK_2};">What makes this case '
                f'different:</strong> {case["distinct"]}</div>'
                ) if case["distinct"] else ""

    _md(st, style.band_panel(band, f"""
          <div class="tz-eyebrow">What kind of situation this is</div>
          <div style="font-size:1.02rem;font-weight:650;margin:0.3rem 0 0.15rem 0;
                      color:{style.INK};">
            {case['title']}
          </div>
          <div style="font-family:{style.MONO};font-size:0.7rem;
                      color:{style.INK_3};letter-spacing:0.04em;">
            {report.get('case_id', '—')} — {report.get('case_name', '')}
          </div>
          <div style="font-size:0.85rem;line-height:1.6;color:{style.INK_2};
                      margin-top:0.5rem;">{case['plain']}</div>
          <div style="display:flex;align-items:center;gap:0.6rem;flex-wrap:wrap;
                      margin-top:0.6rem;">
            {style.chip(action, accent)}
            <span style="font-size:0.78rem;color:{style.INK_2};">
              {glossary.ACTION_SHORT.get(action, '')}</span>
            <span style="font-size:0.72rem;color:{style.INK_3};
                         font-family:{style.MONO};">
              recommended action · {report.get('priority', '')}</span>
          </div>
          {distinct}""", extra="margin-top:0.6rem;"))

    if report.get("action_meaning"):
        st.caption(report["action_meaning"])


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def render_signal_overview(st: Any, report: dict[str, Any]) -> None:
    """The detector grid and the retrieval profile, side by side.

    These two answer the question the architecture exists to answer -- *which
    document tripped which detector, and was it a source we trusted* -- in one
    screen, before any expander is opened. Everything below this point is the
    detail behind these two pictures.
    """
    docs = report.get("documents", []) or []
    if not docs:
        return

    _eyebrow(st, "What the four detectors looked for", top="1.5rem")
    _md(st, style.detector_legend([
        (spec["name"], spec["field"], spec["what"])
        for spec in glossary.DETECTOR.values()]))
    _md(st, f'<div style="margin-top:0.55rem;">'
            f'{style.note("<strong>Reading direction.</strong> " + glossary.DETECTOR_DIRECTION)}'
            f'</div>')

    _eyebrow(st, "Which document tripped which detector", top="1.4rem")
    matrix = charts.signal_matrix(docs)
    if matrix:
        charts.render(st, matrix, height=max(150, 42 * len(docs) + 70))
        st.caption(
            "Colour is the status band, not the value — the four detectors have "
            "different thresholds, so equal colours would not mean equal severity. "
            "The number in each cell is the reading itself.")

    c1, c2 = st.columns(2)
    with c1:
        _eyebrow(c1, "Retrieval profile", top="1.1rem")
        profile = charts.evidence_profile(docs)
        if profile:
            charts.render(c1, profile, height=max(140, 38 * len(docs) + 60))
            c1.caption("Retrieval is partition-blind: it ranks by similarity alone "
                       "and knows nothing about provenance. A Tier 3 bar at the top "
                       "is the attack this system is built to catch.")
    with c2:
        _eyebrow(c2, "Distance to the suspicious threshold", top="1.1rem")
        margins = charts.threshold_distance(docs)
        if margins:
            charts.render(c2, margins, height=max(140, 38 * len(docs) + 60))
            c2.caption("Plotted as a margin rather than a raw score, so one axis is "
                       "meaningful for all four detectors. Left of the dashed line "
                       "is under threshold.")
        else:
            c2.caption("No detector produced a calibrated reading for this query, so "
                       "there is no margin to plot. That is not a clean result.")


def render_score_analysis(st: Any, report: dict[str, Any]) -> None:
    """What the composite score rests on: the interval, and confidence's parts."""
    trust = report.get("trust_percent")
    lo, hi = (report.get("trust_interval") or [None, None])[:2]
    components = report.get("confidence_components") or {}

    c1, c2 = st.columns([1.1, 1])
    with c1:
        _eyebrow(c1, "Trust score on a fixed 0–100 scale", top="1.4rem")
        dial = charts.trust_dial(trust, lo, hi)
        if dial:
            charts.render(c1, dial, height=120)
            c1.caption("Axis fixed at 0–100 so that interval width is comparable "
                       "between queries. The zones are the reporting bands, not "
                       "decision thresholds — the case taxonomy decides the action.")
        else:
            c1.caption("No composite score was computed for this query.")
    with c2:
        _eyebrow(c2, "Why the confidence figure landed where it did", top="1.4rem")
        # Relabelled here rather than in `charts`, which takes a plain mapping and
        # has no business knowing what the keys are called in front of an analyst.
        # The confidence figure is a geometric mean, so the lowest bar is the one
        # holding the whole number down -- naming it is more useful than the
        # composite, which is the reason this chart exists at all.
        labelled = {
            glossary.CONFIDENCE_COMPONENT.get(k, k.replace("_", " ")): v
            for k, v in components.items()}
        comp = charts.confidence_components(labelled)
        if comp:
            charts.render(c2, comp, height=max(130, 30 * len(labelled) + 48))
            c2.caption(
                "Each bar runs 0 to 1. These are combined by a geometric mean, so "
                "the shortest bar is the one holding the figure down — a run held "
                "back by how much evidence there was needs a different response "
                "from one held back by the sources disagreeing.")
            caps = report.get("confidence_caps") or []
            if caps:
                c2.caption("A hard cap was applied: " + ", ".join(str(c) for c in caps))
        else:
            c2.caption("No confidence components were reported for this query.")


def render_performance(st: Any, report: dict[str, Any]) -> None:
    """Wall-clock cost of the security layer, by stage."""
    timings = (report.get("provenance") or {}).get("timings_ms") or {}
    spec = charts.stage_latency(timings)
    if not spec:
        return
    _eyebrow(st, "Where the time went", top="1.4rem")
    charts.render(st, spec, height=110)
    total = timings.get("total")
    if total is not None:
        st.caption(f"Total {float(total):.0f} ms end to end, retrieval through audit "
                   f"write. The cost of the security layer is a fair question to ask "
                   f"of it; this is the answer for this query.")


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
    st.caption(
        "One row per document the retriever returned, in rank order. A row "
        "marked `[MAL]` or `[SUS]` opens by default; the rest stay closed. "
        "Trust tier is provenance, not severity — T1 is a source we verify "
        "ourselves, T3 is one we do not.")

    for doc in docs:
        band = doc.get("headline", "ORANGE")
        readings = doc.get("readings", []) or []
        fired = [r for r in readings
                 if r.get("status") in ("over_malicious", "over_suspicious")]
        flag = f"  ·  {len(fired)} signal(s) fired" if fired else ""
        # `[MAL]` rather than a coloured dot: this row is the one place the
        # colour channel is least dependable -- it is a widget label, it is what
        # a projector washes out first, and it is what somebody screenshots in
        # greyscale -- so the state is carried as a word that always renders.
        title = (f"`[{style.band_code(band)}]`  {doc['rank']}  `{doc['doc_id']}`  ·  "
                 f"T{doc['source_tier']}  ·  sim {_fmt(doc.get('similarity'), 3)}{flag}")

        with st.expander(title, expanded=bool(fired)):
            _md(st, f"""
                <div style="display:flex;align-items:center;gap:0.5rem;
                            flex-wrap:wrap;margin:0.3rem 0 0.7rem 0;">
                  {style.band_chip(band)}
                  {style.tier_badge(doc.get('source_tier'),
                                    doc.get('source_tier_label', ''))}
                  {style.chip(str(doc.get('action', '')), style.INK_2)}
                </div>
                <div style="font-size:0.92rem;font-weight:600;margin-bottom:0.3rem;">
                  {doc.get('title', '')}</div>""")

            doc_case = glossary.case_view(doc.get("case_id"))
            doc_action = str(doc.get("action", ""))
            _md(st, style.kv([
                ("Source", f"{doc.get('source_name', '')} "
                           f"({doc.get('source_id', '')})"),
                ("Trust tier", f"Tier {doc.get('source_tier')} — "
                               f"{doc.get('source_tier_label', '')}"),
                ("Situation", f"{doc_case['title']}<br/>"
                              f"<span style='font-family:{style.MONO};"
                              f"font-size:0.7rem;color:{style.INK_3};'>"
                              f"{doc.get('case_id')} {doc.get('case_name', '')}</span>"),
                ("Action", f"{doc_action} — "
                           f"{glossary.ACTION_SHORT.get(doc_action, '')} "
                           f"<span style='font-family:{style.MONO};"
                           f"font-size:0.7rem;color:{style.INK_3};'>"
                           f"({doc.get('priority')})</span>"),
            ]))

            _eyebrow(st, "Detector readings — higher is worse", top="1rem")
            for r in readings:
                # The meter is labelled with what the detector looks for; the
                # numeric table below carries the report's field name. The bar is
                # the glance, the table is the record, and they need different
                # labels for that split to work.
                _md(st, style.meter(
                    glossary.detector_name(str(r["signal"])),
                    r.get("value"), r.get("suspicious_threshold"),
                    r.get("malicious_threshold"), str(r.get("status", ""))))
                # Only the readings that are NOT a plain sub-threshold
                # measurement get a sentence. Printing "measured, and came in
                # under the line" under all four of a clean document's meters
                # said the same thing four times and buried the one reading that
                # did have something to say; the shared case is stated once,
                # below, instead.
                if str(r.get("status", "")) != "below":
                    status_sentence = glossary.STATUS_SENTENCE.get(
                        str(r.get("status", "")), "")
                    if status_sentence:
                        st.caption(status_sentence)

            if any(str(r.get("status", "")) == "below" for r in readings):
                st.caption(glossary.STATUS_SENTENCE["below"])

            rows = []
            for r in readings:
                status = str(r.get("status", ""))
                # Both names in one cell rather than two columns. The field name
                # has to be here -- it is what somebody quoting a score in a
                # write-up needs -- but a sixth column pushed this table into a
                # horizontal scroll at ordinary widths, and a table that scrolls
                # sideways is one an analyst stops reading.
                rows.append({
                    "Detector": (glossary.detector_name(str(r["signal"]))
                                 + f"  ({SIGNAL_DISPLAY.get(r['signal'], r['signal'])})"),
                    "Score": _fmt(r.get("value")),
                    "Suspicious at": _fmt(r.get("suspicious_threshold")),
                    "Malicious at": _fmt(r.get("malicious_threshold")),
                    "Status": ("FIRED" if status in
                               ("over_malicious", "over_suspicious") else status),
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
    st.subheader("Reasoning, in the system's own words")
    st.caption(
        "Assembled from fixed sentence templates with figures substituted from "
        "this report. No language model wrote any of it, which is why every "
        "number in it can be traced to a field.")
    reasoning = report.get("reasoning", {}) or {}
    sentences = reasoning.get("sentences", []) or []
    if sentences:
        items = "".join(
            f'<li style="margin-bottom:0.4rem;">{s["text"]}</li>' for s in sentences)
        _md(st, f'<div class="tz-panel"><ul style="margin:0;padding-left:1.1rem;'
                f'font-size:0.87rem;line-height:1.6;">{items}</ul></div>')
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
        st.warning(caveat)


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
        confidence = e.get("confidence")
        case = glossary.case_view(e.get("case_id"))
        out.append({
            "Class": display,
            "Case": f"{e.get('case_id', '')} {e.get('case_name', '') or ''}".strip(),
            "Situation": case["title"],
            "Trust %": "—" if trust is None else f"{trust:.1f}",
            # Shown as a percentage here for the same reason as on the results
            # view: a column of 0.49 beside a column of 93.5 reads as two
            # different kinds of quantity when it is the same kind twice.
            "Confidence %": ("—" if confidence is None
                             else f"{float(confidence) * 100:.0f}"),
            "Action": e.get("final_action", ""),
            "Analyst decision": e.get("analyst_decision") or "— not reviewed —",
            "Query": (e.get("query_text", "")[:60]
                      + ("…" if len(e.get("query_text", "")) > 60 else "")),
            "When": (e.get("created_at") or "")[:19],
            "Reference": e.get("event_id", ""),
        })
    return out
