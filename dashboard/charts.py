"""
Charts for the console, as Vega-Lite specifications.

Why Vega-Lite specs and not a plotting library
----------------------------------------------
Streamlit ships the Vega-Lite runtime in its own frontend bundle, so
`st.vega_lite_chart` draws these without importing anything at all. That keeps
the project's dependency list where it is -- the tech-stack constraint is
open-source and free, and the cheapest way to honour it is not to add a
dependency in the first place -- and it keeps the charts declarative: each
function below returns a dict, which is data, so the specs can be unit-tested
without a browser exactly as the render functions are.

Nothing here computes a figure. Every value plotted is read straight off the
report object, on the same rule `components.py` follows: the dashboard displays
numbers, it never derives them. The only arithmetic in this module is layout --
turning a value into a bar position -- and where a chart needs a derived
quantity (a threshold ratio, say) it is not drawn at all, because a chart is a
poor place to introduce a second implementation of the scoring logic.

Two honesty rules are enforced here rather than left to whoever writes the next
chart:

*Absence is not zero.* A detector that did not run, or could not be calibrated,
is plotted in the neutral colour with its status spelled out, never as a bar at
zero. A zero-height bar is a measurement; "we do not know" is not.

*The threshold is drawn, not implied.* Any chart showing a detector value also
shows where that detector's two thresholds sit, because a score of 0.61 means
nothing without the line it is being compared against, and the lines differ per
detector.
"""

from __future__ import annotations

from typing import Any

from dashboard import style

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

_FONT = ('-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, '
         '"Helvetica Neue", Arial, sans-serif')

#: Applied to every spec this module returns. Vega-Lite's defaults assume a white
#: page: black axis text on a transparent ground is invisible here, so the theme
#: is set explicitly rather than inherited.
_CONFIG: dict[str, Any] = {
    "background": "transparent",
    "font": _FONT,
    "view": {"stroke": "transparent"},
    "padding": {"left": 2, "top": 6, "right": 2, "bottom": 2},
    "axis": {
        "labelColor": style.INK_3,
        "titleColor": style.INK_3,
        "labelFontSize": 10,
        "titleFontSize": 10,
        "titleFontWeight": 500,
        "titlePadding": 8,
        "gridColor": style.LINE_SOFT,
        "gridOpacity": 0.85,
        "domainColor": style.LINE,
        "tickColor": style.LINE,
        "labelFont": style.MONO,
    },
    "legend": {
        "labelColor": style.INK_2,
        "titleColor": style.INK_3,
        "labelFontSize": 10,
        "titleFontSize": 9,
        "titleFontWeight": 600,
        "symbolType": "square",
        "orient": "bottom",
        "direction": "horizontal",
        "columns": 4,
    },
    "title": {"color": style.INK, "fontSize": 11, "fontWeight": 600,
              "anchor": "start", "offset": 8},
    "range": {"category": [style.ACCENT, style.GOOD, style.WARN, style.CRIT,
                           style.NEUTRAL]},
}

#: Detector status to plotted colour. Both "unusable" and "missing" resolve to
#: the same colourless grey on purpose: they are different reasons for the same
#: fact, which is that there is no measurement here.
_STATUS_DOMAIN = ["over malicious", "over suspicious", "below threshold",
                  "not calibrated", "did not run"]
_STATUS_RANGE = [style.CRIT, style.WARN, style.ACCENT, style.NEUTRAL,
                 style.NEUTRAL]

#: Axis labels for the four detectors. These are the short forms -- an axis tick
#: has perhaps twenty characters before it wraps or truncates, so the full plain
#: names in `glossary.DETECTOR` will not fit here. They are chosen to be the
#: shortest phrase that still says what was measured rather than which variable
#: held it: "Injection" named the detector, "Hidden instructions" names the
#: finding, and only one of those means anything to a reader seeing the chart
#: for the first time. The detector legend above the chart carries the full
#: names and the report field names beside them.
SIGNAL_LABEL = {
    "injection": "Hidden instructions",
    "anomaly": "Unlike the corpus",
    "unsupport": "Unsupported claims",
    "conflict": "Sources conflict",
}
SIGNAL_ORDER = ["Hidden instructions", "Unlike the corpus", "Unsupported claims",
                "Sources conflict"]


def render(st: Any, spec: dict[str, Any], height: int = 210) -> None:
    """Draw one spec. Themed here so no caller can forget to.

    `theme=None` asks Streamlit not to overlay its own chart theme on top of the
    config above; the two disagree about axis colour and Streamlit's wins, which
    on this background means grey-on-grey. The TypeError fallback covers
    Streamlit versions predating either keyword -- a chart that renders slightly
    wrong is a better failure than a page that will not load.
    """
    full = dict(spec)
    full["$schema"] = "https://vega.github.io/schema/vega-lite/v5.json"
    full.setdefault("width", "container")
    full.setdefault("height", height)
    full["config"] = {**_CONFIG, **full.get("config", {})}
    try:
        st.vega_lite_chart(full, use_container_width=True, theme=None)
    except TypeError:
        st.vega_lite_chart(full)


def _doc_label(doc: dict[str, Any]) -> str:
    """Rank first, so the row order on the chart matches the evidence list."""
    doc_id = str(doc.get("doc_id", ""))
    short = doc_id if len(doc_id) <= 30 else doc_id[:29] + "…"
    return f"{doc.get('rank', '?')}  {short}"


# ---------------------------------------------------------------------------
# Detector signals across the retrieval set
# ---------------------------------------------------------------------------

def signal_matrix(documents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Every detector against every retrieved document, in one grid.

    This is the chart the architecture was built to produce. Four detectors run
    over five documents and the analyst's question is not "what is the mean
    injection score" but "which document tripped which detector" -- a question
    about one cell of a 5x4 grid, which is what a grid answers and a bar chart
    does not.

    Colour is the status band, not the value. Encoding the raw value as a
    continuous ramp would be actively misleading: the four detectors have
    different thresholds, so equal colours would not mean equal severity. The
    value is printed in the cell instead, where it can be read exactly.
    """
    if not documents:
        return None

    rows: list[dict[str, Any]] = []
    for doc in documents:
        label = _doc_label(doc)
        for reading in doc.get("readings", []) or []:
            signal = SIGNAL_LABEL.get(reading.get("signal"), reading.get("signal"))
            status = style.STATUS_LABEL.get(reading.get("status"), "did not run")
            value = reading.get("value")
            rows.append({
                "document": label,
                "signal": signal,
                "status": status,
                "value": value,
                "text": "n/a" if value is None else f"{float(value):.2f}",
                "detail": (f"{signal} = "
                           + ("no measurement" if value is None
                              else f"{float(value):.3f}")
                           + f" ({status})"),
            })
    if not rows:
        return None

    order = [_doc_label(d) for d in documents]
    base = {"data": {"values": rows},
            "encoding": {
                "x": {"field": "signal", "type": "nominal", "title": None,
                      "sort": SIGNAL_ORDER,
                      "axis": {"orient": "top", "labelAngle": 0,
                               "labelFontSize": 10, "domain": False,
                               "ticks": False, "labelColor": style.INK_2}},
                "y": {"field": "document", "type": "nominal", "title": None,
                      "sort": order,
                      "axis": {"labelLimit": 240, "domain": False,
                               "ticks": False, "labelPadding": 6}}}}

    return {
        **base,
        "layer": [
            {"mark": {"type": "rect", "stroke": style.BG, "strokeWidth": 2,
                      "cornerRadius": 2},
             "encoding": {
                 "color": {
                     "field": "status", "type": "nominal",
                     "scale": {"domain": _STATUS_DOMAIN, "range": _STATUS_RANGE},
                     "legend": {"title": "Detector status", "orient": "bottom"}},
                 "opacity": {"condition": {
                     "test": "datum.status === 'below threshold'", "value": 0.32},
                     "value": 0.92},
                 "tooltip": [
                     {"field": "document", "type": "nominal", "title": "Document"},
                     {"field": "detail", "type": "nominal", "title": "Reading"}]}},
            {"mark": {"type": "text", "fontSize": 10, "fontWeight": 600,
                      "font": style.MONO},
             "encoding": {
                 "text": {"field": "text", "type": "nominal"},
                 "color": {"value": "#F2F5F9"}}},
        ],
    }


def evidence_profile(documents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Retrieval similarity by rank, with each document's trust tier on the bar.

    Retrieval is partition-blind -- it ranks by similarity alone, knowing nothing
    about provenance -- so putting the tier on the same bar as the similarity
    shows the thing the design is about: a document can be the closest match in
    the corpus and still be the least trustworthy source in it. When the top bar
    is Tier 3, the picture makes the argument on its own.
    """
    if not documents:
        return None
    rows = [{
        "document": _doc_label(doc),
        "similarity": float(doc.get("similarity") or 0.0),
        "tier": f"Tier {doc.get('source_tier', '?')}",
        "source": doc.get("source_name", ""),
        "band": doc.get("headline", "ORANGE"),
    } for doc in documents]

    return {
        "data": {"values": rows},
        "mark": {"type": "bar", "height": {"band": 0.62}, "cornerRadiusEnd": 2},
        "encoding": {
            "y": {"field": "document", "type": "nominal", "title": None,
                  "sort": [r["document"] for r in rows],
                  "axis": {"labelLimit": 240, "domain": False, "ticks": False}},
            "x": {"field": "similarity", "type": "quantitative",
                  "title": "Similarity to query",
                  "scale": {"domain": [0, 1]},
                  "axis": {"format": ".2f", "grid": True}},
            "color": {"field": "tier", "type": "nominal",
                      "scale": {"domain": ["Tier 1", "Tier 2", "Tier 3"],
                                "range": ["#7F8CA0", "#4E6076", "#33404F"]},
                      "legend": {"title": "Source trust tier"}},
            "tooltip": [
                {"field": "document", "type": "nominal", "title": "Document"},
                {"field": "source", "type": "nominal", "title": "Source"},
                {"field": "tier", "type": "nominal", "title": "Tier"},
                {"field": "similarity", "type": "quantitative",
                 "title": "Similarity", "format": ".4f"}],
        },
    }


def threshold_distance(documents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """How far each measured reading sits from its own suspicious threshold.

    Detector scores are not comparable across detectors -- 0.4 is unremarkable
    for one and over the line for another -- so this plots the margin instead of
    the value: everything left of zero came in under its threshold, everything
    right of it fired. That makes one axis meaningful for all four detectors at
    once, and it makes a reading that only just cleared its line visible as
    exactly that.

    Readings with no measurement are omitted rather than plotted at zero, which
    on a margin axis would place them precisely on the threshold -- the single
    most misleading position available.
    """
    rows: list[dict[str, Any]] = []
    for doc in documents or []:
        label = _doc_label(doc)
        for reading in doc.get("readings", []) or []:
            value, sus = reading.get("value"), reading.get("suspicious_threshold")
            if value is None or sus is None:
                continue
            rows.append({
                "document": label,
                "signal": SIGNAL_LABEL.get(reading.get("signal"),
                                           reading.get("signal")),
                "margin": float(value) - float(sus),
                "value": float(value),
                "threshold": float(sus),
                "status": style.STATUS_LABEL.get(reading.get("status"), ""),
            })
    if not rows:
        return None

    return {
        "data": {"values": rows},
        "layer": [
            {"mark": {"type": "circle", "size": 82, "opacity": 0.95},
             "encoding": {
                 "x": {"field": "margin", "type": "quantitative",
                       "title": "Margin to suspicious threshold "
                                "(left of zero = under the line)",
                       "axis": {"format": "+.2f"}},
                 "y": {"field": "signal", "type": "nominal", "title": None,
                       "sort": SIGNAL_ORDER,
                       "axis": {"domain": False, "ticks": False}},
                 "color": {"field": "status", "type": "nominal",
                           "scale": {"domain": _STATUS_DOMAIN,
                                     "range": _STATUS_RANGE},
                           "legend": {"title": "Detector status"}},
                 "tooltip": [
                     {"field": "document", "type": "nominal", "title": "Document"},
                     {"field": "signal", "type": "nominal", "title": "Detector"},
                     {"field": "value", "type": "quantitative", "title": "Reading",
                      "format": ".3f"},
                     {"field": "threshold", "type": "quantitative",
                      "title": "Suspicious at", "format": ".3f"},
                     {"field": "margin", "type": "quantitative", "title": "Margin",
                      "format": "+.3f"}]}},
            {"mark": {"type": "rule", "color": style.WARN, "strokeWidth": 1,
                      "strokeDash": [4, 3], "opacity": 0.9},
             "encoding": {"x": {"datum": 0}}},
        ],
    }


# ---------------------------------------------------------------------------
# Score, confidence, cost
# ---------------------------------------------------------------------------

def trust_dial(trust: Any, lo: Any, hi: Any) -> dict[str, Any] | None:
    """The composite trust score with its 95% interval, on a fixed 0-100 axis.

    Fixed rather than fitted to the data on purpose. An axis that rescales makes
    a narrow interval and a wide one look the same, and the width of this
    interval is the part an analyst is supposed to act on.
    """
    if trust is None:
        return None
    point = float(trust)
    layers: list[dict[str, Any]] = [
        {"data": {"values": [
            {"start": 0, "end": 40, "zone": "low"},
            {"start": 40, "end": 70, "zone": "mid"},
            {"start": 70, "end": 100, "zone": "high"}]},
         "mark": {"type": "bar", "opacity": 0.2, "height": 26},
         "encoding": {
             "x": {"field": "start", "type": "quantitative",
                   "scale": {"domain": [0, 100]},
                   "title": "Composite trust score (%)",
                   "axis": {"values": [0, 20, 40, 60, 80, 100], "grid": False}},
             "x2": {"field": "end"},
             "color": {"field": "zone", "type": "nominal",
                       "scale": {"domain": ["low", "mid", "high"],
                                 "range": [style.CRIT, style.WARN, style.GOOD]},
                       "legend": None}}},
    ]

    if lo is not None and hi is not None:
        layers.append({
            "data": {"values": [{"lo": float(lo), "hi": float(hi)}]},
            "mark": {"type": "bar", "height": 11, "color": style.INK_2,
                     "opacity": 0.75, "cornerRadius": 1},
            "encoding": {"x": {"field": "lo", "type": "quantitative"},
                         "x2": {"field": "hi"},
                         "tooltip": [
                             {"field": "lo", "type": "quantitative",
                              "title": "95% lower", "format": ".1f"},
                             {"field": "hi", "type": "quantitative",
                              "title": "95% upper", "format": ".1f"}]}})

    layers.append({
        "data": {"values": [{"p": point}]},
        "mark": {"type": "rule", "color": style.INK, "strokeWidth": 3},
        "encoding": {"x": {"field": "p", "type": "quantitative"},
                     "tooltip": [{"field": "p", "type": "quantitative",
                                  "title": "Trust score", "format": ".1f"}]}})

    return {"layer": layers}


def confidence_components(components: dict[str, Any]) -> dict[str, Any] | None:
    """The five inputs to the confidence figure, drawn side by side.

    Confidence is reported separately from the trust score because a high score
    from one document and a high score from five agreeing sources are different
    claims. Breaking it into its components says *which* of those a given
    confidence figure rests on -- a run held back by `volume` and one held back
    by `coherence` need different responses from the analyst.
    """
    if not components:
        return None
    rows = [{"component": k.replace("_", " "), "value": float(v)}
            for k, v in components.items() if v is not None]
    if not rows:
        return None
    rows.sort(key=lambda r: r["value"])

    return {
        "data": {"values": rows},
        "layer": [
            {"mark": {"type": "bar", "height": {"band": 0.55},
                      "cornerRadiusEnd": 2, "color": style.ACCENT,
                      "opacity": 0.85},
             "encoding": {"tooltip": [
                 {"field": "component", "type": "nominal", "title": "Component"},
                 {"field": "value", "type": "quantitative", "title": "Value",
                  "format": ".3f"}]}},
            {"mark": {"type": "text", "align": "left", "dx": 6, "fontSize": 10,
                      "font": style.MONO, "color": style.INK_2},
             "encoding": {"text": {"field": "value", "type": "quantitative",
                                   "format": ".2f"}}},
        ],
        "encoding": {
            "y": {"field": "component", "type": "nominal", "title": None,
                  "sort": [r["component"] for r in rows],
                  "axis": {"domain": False, "ticks": False, "labelLimit": 150}},
            "x": {"field": "value", "type": "quantitative", "title": None,
                  "scale": {"domain": [0, 1]},
                  "axis": {"format": ".1f", "values": [0, 0.25, 0.5, 0.75, 1]}},
        },
    }


def stage_latency(timings: dict[str, Any]) -> dict[str, Any] | None:
    """Where the wall-clock time went, by pipeline stage.

    Worth showing in a demo because the cost of the security layer is a fair
    question to ask of it, and a number answers that better than a claim. Total
    is excluded: it is the sum of the others, and stacking it beside them would
    double every bar.
    """
    if not timings:
        return None
    rows = [{"stage": k, "ms": float(v)}
            for k, v in timings.items() if k != "total" and v is not None]
    if not rows:
        return None

    return {
        "data": {"values": rows},
        "mark": {"type": "bar", "height": 22, "cornerRadius": 1},
        "encoding": {
            "x": {"field": "ms", "type": "quantitative", "title": "milliseconds",
                  "stack": "zero"},
            "color": {"field": "stage", "type": "nominal",
                      "scale": {"domain": ["retrieval", "generation", "scoring",
                                           "report"],
                                "range": ["#3D4B5C", style.NEUTRAL, style.ACCENT,
                                          "#2E5C7E"]},
                      "legend": {"title": "Pipeline stage"}},
            "tooltip": [{"field": "stage", "type": "nominal", "title": "Stage"},
                        {"field": "ms", "type": "quantitative",
                         "title": "Milliseconds", "format": ".1f"}],
        },
    }


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def band_split(by_headline: dict[str, Any]) -> dict[str, Any] | None:
    """How the scored queries divide across the three verdict bands."""
    rows = [{"band": b, "count": int(by_headline.get(b, 0) or 0)}
            for b in ("GREEN", "ORANGE", "RED")]
    if not any(r["count"] for r in rows):
        return None
    return {
        "data": {"values": rows},
        "layer": [
            {"mark": {"type": "bar", "height": {"band": 0.55},
                      "cornerRadiusEnd": 2},
             "encoding": {
                 "color": {"field": "band", "type": "nominal",
                           "scale": {"domain": ["GREEN", "ORANGE", "RED"],
                                     "range": [style.GOOD, style.WARN, style.CRIT]},
                           "legend": None},
                 "tooltip": [{"field": "band", "type": "nominal", "title": "Band"},
                             {"field": "count", "type": "quantitative",
                              "title": "Queries"}]}},
            {"mark": {"type": "text", "align": "left", "dx": 6, "fontSize": 10,
                      "font": style.MONO, "color": style.INK_2},
             "encoding": {"text": {"field": "count", "type": "quantitative"}}},
        ],
        "encoding": {
            "y": {"field": "band", "type": "nominal", "title": None,
                  "sort": ["GREEN", "ORANGE", "RED"],
                  "axis": {"domain": False, "ticks": False}},
            "x": {"field": "count", "type": "quantitative", "title": None,
                  "axis": {"tickMinStep": 1, "format": "d"}},
        },
    }


def case_split(by_case: dict[str, Any]) -> dict[str, Any] | None:
    """Which of the eleven cases the log has actually seen.

    Sorted by case id rather than by count, so the same case sits in the same
    place between runs and a reader comparing two screenshots is comparing the
    bars rather than re-reading the axis.
    """
    rows = [{"case": k, "count": int(v or 0)} for k, v in (by_case or {}).items() if k]
    if not rows:
        return None
    rows.sort(key=lambda r: (len(r["case"]), r["case"]))
    return {
        "data": {"values": rows},
        "mark": {"type": "bar", "width": {"band": 0.6}, "cornerRadiusEnd": 2,
                 "color": style.ACCENT, "opacity": 0.85},
        "encoding": {
            "x": {"field": "case", "type": "nominal", "title": None,
                  "sort": [r["case"] for r in rows],
                  "axis": {"labelAngle": 0, "domain": False, "ticks": False}},
            "y": {"field": "count", "type": "quantitative", "title": "Queries",
                  "axis": {"tickMinStep": 1, "format": "d"}},
            "tooltip": [{"field": "case", "type": "nominal", "title": "Case"},
                        {"field": "count", "type": "quantitative",
                         "title": "Queries"}],
        },
    }


def review_split(total: int, decided: int, by_decision: dict[str, Any]
                 ) -> dict[str, Any] | None:
    """Analyst outcomes, with "not reviewed" shown as its own slice.

    Undecided is the absence of a decision row rather than a stored value
    (design 5.8), so it has to be computed for display here -- as a subtraction
    of two counts the audit log reports, never as a status read from a column
    that does not exist.
    """
    if not total:
        return None
    rows = [{"outcome": k, "count": int(v or 0)}
            for k, v in (by_decision or {}).items() if k]
    unreviewed = int(total) - int(decided or 0)
    if unreviewed > 0:
        rows.append({"outcome": "not reviewed", "count": unreviewed})
    if not rows:
        return None
    return {
        "data": {"values": rows},
        "mark": {"type": "arc", "innerRadius": 46, "stroke": style.BG,
                 "strokeWidth": 2},
        "encoding": {
            "theta": {"field": "count", "type": "quantitative", "stack": True},
            "color": {"field": "outcome", "type": "nominal",
                      "scale": {"domain": ["ACCEPT", "REJECT", "OVERRIDE",
                                           "not reviewed"],
                                "range": [style.GOOD, style.CRIT, style.WARN,
                                          style.NEUTRAL]},
                      "legend": {"title": "Analyst outcome"}},
            "tooltip": [{"field": "outcome", "type": "nominal", "title": "Outcome"},
                        {"field": "count", "type": "quantitative",
                         "title": "Queries"}],
        },
    }


__all__ = [
    "render", "signal_matrix", "evidence_profile", "threshold_distance",
    "trust_dial", "confidence_components", "stage_latency",
    "band_split", "case_split", "review_split", "SIGNAL_LABEL",
]
