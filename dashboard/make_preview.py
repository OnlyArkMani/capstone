"""
Render the console to a standalone HTML file for design review.

    python -m dashboard.make_preview "<query>"      -> dashboard/ui_preview.html
    python -m dashboard.make_preview --fixture      -> same, without the stack

WHY THIS EXISTS
---------------
`test_dashboard.py` checks structure and call order. It cannot check what the
page looks like, and it says so in its own closing note. Appearance was checked
by starting the container, opening a browser and looking -- which is a slow loop,
needs the whole stack up, and cannot be attached to anything or reviewed by
somebody who is not sitting at the machine.

This walks the same render functions the real page calls, with a recorder that
emits static HTML instead of talking to Streamlit, and writes one self-contained
file. The stylesheet is the real one, imported from `dashboard/style.py`, and the
charts are the real specs from `dashboard/charts.py` rendered by vega-embed, so
what the file shows is what the console shows. It is a review aid, not a second
implementation of the page: it renders whatever `components.py` produces and has
no layout opinions of its own.

The report it renders is a real scored query, so the preview carries the same
caveats the console would -- including the fallback-backend warnings when the
models are not installed.

`--fixture` renders the same page from a hand-written report instead. That is a
strictly worse preview and it is not a substitute for the real one: the figures
are invented, so nothing about detection quality can be read off it. What it is
for is LAYOUT, on a machine where the index has not been built or the detector
models are not installed -- a wording change or a panel that collapses at narrow
width can be seen without bringing the whole stack up. Every fixture value is
plainly synthetic and the page says so at the top, so a fixture render cannot be
mistaken for a result.
"""

from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dashboard import components, style  # noqa: E402

OUT = PROJECT_ROOT / "dashboard" / "ui_preview.html"

_VEGA = ("https://cdnjs.cloudflare.com/ajax/libs/vega/5.25.0/vega.min.js",
         "https://cdnjs.cloudflare.com/ajax/libs/vega-lite/5.16.3/vega-lite.min.js",
         "https://cdnjs.cloudflare.com/ajax/libs/vega-embed/6.22.2/vega-embed.min.js")


_COLOUR_MD = {"red": style.CRIT, "orange": style.WARN, "green": style.GOOD,
              "blue": style.ACCENT, "grey": style.INK_3, "gray": style.INK_3}


def _md_inline(text: str) -> str:
    """The small subset of Markdown the render functions actually use.

    Streamlit's `:red[...]` colour syntax is handled too. Nothing in the console
    relies on it any more, but a preview that printed it literally would report a
    rendering fault that the product does not have.
    """
    out = html.escape(str(text))
    out = re.sub(r":(red|orange|green|blue|grey|gray)\[([^\]]*)\]",
                 lambda m: f'<span style="color:{_COLOUR_MD[m.group(1)]}">'
                           f"{m.group(2)}</span>", out)
    while out.count("`") >= 2:
        out = out.replace("`", "<code>", 1).replace("`", "</code>", 1)
    while out.count("**") >= 2:
        out = out.replace("**", "<strong>", 1).replace("**", "</strong>", 1)
    return out.replace("\n", "<br/>")


#: Streamlit routes every `st.*` call to whichever container is currently open,
#: so `with col: st.metric(...)` puts the metric in `col` even though the call
#: was made on the top-level module. Replicating that is the whole reason this
#: recorder has a stack: without it, `render_headline_metrics` -- which opens
#: three columns and then calls `st.metric` on the module -- renders as three
#: stacked full-width cards here and as a row in the product, and the preview
#: would be quietly wrong about the one thing it exists to show.
_OPEN: list[list[str]] = []


class HtmlRecorder:
    """Stands in for `streamlit`, emitting static HTML.

    Columns are flex rows and expanders are `<details>` -- both are the closest
    honest equivalent, and both keep the nesting so that a layout mistake shows
    up here as the same mistake it would be on the page.
    """

    def __init__(self, sink: list[str] | None = None) -> None:
        self.parts: list[str] = sink if sink is not None else []
        self._charts = 0

    # -- context-manager support -------------------------------------------
    def __enter__(self) -> "HtmlRecorder":
        _OPEN.append(self.parts)
        return self

    def __exit__(self, *exc: Any) -> bool:
        if _OPEN:
            _OPEN.pop()
        return False

    def emit(self, chunk: Any) -> None:
        (_OPEN[-1] if _OPEN else self.parts).append(chunk)

    # -- the Streamlit surface the render functions use --------------------
    def markdown(self, body: str = "", *a: Any, **kw: Any) -> None:
        self.emit(str(body) if kw.get("unsafe_allow_html")
                  else f'<p class="tz-p">{_md_inline(body)}</p>')

    def caption(self, body: str = "", *a: Any, **kw: Any) -> None:
        self.emit(f'<div class="tz-cap">{_md_inline(body)}</div>')

    def subheader(self, body: str = "", *a: Any, **kw: Any) -> None:
        self.emit(f'<h2 class="tz-h2">{_md_inline(body)}</h2>')

    def metric(self, label: str = "", value: Any = "", *a: Any, **kw: Any) -> None:
        self.emit(f'<div class="tz-metric"><div class="tz-metric-k">'
                  f'{html.escape(str(label))}</div><div class="tz-metric-v">'
                  f'{html.escape(str(value))}</div></div>')

    def table(self, rows: Any = None, *a: Any, **kw: Any) -> None:
        rows = rows or []
        if not rows:
            return
        head = "".join(f"<th>{html.escape(str(k))}</th>" for k in rows[0])
        body = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in r.values())
            + "</tr>" for r in rows)
        # Wrapped in its own scroller. `st.table` scrolls itself in the product;
        # a bare table here made the whole page scroll sideways at narrow widths
        # and reported an overflow the console does not have.
        self.emit(f'<div style="overflow-x:auto;max-width:100%;">'
                  f'<table class="tz-table"><thead><tr>{head}</tr></thead>'
                  f"<tbody>{body}</tbody></table></div>")

    def _alert(self, kind: str, body: str) -> None:
        colour = {"info": style.ACCENT, "warning": style.WARN,
                  "error": style.CRIT, "success": style.GOOD}[kind]
        self.emit(f'<div class="tz-alert" style="border-left-color:{colour};">'
                  f"{_md_inline(body)}</div>")

    def info(self, body: str = "", *a: Any, **kw: Any) -> None:
        self._alert("info", body)

    def warning(self, body: str = "", *a: Any, **kw: Any) -> None:
        self._alert("warning", body)

    def error(self, body: str = "", *a: Any, **kw: Any) -> None:
        self._alert("error", body)

    def success(self, body: str = "", *a: Any, **kw: Any) -> None:
        self._alert("success", body)

    def columns(self, spec: Any = 1, *a: Any, **kw: Any) -> list["HtmlRecorder"]:
        widths = spec if isinstance(spec, (list, tuple)) else [1] * int(spec)
        cols, inner = [], []
        for w in widths:
            sink: list[str] = []
            cols.append(HtmlRecorder(sink))
            inner.append((float(w), sink))
        self.emit('<div class="tz-cols">')
        # The column bodies are filled by the caller after this returns, so a
        # placeholder is emitted now and resolved in `finish()`.
        self.emit(_Deferred(inner))
        self.emit("</div>")
        return cols

    def expander(self, label: str = "", *a: Any, **kw: Any) -> "HtmlRecorder":
        sink: list[str] = []
        child = HtmlRecorder(sink)
        self.emit(f'<details class="tz-exp" {"open" if kw.get("expanded") else ""}>'
                  f"<summary>{_md_inline(label)}</summary>")
        self.emit(_Deferred([(1.0, sink)], plain=True))
        self.emit("</details>")
        return child

    def vega_lite_chart(self, spec: Any = None, *a: Any, **kw: Any) -> None:
        self._charts += 1
        cid = f"viz{self._charts}_{id(self)}"
        self.emit(f'<div class="tz-viz" id="{cid}"></div>'
                  f'<script>window.__specs=window.__specs||[];'
                  f'window.__specs.push(["{cid}",{json.dumps(spec)}]);</script>')

    # Everything the preview does not draw.
    def __getattr__(self, name: str) -> Any:
        def noop(*a: Any, **kw: Any) -> Any:
            return None
        return noop

    def finish(self) -> str:
        return "".join(
            p.render() if isinstance(p, _Deferred) else str(p) for p in self.parts)


class _Deferred:
    """A column or expander body, resolved after its caller has filled it."""

    def __init__(self, inner: list[tuple[float, list[str]]], plain: bool = False):
        self.inner, self.plain = inner, plain

    def render(self) -> str:
        out = []
        for weight, sink in self.inner:
            body = "".join(p.render() if isinstance(p, _Deferred) else str(p)
                           for p in sink)
            out.append(body if self.plain
                       else f'<div class="tz-col" style="flex:{weight};">{body}</div>')
        return "".join(out)


def _fixture_report() -> tuple[dict[str, Any], str]:
    """A hand-written report for layout review only.

    Deliberately a RED / C5 case: it exercises the sub-type line in the banner,
    the compromise sentence, the escalation checklist, a fired detector, an
    uncalibrated one, and a caveat -- which between them cover every conditional
    branch in the render functions. The values are invented and the page says so.
    """
    readings = [
        {"signal": "injection", "value": 0.91, "suspicious_threshold": 0.60,
         "malicious_threshold": 0.85, "margin_to_suspicious": 0.31,
         "margin_to_malicious": 0.06, "status": "over_malicious"},
        {"signal": "anomaly", "value": 0.42, "suspicious_threshold": 0.55,
         "malicious_threshold": 0.80, "margin_to_suspicious": -0.13,
         "margin_to_malicious": -0.38, "status": "below"},
        {"signal": "unsupport", "value": 0.71, "suspicious_threshold": 0.60,
         "malicious_threshold": 0.85, "margin_to_suspicious": 0.11,
         "margin_to_malicious": -0.14, "status": "over_suspicious"},
        {"signal": "conflict", "value": None, "suspicious_threshold": None,
         "malicious_threshold": None, "margin_to_suspicious": None,
         "margin_to_malicious": None, "status": "unusable"},
    ]
    report: dict[str, Any] = {
        "report_id": "rpt-FIXTURE", "schema_version": "report-v1.0",
        "generated_at": "2026-09-12T00:00:00+00:00",
        "query": "FIXTURE — layout review only",
        "headline": "RED", "headline_subtype": "TRUSTED_SOURCE_COMPROMISE",
        "case_id": "C5", "case_name": "Authoritative Channel Compromise",
        "priority": "P0", "risk_tier": "CRITICAL",
        "recommended_action": "ESCALATE",
        "action_meaning": "Raise a security event to the threat-intelligence owner.",
        "trust_percent": 21.4, "trust_interval": [11.8, 34.2],
        "confidence": 0.58,
        "confidence_components": {
            "volume": 0.72, "agreement": 0.41, "independence": 0.66,
            "detector_concurrence": 0.55, "model_stability": 0.80},
        "confidence_caps": [], "tier_governing": 1, "n_retrieved": 2,
        "entity_count": 2,
        "entities": {"cve": [{"value": "CVE-2020-6961", "doc_ids": ["fx-1"]}],
                     "ipv4": [{"value": "198.51.100.47", "doc_ids": ["fx-1"]}]},
        "documents": [
            {"rank": 1, "doc_id": "fx-1", "title": "FIXTURE advisory (synthetic)",
             "source_id": "fx-tier1", "source_name": "Fixture authority feed",
             "source_tier": 1, "source_tier_label": "verified-authoritative",
             "similarity": 0.88, "case_id": "C5",
             "case_name": "Authoritative Channel Compromise", "headline": "RED",
             "headline_subtype": "TRUSTED_SOURCE_COMPROMISE", "action": "ESCALATE",
             "priority": "P0", "trust_percent": 18.0, "risk": 0.82,
             "signals": {"injection": 0.91, "anomaly": 0.42,
                         "unsupport": 0.71, "conflict": None},
             "readings": readings,
             "provenance": {"published_date": "2026-09-01",
                            "ingestion_date": "2026-09-02",
                            "reference_verified": False},
             "entities": []},
            {"rank": 2, "doc_id": "fx-2", "title": "FIXTURE corroborating note",
             "source_id": "fx-tier2", "source_name": "Fixture open feed",
             "source_tier": 2, "source_tier_label": "trusted-open",
             "similarity": 0.74, "case_id": "C2",
             "case_name": "Community Corroboration", "headline": "ORANGE",
             "headline_subtype": None, "action": "ACCEPT", "priority": "P4",
             "trust_percent": 68.0, "risk": 0.22,
             "signals": {"injection": 0.04, "anomaly": 0.19,
                         "unsupport": 0.31, "conflict": 0.12},
             "readings": [
                 {"signal": s, "value": v, "suspicious_threshold": 0.60,
                  "malicious_threshold": 0.85, "margin_to_suspicious": v - 0.60,
                  "margin_to_malicious": v - 0.85, "status": "below"}
                 for s, v in (("injection", 0.04), ("anomaly", 0.19),
                              ("unsupport", 0.31), ("conflict", 0.12))],
             "provenance": {"published_date": "2026-08-20",
                            "reference_verified": True},
             "entities": []},
        ],
        "reasoning": {
            "text": "FIXTURE narrative.",
            "sentences": [
                {"template_id": "fx1", "text": "A Tier 1 source carried content "
                                               "the injection detector scored at "
                                               "0.910, above its malicious "
                                               "threshold of 0.850.", "facts": []},
                {"template_id": "fx2", "text": "The contradiction detector could "
                                               "not be calibrated on this query, "
                                               "so inter-document conflict is "
                                               "unmeasured.", "facts": []}],
            "grounding": {"fact_count": 4, "generated_by_model": False}},
        "analyst_decision": {"status": "AWAITING_REVIEW", "decision": None},
        "provenance": {
            "n_distinct_sources": 2, "detector_backends": {},
            "timings_ms": {"retrieval": 41.2, "generation": 612.5,
                           "scoring": 884.0, "report": 12.8, "total": 1550.5}},
        "caveats": ["FIXTURE RENDER — every figure on this page is invented. "
                    "Nothing here is a measurement."],
    }
    return report, "evt-FIXTURE"


def build(query: str, db_path: str | None = None, fixture: bool = False) -> Path:
    if fixture:
        report, event_id = _fixture_report()
        query = "FIXTURE — layout review only, no query was run"
    else:
        from dashboard.service import run_query  # noqa: PLC0415
        report, event_id = run_query(query, db_path=db_path)

    # The same order the console renders in: decision first, then verification.
    # Kept in step with `dashboard/app.py` by hand -- the preview walks the render
    # functions directly rather than importing the page, because the page calls
    # `set_page_config` and reads `session_state`.
    rec = HtmlRecorder()
    components.render_banner(rec, report)
    components.render_verdict_sentence(rec, report)
    components.render_classification_strip(rec, report)
    components.render_caveats(rec, report)
    components.render_next_steps(rec, report)
    components.render_case_and_action(rec, report)
    components.render_headline_metrics(rec, report)
    rec.markdown(f'<div style="height:1px;background:{style.LINE};'
                 f'margin:2.2rem 0 1.1rem 0;"></div>'
                 f'<div class="tz-eyebrow">Verification — the evidence behind '
                 f'the verdict</div>', unsafe_allow_html=True)
    components.render_verdict_ladder(rec, report)
    components.render_signal_overview(rec, report)
    components.render_score_analysis(rec, report)
    components.render_reasoning(rec, report)
    components.render_documents(rec, report)
    components.render_entities(rec, report)
    components.render_performance(rec, report)
    body = rec.finish()

    scripts = "".join(f'<script src="{u}"></script>' for u in _VEGA)
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<title>Trust and Risk Layer — console preview</title>
{scripts}
{style._CSS}
<style>
  body {{ background:{style.BG}; color:{style.INK}; margin:0;
          font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
                      "Helvetica Neue",Arial,sans-serif; }}
  /* minmax(0,1fr) rather than 1fr: a bare 1fr grid track takes its minimum
     from its content, so the main column could not shrink below the widest
     thing in it and the whole preview scrolled sideways at narrow widths --
     reporting an overflow the console does not have. */
  .tz-shell {{ display:grid; grid-template-columns:250px minmax(0,1fr);
               min-height:100vh; }}
  .tz-side {{ background:{style.PANEL}; border-right:1px solid {style.LINE};
              padding:1.4rem 1.1rem; }}
  .tz-main {{ padding:1.6rem 2rem 4rem 2rem; max-width:1500px; }}
  .tz-cols {{ display:flex; gap:1.1rem; align-items:flex-start; margin:0.2rem 0; }}
  .tz-col {{ min-width:0; }}
  .tz-p {{ font-size:0.85rem; line-height:1.6; color:{style.INK_2}; }}
  .tz-cap {{ font-size:0.74rem; color:{style.INK_3}; line-height:1.55;
             margin:0.3rem 0 0.6rem 0; }}
  .tz-h2 {{ font-size:1.02rem; font-weight:600; margin:1.7rem 0 0.7rem 0;
            color:{style.INK}; }}
  .tz-metric {{ background:{style.PANEL}; border:1px solid {style.LINE};
                border-radius:3px; padding:0.7rem 0.9rem 0.75rem 0.9rem; }}
  .tz-metric-k {{ font-size:0.65rem; font-weight:600; letter-spacing:0.12em;
                  text-transform:uppercase; color:{style.INK_3}; }}
  .tz-metric-v {{ font-family:{style.MONO}; font-variant-numeric:tabular-nums;
                  font-size:1.62rem; font-weight:500; margin-top:0.2rem; }}
  .tz-table {{ width:100%; border-collapse:collapse; font-size:0.76rem;
               font-family:{style.MONO}; margin:0.5rem 0 0.2rem 0; }}
  .tz-table th {{ text-align:left; font-size:0.62rem; letter-spacing:0.1em;
                  text-transform:uppercase; color:{style.INK_3}; font-weight:600;
                  border-bottom:1px solid {style.LINE}; padding:0.35rem 0.5rem; }}
  .tz-table td {{ border-bottom:1px solid {style.LINE_SOFT}; padding:0.35rem 0.5rem;
                  color:{style.INK_2}; }}
  .tz-alert {{ background:{style.PANEL}; border:1px solid {style.LINE};
               border-left-width:2px; border-radius:3px; padding:0.6rem 0.85rem;
               font-size:0.8rem; margin:0.5rem 0; color:{style.INK_2}; }}
  .tz-exp {{ background:{style.PANEL}; border:1px solid {style.LINE};
             border-radius:3px; margin:0.45rem 0; padding:0.1rem 0.9rem; }}
  .tz-exp summary {{ font-family:{style.MONO}; font-size:0.78rem; cursor:pointer;
                     padding:0.6rem 0; color:{style.INK}; }}
  .tz-viz {{ margin:0.2rem 0 0.4rem 0; }}
  .tz-preview-note {{ font-size:0.7rem; color:{style.INK_3}; border:1px dashed
      {style.LINE}; border-radius:3px; padding:0.5rem 0.7rem; margin-bottom:1.2rem; }}
</style></head>
<body><div class="tz-shell">
  <div class="tz-side">
    <div class="tz-side-brand">Trust and Risk Layer</div>
    <div class="tz-side-brand-sub">Healthcare threat-intelligence RAG<br/>
      Team Zetabyte</div>
    <div style="height:1px;background:{style.LINE};margin:0.9rem 0 1rem 0;"></div>
    <div class="tz-eyebrow">Analyst</div>
    <div class="tz-cap">analyst-01 · tier2_soc</div>
    <div class="tz-eyebrow" style="margin-top:1.3rem;">Queue</div>
    {style.side_stat("Queries logged", "—")}
    {style.side_stat("Awaiting review", "—")}
  </div>
  <div class="tz-main">
    {style.masthead("Trust and Risk Layer — SOC Analyst Console",
                    "Corpus poisoning detection for retrieval-augmented threat "
                    "intelligence", "DESIGN-V1.7 · HEALTHCARE THREAT INTELLIGENCE")}
    <div class="tz-preview-note">
      Static design preview generated by <code>dashboard/make_preview.py</code>.
      The stylesheet and the charts are the console's own. Query:
      <code>{html.escape(query)}</code> · audit reference
      <code>{html.escape(str(event_id))}</code>
    </div>
    {body}
  </div>
</div>
<script>
  window.addEventListener("load", function () {{
    (window.__specs || []).forEach(function (pair) {{
      vegaEmbed("#" + pair[0], pair[1], {{actions:false, renderer:"svg"}})
        .catch(console.error);
    }});
  }});
</script>
</body></html>"""

    OUT.write_text(page, encoding="utf-8")
    return OUT


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--fixture"]
    use_fixture = "--fixture" in sys.argv
    q = (args[0] if args else
         "Is the Contec CMS8000 patient monitor safe to keep connected to our "
         "clinical network?")
    db = args[1] if len(args) > 1 else None
    path = build(q, db, fixture=use_fixture)
    print(f"wrote {path} ({path.stat().st_size:,} bytes)"
          + ("  [FIXTURE — layout only, figures invented]" if use_fixture else ""))
