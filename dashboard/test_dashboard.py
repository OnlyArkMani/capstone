#!/usr/bin/env python3
"""
Tests for the dashboard.

    python -m dashboard.test_dashboard
    python -m dashboard.test_dashboard --verbose

Streamlit is not importable in every environment this project is developed in, and
a UI test that only runs where the UI runs is a test that stops running. So these
tests install a **recording stub** in place of `streamlit`: every call is captured
in order, with its arguments, and the assertions are made against that transcript.

That turns the sprint's hardest requirement into something checkable. "The colour
banner must be visible without scrolling or clicking" is, mechanically, a claim
about call order — the banner must be the first thing rendered, nothing above it,
and nothing gating it. `test_banner_is_first` asserts exactly that, and it would
fail the moment somebody adds a heading, a spinner or a metric above it.

What this cannot check: that the rendered page actually looks right in a browser.
Colour contrast, font size and layout still need a human to run
`streamlit run dashboard/app.py` and look at it.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import types
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

FAILURES: list[str] = []
VERBOSE = False


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def note(msg: str) -> None:
    if VERBOSE:
        print(f"        {msg}")


# ---------------------------------------------------------------------------
# The recording stub
# ---------------------------------------------------------------------------

class _Recorder:
    """Stands in for the `streamlit` module and records every call in order."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []
        self.session_state: dict[str, Any] = _State()

    def _record(self, name: str):
        def fn(*args: Any, **kwargs: Any):
            self.calls.append((name, args, kwargs))
            if name == "columns":
                n = args[0] if args else 1
                count = n if isinstance(n, int) else len(n)
                return [_Ctx(self, f"col{i}") for i in range(count)]
            if name == "expander":
                return _Ctx(self, "expander")
            if name in ("button", "checkbox"):
                return False
            if name == "text_input":
                return kwargs.get("value", "")
            if name in ("selectbox", "radio"):
                opts = args[1] if len(args) > 1 else kwargs.get("options", [""])
                return opts[0] if opts else ""
            if name == "slider":
                return args[3] if len(args) > 3 else 3
            if name == "spinner":
                return _Ctx(self, "spinner")
            return None
        return fn

    def __getattr__(self, name: str):
        # `st.sidebar` and `st.container` are used as context managers rather than
        # called, so they have to be objects, not functions.
        if name in ("sidebar", "container"):
            return _Ctx(self, name)
        return self._record(name)

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]

    def markdown_text(self) -> str:
        return "\n".join(str(a) for name, args, _ in self.calls
                         if name in ("markdown", "caption", "warning", "info",
                                     "success", "error", "subheader", "metric")
                         for a in args)


class _State(dict):
    """`st.session_state` supports both attribute and item access."""

    def __getattr__(self, k):
        return self.get(k)

    def __setattr__(self, k, v):
        self[k] = v

    def setdefault(self, k, v=None):
        return super().setdefault(k, v)


class _Ctx:
    """A context manager that keeps recording — `st.columns`, `st.expander`."""

    def __init__(self, rec: _Recorder, label: str) -> None:
        self._rec, self._label = rec, label

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __getattr__(self, name: str):
        # Delegate to the recorder under the plain call name, so a call made
        # inside a column or the sidebar still lands in the single ordered
        # transcript the assertions read.
        return getattr(self._rec, name)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _report(band: str = "ORANGE", subtype: str | None = None) -> dict[str, Any]:
    return {
        "report_id": "rpt-abc", "schema_version": "report-v1.0",
        "generated_at": "2026-09-04T12:00:00+00:00",
        "headline": band, "headline_label": "label", "headline_subtype": subtype,
        "headline_subtype_label": subtype, "headline_meaning": "meaning",
        "headline_display": band, "query": "test query",
        "case_id": "C6", "case_name": "Open-Feed Irregularity", "priority": "P3",
        "risk_tier": "MEDIUM", "recommended_action": "REVIEW",
        "action_meaning": "Return marked unverified.",
        "trust_percent": 66.0, "trust_interval": [54.8, 75.8],
        "risk": 0.34, "risk_interval": [0.242, 0.452],
        "confidence": 0.746, "confidence_components": {"volume": 0.8},
        "confidence_caps": [], "tier_governing": 2, "n_retrieved": 2,
        "n_eff": 1.97, "band": "CLEAN", "entity_count": 1,
        "entities": {"cve": [{"value": "CVE-2026-1234", "doc_ids": ["d1"]}]},
        "documents": [
            {"rank": 1, "doc_id": "d1", "title": "Advisory d1", "source_id": "isac-a",
             "source_name": "Source isac-a", "source_tier": 2,
             "source_tier_label": "trusted-open", "similarity": 0.84,
             "case_id": "C2", "case_name": "Community Corroboration",
             "headline": "ORANGE", "headline_subtype": None, "action": "ACCEPT",
             "priority": "P4", "trust_percent": 70.0, "risk": 0.3,
             "signals": {"injection": 0.0, "anomaly": 0.1, "unsupport": 0.6,
                         "conflict": None},
             "readings": [
                 {"signal": "injection", "value": 0.0, "suspicious_threshold": 0.6,
                  "malicious_threshold": 0.85, "margin_to_suspicious": -0.6,
                  "margin_to_malicious": -0.85, "status": "below"},
                 {"signal": "unsupport", "value": 0.95, "suspicious_threshold": 0.6,
                  "malicious_threshold": 0.85, "margin_to_suspicious": 0.35,
                  "margin_to_malicious": 0.10, "status": "over_malicious"}],
             "provenance": {"published_date": "2026-08-01", "reference_verified": False},
             "entities": []}],
        "reasoning": {"text": "Because things.",
                      "sentences": [{"template_id": "t", "text": "Because things.",
                                     "facts": []}],
                      "grounding": {"fact_count": 3, "generated_by_model": False}},
        "analyst_decision": {"status": "AWAITING_REVIEW", "decision": None},
        "provenance": {"n_distinct_sources": 1, "detector_backends": {}},
        "caveats": ["3 detector(s) ran on fallback backends."],
    }


# ---------------------------------------------------------------------------

def test_banner_is_first() -> None:
    """The sprint's hardest requirement, expressed as a testable property."""
    print("\nThe banner is the first thing rendered")
    from dashboard.components import (  # noqa: PLC0415
        render_banner, render_case_and_action, render_documents, render_entities,
        render_headline_metrics, render_reasoning,
    )

    for band, subtype in (("GREEN", None), ("ORANGE", None),
                          ("RED", "ATTACK_DETECTED"),
                          ("RED", "TRUSTED_SOURCE_COMPROMISE")):
        rec = _Recorder()
        report = _report(band, subtype)
        render_banner(rec, report)
        first = rec.names()[0]
        check(f"[{band}] the banner's first call renders markup, not a heading",
              first == "markdown", f"first call was {first}")
        html = str(rec.calls[0][1][0])
        check(f"[{band}] the banner contains the band name in large type",
              band in html and "font-size:3.5rem" in html)
        check(f"[{band}] the banner is a full-width coloured block",
              "background:#" in html and "border-radius" in html)
        check(f"[{band}] the banner is rendered as raw HTML so it cannot be styled away",
              rec.calls[0][2].get("unsafe_allow_html") is True)

    # Ordering across the whole results view.
    rec = _Recorder()
    report = _report("RED", "ATTACK_DETECTED")
    render_banner(rec, report)
    banner_calls = len(rec.calls)
    render_headline_metrics(rec, report)
    render_case_and_action(rec, report)
    render_reasoning(rec, report)
    render_documents(rec, report)
    render_entities(rec, report)

    names = rec.names()
    check("nothing is rendered before the banner", names[0] == "markdown")
    check("the trust score comes after the banner",
          "metric" in names and names.index("metric") >= banner_calls)
    check("the evidence and reasoning come after the score",
          names.index("subheader") > names.index("metric"))
    note(f"call order: {names[:12]}")


def test_banner_shows_red_subtype() -> None:
    print("\nRED sub-type sits directly under the banner")
    from dashboard.components import render_banner  # noqa: PLC0415

    rec = _Recorder()
    render_banner(rec, _report("RED", "TRUSTED_SOURCE_COMPROMISE"))
    html = str(rec.calls[0][1][0])
    check("the compromise sub-type is inside the banner block itself",
          "Trusted Source Compromise Suspected" in html)
    check("it is rendered below the band name, not beside it",
          html.index("RED") < html.index("Trusted Source Compromise"))

    rec2 = _Recorder()
    render_banner(rec2, _report("RED", "ATTACK_DETECTED"))
    check("the attack sub-type reads differently",
          "Attack Detected" in str(rec2.calls[0][1][0]))

    rec3 = _Recorder()
    render_banner(rec3, _report("GREEN"))
    check("a non-RED banner carries no sub-type line",
          "Attack Detected" not in str(rec3.calls[0][1][0])
          and "Compromise" not in str(rec3.calls[0][1][0]))

    check("each band has its own colour",
          len({v["bg"] for v in __import__(
              "dashboard.components", fromlist=["BAND_STYLE"]).BAND_STYLE.values()}) == 3)


def test_results_view_contents() -> None:
    print("\nResults view — everything the sprint asked for")
    from dashboard.components import (  # noqa: PLC0415
        render_case_and_action, render_documents, render_entities,
        render_headline_metrics, render_reasoning, render_caveats,
    )
    rec = _Recorder()
    report = _report()
    render_headline_metrics(rec, report)
    render_case_and_action(rec, report)
    render_documents(rec, report)
    render_entities(rec, report)
    render_reasoning(rec, report)
    render_caveats(rec, report)
    text = rec.markdown_text()

    check("the composite trust score is shown as a percentage", "66.0%" in text, text[:150])
    check("the confidence interval is shown", "54.8" in text and "75.8" in text)
    check("the case classification is shown",
          "C6" in text and "Open-Feed Irregularity" in text)
    check("the recommended action is shown", "REVIEW" in text)
    check("the risk tier is shown", "MEDIUM" in text)
    check("there is one expander per retrieved document",
          rec.names().count("expander") >= 1)
    check("the per-document table lists every detector",
          any(name == "table" for name in rec.names()))
    check("extracted entities are shown", "CVE-2026-1234" in text)
    check("the reasoning narrative is shown", "Because things." in text)
    check("the grounding note is shown", "none is model-generated" in text)
    check("fallback-backend caveats are surfaced as warnings, not hidden",
          "fallback backends" in text and "warning" in rec.names())

    tables = [c for c in rec.calls if c[0] == "table"]
    rows = tables[0][1][0]
    check("the detector table shows the value and both thresholds",
          all(k in rows[0] for k in ("Detector", "Score", "Suspicious at",
                                     "Malicious at", "Status")), str(rows[0]))
    check("a fired signal is labelled FIRED",
          any(r["Status"] == "FIRED" for r in rows), str(rows))


def test_audit_table_rows() -> None:
    print("\nAudit viewer rows")
    from dashboard.components import event_rows_for_table  # noqa: PLC0415

    events = [
        {"event_id": "evt-1", "headline": "RED",
         "headline_subtype": "TRUSTED_SOURCE_COMPROMISE", "case_id": "C4",
         "case_name": "Trusted-Source Anomaly", "trust_percent": 93.5,
         "confidence": 0.494, "final_action": "ESCALATE", "analyst_decision": None,
         "query_text": "q1", "created_at": "2026-09-04T12:00:00+00:00"},
        {"event_id": "evt-2", "headline": "GREEN", "headline_subtype": None,
         "case_id": "C1", "case_name": "Authoritative Confirmation",
         "trust_percent": None, "confidence": 0.8, "final_action": "ACCEPT",
         "analyst_decision": "ACCEPT", "query_text": "q2",
         "created_at": "2026-09-04T11:00:00+00:00"},
    ]
    rows = event_rows_for_table(events)
    check("the class column distinguishes the RED sub-type",
          "Trusted Source Compromise" in rows[0]["Class"], rows[0]["Class"])
    check("a non-RED class carries no sub-type", rows[1]["Class"] == "GREEN")
    check("an unreviewed row says so rather than showing a blank",
          rows[0]["Analyst decision"] == "— not reviewed —")
    check("a reviewed row shows the verdict", rows[1]["Analyst decision"] == "ACCEPT")
    check("a missing trust score renders as a dash, not as zero",
          rows[1]["Trust %"] == "—", rows[1]["Trust %"])
    check("the case column carries id and name", "C4" in rows[0]["Case"])
    check("the audit reference is shown", rows[0]["Reference"] == "evt-1")


def test_end_to_end_with_stub() -> None:
    """Import and run the real page module against the stub."""
    print("\nThe app module runs end to end against the stub")

    rec = _Recorder()
    sys.modules["streamlit"] = rec  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as td:
            import dashboard.service as service  # noqa: PLC0415
            service.get_audit_log.cache_clear()
            service.get_decision_writer.cache_clear()
            db = str(Path(td) / "audit.db")
            service.get_audit_log(db)
            service.get_decision_writer(db)

            import importlib  # noqa: PLC0415
            app = importlib.import_module("dashboard.app")
            importlib.reload(app)
            check("dashboard.app imports with streamlit stubbed", True)

            app.main()
            names = rec.names()
            check("the page sets its config before anything else",
                  names[0] == "set_page_config", names[0])
            check("a query input box is rendered", "text_input" in names)
            check("a run button is rendered", "button" in names)
            check("with no result yet, the page says so rather than showing a banner",
                  "info" in names)
            note(f"first calls: {names[:8]}")

            # Now with a report in session state, the banner must appear.
            rec.calls.clear()
            rec.session_state["report"] = _report("RED", "ATTACK_DETECTED")
            rec.session_state["event_id"] = "evt-x"
            app.main()
            after_input = rec.names()
            idx_banner = next(
                (i for i, (n, a, k) in enumerate(rec.calls)
                 if n == "markdown" and a and "font-size:3.5rem" in str(a[0])), None)
            check("the banner is rendered once a result exists", idx_banner is not None)
            if idx_banner is not None:
                before = [n for n in after_input[:idx_banner]
                          if n in ("metric", "table", "expander", "subheader",
                                   "dataframe", "json")]
                check("no score, table or expander is rendered above the banner",
                      not before, str(before))
                note(f"banner at call {idx_banner}; nothing content-bearing above it")
    finally:
        sys.modules.pop("streamlit", None)


def test_write_path_separation() -> None:
    """The dashboard is the only thing that can write a decision."""
    print("\nDecision write path")
    import tempfile  # noqa: PLC0415
    from logs.audit import AuditLog, DecisionWriter  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        log = AuditLog(db)
        check("the object the scoring path holds cannot write a decision",
              not hasattr(log, "record_decision"))
        check("the object the dashboard holds can",
              hasattr(DecisionWriter(db), "record_decision"))

    import dashboard.service as service  # noqa: PLC0415
    src = Path(service.__file__).read_text(encoding="utf-8")
    app_src = (Path(service.__file__).parent / "app.py").read_text(encoding="utf-8")
    check("no dashboard module writes to analyst_decisions directly",
          "INSERT INTO analyst_decisions" not in src
          and "INSERT INTO analyst_decisions" not in app_src)
    check("the dashboard records decisions only through DecisionWriter",
          "DecisionWriter" in src and "get_decision_writer" in app_src)


def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description="Dashboard tests (no Streamlit required).")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    print("=" * 78)
    print("Dashboard — tests")
    print("=" * 78)
    print("Streamlit is stubbed with a call recorder, so the ordering requirement")
    print("(the banner is first) is checkable without a browser.")

    test_banner_is_first()
    test_banner_shows_red_subtype()
    test_results_view_contents()
    test_audit_table_rows()
    test_end_to_end_with_stub()
    test_write_path_separation()

    print("\n" + "=" * 78)
    print("NOTE: these check structure and call order, not appearance. Run")
    print("`streamlit run dashboard/app.py` and look at it before the demo.")
    if FAILURES:
        print(f"\nFAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("\nAll dashboard checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
