"""
What the dashboard calls. No Streamlit imports here.

Keeping the work out of the page files means the pipeline can be exercised
without a browser — `test_dashboard.py` calls straight into `run_query` — and it
keeps the two write grants visible in one place: `get_audit_log()` hands out the
read/record-query object, `get_decision_writer()` hands out the only object in the
project that may insert an analyst decision.
"""

from __future__ import annotations

import sys
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logs.audit import DEFAULT_DB, AuditLog, DecisionWriter  # noqa: E402
from reports.schema import OVERRIDE_REASON_CODES  # noqa: E402

DEFAULT_K = 5


class ScoringUnavailable(RuntimeError):
    """Raised when a query cannot be scored — no index, no corpus, no backend.

    Distinct from a low-trust result. "We could not evaluate this" and "we
    evaluated this and it looks dangerous" are different answers, and collapsing
    them into one error message is how an analyst learns to ignore both.
    """


@lru_cache(maxsize=1)
def get_audit_log(db_path: str | None = None) -> AuditLog:
    return AuditLog(Path(db_path) if db_path else DEFAULT_DB)


@lru_cache(maxsize=1)
def get_decision_writer(db_path: str | None = None) -> DecisionWriter:
    """The only write grant on `analyst_decisions` in the whole system."""
    return DecisionWriter(Path(db_path) if db_path else DEFAULT_DB)


@lru_cache(maxsize=1)
def _rag() -> Any:
    from pipeline.rag import BaselineRAG  # noqa: PLC0415
    return BaselineRAG()


@lru_cache(maxsize=1)
def _scorer() -> Any:
    from fusion.scorer import FusionScorer  # noqa: PLC0415
    return FusionScorer.load(verbose=False)


def run_query(query: str, k: int = DEFAULT_K,
              db_path: str | None = None) -> tuple[dict[str, Any], str]:
    """Retrieve, score, build the report, log it. Returns (report dict, event id).

    Timings for each stage are attached to the report's provenance, because the
    evaluation needs the same numbers and computing them twice in two places is
    how two sets of latency figures end up disagreeing in a presentation.
    """
    from reports import build_report  # noqa: PLC0415

    t0 = time.perf_counter()
    try:
        retrieval = _rag().retrieve(query, k=k)
    except Exception as exc:
        raise ScoringUnavailable(
            f"retrieval failed ({type(exc).__name__}: {exc}). Has the index been "
            f"built? Run `python -m pipeline.build_index`.") from exc

    records = retrieval.records if hasattr(retrieval, "records") else retrieval
    if not records:
        raise ScoringUnavailable("retrieval returned no documents for this query")
    t_retrieval = time.perf_counter() - t0

    t1 = time.perf_counter()
    score = _scorer().score_query(query, records)
    t_scoring = time.perf_counter() - t1

    t2 = time.perf_counter()
    report = build_report(query, score, records)
    t_report = time.perf_counter() - t2

    report.provenance["timings_ms"] = {
        "retrieval": round(t_retrieval * 1000, 2),
        "scoring": round(t_scoring * 1000, 2),
        "report": round(t_report * 1000, 2),
        "total": round((time.perf_counter() - t0) * 1000, 2),
    }

    event_id = get_audit_log(db_path).record_query(report)
    return report.to_dict(), event_id


def list_events(**kwargs: Any) -> list[dict[str, Any]]:
    return get_audit_log().list_events(**kwargs)


def distinct_cases() -> list[str]:
    rows = get_audit_log().list_events(limit=5000)
    return sorted({r["case_id"] for r in rows if r.get("case_id")})


__all__ = [
    "run_query", "list_events", "distinct_cases", "get_audit_log",
    "get_decision_writer", "ScoringUnavailable", "OVERRIDE_REASON_CODES", "DEFAULT_K",
]
