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
    """The scorer shares the retriever's embedder rather than resolving its own.

    getattr rather than attribute access because _rag() may hold a retriever that
    has not resolved an embedder yet; embedder=None is a supported argument and
    the anomaly detector falls back cleanly. The point of passing it is that the
    console and the retrieval path then demonstrably score against the SAME
    vector space, which is a correctness property, not only a speed one.
    """
    from fusion.scorer import FusionScorer  # noqa: PLC0415
    embedder = getattr(getattr(_rag(), "retriever", None), "embedder", None)
    scorer = FusionScorer.load(embedder=embedder, verbose=False)
    # Encode the corpus once here rather than a retrieval set at a time inside
    # the first few queries an analyst runs. Same vectors, moved off the wait.
    scorer.warm_documents(getattr(getattr(_rag(), "retriever", None), "documents", []))
    return scorer


# The stages a caller can be told about, in the order they happen, with the
# words an analyst should see. They live here rather than in the page file
# because the sequence is a property of the pipeline: if a stage is added or
# reordered, this is the list that has to change, and the console then follows.
STAGES: dict[str, str] = {
    "retrieval": "Retrieving evidence…",
    "security": "Running security checks…",
    "report": "Building the analyst report…",
    "audit": "Recording to the audit log…",
    "done": "Security checks complete",
}


def run_query(query: str, k: int = DEFAULT_K,
              db_path: str | None = None,
              on_stage: Any | None = None) -> tuple[dict[str, Any], str]:
    """Retrieve, score, build the report, log it. Returns (report dict, event id).

    Timings for each stage are attached to the report's provenance, because the
    evaluation needs the same numbers and computing them twice in two places is
    how two sets of latency figures end up disagreeing in a presentation.

    `on_stage(key, label)` is called as each stage begins, so a caller with a
    user in front of it can say which one is running. It is optional and purely
    advisory: nothing here waits on it, and a caller that does not pass one gets
    exactly the behaviour it got before. Exceptions raised by the callback are
    swallowed -- a progress indicator must never be able to fail a query.
    """
    from reports import build_report  # noqa: PLC0415

    def stage(key: str) -> None:
        if on_stage is None:
            return
        try:
            on_stage(key, STAGES.get(key, key))
        except Exception:
            pass

    stage("retrieval")
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

    stage("security")
    t1 = time.perf_counter()
    score = _scorer().score_query(query, records)
    t_scoring = time.perf_counter() - t1

    stage("report")
    t2 = time.perf_counter()
    report = build_report(query, score, records)
    t_report = time.perf_counter() - t2

    report.provenance["timings_ms"] = {
        "retrieval": round(t_retrieval * 1000, 2),
        "scoring": round(t_scoring * 1000, 2),
        "report": round(t_report * 1000, 2),
        "total": round((time.perf_counter() - t0) * 1000, 2),
    }

    stage("audit")
    event_id = get_audit_log(db_path).record_query(report)
    stage("done")
    return report.to_dict(), event_id


def list_events(**kwargs: Any) -> list[dict[str, Any]]:
    return get_audit_log().list_events(**kwargs)


def distinct_cases() -> list[str]:
    rows = get_audit_log().list_events(limit=5000)
    return sorted({r["case_id"] for r in rows if r.get("case_id")})


__all__ = [
    "run_query", "list_events", "distinct_cases", "get_audit_log",
    "get_decision_writer", "ScoringUnavailable", "OVERRIDE_REASON_CODES", "DEFAULT_K",
    "STAGES",
]
