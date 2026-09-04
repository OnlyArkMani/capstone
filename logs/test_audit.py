#!/usr/bin/env python3
"""
Tests for the audit log.

The invariant under test is design §5.8: **`analyst_decision` is never populated
by the system.** Most of these checks exist to prove that a future edit cannot
quietly break it — the schema has no DEFAULT, the pipeline's class has no method
that reaches the table, and an unreviewed event is the absence of a row rather
than a sentinel that some later aggregate forgets to exclude.

    python -m logs.test_audit
    python -m logs.test_audit --verbose
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.records import Provenance, RetrievedRecord  # noqa: E402
from fusion.bands import BandThresholds  # noqa: E402
from fusion.scorer import FusionScorer  # noqa: E402
from reports import build_report  # noqa: E402

from logs.audit import (  # noqa: E402
    AuditLog, DecisionInput, DecisionWriter, SCHEMA_VERSION, SOURCE_ANALYST_UI,
)

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
# Fixtures
# ---------------------------------------------------------------------------

TIER_LABEL = {1: "verified-authoritative", 2: "trusted-open", 3: "unverified"}

FIRING = BandThresholds(
    suspicious={"unsupport": 0.60, "anomaly": 0.20, "injection": 0.60, "conflict": 0.60},
    malicious={"unsupport": 0.85, "anomaly": 0.40, "injection": 0.85, "conflict": 0.85},
    n_clean_calibration=100, fitted=True, note="fixture")

_SCORER: FusionScorer | None = None


def rec(doc_id: str, tier: int, similarity: float = 0.8, source_id: str | None = None,
        content: str = "") -> RetrievedRecord:
    sid = source_id or f"src-t{tier}"
    return RetrievedRecord(
        rank=0, doc_id=doc_id, similarity=similarity, raw_score=similarity,
        title=f"Advisory {doc_id}", summary="fixture",
        content=content or ("Ransomware affecting imaging systems. CVE-2026-1234 at "
                            "203.0.113.45. Patch and segment."),
        provenance=Provenance(
            source_id=sid, source_name=f"Source {sid}", source_tier=tier,
            source_tier_label=TIER_LABEL[tier], source_type="advisory",
            published_date="2026-08-01", ingestion_date="2026-09-01",
            reference_verified=(tier == 1)))


def make_report(docs, query: str = "ransomware targeting hospital imaging"):
    global _SCORER
    if _SCORER is None:
        _SCORER = FusionScorer.load(verbose=False)
        _SCORER.bands = FIRING
    return build_report(query, _SCORER.score_query(query, docs), docs, thresholds=FIRING)


DOCS = [rec("d1", 2, 0.84, "isac-a"), rec("d2", 2, 0.71, "isac-b"),
        rec("d3", 3, 0.66, "blog-c")]
T1_DOCS = [rec("cisa-1", 1, 0.9, "cisa"), rec("hhs-1", 1, 0.7, "hhs")]


# ---------------------------------------------------------------------------

def test_schema() -> None:
    print("\nSchema")
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        log = AuditLog(db)
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            views = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='view'")}
            ddl = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name='analyst_decisions'"
            ).fetchone()[0]

        check("both tables exist",
              {"query_events", "analyst_decisions"} <= tables, str(tables))
        check("the three design views exist",
              {"v_current_decisions", "v_labelled_decisions", "v_pending_review"} <= views,
              str(views))

        # The load-bearing absence.
        decision_line = [ln for ln in ddl.splitlines()
                         if "analyst_decision " in ln and "system" not in ln][0]
        check("analyst_decision is NOT NULL", "NOT NULL" in decision_line, decision_line)
        check("analyst_decision has NO DEFAULT clause — the absence is load-bearing",
              "DEFAULT" not in decision_line.upper(), decision_line)
        check("a CHECK constrains it to the three verdicts",
              "CHECK (analyst_decision IN ('ACCEPT','REJECT','OVERRIDE'))" in ddl)
        check("the schema version is recorded", SCHEMA_VERSION.startswith("audit-v"))

        # A raw insert with no verdict must be refused by the database itself.
        refused = False
        try:
            with sqlite3.connect(db) as conn:
                conn.execute("INSERT INTO analyst_decisions (decision_id, event_id, "
                             "analyst_id, system_recommended_action, system_case_id, "
                             "system_confidence, system_headline, decided_at, logged_at, "
                             "decision_source, system_action_shown, prev_row_hash, row_hash) "
                             "VALUES ('d','e','a','ACCEPT','C1',0.5,'GREEN','t','t','x','ACCEPT','h','h')")
        except sqlite3.IntegrityError:
            refused = True
        check("the database refuses a decision row with no verdict", refused)


def test_record_query() -> None:
    print("\nRecording a scored query")
    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "a.db")
        report = make_report(DOCS)
        event_id = log.record_query(report)

        check("record_query returns a unique reference ID",
              event_id.startswith("evt-") and len(event_id) > 10, event_id)
        note(f"event id: {event_id}")

        event = log.get_event(event_id)
        check("the event round-trips", event is not None)
        check("the query text is stored", event["query_text"] == report.query)
        check("a timestamp is stored", bool(event["created_at"]))
        check("the headline band is stored",
              event["headline"] == report.headline, event["headline"])
        check("the case, action and priority are stored",
              event["case_id"] == report.case_id
              and event["final_action"] == report.recommended_action
              and event["risk_priority"] == report.priority)
        check("both track proposals are stored separately from the final action",
              event["taxonomy_action"] and event["score_action"])
        check("confidence and its components are stored",
              event["confidence"] == report.confidence
              and json.loads(event["confidence_components"]))

        docs = json.loads(event["documents"])
        check("every retrieved document is stored with its scores",
              len(docs) == len(DOCS)
              and all(isinstance(d["signals"], dict) for d in docs))
        check("each stored document carries every detector's individual score",
              all(set(d["signals"]) == {"unsupport", "anomaly", "injection", "conflict"}
                  for d in docs))
        check("response-level signal maxima are stored",
              "injection_probability_max" in event)
        check("retrieved doc ids are stored as a JSON array",
              json.loads(event["retrieved_doc_ids"]) == [d.doc_id for d in DOCS])
        check("entities and reasoning are stored",
              json.loads(event["entities"]) is not None
              and json.loads(event["reasoning"])["text"])
        check("whether the detectors were real models is recorded",
              event["backends_are_models"] in (0, 1))
        note(f"backends_are_models = {event['backends_are_models']}")


def test_red_subtype_stored() -> None:
    print("\nRED sub-type")
    with tempfile.TemporaryDirectory() as td:
        log = AuditLog(Path(td) / "a.db")
        everything = BandThresholds(
            suspicious={"unsupport": 0.01, "anomaly": 0.01, "injection": 0.6, "conflict": 0.6},
            malicious={"unsupport": 0.99, "anomaly": 0.99, "injection": 0.85, "conflict": 0.85},
            n_clean_calibration=100, fitted=True, note="fixture")
        s = FusionScorer.load(verbose=False)
        s.bands = everything
        r1 = build_report("q", s.score_query("q", T1_DOCS), T1_DOCS, thresholds=everything)
        t3 = [rec("b1", 3, 0.9, "blog-a"), rec("b2", 3, 0.7, "blog-b")]
        r3 = build_report("q", s.score_query("q", t3), t3, thresholds=everything)

        e1 = log.get_event(log.record_query(r1))
        e3 = log.get_event(log.record_query(r3))

        check("a Tier-1 RED stores the compromise sub-type",
              e1["headline"] == "RED"
              and e1["headline_subtype"] == "TRUSTED_SOURCE_COMPROMISE",
              f"{e1['headline']}/{e1['headline_subtype']}")
        check("a Tier-3 RED stores the attack sub-type",
              e3["headline"] == "RED" and e3["headline_subtype"] == "ATTACK_DETECTED",
              f"{e3['headline']}/{e3['headline_subtype']}")
        check("the sub-types are distinguishable in the log",
              e1["headline_subtype"] != e3["headline_subtype"])

        # The schema itself must enforce the pairing.
        bad = False
        try:
            with sqlite3.connect(log.db_path) as conn:
                conn.execute("UPDATE query_events SET headline_subtype = NULL "
                             "WHERE event_id = ?", (e1["event_id"],))
        except sqlite3.IntegrityError:
            bad = True
        check("the schema refuses a RED event with no sub-type", bad)


def test_decision_never_auto_populated() -> None:
    """The central invariant."""
    print("\nanalyst_decision is never set by the system (design 5.8)")
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        log = AuditLog(db)
        event_id = log.record_query(make_report(DOCS))

        check("a freshly recorded event has NO decision row",
              log.current_decision(event_id) is None)
        check("undecided is the absence of a row, not a stored sentinel",
              all("PENDING" not in str(v) for v in (log.get_event(event_id) or {}).values()))

        # Layer two: the pipeline's class physically cannot write a decision.
        check("AuditLog has no method that writes a decision",
              not any(hasattr(log, m) for m in
                      ("record_decision", "set_decision", "write_decision",
                       "update_decision", "correct_decision")),
              str([m for m in dir(log) if "decision" in m and not m.startswith("_")]))
        writable = [m for m in dir(log) if "decision" in m.lower()
                    and not m.startswith("_")]
        check("the only decision methods on AuditLog are read-only",
              set(writable) <= {"current_decision", "labelled_decisions"}, str(writable))

        check("the event appears in the pending-review queue",
              event_id in [e["event_id"] for e in log.pending_review()])

        # And it leaves the queue only once a human acts.
        writer = DecisionWriter(db)
        writer.record_decision(event_id, DecisionInput(decision="ACCEPT",
                                                       analyst_id="analyst-01"))
        check("after a human decides, the event leaves the pending queue",
              event_id not in [e["event_id"] for e in log.pending_review()])
        check("and a decision row now exists",
              (log.current_decision(event_id) or {}).get("analyst_decision") == "ACCEPT")


def test_decision_writer() -> None:
    print("\nDecisionWriter — validation and updates after the fact")
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        log = AuditLog(db)
        writer = DecisionWriter(db)
        event_id = log.record_query(make_report(DOCS))

        for bad in ("PENDING", "MAYBE", "", "accept", None):
            raised = False
            try:
                writer.record_decision(event_id, DecisionInput(decision=bad, analyst_id="a"))
            except (ValueError, TypeError):
                raised = True
            check(f"a verdict of {bad!r} is rejected", raised)

        raised = False
        try:
            writer.record_decision(event_id, DecisionInput(
                decision="OVERRIDE", analyst_id="a"))
        except ValueError:
            raised = True
        check("an OVERRIDE with no action and reason code is rejected", raised)

        raised = False
        try:
            writer.record_decision(event_id, DecisionInput(
                decision="OVERRIDE", analyst_id="a", override_action="REJECT",
                override_reason_code="OTHER"))
        except ValueError:
            raised = True
        check("reason code OTHER with no free text is rejected", raised)

        raised = False
        try:
            writer.record_decision("evt-does-not-exist",
                                   DecisionInput(decision="ACCEPT", analyst_id="a"))
        except ValueError:
            raised = True
        check("a decision on a non-existent event is rejected", raised)

        dec_id = writer.record_decision(event_id, DecisionInput(
            decision="OVERRIDE", analyst_id="analyst-01", analyst_role="tier2_soc",
            override_action="ESCALATE",
            override_reason_code="MISSED_ATTACK_SYSTEM_UNDERSCORED",
            per_document_verdicts=[{"doc_id": "d1", "verdict": "POISONED", "note": "n"}],
            analyst_confidence=4, time_to_decision_ms=42000))
        check("a valid override is written", dec_id.startswith("dec-"))

        d = log.current_decision(event_id)
        check("the decision is readable back", d["analyst_decision"] == "OVERRIDE")
        check("the system's own recommendation is snapshotted onto the row",
              d["system_recommended_action"] and d["system_case_id"]
              and d["system_headline"])
        check("per-document verdicts are stored",
              json.loads(d["per_document_verdicts"])[0]["verdict"] == "POISONED")
        check("decision latency is stored (it measures what a false alarm costs)",
              d["time_to_decision_ms"] == 42000)
        check("the write path is recorded as provenance",
              d["decision_source"] == SOURCE_ANALYST_UI)


def test_supersede_and_chain() -> None:
    print("\nCorrections and the hash chain")
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        log, writer = AuditLog(db), DecisionWriter(db)
        e1 = log.record_query(make_report(DOCS))
        e2 = log.record_query(make_report(DOCS, "second query"))

        first = writer.record_decision(e1, DecisionInput(decision="ACCEPT", analyst_id="a1"))
        writer.record_decision(e2, DecisionInput(decision="REJECT", analyst_id="a2"))
        second = writer.correct_decision(e1, DecisionInput(
            decision="OVERRIDE", analyst_id="a1", override_action="REJECT",
            override_reason_code="MISSED_ATTACK_SYSTEM_UNDERSCORED"))

        current = log.current_decision(e1)
        check("the correction supersedes the original",
              current["decision_id"] == second
              and current["supersedes_decision_id"] == first)

        with sqlite3.connect(db) as conn:
            n = conn.execute("SELECT COUNT(*) FROM analyst_decisions "
                             "WHERE event_id = ?", (e1,)).fetchone()[0]
        check("the original row is kept, not edited or deleted", n == 2)

        chain = log.verify_chain()
        check("the hash chain verifies", chain["ok"], str(chain))
        check("the chain covers every decision row", chain["n_rows"] == 3, str(chain))
        note(f"chain head: {chain['head'][:16]}...")

        # Tamper, and prove the chain notices.
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE analyst_decisions SET analyst_decision = 'ACCEPT' "
                         "WHERE decision_id = ?", (second,))
        broken = log.verify_chain()
        check("editing a historical row breaks the chain",
              not broken["ok"], str(broken))
        note(f"break reported at row {broken.get('broken_at')}: {broken.get('reason')}")


def test_filters_and_stats() -> None:
    print("\nFiltering and stats — what the audit viewer needs")
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "a.db"
        log, writer = AuditLog(db), DecisionWriter(db)

        ids = [log.record_query(make_report(DOCS, f"query {i}")) for i in range(4)]
        writer.record_decision(ids[0], DecisionInput(decision="ACCEPT", analyst_id="a"))
        writer.record_decision(ids[1], DecisionInput(decision="REJECT", analyst_id="a"))

        rows = log.list_events()
        check("every event is listed", len(rows) == 4)
        check("the listing carries the current decision where one exists",
              sum(1 for r in rows if r["analyst_decision"]) == 2)
        check("unreviewed events show a null decision rather than a sentinel",
              all(r["analyst_decision"] is None for r in rows
                  if r["event_id"] in ids[2:]))

        band = rows[0]["headline"]
        check("filtering by headline class works",
              all(r["headline"] == band for r in log.list_events(headline=band)))
        case = rows[0]["case_id"]
        check("filtering by case classification works",
              all(r["case_id"] == case for r in log.list_events(case_id=case)))
        check("filtering by analyst decision works",
              [r["event_id"] for r in log.list_events(decision="ACCEPT")] == [ids[0]])
        check("filtering for unreviewed works without a sentinel value",
              sorted(r["event_id"] for r in log.list_events(decision="UNREVIEWED"))
              == sorted(ids[2:]))

        s = log.stats()
        check("stats count events, decisions and the unreviewed remainder",
              s["total_events"] == 4 and s["decided"] == 2 and s["unreviewed"] == 2,
              str(s))
        note(f"stats: {s}")

        labelled = log.labelled_decisions()
        check("the labelled view returns only analyst-written rows",
              len(labelled) == 2 and all(d["decision_source"] == SOURCE_ANALYST_UI
                                         for d in labelled))

        # A non-analyst source is recorded but excluded from the label set.
        importer = DecisionWriter(db, source="import")
        importer.record_decision(ids[2], DecisionInput(decision="ACCEPT", analyst_id="bot"))
        check("an imported decision is stored",
              log.current_decision(ids[2]) is not None)
        check("but is excluded from the labelled view",
              len(log.labelled_decisions()) == 2,
              f"{len(log.labelled_decisions())} labelled rows")


def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description="Tests for the audit log.")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    print("=" * 78)
    print("Audit log — tests")
    print("=" * 78)
    print("Central invariant: analyst_decision is never populated by the system.")

    test_schema()
    test_record_query()
    test_red_subtype_stored()
    test_decision_never_auto_populated()
    test_decision_writer()
    test_supersede_and_chain()
    test_filters_and_stats()

    print("\n" + "=" * 78)
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All audit log checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
