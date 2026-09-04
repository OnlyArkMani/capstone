"""
The audit log — SQLite, append-only, hash-chained.

Implements design §5.2 (`query_events`), §5.3 (`analyst_decisions`), §5.8 (the
decision lifecycle) and §5.9 (the query views).

Two tables, and the separation between them is the point
--------------------------------------------------------
`query_events` is what the *system* did: the query, what was retrieved, every
detector score, the composite, the headline band, the case, and what it
recommended. Written automatically on every scored query.

`analyst_decisions` is what a *human* concluded. Written only when a person acts.

**The write paths are separate classes, and that is deliberate.** `AuditLog`
records query events and physically cannot insert a decision — the method does
not exist on it. Only `DecisionWriter` can, and it is the class the dashboard
holds. Design §5.8 asks for three enforcement layers; this module supplies all
three:

1. **Schema.** `analyst_decision` is `NOT NULL` with a `CHECK` and *no `DEFAULT`*.
   The database will not invent a value. The absence of a `DEFAULT` is
   load-bearing and must survive any future migration.
2. **Write-path separation.** Two classes, one grant each.
3. **Provenance.** `decision_source` records who wrote the row, and the
   `v_labelled_decisions` view excludes anything that is not `analyst_ui`, so a
   backfill or an import cannot silently become training data.

An unreviewed event has **no row here at all** — not a NULL, and specifically not
a `PENDING` sentinel. A sentinel sitting in the same column as real verdicts means
every future aggregate has to remember to exclude it, and the first query that
forgets is silently wrong rather than an error. The cost is one `LEFT JOIN` in the
queue query. That is the right trade.

Hash chaining
-------------
Each decision row carries `prev_row_hash` and `row_hash`, where `row_hash` is
SHA-256 over the canonical JSON of the row plus its predecessor's hash. Tampering
with any historical row breaks every hash after it, and `verify_chain()` reports
where. This costs nothing — no dependency, one hash per insert — and makes the
decision history evidence rather than merely data.

Corrections never edit. A corrected decision is a NEW row whose
`supersedes_decision_id` points at the original; `v_current_decisions` resolves
the chain to its head.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_DB = Path(__file__).resolve().parent / "audit.db"
SCHEMA_VERSION = "audit-v1.0"

DECISION_VALUES = ("ACCEPT", "REJECT", "OVERRIDE")
OVERRIDE_ACTIONS = ("ACCEPT", "REVIEW", "REJECT", "ESCALATE")
HEADLINE_BANDS = ("GREEN", "ORANGE", "RED")
RED_SUBTYPES = ("ATTACK_DETECTED", "TRUSTED_SOURCE_COMPROMISE")

# Only rows written by a human through the dashboard are eligible to become
# training labels. Anything else is recorded but excluded by the labelled view.
SOURCE_ANALYST_UI = "analyst_ui"
DECISION_SOURCES = (SOURCE_ANALYST_UI, "import", "backfill", "test_fixture")

GENESIS_HASH = "0" * 64


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS query_events (
    event_id                   TEXT PRIMARY KEY,
    created_at                 TEXT NOT NULL,
    query_text                 TEXT NOT NULL,
    query_hash                 TEXT NOT NULL,
    retrieved_doc_ids          TEXT NOT NULL,
    cited_doc_ids              TEXT NOT NULL,
    generated_answer           TEXT,

    -- per-document detail: every detector score on every retrieved document
    documents                  TEXT NOT NULL,

    -- response-level detector signals
    entailment_score           REAL,
    anomaly_score_max          REAL,
    injection_probability_max  REAL,
    conflict_score             REAL,
    d_conflict_max             REAL,

    feature_vector             TEXT,

    tier_governing             INTEGER NOT NULL,
    tier_min                   INTEGER,
    n_retrieved                INTEGER NOT NULL,
    n_eff                      REAL NOT NULL,
    band                       TEXT,

    case_id                    TEXT NOT NULL,
    case_name                  TEXT,
    all_matched_cases          TEXT NOT NULL,
    taxonomy_action            TEXT NOT NULL,
    risk_score                 REAL,
    risk_p_upper               REAL,
    trust_percent              REAL,
    trust_low                  REAL,
    trust_high                 REAL,
    score_action               TEXT NOT NULL,
    confidence                 REAL NOT NULL,
    confidence_components      TEXT NOT NULL,
    final_action               TEXT NOT NULL,
    risk_priority              TEXT NOT NULL,

    -- design 2.9: the headline band an analyst reads first
    headline                   TEXT NOT NULL,
    headline_subtype           TEXT,
    headline_rule              TEXT,
    risk_tier                  TEXT,

    entities                   TEXT,
    reasoning                  TEXT,

    model_version              TEXT NOT NULL,
    threshold_set_version      TEXT NOT NULL,
    taxonomy_version           TEXT NOT NULL,
    detector_versions          TEXT NOT NULL,
    backends_are_models        INTEGER NOT NULL DEFAULT 0,

    is_verification_sample     INTEGER NOT NULL DEFAULT 0,

    CHECK (headline IN ('GREEN','ORANGE','RED')),
    CHECK (headline != 'RED' OR headline_subtype IS NOT NULL),
    CHECK (headline = 'RED' OR headline_subtype IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_qe_created  ON query_events(created_at);
CREATE INDEX IF NOT EXISTS idx_qe_headline ON query_events(headline);
CREATE INDEX IF NOT EXISTS idx_qe_case     ON query_events(case_id);
CREATE INDEX IF NOT EXISTS idx_qe_action   ON query_events(final_action);

-- analyst_decision is NOT NULL with no DEFAULT. That absence is load-bearing:
-- it is what makes "never auto-populated" enforceable rather than aspirational.
CREATE TABLE IF NOT EXISTS analyst_decisions (
    decision_id                TEXT PRIMARY KEY,
    event_id                   TEXT NOT NULL REFERENCES query_events(event_id),
    analyst_id                 TEXT NOT NULL,
    analyst_role               TEXT,

    system_recommended_action  TEXT NOT NULL,
    system_case_id             TEXT NOT NULL,
    system_risk_score          REAL,
    system_confidence          REAL NOT NULL,
    system_headline            TEXT NOT NULL,

    analyst_decision           TEXT NOT NULL,
    override_action            TEXT,
    override_reason_code       TEXT,
    override_reason_text       TEXT,

    per_document_verdicts      TEXT,

    analyst_confidence         INTEGER,
    time_to_decision_ms        INTEGER,

    decided_at                 TEXT NOT NULL,
    logged_at                  TEXT NOT NULL,
    review_started_at          TEXT,

    decision_source            TEXT NOT NULL,
    system_action_shown        TEXT NOT NULL,

    supersedes_decision_id     TEXT REFERENCES analyst_decisions(decision_id),
    prev_row_hash              TEXT NOT NULL,
    row_hash                   TEXT NOT NULL,

    CHECK (analyst_decision IN ('ACCEPT','REJECT','OVERRIDE')),
    CHECK (analyst_decision != 'OVERRIDE'
           OR (override_action IS NOT NULL AND override_reason_code IS NOT NULL)),
    CHECK (override_reason_code != 'OTHER' OR override_reason_text IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_ad_event   ON analyst_decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_ad_code    ON analyst_decisions(override_reason_code);
CREATE INDEX IF NOT EXISTS idx_ad_decided ON analyst_decisions(decided_at);

-- Design 5.9. The head of every supersede chain: the decision that currently stands.
CREATE VIEW IF NOT EXISTS v_current_decisions AS
SELECT d.*
FROM analyst_decisions d
WHERE NOT EXISTS (
    SELECT 1 FROM analyst_decisions s WHERE s.supersedes_decision_id = d.decision_id
);

-- Design 5.9. The only sanctioned source of labels for a future recalibration:
-- current decisions, written by a human, that actually express a judgement.
CREATE VIEW IF NOT EXISTS v_labelled_decisions AS
SELECT d.*, e.query_text, e.headline, e.headline_subtype, e.case_id, e.final_action
FROM v_current_decisions d
JOIN query_events e ON e.event_id = d.event_id
WHERE d.decision_source = 'analyst_ui'
  AND d.override_reason_code IS NOT 'INSUFFICIENT_EVIDENCE_TO_JUDGE';

-- The analyst queue: events with no decision yet. Undecided is the ABSENCE of a
-- row, so this is a LEFT JOIN and not a status filter.
CREATE VIEW IF NOT EXISTS v_pending_review AS
SELECT e.*
FROM query_events e
LEFT JOIN v_current_decisions d ON d.event_id = e.event_id
WHERE d.decision_id IS NULL;
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(payload: dict[str, Any]) -> str:
    """Stable serialisation, so a hash computed today matches one recomputed later."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _jdump(value: Any) -> str:
    return json.dumps(value, default=str)


# ---------------------------------------------------------------------------
# Reading and writing query events
# ---------------------------------------------------------------------------

class AuditLog:
    """Records what the system did. **Cannot write an analyst decision.**

    There is no method here that inserts into `analyst_decisions`, and that is the
    second of the three enforcement layers in design §5.8. The scoring pipeline
    holds an instance of this class; it does not hold a `DecisionWriter`.
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                (SCHEMA_VERSION,))

    # ---------------- writing ----------------

    def record_query(self, report: Any, *, generated_answer: str | None = None,
                     is_verification_sample: bool = False) -> str:
        """Write one scored query. Returns the event's reference ID.

        Takes a `reports.Report` — which already holds everything the schema wants,
        assembled once — rather than re-deriving any of it here. A second derivation
        is a second implementation, and the two drift.
        """
        r = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        event_id = f"evt-{uuid.uuid4()}"
        prov = r.get("provenance", {}) or {}
        docs = r.get("documents", []) or []

        def _sig_max(name: str) -> float | None:
            vals = [d["signals"].get(name) for d in docs
                    if isinstance(d.get("signals"), dict)
                    and d["signals"].get(name) is not None]
            return max(vals) if vals else None

        backends = prov.get("detector_backends") or {}
        all_real = bool(backends) and all(
            isinstance(v, dict) and v.get("is_model") is True for v in backends.values())

        row = {
            "event_id": event_id,
            "created_at": r.get("generated_at") or _now(),
            "query_text": r["query"],
            "query_hash": _sha256(r["query"]),
            "retrieved_doc_ids": _jdump([d["doc_id"] for d in docs]),
            "cited_doc_ids": _jdump([d["doc_id"] for d in docs]),
            "generated_answer": generated_answer,
            "documents": _jdump(docs),
            "entailment_score": _sig_max("unsupport"),
            "anomaly_score_max": _sig_max("anomaly"),
            "injection_probability_max": _sig_max("injection"),
            "conflict_score": _sig_max("conflict"),
            "d_conflict_max": prov.get("d_conflict_max"),
            "feature_vector": _jdump(prov.get("feature_vector")),
            "tier_governing": r["tier_governing"],
            "tier_min": max((d["source_tier"] for d in docs), default=None),
            "n_retrieved": r["n_retrieved"],
            "n_eff": r["n_eff"],
            "band": r.get("band"),
            "case_id": r["case_id"],
            "case_name": r.get("case_name"),
            "all_matched_cases": _jdump(prov.get("all_matched_cases", [])),
            "taxonomy_action": prov.get("taxonomy_action") or r["recommended_action"],
            "risk_score": r.get("risk"),
            "risk_p_upper": (r.get("risk_interval") or [None, None])[1],
            "trust_percent": r.get("trust_percent"),
            "trust_low": (r.get("trust_interval") or [None, None])[0],
            "trust_high": (r.get("trust_interval") or [None, None])[1],
            "score_action": prov.get("score_action") or r["recommended_action"],
            "confidence": r["confidence"],
            "confidence_components": _jdump(r.get("confidence_components", {})),
            "final_action": r["recommended_action"],
            "risk_priority": r["priority"],
            "headline": r["headline"],
            "headline_subtype": r.get("headline_subtype"),
            "headline_rule": prov.get("headline_rule"),
            "risk_tier": r.get("risk_tier"),
            "entities": _jdump(r.get("entities", {})),
            "reasoning": _jdump(r.get("reasoning", {})),
            "model_version": str(prov.get("model_fitted")),
            "threshold_set_version": str(prov.get("bands_fitted")),
            "taxonomy_version": "design-v1.2",
            "detector_versions": _jdump(backends),
            "backends_are_models": int(all_real),
            "is_verification_sample": int(is_verification_sample),
        }

        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        with self._conn() as conn:
            conn.execute(f"INSERT INTO query_events ({cols}) VALUES ({marks})",
                         tuple(row.values()))
        return event_id

    # ---------------- reading ----------------

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM query_events WHERE event_id = ?",
                               (event_id,)).fetchone()
        return dict(row) if row else None

    def list_events(
        self,
        *,
        headline: str | None = None,
        case_id: str | None = None,
        decision: str | None = None,
        subtype: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Recent events with their current decision, if any.

        `decision` accepts the three verdicts plus the sentinel-free spelling of
        "not yet reviewed": `UNREVIEWED`, which is expressed as a NULL join result
        rather than as a stored value.
        """
        sql = ["""
            SELECT e.*, d.analyst_decision, d.override_action, d.override_reason_code,
                   d.decided_at, d.analyst_id
            FROM query_events e
            LEFT JOIN v_current_decisions d ON d.event_id = e.event_id
            WHERE 1 = 1"""]
        params: list[Any] = []
        if headline:
            sql.append("AND e.headline = ?"); params.append(headline)
        if subtype:
            sql.append("AND e.headline_subtype = ?"); params.append(subtype)
        if case_id:
            sql.append("AND e.case_id = ?"); params.append(case_id)
        if decision == "UNREVIEWED":
            sql.append("AND d.analyst_decision IS NULL")
        elif decision:
            sql.append("AND d.analyst_decision = ?"); params.append(decision)
        sql.append("ORDER BY e.created_at DESC, e.rowid DESC LIMIT ?")
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(" ".join(sql), tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def current_decision(self, event_id: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM v_current_decisions WHERE event_id = ?", (event_id,)).fetchone()
        return dict(row) if row else None

    def pending_review(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM v_pending_review ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def labelled_decisions(self) -> list[dict[str, Any]]:
        """The sanctioned label source for a future recalibration (design §5.9)."""
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM v_labelled_decisions").fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM query_events").fetchone()["c"]
            by_band = {r["headline"]: r["c"] for r in conn.execute(
                "SELECT headline, COUNT(*) c FROM query_events GROUP BY headline")}
            by_case = {r["case_id"]: r["c"] for r in conn.execute(
                "SELECT case_id, COUNT(*) c FROM query_events GROUP BY case_id")}
            decided = conn.execute(
                "SELECT COUNT(*) c FROM v_current_decisions").fetchone()["c"]
            by_decision = {r["analyst_decision"]: r["c"] for r in conn.execute(
                "SELECT analyst_decision, COUNT(*) c FROM v_current_decisions "
                "GROUP BY analyst_decision")}
        return {
            "total_events": total, "by_headline": by_band, "by_case": by_case,
            "decided": decided, "unreviewed": total - decided,
            "by_decision": by_decision,
        }

    # ---------------- integrity ----------------

    def verify_chain(self) -> dict[str, Any]:
        """Recompute every decision hash and report the first break.

        Cheap to run and worth running before quoting the decision history as
        evidence. A break does not prove tampering — a schema change would do it
        too — but an intact chain does mean no row was edited after it was written.
        """
        with self._conn() as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM analyst_decisions ORDER BY rowid")]
        prev = GENESIS_HASH
        for i, row in enumerate(rows):
            if row["prev_row_hash"] != prev:
                return {"ok": False, "broken_at": i, "decision_id": row["decision_id"],
                        "reason": "prev_row_hash does not match the preceding row"}
            expected = _decision_hash(row, prev)
            if expected != row["row_hash"]:
                return {"ok": False, "broken_at": i, "decision_id": row["decision_id"],
                        "reason": "row_hash does not match the row's own content"}
            prev = row["row_hash"]
        return {"ok": True, "n_rows": len(rows), "head": prev}


# Columns excluded from the hash: the primary key is in it, but the two hash
# columns obviously cannot hash themselves.
_HASH_EXCLUDE = frozenset({"row_hash"})


def _decision_hash(row: dict[str, Any], prev_hash: str) -> str:
    payload = {k: v for k, v in row.items() if k not in _HASH_EXCLUDE and k != "rowid"}
    payload["prev_row_hash"] = prev_hash
    return _sha256(_canonical(payload))


# ---------------------------------------------------------------------------
# The decision write path — separate class, separate grant
# ---------------------------------------------------------------------------

@dataclass
class DecisionInput:
    """What a human supplies. Nothing here has a default verdict."""

    decision: str                        # ACCEPT | REJECT | OVERRIDE
    analyst_id: str
    analyst_role: str | None = None
    override_action: str | None = None
    override_reason_code: str | None = None
    override_reason_text: str | None = None
    per_document_verdicts: list[dict[str, Any]] | None = None
    analyst_confidence: int | None = None
    time_to_decision_ms: int | None = None
    review_started_at: str | None = None
    supersedes_decision_id: str | None = None


class DecisionWriter:
    """The **only** class that may insert into `analyst_decisions`.

    The dashboard's decision handler holds one of these. The scoring pipeline does
    not. That separation is layer two of design §5.8's three, and it is why
    `AuditLog` above has no `record_decision` method — not as an oversight, but so
    that a future edit to the pipeline cannot reach the table by accident.
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB,
                 source: str = SOURCE_ANALYST_UI) -> None:
        if source not in DECISION_SOURCES:
            raise ValueError(f"unknown decision_source {source!r}")
        self.db_path = Path(db_path)
        self.source = source
        self._log = AuditLog(db_path)

    def record_decision(self, event_id: str, decision: DecisionInput) -> str:
        """Append a decision. Validates before writing; never edits an existing row."""
        if decision.decision not in DECISION_VALUES:
            raise ValueError(
                f"analyst_decision must be one of {DECISION_VALUES}; "
                f"got {decision.decision!r}. There is no default.")
        if decision.decision == "OVERRIDE":
            if not decision.override_action or not decision.override_reason_code:
                raise ValueError(
                    "an OVERRIDE requires both override_action and override_reason_code — "
                    "free text alone cannot be used as a future training label")
            if decision.override_action not in OVERRIDE_ACTIONS:
                raise ValueError(f"override_action must be one of {OVERRIDE_ACTIONS}")
            if (decision.override_reason_code == "OTHER"
                    and not decision.override_reason_text):
                raise ValueError("reason code OTHER requires override_reason_text")

        event = self._log.get_event(event_id)
        if event is None:
            raise ValueError(f"no query_event {event_id!r}; a decision needs an event")

        now = _now()
        row = {
            "decision_id": f"dec-{uuid.uuid4()}",
            "event_id": event_id,
            "analyst_id": decision.analyst_id,
            "analyst_role": decision.analyst_role,
            # Snapshotted so the row stands alone without a join (design §5.3).
            "system_recommended_action": event["final_action"],
            "system_case_id": event["case_id"],
            "system_risk_score": event["risk_score"],
            "system_confidence": event["confidence"],
            "system_headline": event["headline"],
            "analyst_decision": decision.decision,
            "override_action": decision.override_action,
            "override_reason_code": decision.override_reason_code,
            "override_reason_text": decision.override_reason_text,
            "per_document_verdicts": _jdump(decision.per_document_verdicts or []),
            "analyst_confidence": decision.analyst_confidence,
            "time_to_decision_ms": decision.time_to_decision_ms,
            "decided_at": now,
            "logged_at": now,
            "review_started_at": decision.review_started_at,
            "decision_source": self.source,
            "system_action_shown": event["final_action"],
            "supersedes_decision_id": decision.supersedes_decision_id,
        }

        with self._log._conn() as conn:
            head = conn.execute(
                "SELECT row_hash FROM analyst_decisions ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            prev = head["row_hash"] if head else GENESIS_HASH
            row["prev_row_hash"] = prev
            row["row_hash"] = _decision_hash(row, prev)
            cols = ", ".join(row)
            marks = ", ".join("?" for _ in row)
            conn.execute(f"INSERT INTO analyst_decisions ({cols}) VALUES ({marks})",
                         tuple(row.values()))
        return row["decision_id"]

    def correct_decision(self, event_id: str, decision: DecisionInput) -> str:
        """Supersede the standing decision with a new row. The original is kept.

        Corrections never edit and never delete — the earlier judgement is part of
        the record, and a recalibration pass that cannot see analysts changing
        their minds is missing the most informative signal in the table.
        """
        current = self._log.current_decision(event_id)
        if current is None:
            raise ValueError(f"no standing decision for {event_id!r} to correct")
        decision.supersedes_decision_id = current["decision_id"]
        return self.record_decision(event_id, decision)


__all__ = [
    "AuditLog", "DecisionWriter", "DecisionInput", "DEFAULT_DB", "SCHEMA_VERSION",
    "DECISION_VALUES", "OVERRIDE_ACTIONS", "HEADLINE_BANDS", "RED_SUBTYPES",
    "DECISION_SOURCES", "SOURCE_ANALYST_UI",
]
