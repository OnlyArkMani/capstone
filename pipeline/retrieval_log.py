"""
Passive retrieval logging (Level 1).

Every query and every record it retrieved, with scores and provenance, appended
to a JSON Lines file under logs/. One line per query, append-only.

Passive means passive: nothing here scores, filters, flags or reorders anything.
The detectors do not exist yet, and this stage must not anticipate them -- the
baseline has to remain the naive system for the comparison to mean anything.

Why JSONL rather than the SQLite audit log from design section 5.2: that table
carries detector signals, case identifiers and both track proposals, none of
which exist at this stage. Writing rows with those columns null would give the
audit trail a large block of meaningless history. This log is the input the
audit writer will consume when it is built; the `_schema` field on every line
lets that migration key off a version rather than guess.

NOT LOGGED: perplexity. Scoped out on the literature review -- clean and
adversarial text overlap in perplexity (design references P1, P5) and no
perplexity term appears in the composite score (design section 3.2). Its absence
is a decision, not an oversight.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import uuid
from pathlib import Path
from typing import Any

from .config import PipelineConfig, DEFAULT_CONFIG
from .records import RetrievalResult, GenerationResult

LOG_SCHEMA_VERSION = "retrieval-log-v1"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def build_log_record(
    retrieval: RetrievalResult,
    generation: GenerationResult | None = None,
    run_id: str | None = None,
    include_content: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "_schema": LOG_SCHEMA_VERSION,
        "run_id": run_id or uuid.uuid4().hex,
        "logged_at": _utc_now(),
        "stage": "baseline_rag_no_security_layer",
        "query": retrieval.query,
        "query_hash": retrieval.query_hash,
        "k": retrieval.k,
        "n_retrieved": retrieval.n_retrieved,
        "embedding_model": retrieval.embedding_model,
        "index_id": retrieval.index_id,
        "retrieval_latency_ms": round(retrieval.latency_ms, 2),
        # Set-level retrieval geometry. Recorded now because the anomaly
        # detector normalises within the retrieval set (design section 3.2) and
        # the confidence measure reads evidence volume and spread (section 4.2);
        # both need this even for queries replayed from the log later.
        "similarity_top": retrieval.similarities[0] if retrieval.records else None,
        "similarity_min": min(retrieval.similarities) if retrieval.records else None,
        "similarity_spread": (
            round(retrieval.similarities[0] - min(retrieval.similarities), 6)
            if retrieval.records else None
        ),
        "tier_min": retrieval.tier_min,
        "top_tier": retrieval.top_tier,
        "retrieved": [
            {
                "rank": r.rank,
                "doc_id": r.doc_id,
                "similarity": round(r.similarity, 6),
                "title": r.title,
                "provenance": r.provenance.to_dict(),
                "tags": r.tags,
                "cve_ids": r.cve_ids,
                "attack_techniques": r.attack_techniques,
                **({"content": r.content} if include_content else {}),
            }
            for r in retrieval.records
        ],
    }
    if generation is not None:
        record["generation"] = {
            "backend": generation.backend,
            "model": generation.model,
            "answer": generation.answer,
            "cited_doc_ids": generation.cited_doc_ids,
            "prompt_chars": generation.prompt_chars,
            "latency_ms": round(generation.latency_ms, 2),
            "error": generation.error,
        }
    if extra:
        record.update(extra)
    return record


def log_query(
    retrieval: RetrievalResult,
    generation: GenerationResult | None = None,
    config: PipelineConfig | None = None,
    run_id: str | None = None,
    per_query_file: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one line to the retrieval log. Returns the record written."""
    cfg = config or DEFAULT_CONFIG
    record = build_log_record(
        retrieval, generation, run_id=run_id,
        include_content=cfg.log_content_in_jsonl, extra=extra,
    )

    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    path = cfg.log_dir / cfg.retrieval_log_file
    line = json.dumps(record, ensure_ascii=False)

    # Append with an explicit flush + fsync: a crash mid-run must not lose the
    # record of what was retrieved, since that is the only account of what the
    # pipeline saw.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())

    if per_query_file:
        qdir = cfg.log_dir / cfg.per_query_dir
        qdir.mkdir(parents=True, exist_ok=True)
        with (qdir / f"{record['run_id']}.json").open("w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    return record


def read_log(config: PipelineConfig | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    """Read the retrieval log back. Malformed lines are skipped, not fatal."""
    cfg = config or DEFAULT_CONFIG
    path = cfg.log_dir / cfg.retrieval_log_file
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out[-limit:] if limit else out
