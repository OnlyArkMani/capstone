#!/usr/bin/env python3
"""
Run one or more queries through the baseline pipeline and log them.

    python -m pipeline.run_query "Is 198.51.100.47 associated with ransomware?"
    python -m pipeline.run_query --queries-file eval/target_queries.txt -k 5
    python -m pipeline.run_query "..." --no-generate       # retrieval only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import PipelineConfig
from .rag import BaselineRAG


def _render(result: dict, show_answer: bool) -> None:
    retrieval = result["retrieval"]
    print(f"\nQuery: {retrieval.query}")
    print(f"  run_id={result['run_id']}  model={retrieval.embedding_model}  "
          f"k={retrieval.k}  {retrieval.latency_ms:.1f} ms")
    print(f"  {'rank':<5}{'sim':<9}{'tier':<6}{'source_id':<24}doc_id")
    for r in retrieval.records:
        print(f"  {r.rank:<5}{r.similarity:<9.4f}{r.provenance.source_tier:<6}"
              f"{r.provenance.source_id:<24}{r.doc_id}")
    gen = result.get("generation")
    if gen and show_answer:
        print(f"\n  --- answer ({gen.backend}/{gen.model}, {gen.latency_ms:.0f} ms) ---")
        if gen.error:
            print(f"  ERROR: {gen.error}")
        else:
            for line in gen.answer.splitlines():
                print(f"  {line}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Run queries through the baseline RAG pipeline.")
    ap.add_argument("query", nargs="*", help="one or more queries")
    ap.add_argument("--queries-file", type=Path, help="file with one query per line")
    ap.add_argument("-k", "--top-k", type=int, default=None)
    ap.add_argument("--no-generate", action="store_true", help="retrieval only")
    ap.add_argument("--no-log", action="store_true")
    ap.add_argument("--per-query-file", action="store_true",
                    help="also write logs/queries/<run_id>.json")
    ap.add_argument("--in-memory", action="store_true",
                    help="build the index now instead of loading from disk")
    ap.add_argument("--embedding-backend", choices=["auto", "sentence_transformers", "hashing"])
    ap.add_argument("--generation-backend", choices=["auto", "ollama", "groq", "extractive"])
    args = ap.parse_args()

    queries = list(args.query)
    if args.queries_file:
        queries += [l.strip() for l in args.queries_file.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")]
    if not queries:
        ap.error("provide at least one query, or --queries-file")

    cfg = PipelineConfig()
    if args.embedding_backend:
        cfg.embedding_backend = args.embedding_backend
    if args.generation_backend:
        cfg.generation_backend = args.generation_backend

    try:
        rag = BaselineRAG.build(cfg) if args.in_memory else BaselineRAG.from_disk(cfg)
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    for q in queries:
        result = rag.answer(
            q, k=args.top_k,
            generate=not args.no_generate,
            log=not args.no_log,
            per_query_file=args.per_query_file,
        )
        _render(result, show_answer=not args.no_generate)

    if not args.no_log:
        print(f"\nLogged {len(queries)} quer{'y' if len(queries) == 1 else 'ies'} to "
              f"{cfg.log_dir / cfg.retrieval_log_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
