#!/usr/bin/env python3
"""
Build and persist the vector index over the whole corpus.

    python -m pipeline.build_index
    python -m pipeline.build_index --embedding-backend hashing   # offline check

Indexes corpus/clean/ and corpus/poisoned/ together. The pipeline is never told
which partition a document came from.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from .config import DEFAULT_CONFIG, PipelineConfig
from .retrieval import Retriever


def main() -> int:
    ap = argparse.ArgumentParser(description="Build the baseline RAG vector index.")
    ap.add_argument("--embedding-backend", choices=["auto", "sentence_transformers", "hashing"])
    ap.add_argument("--index-backend", choices=["auto", "faiss", "numpy"])
    ap.add_argument("--embedding-model")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    cfg = PipelineConfig()
    if args.embedding_backend:
        cfg.embedding_backend = args.embedding_backend
    if args.index_backend:
        cfg.index_backend = args.index_backend
    if args.embedding_model:
        cfg.embedding_model = args.embedding_model

    try:
        retriever = Retriever.build(cfg, verbose=not args.quiet)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    retriever.save(cfg)

    tiers = Counter(d["source_tier"] for d in retriever.documents)
    sources = Counter(d["source_id"] for d in retriever.documents)
    print(f"Indexed {len(retriever.documents)} documents")
    print(f"  tiers   : T1={tiers[1]}  T2={tiers[2]}  T3={tiers[3]}")
    print(f"  sources : {len(sources)} distinct")
    print(f"  model   : {retriever.embedder.name} (dim {retriever.embedder.dim}, "
          f"semantic={retriever.embedder.is_semantic})")
    print(f"  index   : {retriever.index.backend}, index_id={retriever.index_id}")
    print(f"  saved   : {cfg.index_path}  +  {cfg.meta_path}")
    if not retriever.embedder.is_semantic:
        print("\n  WARNING: this index was built with the non-semantic fallback embedder. "
              "It is structurally valid but retrieval quality figures from it are NOT meaningful.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
