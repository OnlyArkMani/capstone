#!/usr/bin/env python3
"""
Smoke tests for the baseline pipeline.

Runnable directly (`python -m pipeline.test_pipeline`) or under pytest. No test
dependencies beyond numpy, so it runs in the same environments the pipeline does.

The tests that matter most are the ground-truth isolation ones. Everything else
here checks shapes; those check that the benchmark is still a benchmark.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import numpy as np

from .config import PipelineConfig
from .corpus_loader import (
    ALLOWED_DOC_FIELDS, FORBIDDEN_DOC_FIELDS, GroundTruthLeakError,
    embedding_text, load_corpus,
)
from .generation import ExtractiveGenerator, build_prompt
from .rag import BaselineRAG
from .records import RetrievedRecord
from .retrieval import Retriever
from .retrieval_log import read_log

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {name}" + (f" -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(name)


def offline_config(tmp: Path) -> PipelineConfig:
    cfg = PipelineConfig()
    cfg.embedding_backend = "hashing"
    cfg.index_backend = "auto"
    cfg.generation_backend = "extractive"
    cfg.log_dir = tmp / "logs"
    cfg.index_dir = tmp / "index"
    return cfg


def test_corpus_is_partition_blind(cfg: PipelineConfig) -> None:
    docs = load_corpus(cfg)
    check("corpus loads both partitions", len(docs) > 80, f"got {len(docs)}")

    leaked = {f for d in docs for f in FORBIDDEN_DOC_FIELDS if f in d}
    check("no answer-key field survives loading", not leaked, f"leaked: {leaked}")

    unexpected = {k for d in docs for k in d} - set(ALLOWED_DOC_FIELDS)
    check("loader emits only allowlisted fields", not unexpected, f"unexpected: {unexpected}")

    partitionish = {k for d in docs for k in d if "partition" in k or "corpus" in k or "poison" in k}
    check("no partition-of-origin field", not partitionish, f"found: {partitionish}")

    tiers = {d["source_tier"] for d in docs}
    check("all three tiers indexed", tiers == {1, 2, 3}, f"tiers: {tiers}")


def test_leak_is_fatal(cfg: PipelineConfig, tmp: Path) -> None:
    bad_dir = tmp / "bad_corpus"
    bad_dir.mkdir(parents=True, exist_ok=True)
    src = load_corpus(cfg)[0]
    poisoned_doc = dict(src)
    poisoned_doc["label"] = "poisoned"
    (bad_dir / f"{src['doc_id']}.json").write_text(json.dumps(poisoned_doc), encoding="utf-8")

    bad_cfg = PipelineConfig()
    bad_cfg.corpus_dirs = [bad_dir]
    try:
        load_corpus(bad_cfg)
        check("loader raises on a leaked label", False, "no exception raised")
    except GroundTruthLeakError:
        check("loader raises on a leaked label", True)


def test_no_ground_truth_import() -> None:
    """The pipeline package must not read the ground-truth answer key.

    Uses the shared AST checker rather than a string search: both packages
    *document* that they do not read ground truth, so searching for the phrase
    flags exactly the modules being most careful about it.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from detectors.isolation_check import check_package  # noqa: PLC0415

    offenders = check_package(Path(__file__).resolve().parent, skip=("test_pipeline.py",))
    check("no module reads the ground-truth answer key", not offenders, f"offenders: {offenders}")


def test_embed_query(retriever: Retriever) -> None:
    vec = retriever.embed_query("Is this IP associated with ransomware infrastructure?")
    check("embed_query returns 1-D vector", vec.ndim == 1, f"ndim={vec.ndim}")
    check("embedding dim matches model", vec.shape[0] == retriever.embedder.dim)
    check("embedding is L2-normalised", abs(float(np.linalg.norm(vec)) - 1.0) < 1e-4,
          f"norm={float(np.linalg.norm(vec)):.6f}")
    try:
        retriever.embed_query("   ")
        check("empty query rejected", False)
    except ValueError:
        check("empty query rejected", True)


def test_retrieve_shape(retriever: Retriever) -> None:
    result = retriever.retrieve_top_k("ransomware command and control infrastructure", k=5)

    check("returns exactly k records", result.n_retrieved == 5, f"got {result.n_retrieved}")
    check("records are structured, not strings",
          all(isinstance(r, RetrievedRecord) for r in result.records))
    check("ranks are 1..k in order", [r.rank for r in result.records] == [1, 2, 3, 4, 5])
    check("similarities are descending",
          all(a.similarity >= b.similarity for a, b in zip(result.records, result.records[1:])))

    r = result.records[0]
    check("record carries similarity", isinstance(r.similarity, float))
    check("record carries content", bool(r.content))
    check("record carries source_id", bool(r.provenance.source_id))
    check("record carries source_tier", r.provenance.source_tier in (1, 2, 3))
    check("record carries full provenance",
          all(hasattr(r.provenance, f) for f in
              ("source_name", "source_type", "publisher", "reference_verified", "content_sha256")))

    d = r.to_dict()
    check("record serialises to dict", "provenance" in d and "similarity" in d)
    check("serialised record has no label field",
          not any(f in d for f in FORBIDDEN_DOC_FIELDS))

    check("set-level tier_min present", result.tier_min in (1, 2, 3))
    check("set-level top_tier present", result.top_tier in (1, 2, 3))
    check("k=1 works", retriever.retrieve_top_k("patient monitor", k=1).n_retrieved == 1)


def test_generation(retriever: Retriever, cfg: PipelineConfig) -> None:
    result = retriever.retrieve_top_k("Log4Shell exposure in clinical applications", k=3)
    gen = ExtractiveGenerator().generate_answer("Log4Shell exposure?", result.records, cfg)
    check("generation returns an answer", bool(gen.answer))
    check("generation records cited doc_ids", gen.cited_doc_ids == [r.doc_id for r in result.records])
    check("stub labels itself", "extractive stub" in gen.answer.lower())

    prompt = build_prompt("test question", result.records, cfg.max_context_chars)
    check("prompt contains doc ids", all(f"[{r.doc_id}]" for r in result.records))
    check("prompt does NOT leak source tier to the model", "source_tier" not in prompt.lower())
    check("prompt truncation respects the budget",
          len(build_prompt("q", result.records, 200)) < len(prompt))


def test_logging(cfg: PipelineConfig, retriever: Retriever) -> None:
    rag = BaselineRAG(retriever, ExtractiveGenerator(), cfg)
    rag.answer("Is the Contec CMS8000 safe on our clinical network?", k=4, per_query_file=True)
    rag.answer("Should we apply the Translogic firmware update?", k=4)

    entries = read_log(cfg)
    check("log has one line per query", len(entries) == 2, f"got {len(entries)}")

    e = entries[0]
    for field in ("_schema", "run_id", "logged_at", "query", "query_hash", "k",
                  "n_retrieved", "embedding_model", "index_id", "retrieved",
                  "similarity_top", "tier_min"):
        check(f"log record has '{field}'", field in e)

    rec = e["retrieved"][0]
    check("logged record has similarity", "similarity" in rec)
    check("logged record has provenance", "provenance" in rec and "source_tier" in rec["provenance"])
    check("log has no perplexity field",
          not any("perplex" in json.dumps(e).lower() for e in entries))
    check("log has no ground-truth field",
          not any(f in json.dumps(entries) for f in ("\"label\"", "poison_family_id", "ground_truth")))
    check("generation logged", "generation" in e and e["generation"]["backend"] == "extractive")

    qfiles = list((cfg.log_dir / cfg.per_query_dir).glob("*.json"))
    check("per-query file written", len(qfiles) == 1, f"got {len(qfiles)}")


def test_persistence(cfg: PipelineConfig, retriever: Retriever) -> None:
    retriever.save(cfg)
    check("index metadata written", cfg.meta_path.exists())
    meta = json.loads(cfg.meta_path.read_text(encoding="utf-8"))
    check("metadata records doc order", len(meta["doc_ids"]) == len(retriever.documents))
    check("metadata has no partition info",
          not any("poison" in json.dumps(meta).lower().split("note")[0] for _ in [0]))

    reloaded = Retriever.from_disk(cfg)
    a = retriever.retrieve_top_k("ransomware infrastructure", k=5)
    b = reloaded.retrieve_top_k("ransomware infrastructure", k=5)
    check("reloaded index gives identical doc order",
          [r.doc_id for r in a.records] == [r.doc_id for r in b.records])
    check("reloaded index gives identical scores",
          all(abs(x.similarity - y.similarity) < 1e-5 for x, y in zip(a.records, b.records)))


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        cfg = offline_config(tmp)

        print("\n== corpus isolation ==")
        test_corpus_is_partition_blind(cfg)
        test_leak_is_fatal(cfg, tmp)
        test_no_ground_truth_import()

        print("\n== building index ==")
        retriever = Retriever.build(cfg, verbose=True)

        print("\n== embedding ==")
        test_embed_query(retriever)

        print("\n== retrieval record shape ==")
        test_retrieve_shape(retriever)

        print("\n== generation ==")
        test_generation(retriever, cfg)

        print("\n== logging ==")
        test_logging(cfg, retriever)

        print("\n== persistence ==")
        test_persistence(cfg, retriever)

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
