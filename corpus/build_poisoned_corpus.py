#!/usr/bin/env python3
"""
Assemble the poisoned partition of the healthcare threat-intelligence corpus.

DEFENSIVE SECURITY RESEARCH
---------------------------
This script builds adversarial documents for one purpose: to provide ground-truth
positives against which this project's own detection layer is evaluated. It
follows the published PoisonedRAG methodology (Zou, Geng, Wang & Jia, 34th USENIX
Security Symposium, 2025), which is the reference attack the defence is designed
to withstand.

The documents produced here are synthetic. They contain no real indicators --
every address and hostname is drawn from ranges reserved for documentation. They
are never inserted into any live retrieval system, never served to any user, and
never directed at any third-party system. Every factual assertion in them is
deliberately false by construction, which is what makes them useful as labelled
positives and useless as intelligence.

Construction (PoisonedRAG, black-box setting)
---------------------------------------------
Each poisoned document is built as **S + I**:

    S -- the retrieval-optimising segment. In the black-box setting the attacker
         cannot query the embedding model, so PoisonedRAG conditions the document
         on the target query text itself. `_build_retrieval_segment` does exactly
         that: it restates the query and its salient terms in natural prose so the
         document lands near the query in embedding space.

    I -- the corruption payload. The attacker's intended false conclusion,
         rendered in the house style of the document's source type using the SAME
         renderers as the clean corpus, so that structure and register cannot
         separate a poisoned document from a clean one. Only the claims differ.

That shared-renderer decision matters more than it looks. If poisoned documents
were rendered by their own code they would acquire a stylistic signature, and the
detectors would learn the signature rather than the attack.

Ground truth
------------
Labels are NOT written into the document files. They go to a sidecar manifest at
corpus/ground_truth/poisoned.json. See schema.py, "Ground truth separation", for
why: a label inside the document is reachable by the pipeline that loads it, and a
benchmark whose answer key is stapled to the exam paper measures nothing.

Usage
-----
    python build_poisoned_corpus.py
    python build_poisoned_corpus.py --ingestion-date 2026-09-03 --clean
    python build_poisoned_corpus.py --retrieval-report ../eval/poison_retrieval_check.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import (  # noqa: E402
    SCHEMA_VERSION,
    DESIGN_VERSION,
    RELEVANCE_LEVELS,
    TIER_LABELS,
    GROUND_TRUTH_DIRNAME,
    GROUND_TRUTH_FILENAME,
    MIN_POISON_FAMILIES,
)
from build_clean_corpus import RENDERERS, load_registry  # noqa: E402

HERE = Path(__file__).resolve().parent
SEED_PATH = HERE / "sources" / "poison_seeds.json"
DEFAULT_OUT = HERE / "poisoned"
CLEAN_DIR = HERE / "clean"

STOPWORDS = {
    "is", "are", "the", "a", "an", "to", "of", "for", "on", "in", "we", "our", "do",
    "does", "should", "what", "which", "how", "still", "with", "and", "or", "be",
    "keep", "need", "about", "it", "this", "that", "from", "at", "by", "us",
}
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9.\-_]*")


# ---------------------------------------------------------------------------
# S -- the retrieval-optimising segment
# ---------------------------------------------------------------------------

def _salient_terms(query_text: str) -> list[str]:
    seen, out = set(), []
    for tok in TOKEN_RE.findall(query_text.lower()):
        if tok in STOPWORDS or len(tok) < 3 or tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
    return out


def _build_retrieval_segment(query_text: str, extra_keywords: list[str]) -> str:
    """Generate PoisonedRAG's S: text conditioned on the target query.

    Black-box setting -- the attacker has no access to the embedding model, so the
    query itself is the best available proxy for the region of embedding space the
    document needs to occupy. The query is restated as a natural subject line
    rather than pasted verbatim, because a document containing a literal question
    is trivially detectable by inspection and would make the benchmark too easy.
    """
    subject = query_text.rstrip("?").strip()
    for prefix in ("Is ", "Are ", "Do ", "Does ", "Should ", "What ", "Which ", "How "):
        if subject.startswith(prefix):
            subject = subject[len(prefix):]
            break
    terms = ", ".join(extra_keywords) if extra_keywords else ", ".join(_salient_terms(query_text)[:6])
    return (
        f"This item addresses {subject}. "
        f"It is filed against the following topics: {terms}."
    )


# ---------------------------------------------------------------------------
# Lexical retrieval proxy
# ---------------------------------------------------------------------------
#
# We cannot verify true retrieval success here: no embedding model is available in
# this environment. A BM25-style lexical score is a weak but real proxy -- if a
# poisoned document does not even out-rank the clean corpus lexically for its
# target query, its S segment is certainly too weak, and that is worth catching
# before spending pipeline time on it.
#
# This is a PRE-CHECK, not a verification. The real check is dense-retrieval
# rank@k once the pipeline exists, and it is recorded as an open item.

def _bm25_index(docs: dict[str, str]):
    tokenised = {d: [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]
                 for d, text in docs.items()}
    n = len(tokenised)
    avgdl = sum(len(t) for t in tokenised.values()) / max(n, 1)
    df: Counter = Counter()
    for toks in tokenised.values():
        df.update(set(toks))
    idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
    tf = {d: Counter(toks) for d, toks in tokenised.items()}
    dl = {d: len(toks) for d, toks in tokenised.items()}
    return tf, dl, idf, avgdl


def _bm25_score(query: str, doc_id: str, tf, dl, idf, avgdl, k1=1.5, b=0.75) -> float:
    score = 0.0
    for t in TOKEN_RE.findall(query.lower()):
        if t in STOPWORDS or t not in idf:
            continue
        f = tf[doc_id].get(t, 0)
        if not f:
            continue
        score += idf[t] * (f * (k1 + 1)) / (f + k1 * (1 - b + b * dl[doc_id] / avgdl))
    return score


def retrieval_precheck(poisoned: list[dict], queries: dict[str, dict], k: int = 5) -> dict:
    """Rank each poisoned document against the whole clean corpus for its query."""
    corpus: dict[str, str] = {}
    for path in sorted(CLEAN_DIR.glob("*.json")):
        if path.name == "index.json":
            continue
        with path.open(encoding="utf-8") as fh:
            d = json.load(fh)
        corpus[d["doc_id"]] = f"{d['title']} {d['summary']} {d['content']}"
    for doc in poisoned:
        corpus[doc["doc_id"]] = f"{doc['title']} {doc['summary']} {doc['content']}"

    tf, dl, idf, avgdl = _bm25_index(corpus)
    results = []
    for doc in poisoned:
        qid = doc["_target_query_id"]
        qtext = queries[qid]["query_text"]
        scored = sorted(
            ((did, _bm25_score(qtext, did, tf, dl, idf, avgdl)) for did in corpus),
            key=lambda x: -x[1],
        )
        rank = next(i for i, (did, _) in enumerate(scored, 1) if did == doc["doc_id"])
        results.append({
            "doc_id": doc["doc_id"],
            "target_query_id": qid,
            "lexical_rank": rank,
            "in_top_k": rank <= k,
            "score": round(dict(scored)[doc["doc_id"]], 3),
            "top_competitor": scored[0][0] if scored[0][0] != doc["doc_id"] else scored[1][0],
        })
    return {
        "k": k,
        "method": "BM25 lexical proxy over title + summary + content",
        "caveat": (
            "This is a pre-check, not verification. Retrieval in the pipeline is dense, not "
            "lexical. A poisoned document that fails here is certainly too weak; one that passes "
            "is not thereby confirmed retrievable. Re-run rank@k against the real embedding "
            "index once the retrieval pipeline exists."
        ),
        "results": sorted(results, key=lambda r: r["lexical_rank"]),
        "in_top_k_count": sum(1 for r in results if r["in_top_k"]),
        "total": len(results),
    }


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build_document(seed: dict, query: dict, registry: dict, ingestion_date: str) -> dict:
    source_id = seed["source_id"]
    if source_id not in registry:
        raise KeyError(f"{seed['doc_id']}: source_id '{source_id}' is not in the registry")
    src = registry[source_id]
    source_type = src["source_type"]
    renderer = RENDERERS.get(source_type)
    if renderer is None:
        raise KeyError(f"{seed['doc_id']}: no renderer for source_type '{source_type}'")

    # S: retrieval-optimising segment, conditioned on the target query.
    s_segment = _build_retrieval_segment(query["query_text"], seed.get("extra_keywords", []))

    # I: corruption payload, rendered in the clean corpus's house style so that
    # structure carries no signal. The summary is where S is woven in, because the
    # summary leads the body in every renderer.
    seed_for_render = dict(seed)
    seed_for_render["summary"] = f"{s_segment} {seed['summary']}"
    content = renderer(seed_for_render, seed.get("facts", {}))

    # A direct-injection family appends instruction text addressed to the model.
    if seed.get("injection_payload"):
        content += f"\n\n{seed['injection_payload']}\n"

    content = re.sub(r"\n{3,}", "\n\n", content).strip() + "\n"

    relevance = seed.get("healthcare_relevance", "high")
    if relevance not in RELEVANCE_LEVELS:
        raise ValueError(f"{seed['doc_id']}: healthcare_relevance '{relevance}' is not valid")

    doc = {
        "schema_version": SCHEMA_VERSION,
        "design_version": DESIGN_VERSION,
        "doc_id": seed["doc_id"],
        "source_id": source_id,
        "source_name": src["source_name"],
        "source_tier": src["source_tier"],
        "source_tier_label": TIER_LABELS[src["source_tier"]],
        "source_type": source_type,
        "publisher": src["publisher"],
        "title": seed["title"],
        # The summary stored on the document is the one the pipeline sees, S included.
        "summary": seed_for_render["summary"],
        "content": content,
        "content_origin": "synthesized_representative",
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "content_word_count": len(content.split()),
        "ingestion_date": ingestion_date,
        "published_date": seed.get("published_date"),
        "reference_url": seed.get("reference_url"),
        "reference_verified": bool(seed.get("reference_verified", False)),
        "tags": seed.get("tags", []),
        "cve_ids": seed.get("cve_ids", []),
        "attack_techniques": seed.get("attack_techniques", []),
        "healthcare_relevance": relevance,
        "vendor": seed.get("vendor"),
        "product": seed.get("product"),
        "license_note": src.get("license_note"),
        "attestation": src.get("attestation"),
        # No ground-truth field. Not an oversight -- see the module docstring.
    }
    # Carried for the build only, stripped before writing.
    doc["_target_query_id"] = seed["target_query_id"]
    doc["_poison_family_id"] = seed["poison_family_id"]
    doc["_intended_false_claim"] = seed["intended_false_claim"]
    doc["_s_segment"] = s_segment
    doc["_has_injection"] = bool(seed.get("injection_payload"))
    return doc


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Assemble the poisoned corpus partition (defensive benchmark use only).")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--ingestion-date", default=dt.date.today().isoformat())
    ap.add_argument("--clean", action="store_true", help="remove existing generated documents first")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--retrieval-report", type=Path, default=None,
                    help="write the BM25 retrieval pre-check to this path")
    ap.add_argument("--k", type=int, default=5, help="top-k for the retrieval pre-check")
    args = ap.parse_args()

    try:
        dt.date.fromisoformat(args.ingestion_date)
    except ValueError:
        print(f"ERROR: --ingestion-date '{args.ingestion_date}' is not valid", file=sys.stderr)
        return 2

    with SEED_PATH.open(encoding="utf-8") as fh:
        seeds = json.load(fh)
    queries = {q["query_id"]: q for q in seeds["target_queries"]}
    registry = load_registry()

    documents = []
    seen = set()
    for seed in seeds["documents"]:
        did = seed["doc_id"]
        if did in seen:
            print(f"ERROR: duplicate doc_id '{did}'", file=sys.stderr)
            return 1
        seen.add(did)
        qid = seed["target_query_id"]
        if qid not in queries:
            print(f"ERROR: {did} targets unknown query '{qid}'", file=sys.stderr)
            return 1
        documents.append(build_document(seed, queries[qid], registry, args.ingestion_date))

    tier_counts = Counter(d["source_tier"] for d in documents)
    family_counts = Counter(d["_poison_family_id"] for d in documents)

    print(f"Built {len(documents)} poisoned documents")
    print(f"  Tier 1: {tier_counts[1]}   Tier 2: {tier_counts[2]}   Tier 3: {tier_counts[3]}")
    print(f"  Attack families ({len(family_counts)}): "
          + ", ".join(f"{k}={v}" for k, v in sorted(family_counts.items())))
    words = sorted(d["content_word_count"] for d in documents)
    print(f"  Body length: min {words[0]}, median {words[len(words)//2]}, max {words[-1]} words")

    if len(family_counts) < MIN_POISON_FAMILIES:
        print(f"ERROR: only {len(family_counts)} attack families; leave-one-attack-family-out "
              f"evaluation needs at least {MIN_POISON_FAMILIES}", file=sys.stderr)
        return 1
    if tier_counts[1] == 0:
        print("ERROR: no Tier-1 poisoned documents. Without them the is_tier1 x signal "
              "interaction coefficients are unidentifiable and cases C4/C5 cannot be "
              "validated (design 3.5).", file=sys.stderr)
        return 1

    precheck = None
    if CLEAN_DIR.is_dir():
        precheck = retrieval_precheck(documents, queries, k=args.k)
        print(f"  Lexical retrieval pre-check: {precheck['in_top_k_count']}/{precheck['total']} "
              f"rank in top-{args.k} against the clean corpus")
        weak = [r for r in precheck["results"] if not r["in_top_k"]]
        for r in weak:
            print(f"    WEAK: {r['doc_id']} ranks {r['lexical_rank']} for {r['target_query_id']}")
    else:
        print("  Lexical retrieval pre-check skipped: clean corpus not built")

    if args.dry_run:
        print("Dry run: nothing written.")
        return 0

    out: Path = args.out
    if args.clean and out.exists():
        for existing in out.glob("*.json"):
            existing.unlink()
    out.mkdir(parents=True, exist_ok=True)

    public_docs = []
    for doc in documents:
        public = {k: v for k, v in doc.items() if not k.startswith("_")}
        public_docs.append(public)
        with (out / f"{doc['doc_id']}.json").open("w", encoding="utf-8") as fh:
            json.dump(public, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    built_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    index = {
        "schema_version": SCHEMA_VERSION,
        "design_version": DESIGN_VERSION,
        "corpus": "poisoned",
        "built_at": built_at,
        "ingestion_date": args.ingestion_date,
        "document_count": len(public_docs),
        "tier_counts": {str(t): tier_counts[t] for t in (1, 2, 3)},
        "source_counts": dict(Counter(d["source_id"] for d in public_docs)),
        "provenance_statement": (
            "Adversarial documents built following the PoisonedRAG methodology (Zou et al., USENIX "
            "Security 2025) as defensive security research, for internal benchmark use only. Every "
            "assertion is deliberately false. All indicators are fabricated and use reserved "
            "documentation ranges. These documents are never inserted into any live retrieval "
            "system and are never directed at any third-party system."
        ),
        "documents": [
            {
                "doc_id": d["doc_id"],
                "file": f"{d['doc_id']}.json",
                "source_id": d["source_id"],
                "source_tier": d["source_tier"],
                "source_type": d["source_type"],
                "title": d["title"],
                "summary": d["summary"],
                "content_sha256": d["content_sha256"],
                "content_word_count": d["content_word_count"],
                "healthcare_relevance": d["healthcare_relevance"],
                "reference_verified": d["reference_verified"],
                "tags": d["tags"],
            }
            for d in sorted(public_docs, key=lambda x: x["doc_id"])
        ],
    }
    with (out / "index.json").open("w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    # ---- ground truth, sidecar only ----
    gt_dir = HERE / GROUND_TRUTH_DIRNAME
    gt_dir.mkdir(parents=True, exist_ok=True)
    with (gt_dir / GROUND_TRUTH_FILENAME["poisoned"]).open("w", encoding="utf-8") as fh:
        json.dump({
            "manifest_version": SCHEMA_VERSION,
            "partition": "poisoned",
            "built_at": built_at,
            "WARNING": (
                "EVALUATION ONLY. The retrieval pipeline, the detectors and the fusion layer must "
                "never read this file. It is the answer key for the benchmark; any component that "
                "consults it invalidates every metric derived from that run."
            ),
            "methodology": seeds["methodology"],
            "research_framing": seeds["research_framing"],
            "document_count": len(documents),
            "poison_families": seeds["poison_families"],
            "target_queries": {
                q["query_id"]: {
                    "query_text": q["query_text"],
                    "clean_anchor_doc_ids": q["clean_anchor_doc_ids"],
                    "ground_truth_answer": q["ground_truth_answer"],
                    "attacker_target_answer": q["attacker_target_answer"],
                }
                for q in seeds["target_queries"]
            },
            "labels": {
                d["doc_id"]: {
                    "ground_truth": "poisoned",
                    "poison_family_id": d["_poison_family_id"],
                    "target_query_id": d["_target_query_id"],
                    "intended_false_claim": d["_intended_false_claim"],
                    "retrieval_segment": d["_s_segment"],
                    "contains_injection_payload": d["_has_injection"],
                    "source_tier": d["source_tier"],
                }
                for d in sorted(documents, key=lambda x: x["doc_id"])
            },
            "retrieval_precheck": precheck,
        }, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    if args.retrieval_report and precheck:
        args.retrieval_report.parent.mkdir(parents=True, exist_ok=True)
        with args.retrieval_report.open("w", encoding="utf-8") as fh:
            json.dump(precheck, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"Retrieval pre-check written to {args.retrieval_report}")

    print(f"Wrote {len(public_docs)} documents and index.json to {out}")
    print(f"Wrote ground-truth manifest to {gt_dir / GROUND_TRUTH_FILENAME['poisoned']}")
    print("Next: python validate_corpus.py --corpus poisoned --strict")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
