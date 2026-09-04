#!/usr/bin/env python3
"""
Validate a corpus directory before it is used downstream.

Nothing in the pipeline should embed, retrieve or score a corpus that has not
passed this check. A document with a missing tier, a mismatched hash or an
absent index entry will not fail loudly later -- it will quietly distort a
metric, which is far worse.

Checks performed
----------------
Structural
    1. Index file exists and parses; every document file parses.
    2. doc_id matches its filename; doc_id is unique across the corpus.
    3. Index and directory agree in both directions, and index hashes match.

Metadata completeness
    4. Every required field is present, correctly typed and non-empty.
    5. Enumerated fields carry a permitted value.
    6. Dates are valid ISO-8601.
    7. reference_verified documents carry a reference_url.

Provenance integrity
    8. source_id exists in the registry.
    9. source_tier, source_name and source_type agree with the registry.
       This is the check that matters most. Tier is the foundation of the case
       taxonomy in docs/design/TRUST_RISK_DESIGN.md, and a document whose tier
       has drifted from its source silently corrupts every case assignment and
       every per-tier threshold calibrated from it. It is the corpus-side
       equivalent of the TIER_MISLABELLED override reason code in design 5.5.
   10. content_sha256 matches the content actually stored.

Quality gates
   11. Content and summary lengths fall inside the bounds in schema.py.
   12. Tier distribution meets the minimum the design requires. The taxonomy
       defines cases at all three tiers and calibrates band thresholds per tier,
       so a corpus that is entirely Tier 1 cannot exercise or calibrate most of
       it.
   13. Near-duplicate detection over token sets. Documents rendered from shared
       templates cluster tightly in embedding space and would hand the anomaly
       detector an artificially clean baseline.

Benchmark validity
   14. Ground-truth leakage. No document file may carry any answer-key field.
       A document file is what the retrieval pipeline loads; a label inside it is
       reachable by the detectors, and the measured performance stops meaning
       anything.
   15. Schema symmetry between partitions. Clean and poisoned documents must
       expose the identical key set, so that shape alone cannot separate them.
   16. Ground-truth manifest agreement in both directions, plus -- for the
       poisoned partition -- a poison_family_id and target_query_id on every
       document, at least MIN_POISON_FAMILIES distinct families, and at least one
       Tier-1 poisoned document.

Exit codes
    0  passed (warnings may be present unless --strict)
    1  validation failed
    2  could not run (bad arguments, missing corpus)

Usage
-----
    python validate_corpus.py
    python validate_corpus.py --corpus clean --strict
    python validate_corpus.py --corpus poisoned --report ../eval/corpus_validation.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import itertools
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import (  # noqa: E402
    REQUIRED_FIELDS,
    FIELD_TYPES,
    TIERS,
    CONTENT_ORIGINS,
    RELEVANCE_LEVELS,
    MIN_CONTENT_WORDS,
    MAX_CONTENT_WORDS,
    MIN_SUMMARY_CHARS,
    MAX_SUMMARY_CHARS,
    JACCARD_WARN_THRESHOLD,
    JACCARD_FAIL_THRESHOLD,
    MIN_DOCS_PER_TIER,
    FORBIDDEN_DOC_FIELDS,
    GROUND_TRUTH_DIRNAME,
    GROUND_TRUTH_FILENAME,
    GROUND_TRUTH_VALUES,
    MIN_POISON_FAMILIES,
)

HERE = Path(__file__).resolve().parent
REGISTRY_PATH = HERE / "sources" / "registry.json"
TOKEN_RE = re.compile(r"[a-z0-9]+")


class Report:
    def __init__(self) -> None:
        self.errors: list[dict] = []
        self.warnings: list[dict] = []
        self.info: dict = {}

    def error(self, scope: str, message: str) -> None:
        self.errors.append({"scope": scope, "message": message})

    def warn(self, scope: str, message: str) -> None:
        self.warnings.append({"scope": scope, "message": message})


def is_iso_date(value: str) -> bool:
    try:
        dt.date.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def tokens(text: str) -> set[str]:
    return {t for t in TOKEN_RE.findall(text.lower()) if len(t) > 3}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


# ---------------------------------------------------------------------------
# Per-document checks
# ---------------------------------------------------------------------------

def check_document(doc: dict, path: Path, registry: dict, expected_label: str, rep: Report) -> None:
    scope = path.name

    # 4/5. Required fields, types, emptiness, enums.
    for field in REQUIRED_FIELDS:
        if field not in doc:
            rep.error(scope, f"missing required field '{field}'")
            continue
        value = doc[field]
        expected = FIELD_TYPES.get(field)
        if expected is not None and not isinstance(value, expected):
            rep.error(scope, f"field '{field}' has type {type(value).__name__}, expected {expected}")
            continue
        if isinstance(value, str) and not value.strip():
            rep.error(scope, f"required field '{field}' is empty")
        if isinstance(value, list) and field == "tags" and not value:
            rep.warn(scope, "tags is empty; retrieval filtering and error analysis both use tags")

    if doc.get("source_tier") not in TIERS:
        rep.error(scope, f"source_tier {doc.get('source_tier')!r} is not one of {TIERS}")
    if doc.get("content_origin") not in CONTENT_ORIGINS:
        rep.error(scope, f"content_origin {doc.get('content_origin')!r} is not permitted")
    if doc.get("healthcare_relevance") not in RELEVANCE_LEVELS:
        rep.error(scope, f"healthcare_relevance {doc.get('healthcare_relevance')!r} is not permitted")

    # 2. Filename agreement.
    if doc.get("doc_id") and path.stem != doc["doc_id"]:
        rep.error(scope, f"doc_id '{doc['doc_id']}' does not match filename stem '{path.stem}'")

    # 6. Dates.
    if not is_iso_date(doc.get("ingestion_date", "")):
        rep.error(scope, f"ingestion_date {doc.get('ingestion_date')!r} is not a valid ISO-8601 date")
    published = doc.get("published_date")
    if published is not None:
        if not is_iso_date(published):
            rep.error(scope, f"published_date {published!r} is not a valid ISO-8601 date")
        elif is_iso_date(doc.get("ingestion_date", "")) and published > doc["ingestion_date"]:
            rep.error(scope, f"published_date {published} is after ingestion_date {doc['ingestion_date']}")
    elif doc.get("source_tier") in (1, 2):
        rep.warn(scope, "published_date is null on a Tier 1/2 document; recency features will treat it as unknown")

    # 7. Verified references must be citable.
    if doc.get("reference_verified") and not doc.get("reference_url"):
        rep.error(scope, "reference_verified is true but no reference_url is present")

    # 8/9. Registry agreement -- the provenance integrity check.
    source_id = doc.get("source_id")
    if source_id not in registry:
        rep.error(scope, f"source_id '{source_id}' is not present in the source registry")
    else:
        src = registry[source_id]
        if doc.get("source_tier") != src["source_tier"]:
            rep.error(
                scope,
                f"TIER MISMATCH: document declares tier {doc.get('source_tier')} but the registry assigns "
                f"tier {src['source_tier']} to source '{source_id}'. Tier drift silently corrupts case "
                f"assignment and per-tier threshold calibration.",
            )
        if doc.get("source_name") != src["source_name"]:
            rep.error(scope, f"source_name '{doc.get('source_name')}' disagrees with registry '{src['source_name']}'")
        if doc.get("source_type") != src["source_type"]:
            rep.error(scope, f"source_type '{doc.get('source_type')}' disagrees with registry '{src['source_type']}'")

    # 10. Content integrity.
    content = doc.get("content", "")
    if isinstance(content, str) and content:
        actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if actual != doc.get("content_sha256"):
            rep.error(scope, "content_sha256 does not match the stored content")

    # 11. Quality gates.
    words = len(content.split()) if isinstance(content, str) else 0
    if words < MIN_CONTENT_WORDS:
        rep.error(scope, f"content is {words} words, below the {MIN_CONTENT_WORDS}-word minimum for a usable embedding")
    elif words > MAX_CONTENT_WORDS:
        rep.warn(scope, f"content is {words} words, above the {MAX_CONTENT_WORDS}-word guideline; "
                        "this document may need chunking, which breaks the one-document-one-unit assumption")
    if doc.get("content_word_count") not in (None, words):
        rep.error(scope, f"content_word_count {doc.get('content_word_count')} disagrees with actual {words}")

    summary = doc.get("summary", "")
    if isinstance(summary, str):
        if len(summary) < MIN_SUMMARY_CHARS:
            rep.error(scope, f"summary is {len(summary)} characters, below the {MIN_SUMMARY_CHARS} minimum")
        elif len(summary) > MAX_SUMMARY_CHARS:
            rep.warn(scope, f"summary is {len(summary)} characters, above the {MAX_SUMMARY_CHARS} guideline")

    # Ground-truth leakage. A document file is what the retrieval pipeline loads;
    # any answer-key field inside it is reachable by the detectors and invalidates
    # every metric derived from the run.
    for field in FORBIDDEN_DOC_FIELDS:
        if field in doc:
            rep.error(scope, f"GROUND-TRUTH LEAK: document carries the field '{field}'. Labels belong "
                             f"only in corpus/{GROUND_TRUTH_DIRNAME}/, never in a document the pipeline loads.")


# ---------------------------------------------------------------------------
# Corpus-level checks
# ---------------------------------------------------------------------------

def check_ground_truth(docs: dict[str, dict], partition: str, rep: Report) -> None:
    """The manifest must label exactly this partition's documents, and no others.

    Separating ground truth from the documents only helps if the separation is
    complete in both directions: an unlabelled document cannot be scored, and a
    label with no document silently shrinks the evaluation set without anyone
    noticing the count changed.
    """
    gt_path = HERE / GROUND_TRUTH_DIRNAME / GROUND_TRUTH_FILENAME[partition]
    if not gt_path.exists():
        rep.error("ground_truth", f"manifest missing: {gt_path}. Without it the partition has no labels "
                                  f"and cannot be evaluated.")
        return
    try:
        with gt_path.open(encoding="utf-8") as fh:
            gt = json.load(fh)
    except json.JSONDecodeError as exc:
        rep.error("ground_truth", f"manifest does not parse: {exc}")
        return

    labels = gt.get("labels", {})
    for doc_id in docs:
        if doc_id not in labels:
            rep.error("ground_truth", f"document '{doc_id}' has no ground-truth label")
    for doc_id, entry in labels.items():
        if doc_id not in docs:
            rep.error("ground_truth", f"manifest labels '{doc_id}' but no such document exists")
            continue
        value = entry.get("ground_truth")
        if value not in GROUND_TRUTH_VALUES:
            rep.error("ground_truth", f"'{doc_id}' has label {value!r}, not one of {GROUND_TRUTH_VALUES}")
        elif value != partition:
            rep.error("ground_truth", f"'{doc_id}' is labelled '{value}' inside the '{partition}' partition")
        if entry.get("source_tier") != docs[doc_id].get("source_tier"):
            rep.error("ground_truth", f"'{doc_id}' tier in manifest ({entry.get('source_tier')}) disagrees "
                                      f"with the document ({docs[doc_id].get('source_tier')})")

    if partition == "poisoned":
        families = set()
        for doc_id, entry in labels.items():
            fam = entry.get("poison_family_id")
            if not fam:
                rep.error("ground_truth", f"poisoned document '{doc_id}' has no poison_family_id; grouped "
                                          f"splitting and leave-one-attack-family-out (design 3.6) require one")
            else:
                families.add(fam)
            if not entry.get("target_query_id"):
                rep.error("ground_truth", f"poisoned document '{doc_id}' names no target_query_id")
        rep.info["poison_families"] = sorted(families)
        if len(families) < MIN_POISON_FAMILIES:
            rep.error("ground_truth", f"only {len(families)} attack families present; leave-one-attack-family-out "
                                      f"evaluation needs at least {MIN_POISON_FAMILIES}")
        tiers = {d.get("source_tier") for d in docs.values()}
        if 1 not in tiers:
            rep.error("ground_truth", "no Tier-1 poisoned documents. The is_tier1 x signal interaction "
                                      "coefficients are then unidentifiable and cases C4/C5 cannot be "
                                      "validated (design 3.5) — the project's central claim goes untested.")


def check_schema_symmetry(docs: dict[str, dict], partition: str, rep: Report) -> None:
    """Clean and poisoned documents must expose the identical set of keys.

    If either partition carries a field the other lacks, that field alone separates
    them perfectly, and any detector with access to the document dict can reach it
    without doing any detection at all.
    """
    other = "clean" if partition == "poisoned" else "poisoned"
    other_dir = HERE / other
    other_files = [p for p in other_dir.glob("*.json") if p.name != "index.json"] if other_dir.is_dir() else []
    if not other_files:
        rep.warn("corpus", f"the '{other}' partition is not built, so schema symmetry could not be checked")
        return
    with other_files[0].open(encoding="utf-8") as fh:
        other_keys = set(json.load(fh).keys())
    # Group by the distinct difference so a systemic asymmetry reports once, not
    # once per document.
    seen: dict[tuple, list[str]] = {}
    for doc_id, doc in docs.items():
        keys = set(doc.keys())
        if keys != other_keys:
            sig = (tuple(sorted(other_keys - keys)), tuple(sorted(keys - other_keys)))
            seen.setdefault(sig, []).append(doc_id)
    for (missing, extra), ids in seen.items():
        shown = ", ".join(sorted(ids)[:3]) + (f" and {len(ids) - 3} more" if len(ids) > 3 else "")
        rep.error("corpus", f"SCHEMA ASYMMETRY: {len(ids)} document(s) differ from the '{other}' partition "
                            f"(missing: {list(missing) or 'none'}; extra: {list(extra) or 'none'}) -- {shown}. "
                            f"A field present in one partition and absent in the other is a free label.")


def check_corpus(docs: dict[str, dict], index: dict | None, partition: str, rep: Report) -> None:
    # 3. Index agreement, both directions.
    if index is None:
        rep.error("index.json", "index file is missing; downstream loaders depend on it")
    else:
        indexed = {e["doc_id"]: e for e in index.get("documents", [])}
        for doc_id in docs:
            if doc_id not in indexed:
                rep.error("index.json", f"document '{doc_id}' exists on disk but is absent from the index")
        for doc_id, entry in indexed.items():
            if doc_id not in docs:
                rep.error("index.json", f"index lists '{doc_id}' but no such document file exists")
            elif entry.get("content_sha256") != docs[doc_id].get("content_sha256"):
                rep.error("index.json", f"index hash for '{doc_id}' disagrees with the document file")
        if index.get("document_count") != len(docs):
            rep.error("index.json",
                      f"index document_count is {index.get('document_count')} but {len(docs)} files are present")

    # 12. Tier distribution.
    tier_counts = {t: 0 for t in TIERS}
    for doc in docs.values():
        tier = doc.get("source_tier")
        if tier in tier_counts:
            tier_counts[tier] += 1
    rep.info["tier_counts"] = tier_counts
    for tier, count in tier_counts.items():
        if count == 0:
            rep.error("corpus", f"tier {tier} has no documents. The case taxonomy defines cases at every tier and "
                                f"calibrates band thresholds per tier; those cases cannot be exercised or calibrated.")
        else:
            floor = MIN_DOCS_PER_TIER.get(partition, 1)
            if count < floor:
                rep.warn("corpus", f"tier {tier} has only {count} documents (minimum {floor} for the "
                                   f"'{partition}' partition)")

    # 13. Near-duplicate detection.
    token_sets = {doc_id: tokens(doc.get("content", "")) for doc_id, doc in docs.items()}
    worst = 0.0
    worst_pair = None
    near_dupes = []
    for a, b in itertools.combinations(sorted(token_sets), 2):
        score = jaccard(token_sets[a], token_sets[b])
        if score > worst:
            worst, worst_pair = score, (a, b)
        if score >= JACCARD_FAIL_THRESHOLD:
            rep.error("corpus", f"near-duplicate content: '{a}' and '{b}' overlap at Jaccard {score:.2f}")
        elif score >= JACCARD_WARN_THRESHOLD:
            near_dupes.append((a, b, score))
    for a, b, score in near_dupes:
        rep.warn("corpus", f"high content overlap: '{a}' and '{b}' at Jaccard {score:.2f}; "
                           f"template variation may be insufficient")
    rep.info["max_pairwise_jaccard"] = round(worst, 4)
    rep.info["max_pairwise_jaccard_pair"] = list(worst_pair) if worst_pair else None

    # Descriptive statistics that are worth seeing on every run.
    words = sorted(len(d.get("content", "").split()) for d in docs.values())
    if words:
        rep.info["content_words"] = {
            "min": words[0],
            "median": words[len(words) // 2],
            "max": words[-1],
            "mean": round(sum(words) / len(words), 1),
        }
    rep.info["document_count"] = len(docs)
    rep.info["reference_verified_count"] = sum(1 for d in docs.values() if d.get("reference_verified"))
    rep.info["source_counts"] = {}
    for doc in docs.values():
        sid = doc.get("source_id", "unknown")
        rep.info["source_counts"][sid] = rep.info["source_counts"].get(sid, 0) + 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Validate a corpus partition before downstream use.")
    ap.add_argument("--corpus", default="clean", choices=["clean", "poisoned"],
                    help="which corpus partition to validate (default: clean)")
    ap.add_argument("--path", type=Path, default=None,
                    help="explicit corpus directory, overriding --corpus")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as failures")
    ap.add_argument("--report", type=Path, default=None,
                    help="write a machine-readable JSON report to this path")
    args = ap.parse_args()

    corpus_dir = args.path or (HERE / args.corpus)
    if not corpus_dir.is_dir():
        print(f"ERROR: corpus directory not found: {corpus_dir}", file=sys.stderr)
        return 2

    try:
        with REGISTRY_PATH.open(encoding="utf-8") as fh:
            registry = json.load(fh)["sources"]
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"ERROR: cannot load source registry: {exc}", file=sys.stderr)
        return 2

    rep = Report()

    index = None
    index_path = corpus_dir / "index.json"
    if index_path.exists():
        try:
            with index_path.open(encoding="utf-8") as fh:
                index = json.load(fh)
        except json.JSONDecodeError as exc:
            rep.error("index.json", f"index file does not parse: {exc}")

    docs: dict[str, dict] = {}
    doc_paths = sorted(p for p in corpus_dir.glob("*.json") if p.name != "index.json")
    if not doc_paths:
        print(f"ERROR: no document files found in {corpus_dir}", file=sys.stderr)
        return 2

    for path in doc_paths:
        try:
            with path.open(encoding="utf-8") as fh:
                doc = json.load(fh)
        except json.JSONDecodeError as exc:
            rep.error(path.name, f"file does not parse as JSON: {exc}")
            continue
        doc_id = doc.get("doc_id")
        if doc_id in docs:
            rep.error(path.name, f"duplicate doc_id '{doc_id}'")
            continue
        check_document(doc, path, registry, args.corpus, rep)
        if doc_id:
            docs[doc_id] = doc

    check_corpus(docs, index, args.corpus, rep)
    check_ground_truth(docs, args.corpus, rep)
    check_schema_symmetry(docs, args.corpus, rep)

    # ---------------- output ----------------
    print(f"Corpus validation: {corpus_dir}")
    print(f"  documents           : {rep.info.get('document_count', 0)}")
    tc = rep.info.get("tier_counts", {})
    print(f"  tier distribution   : T1={tc.get(1, 0)}  T2={tc.get(2, 0)}  T3={tc.get(3, 0)}")
    cw = rep.info.get("content_words", {})
    if cw:
        print(f"  body length (words) : min={cw['min']} median={cw['median']} mean={cw['mean']} max={cw['max']}")
    print(f"  verified anchors    : {rep.info.get('reference_verified_count', 0)}")
    print(f"  max pairwise overlap: {rep.info.get('max_pairwise_jaccard', 0):.3f} "
          f"{rep.info.get('max_pairwise_jaccard_pair') or ''}")
    if rep.info.get("poison_families"):
        print(f"  attack families     : {len(rep.info['poison_families'])} "
              f"({', '.join(rep.info['poison_families'])})")
    print()

    for item in rep.errors:
        print(f"  ERROR  [{item['scope']}] {item['message']}")
    for item in rep.warnings:
        print(f"  WARN   [{item['scope']}] {item['message']}")

    failed = bool(rep.errors) or (args.strict and bool(rep.warnings))

    print()
    if failed:
        print(f"FAILED: {len(rep.errors)} error(s), {len(rep.warnings)} warning(s)")
        print("This corpus must not be used downstream until the errors above are resolved.")
    else:
        print(f"PASSED: {len(rep.errors)} error(s), {len(rep.warnings)} warning(s)")
        print("Corpus is complete and internally consistent; safe for downstream use.")

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("w", encoding="utf-8") as fh:
            json.dump({
                "corpus": str(corpus_dir),
                "validated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "passed": not failed,
                "strict": args.strict,
                "summary": rep.info,
                "errors": rep.errors,
                "warnings": rep.warnings,
            }, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"Report written to {args.report}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
