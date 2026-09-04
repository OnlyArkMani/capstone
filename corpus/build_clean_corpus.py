#!/usr/bin/env python3
"""
Assemble the clean healthcare threat-intelligence corpus.

Reads the source registry and the structured seed sets, renders each seed into a
document body appropriate to its source type, and writes one JSON file per
document plus an index file into corpus/clean/.

Design contract
---------------
* Source tier is assigned ONLY by corpus/sources/registry.json. A seed never
  carries its own tier. This mirrors docs/design/TRUST_RISK_DESIGN.md section 1:
  tier is a property of the source, not of the content.
* Every rendered body is labelled `content_origin`. Nothing in this corpus is a
  verbatim reproduction of a published advisory. Where an identifier and title
  were confirmed against the public source, `reference_verified` is true -- that
  attests to the ANCHOR, not to the body text.
* The build is deterministic. Given the same seeds and the same
  --ingestion-date, byte-identical output is produced. A research benchmark that
  changes between runs cannot support reproducible evaluation.

Usage
-----
    python build_clean_corpus.py
    python build_clean_corpus.py --ingestion-date 2026-09-02 --clean
    python build_clean_corpus.py --out ../corpus/clean --dry-run

Poisoned documents are NOT built here. They are constructed separately under
corpus/poisoned/ following the PoisonedRAG methodology, as defensive security
research for internal benchmark use only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import (  # noqa: E402
    SCHEMA_VERSION,
    DESIGN_VERSION,
    CONTENT_ORIGINS,
    RELEVANCE_LEVELS,
    TIER_LABELS,
    GROUND_TRUTH_DIRNAME,
    GROUND_TRUTH_FILENAME,
)

HERE = Path(__file__).resolve().parent
REGISTRY_PATH = HERE / "sources" / "registry.json"
SEED_GLOB = "seeds_*.json"
DEFAULT_OUT = HERE / "clean"


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _variant(doc_id: str, options: list[str]) -> str:
    """Pick a deterministic variant for this document.

    Template variation is deliberate. Documents rendered from a single template
    collapse toward one another in embedding space, which would hand the Level 2
    anomaly detector an artificially tight clean baseline and flatter its
    measured performance. Varying the opening and connective phrasing per
    document widens the clean distribution without changing the facts.
    """
    h = int(hashlib.sha256(doc_id.encode("utf-8")).hexdigest()[:8], 16)
    return options[h % len(options)]


def _bullets(items) -> str:
    return "\n".join(f"- {item}" for item in items if item)


def _para(*parts) -> str:
    return " ".join(p.strip() for p in parts if p and p.strip())


def _join_points(points, lead_options, doc_id) -> str:
    if not points:
        return ""
    lead = _variant(doc_id, lead_options)
    return f"{lead}\n\n" + _bullets(points)


# ---------------------------------------------------------------------------
# Per-source-type renderers
# ---------------------------------------------------------------------------

def render_cisa_advisory(seed, facts) -> str:
    did = seed["doc_id"]
    if "equipment" in facts:
        opening = _variant(did, [
            "This advisory concerns a vulnerability affecting equipment deployed in clinical environments.",
            "The following advisory describes a security issue in equipment used in healthcare delivery settings.",
            "A vulnerability has been identified in equipment operating within clinical care environments.",
        ])
        body = [
            f"## Executive summary\n\n{_para(opening, seed['summary'])}",
            "## Affected equipment\n\n"
            f"**Equipment:** {facts['equipment']}\n\n"
            f"**Vendor:** {seed.get('vendor') or 'Not specified'}\n\n"
            f"**Vulnerability type:** {facts['vulnerability_type']}\n\n"
            f"**CVSS base score:** {facts['cvss']}",
            "## Affected versions\n\n" + _bullets(facts.get("affected_versions", [])),
            f"## Risk evaluation\n\n{facts['risk_note']}\n\n"
            f"**Exploitability:** {facts['exploitability']}",
            "## Mitigations\n\n" + _bullets(facts.get("mitigations", [])),
            _join_points(seed.get("key_points"), [
                "## Analyst notes",
                "## Additional considerations",
                "## Context for defenders",
            ], did),
        ]
    else:
        opening = _variant(did, [
            "This joint advisory is released to warn network defenders in the health and public health sector.",
            "The authoring agencies are releasing this advisory to inform health sector defenders of observed activity.",
            "This advisory documents observed threat activity affecting health and public health sector organisations.",
        ])
        agencies = ", ".join(facts.get("sealing_agencies", []))
        body = [
            f"## Summary\n\n{_para(opening, seed['summary'])}",
            f"**Advisory type:** {facts['advisory_type']}\n\n**Authoring agencies:** {agencies}",
            "## Observed tactics, techniques and procedures\n\n" + _bullets(facts.get("observed_ttps", [])),
            "## Recommended actions\n\n" + _bullets(facts.get("recommended_actions", [])),
            _join_points(seed.get("key_points"), [
                "## Assessment",
                "## Defender considerations",
                "## Analytic notes",
            ], did),
        ]
    return "\n\n".join(b for b in body if b.strip())


def render_attack_technique(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "The following describes an adversary technique and its expression in healthcare environments.",
        "This entry covers an adversary behaviour observed in intrusions against provider organisations.",
        "The technique described here is documented across intrusions affecting the health sector.",
    ])
    return "\n\n".join([
        f"## {facts['technique_id']} - {seed['title'].split(': ', 1)[-1]}\n\n{_para(opening, seed['summary'])}",
        f"**Tactic:** {facts['tactic']}\n\n**Platforms:** {', '.join(facts.get('platforms', []))}",
        f"## Healthcare context\n\n{facts['healthcare_context']}",
        f"## Detection\n\n{facts['detection']}",
        "## Mitigations\n\n" + _bullets(facts.get("mitigations", [])),
        _join_points(seed.get("key_points"), [
            "## Practical considerations",
            "## Notes for defenders",
            "## Observations",
        ], did),
    ])


def render_cve_record(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "The following vulnerability record concerns a product used in healthcare delivery.",
        "This record describes a published vulnerability affecting healthcare technology.",
        "The vulnerability below affects a component deployed in clinical or health sector settings.",
    ])
    return "\n\n".join([
        f"## {facts['cve_id'] if 'cve_id' in facts else seed['cve_ids'][0]}\n\n{_para(opening, seed['summary'])}",
        f"**Weakness:** {facts['cwe']}\n\n"
        f"**CVSS base score:** {facts['cvss']}\n\n"
        f"**Attack vector:** {facts['attack_vector']}\n\n"
        f"**Vendor:** {seed.get('vendor') or 'Not specified'}\n\n"
        f"**Product:** {seed.get('product') or 'Not specified'}",
        f"## Affected products\n\n{facts['affected']}",
        f"## Remediation\n\n{facts['remediation']}",
        f"## Context\n\n{facts['context']}",
        _join_points(seed.get("key_points"), [
            "## Healthcare impact considerations",
            "## Sector-specific notes",
            "## Practical assessment",
        ], did),
    ])


def render_hc3_brief(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "This product is provided to health sector partners for situational awareness.",
        "The following is shared with health and public health sector partners to support defensive planning.",
        "This brief is issued to assist health sector organisations in prioritising defensive effort.",
    ])
    return "\n\n".join([
        f"## {facts['tlp']}\n\n{_para(opening, seed['summary'])}",
        f"**Topic:** {facts['topic']}",
        "## Sector impact\n\n" + _bullets(facts.get("sector_impact", [])),
        "## Recommended actions\n\n" + _bullets(facts.get("recommended_actions", [])),
        _join_points(seed.get("key_points"), [
            "## Analyst comment",
            "## Assessment",
            "## Additional observations",
        ], did),
    ])


def render_vendor_psirt(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "This product security bulletin is issued to affected customers.",
        "The manufacturer is issuing this bulletin to inform customers of a product security issue.",
        "This bulletin describes a security issue identified in the product named below.",
    ])
    return "\n\n".join([
        f"## Bulletin {facts['bulletin_id']}\n\n{_para(opening, seed['summary'])}",
        f"**Severity:** {facts['severity']}\n\n**Vendor:** {seed.get('vendor')}\n\n**Product:** {seed.get('product')}",
        "## Affected products\n\n" + _bullets(facts.get("affected_products", [])),
        f"## Interim workaround\n\n{facts['workaround']}",
        "## Remediation\n\n" + _bullets(facts.get("remediation", [])),
        _join_points(seed.get("key_points"), [
            "## Customer guidance notes",
            "## Additional considerations",
            "## Deployment notes",
        ], did),
    ])


def render_isac_bulletin(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "This bulletin consolidates reporting contributed by member organisations.",
        "The following is shared with members on the basis of member-contributed reporting.",
        "This bulletin summarises activity reported to the community by member organisations.",
    ])
    return "\n\n".join([
        f"## {facts['tlp']} - Alert level: {facts['alert_level']}\n\n{_para(opening, seed['summary'])}",
        f"## Observed activity\n\n{facts['observed_activity']}",
        "## Recommended member actions\n\n" + _bullets(facts.get("member_actions", [])),
        _join_points(seed.get("key_points"), [
            "## Community assessment",
            "## Notes on this reporting",
            "## Analytic caveats",
        ], did),
    ])


def render_vendor_blog(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "Our research team is publishing the following analysis.",
        "This post presents findings from our recent research work.",
        "The analysis below summarises what our team observed during this work.",
    ])
    iocs = facts.get("iocs") or []
    parts = [
        f"## Overview\n\n{_para(opening, seed['summary'])}",
        f"**Scope:** {facts['campaign']}\n\n**Confidence:** {facts['confidence']}",
        f"## Data and methodology\n\n{facts['telemetry_note']}",
        _join_points(seed.get("key_points"), [
            "## Findings",
            "## What we observed",
            "## Key observations",
        ], did),
    ]
    if iocs:
        parts.append("## Indicators\n\n" + _bullets(iocs))
    return "\n\n".join(parts)


def render_osint_feed(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "This feed entry is published for community consumption.",
        "The following entry is distributed as part of a curated indicator feed.",
        "This entry is generated for community use and carries the caveats noted below.",
    ])
    parts = [
        f"## Feed entry\n\n{_para(opening, seed['summary'])}",
        f"**Feed type:** {facts['feed_type']}\n\n"
        f"**Confidence:** {facts['confidence']}\n\n"
        f"**First seen:** {facts['first_seen']}\n\n"
        f"**Last seen:** {facts['last_seen']}",
    ]
    if facts.get("indicators"):
        parts.append("## Indicators\n\n" + _bullets(facts["indicators"]))
    parts.append(_join_points(seed.get("key_points"), [
        "## Caveats and usage guidance",
        "## How to use this entry",
        "## Reliability notes",
    ], did))
    return "\n\n".join(p for p in parts if p.strip())


def render_unattributed_report(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "The origin of this document could not be established.",
        "No provenance information accompanies this document.",
        "This document arrived without any attribution or verification information.",
    ])
    return "\n\n".join([
        f"## Document summary\n\n{_para(opening, seed['summary'])}",
        f"## Content as received\n\n{facts['claim']}",
        f"## Provenance\n\n{facts['provenance_note']}\n\n**Circulation:** {facts['circulation']}",
        _join_points(seed.get("key_points"), [
            "## Reliability assessment",
            "## Assessment of this document",
            "## Notes on trustworthiness",
        ], did),
    ])


def render_forum_post(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "The following is a community discussion thread captured in full summary.",
        "This entry records a public discussion thread among practitioners.",
        "The thread summarised below took place on a public practitioner board.",
    ])
    return "\n\n".join([
        f"## Thread: {facts['thread_title']}\n\n{_para(opening, seed['summary'])}",
        f"**Board:** {facts['board']}\n\n"
        f"**Original poster:** {facts['poster_handle']}\n\n"
        f"**Replies:** {facts['reply_count']}",
        f"## Discussion summary\n\n{facts['discussion_summary']}",
        _join_points(seed.get("key_points"), [
            "## Reliability assessment",
            "## Caveats",
            "## Notes on this thread",
        ], did),
    ])


def render_analyst_note(seed, facts) -> str:
    did = seed["doc_id"]
    opening = _variant(did, [
        "This is an internal working note ingested from an analyst upload.",
        "The following working note was uploaded without review or sign-off.",
        "This document is an analyst working note and has not been through any review step.",
    ])
    return "\n\n".join([
        f"## Working note {facts['analyst_ref']}\n\n{_para(opening, seed['summary'])}",
        f"**Status:** {facts['status']}",
        f"## Note content\n\n{facts['note_body']}",
        "## Open questions\n\n" + _bullets(facts.get("open_questions", [])),
        _join_points(seed.get("key_points"), [
            "## Handling notes",
            "## Caveats on this note",
            "## Reliability assessment",
        ], did),
    ])


RENDERERS = {
    "cisa_advisory": render_cisa_advisory,
    "attack_technique": render_attack_technique,
    "cve_record": render_cve_record,
    "hc3_brief": render_hc3_brief,
    "vendor_psirt": render_vendor_psirt,
    "isac_bulletin": render_isac_bulletin,
    "vendor_blog": render_vendor_blog,
    "osint_feed": render_osint_feed,
    "unattributed_report": render_unattributed_report,
    "forum_post": render_forum_post,
    "analyst_note": render_analyst_note,
}


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def load_registry() -> dict:
    with REGISTRY_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)["sources"]


def load_seeds() -> list[dict]:
    seeds = []
    for path in sorted((HERE / "sources").glob(SEED_GLOB)):
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        for doc in data["documents"]:
            doc["_seed_file"] = path.name
            seeds.append(doc)
    return seeds


def build_document(seed: dict, registry: dict, ingestion_date: str) -> dict:
    source_id = seed["source_id"]
    if source_id not in registry:
        raise KeyError(f"{seed['doc_id']}: source_id '{source_id}' is not in the registry")
    src = registry[source_id]
    source_type = src["source_type"]

    renderer = RENDERERS.get(source_type)
    if renderer is None:
        raise KeyError(f"{seed['doc_id']}: no renderer for source_type '{source_type}'")

    content = renderer(seed, seed.get("facts", {}))
    content = re.sub(r"\n{3,}", "\n\n", content).strip() + "\n"

    relevance = seed.get("healthcare_relevance", "medium")
    if relevance not in RELEVANCE_LEVELS:
        raise ValueError(f"{seed['doc_id']}: healthcare_relevance '{relevance}' is not valid")

    return {
        "schema_version": SCHEMA_VERSION,
        "design_version": DESIGN_VERSION,
        "doc_id": seed["doc_id"],
        "source_id": source_id,
        "source_name": src["source_name"],
        # Tier comes from the registry and from nowhere else.
        "source_tier": src["source_tier"],
        "source_tier_label": TIER_LABELS[src["source_tier"]],
        "source_type": source_type,
        "publisher": src["publisher"],
        "title": seed["title"],
        "summary": seed["summary"],
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
        # NOTE: no ground-truth label here, deliberately. See schema.py,
        # "Ground truth separation". The label lives in the sidecar manifest at
        # corpus/ground_truth/clean.json and never inside a document file.
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Assemble the clean healthcare threat-intelligence corpus.")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT,
                    help="output directory (default: corpus/clean)")
    ap.add_argument("--ingestion-date", default=dt.date.today().isoformat(),
                    help="ISO date recorded as ingestion_date on every document (default: today)")
    ap.add_argument("--clean", action="store_true",
                    help="remove existing generated documents before writing")
    ap.add_argument("--dry-run", action="store_true",
                    help="build and report without writing files")
    args = ap.parse_args()

    try:
        dt.date.fromisoformat(args.ingestion_date)
    except ValueError:
        print(f"ERROR: --ingestion-date '{args.ingestion_date}' is not a valid ISO date", file=sys.stderr)
        return 2

    registry = load_registry()
    seeds = load_seeds()

    seen = {}
    documents = []
    for seed in seeds:
        did = seed["doc_id"]
        if did in seen:
            print(f"ERROR: duplicate doc_id '{did}' in {seed['_seed_file']} and {seen[did]}", file=sys.stderr)
            return 1
        seen[did] = seed["_seed_file"]
        documents.append(build_document(seed, registry, args.ingestion_date))

    tier_counts = {1: 0, 2: 0, 3: 0}
    source_counts: dict[str, int] = {}
    for doc in documents:
        tier_counts[doc["source_tier"]] += 1
        source_counts[doc["source_id"]] = source_counts.get(doc["source_id"], 0) + 1

    index = {
        "schema_version": SCHEMA_VERSION,
        "design_version": DESIGN_VERSION,
        "corpus": "clean",
        "built_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "ingestion_date": args.ingestion_date,
        "document_count": len(documents),
        "tier_counts": {str(k): v for k, v in tier_counts.items()},
        "source_counts": source_counts,
        "content_origin_counts": {
            origin: sum(1 for d in documents if d["content_origin"] == origin)
            for origin in CONTENT_ORIGINS
        },
        "reference_verified_count": sum(1 for d in documents if d["reference_verified"]),
        "provenance_statement": (
            "Document bodies in this corpus are synthesized representative text. Structure, register and field "
            "conventions model the named source type; no body is a verbatim reproduction of a published advisory. "
            "Where reference_verified is true, the identifier and title were confirmed against the public source -- "
            "that attests to the anchor, not to the body text. All indicators are fabricated and use reserved "
            "documentation ranges."
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
            for d in sorted(documents, key=lambda x: x["doc_id"])
        ],
    }

    print(f"Built {len(documents)} clean documents")
    print(f"  Tier 1: {tier_counts[1]}   Tier 2: {tier_counts[2]}   Tier 3: {tier_counts[3]}")
    print(f"  Reference-verified anchors: {index['reference_verified_count']}")
    words = [d["content_word_count"] for d in documents]
    print(f"  Body length: min {min(words)}, median {sorted(words)[len(words)//2]}, max {max(words)} words")

    if args.dry_run:
        print("Dry run: nothing written.")
        return 0

    out: Path = args.out
    if args.clean and out.exists():
        for existing in out.glob("*.json"):
            existing.unlink()
    out.mkdir(parents=True, exist_ok=True)

    for doc in documents:
        with (out / f"{doc['doc_id']}.json").open("w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")

    with (out / "index.json").open("w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    # Ground truth is written to a sidecar manifest, never into the document
    # files. See schema.py, "Ground truth separation".
    gt_dir = HERE / GROUND_TRUTH_DIRNAME
    gt_dir.mkdir(parents=True, exist_ok=True)
    with (gt_dir / GROUND_TRUTH_FILENAME["clean"]).open("w", encoding="utf-8") as fh:
        json.dump({
            "manifest_version": SCHEMA_VERSION,
            "partition": "clean",
            "built_at": index["built_at"],
            "WARNING": (
                "EVALUATION ONLY. The retrieval pipeline, the detectors and the fusion layer must "
                "never read this file. It is the answer key for the benchmark; any component that "
                "consults it invalidates every metric derived from that run."
            ),
            "document_count": len(documents),
            "labels": {
                d["doc_id"]: {
                    "ground_truth": "clean",
                    "poison_family_id": None,
                    "target_query_id": None,
                    "source_tier": d["source_tier"],
                }
                for d in sorted(documents, key=lambda x: x["doc_id"])
            },
        }, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"Wrote {len(documents)} documents and index.json to {out}")
    print(f"Wrote ground-truth manifest to {gt_dir / GROUND_TRUTH_FILENAME['clean']}")
    print("Next: python validate_corpus.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
