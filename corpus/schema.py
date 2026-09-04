"""
Corpus schema definitions for the healthcare threat-intelligence corpus.

Single source of truth for field names, enumerations and tier rules, shared by
build_clean_corpus.py and validate_corpus.py so that the builder and the
validator can never drift apart.

Tier semantics follow docs/design/TRUST_RISK_DESIGN.md section 1. Tier is a
property of the SOURCE, not of the content, and is never modified by detector
output -- it is assigned here at ingestion time and nowhere else.

Field-name note: the design document refers to `source_doc_id` as the grouping
key used when partitioning data by document (design section 3.6). In this
corpus that key is `doc_id`. `source_id` is a different thing entirely -- it
identifies the publishing FEED, not the document. Downstream code must group by
`doc_id`, not `source_id`.
"""

from __future__ import annotations

SCHEMA_VERSION = "corpus-clean-v1.0"
DESIGN_VERSION = "design-v1.0"

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------

TIERS = (1, 2, 3)

TIER_LABELS = {
    1: "verified_authoritative",
    2: "trusted_open",
    3: "unverified_unknown",
}

# How the document body came to exist. This distinction is deliberate and load
# bearing: nothing in this corpus is a verbatim reproduction of a published
# advisory, and the corpus must never imply otherwise.
#
#   synthesized_representative
#       Body text authored for this benchmark. Structure, register and field
#       conventions model the named source type; the prose is not copied.
#
#   fetched_public_source
#       Body text retrieved verbatim from a public source by a live adapter.
#       No document currently carries this value -- reserved for adapters in
#       corpus/adapters/ when they are run in an environment with egress.
CONTENT_ORIGINS = (
    "synthesized_representative",
    "fetched_public_source",
)

# Whether the identifier and title anchor to a real, publicly published item.
# reference_verified=True means the advisory ID / technique ID / CVE ID and its
# title were confirmed against the public source; it does NOT mean the body
# text is a copy of that item.
RELEVANCE_LEVELS = ("high", "medium", "low")

# --------------------------------------------------------------------------
# Required fields
# --------------------------------------------------------------------------

# Every field here must be present and non-empty for a document to be usable
# downstream. validate_corpus.py enforces this.
REQUIRED_FIELDS = (
    "schema_version",
    "doc_id",
    "source_id",
    "source_name",
    "source_tier",
    "source_type",
    "title",
    "summary",
    "content",
    "content_origin",
    "content_sha256",
    "ingestion_date",
    "tags",
    "healthcare_relevance",
    "reference_verified",
)

# Present but permitted to be null/empty.
OPTIONAL_FIELDS = (
    "published_date",
    "reference_url",
    "cve_ids",
    "attack_techniques",
    "vendor",
    "product",
    "license_note",
)

FIELD_TYPES = {
    "schema_version": str,
    "doc_id": str,
    "source_id": str,
    "source_name": str,
    "source_tier": int,
    "source_type": str,
    "title": str,
    "summary": str,
    "content": str,
    "content_origin": str,
    "content_sha256": str,
    "ingestion_date": str,
    "published_date": (str, type(None)),
    "reference_url": (str, type(None)),
    "reference_verified": bool,
    "tags": list,
    "cve_ids": list,
    "attack_techniques": list,
    "healthcare_relevance": str,
    "vendor": (str, type(None)),
    "product": (str, type(None)),
    "license_note": (str, type(None)),
}

# --------------------------------------------------------------------------
# Content bounds
# --------------------------------------------------------------------------

# Bounds are advisory quality gates, not arbitrary limits. A body under
# MIN_CONTENT_WORDS carries too little text for a meaningful embedding; one over
# MAX_CONTENT_WORDS would need chunking before retrieval, which this corpus
# deliberately avoids so that one document equals one retrievable unit.
MIN_CONTENT_WORDS = 90
MAX_CONTENT_WORDS = 420
MIN_SUMMARY_CHARS = 60
MAX_SUMMARY_CHARS = 400

# Near-duplicate guard. Documents rendered from shared templates can collapse
# into a tight cluster in embedding space, which would give the Level 2 anomaly
# detector an artificially clean baseline and flatter its measured performance.
# See docs/design/TRUST_RISK_DESIGN.md section 3.2.
JACCARD_WARN_THRESHOLD = 0.70
JACCARD_FAIL_THRESHOLD = 0.85

# Minimum documents required per tier, per partition. The case taxonomy defines
# cases at all three tiers (C1-C9), and a partition missing a tier cannot
# exercise the cases that depend on it. The clean figure exists because per-tier band thresholds
# are quantiles of the CLEAN distribution (design 2.1) and are unstable on few
# points. The poisoned partition calibrates nothing, so it needs only enough
# documents per tier to exercise the cases at that tier.
MIN_DOCS_PER_TIER = {"clean": 8, "poisoned": 2}

# --------------------------------------------------------------------------
# Ground truth separation
# --------------------------------------------------------------------------

# Ground-truth labels live OUTSIDE the document files, in a sidecar manifest
# per partition. This is not tidiness -- it is what makes the benchmark valid.
#
# A document file is what the retrieval pipeline loads. If the answer key rides
# along inside it, the detection layer can reach the label through any code path
# that reads document fields, and the measured performance stops meaning
# anything. Worse, the leak need not be deliberate: a field that is populated on
# poisoned documents and null on clean ones is a perfect classifier available to
# any component that touches the dict.
#
# Two properties are therefore enforced by validate_corpus.py:
#   1. No document file contains any field in FORBIDDEN_DOC_FIELDS.
#   2. Clean and poisoned documents carry the IDENTICAL set of keys, so that
#      schema shape alone cannot separate them.
GROUND_TRUTH_DIRNAME = "ground_truth"
GROUND_TRUTH_FILENAME = {"clean": "clean.json", "poisoned": "poisoned.json"}

# Fields that must never appear in a document file, in either partition.
FORBIDDEN_DOC_FIELDS = (
    "label",
    "ground_truth",
    "is_poisoned",
    "poison_family_id",
    "target_query_id",
    "intended_false_claim",
    "attacker_target_answer",
    "injection_payload",
    "corruption",
)

GROUND_TRUTH_VALUES = ("clean", "poisoned")

# Every poisoned document must name the attack template it came from. Grouped
# splitting (design section 3.6) uses it as the group key, and the
# leave-one-attack-family-out evaluation holds one out at a time.
MIN_POISON_FAMILIES = 3
