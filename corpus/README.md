# Corpus

Construction and validation of the document corpora used to evaluate the trust and
risk layer. Two partitions exist:

| Partition | Contents | Built by |
|---|---|---|
| `clean/` | Representative healthcare threat-intelligence documents across all three source trust tiers | `build_clean_corpus.py` |
| `poisoned/` | 12 adversarial documents built following the PoisonedRAG methodology | `build_poisoned_corpus.py` |
| `ground_truth/` | The clean/poisoned answer key, per partition | both builders |

Both partitions are checked by the same validator, `validate_corpus.py`.

---

## Quick start

```bash
cd corpus
python build_clean_corpus.py    --ingestion-date 2026-09-02 --clean
python build_poisoned_corpus.py --ingestion-date 2026-09-03 --clean \
       --retrieval-report ../eval/poison_retrieval_check.json
python validate_corpus.py --corpus clean    --strict
python validate_corpus.py --corpus poisoned --strict
```

The build is **deterministic**: the same seeds and the same `--ingestion-date`
produce byte-identical output. This is intentional. A benchmark corpus that
changes between runs cannot support reproducible evaluation, and a live-fetching
builder would produce exactly that.

---

## Layout

```
corpus/
  schema.py                  shared field names, enums, bounds, tier rules
  build_clean_corpus.py      clean partition assembler
  build_poisoned_corpus.py   poisoned partition assembler (PoisonedRAG method)
  validate_corpus.py         validator (run before any downstream use)
  sources/
    registry.json            source registry -- the ONLY place tier is assigned
    seeds_tier1.json         structured seeds, Tier 1 sources
    seeds_tier2.json         structured seeds, Tier 2 sources
    seeds_tier3.json         structured seeds, Tier 3 sources
    poison_seeds.json        target queries, attack families, corruption payloads
  clean/                     generated: one JSON per document plus index.json
  poisoned/                  generated: same, same schema, same renderers
  ground_truth/              generated: the answer key, kept OUT of the documents
    clean.json
    poisoned.json
```

---

## Composition of the clean corpus

72 documents, distributed so that every tier in the case taxonomy can be
exercised and calibrated.

| Tier | Sources | Count |
|---|---|---|
| **1** — verified / authoritative | CISA ICS Medical Advisories (8), CISA Cybersecurity Advisories (7), MITRE ATT&CK techniques (12), NVD CVE records (7), HHS HC3 briefs (4), vendor PSIRT bulletins (2) | **40** |
| **2** — trusted but open | Health-ISAC member bulletins (6), security vendor research (7), curated OSINT feeds (8) | **21** |
| **3** — unverified / unknown | unattributed reports (4), community forum threads (4), uploaded analyst notes (3) | **11** |

**Tier 2 and Tier 3 documents are here on purpose.** The original scope named only
authoritative sources, all of which are Tier 1. A corpus made entirely of Tier 1
documents cannot support the design: cases C2, C3, C6 and C8 are defined at Tiers
2 and 3, and signal band thresholds are calibrated *per tier* from clean data
(`docs/design/TRUST_RISK_DESIGN.md` sections 2.1 and 2.4). Without clean Tier 2 and
Tier 3 documents there is no reference distribution against which a Tier 2 or Tier 3
anomaly could be judged.

Note also that **Tier 3 documents in this partition are clean**. Low source trust is
not the same thing as malicious content; that distinction is the entire point of
crossing the two axes in the taxonomy. Tier 3 clean documents populate case C3,
"Unverified but Unremarkable".

---

## Provenance and honesty

Every document carries `content_origin`, and every document in this corpus is
`synthesized_representative`.

- **Bodies are authored for this benchmark.** Structure, register and field
  conventions model the named source type. No body is a verbatim reproduction of a
  published advisory.
- **`reference_verified: true` attests to the anchor, not the body.** It means the
  advisory ID, technique ID or CVE ID and its title were confirmed against the
  public source. 27 of the 72 documents carry a verified anchor: 8 CISA ICS medical
  advisory identifiers, 12 MITRE ATT&CK technique identifiers, and 7 CVE records.
- **All indicators are fabricated** and use reserved documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `.invalid`). None
  corresponds to real infrastructure.

This matters for two reasons beyond honesty. Synthesized bodies avoid redistributing
third-party licensed content in a student repository, and they let the corpus stay
fixed while the real advisories they model continue to change.

---

## Document schema

```jsonc
{
  "schema_version": "corpus-clean-v1.0",
  "design_version": "design-v1.0",

  "doc_id":        "cisa-icsma-26-176-01",   // unique; this is the design's `source_doc_id`
  "source_id":     "cisa_ics_medical",       // identifies the FEED, not the document
  "source_name":   "CISA ICS Medical Advisory",
  "source_tier":   1,                        // 1 | 2 | 3, assigned by registry.json only
  "source_tier_label": "verified_authoritative",
  "source_type":   "cisa_advisory",
  "publisher":     "Cybersecurity and Infrastructure Security Agency (CISA)",

  "title":         "...",
  "summary":       "...",                    // short content summary
  "content":       "...",                    // the retrievable body
  "content_origin":"synthesized_representative",
  "content_sha256":"...",                    // integrity check over `content`
  "content_word_count": 186,

  "ingestion_date":  "2026-09-02",           // ISO-8601
  "published_date":  "2026-06-25",           // ISO-8601 or null
  "reference_url":   "https://...",
  "reference_verified": true,

  "tags": ["dicom", "medical-imaging"],
  "cve_ids": [],
  "attack_techniques": ["T1190"],
  "healthcare_relevance": "high",            // high | medium | low
  "vendor": "...", "product": "...",

  "license_note": "...", "attestation": "...",
  "label": "clean",
  "poison_family_id": null                   // set only in the poisoned partition
}
```

### A naming trap worth knowing about

The design document calls the per-document grouping key `source_doc_id`
(section 3.6). In this corpus that key is **`doc_id`**. `source_id` is a different
thing: it identifies the publishing feed and is shared by many documents.

**Downstream grouped splitting must group by `doc_id`, not `source_id`.** Grouping
by `source_id` would put all 12 MITRE ATT&CK documents in one group and collapse
the split.

---

## What the validator checks

Run `validate_corpus.py` before any embedding, retrieval or scoring work. A corpus
fault does not fail loudly downstream — it quietly distorts a metric.

**Structural** — index exists and parses; every file parses; `doc_id` matches its
filename and is unique; index and directory agree in both directions and their
hashes match.

**Metadata completeness** — every required field present, correctly typed and
non-empty; enumerated fields carry permitted values; dates are valid ISO-8601 and
`published_date` is not after `ingestion_date`; `reference_verified` documents carry
a `reference_url`.

**Provenance integrity** — `source_id` exists in the registry, and `source_tier`,
`source_name` and `source_type` all agree with it. The tier check is the most
important one in the file: tier is the foundation of the case taxonomy, and a
document whose tier has drifted from its source silently corrupts every case
assignment and every per-tier threshold calibrated from it. It is the corpus-side
equivalent of the `TIER_MISLABELLED` override reason code in design section 5.5.
`content_sha256` is verified against the stored content.

**Quality gates** — content and summary length bounds; per-tier minimum document
counts; and pairwise near-duplicate detection over token sets.

**Benchmark validity** -- no document file may carry any answer-key field; clean and
poisoned documents must expose the identical key set; and the ground-truth manifest
must label exactly this partition's documents, with every poisoned document naming a
`poison_family_id` and a `target_query_id`, at least three distinct attack families
present, and at least one Tier-1 poisoned document. See *Ground truth separation*
below for why these are errors rather than warnings.

### Why near-duplicate detection is in there

Documents rendered from a shared template cluster tightly in embedding space. That
would hand the Level 2 anomaly detector an artificially clean baseline and flatter
its measured performance — an evaluation artifact, not a result. The builder
mitigates this by varying opening and connective phrasing per document
(`_variant()`), and the validator measures whether the mitigation worked.

Current maximum pairwise Jaccard overlap is **0.34**, against a warning threshold of
0.70 and a failure threshold of 0.85. Re-check this figure whenever seeds are added.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | passed (warnings may be present unless `--strict`) |
| 1 | validation failed — do not use downstream |
| 2 | could not run (bad arguments, corpus missing) |

`--report <path>` writes a machine-readable JSON report for the evaluation harness.

---

## Extending the corpus

**To add documents:** add a structured seed to the appropriate `sources/seeds_tier*.json`,
then rebuild and revalidate. A seed supplies facts, a summary and key points; the
builder renders the body. Seeds never carry a tier — the tier comes from the source
registry.

**To add a source:** add it to `sources/registry.json` with its tier, then add a
renderer for its `source_type` in `build_clean_corpus.py` if the type is new.

**To add live fetching:** the "pull" path is deliberately not implemented. Neither
the build environment nor the project's egress policy currently permits reaching
NVD, MITRE or CISA, and shipping an untested fetcher would be worse than shipping
none. If it is added later, an adapter should:

1. Fetch and cache the raw upstream response under `sources/cache/` with the fetch
   timestamp, so the build stays reproducible from the cache.
2. Emit seeds in the existing seed format rather than emitting documents directly.
3. Set `content_origin` to `fetched_public_source` on any document whose body is
   upstream text verbatim, and record the licence terms in `license_note`.

Keeping fetch and render separate is what preserves determinism: the network is
touched when refreshing the cache, never during a build.

---

## Ground truth separation

**The clean/poisoned label is not stored in the document files.** It lives in
`ground_truth/<partition>.json`, and the validator fails any document that carries an
answer-key field.

This is the difference between a benchmark and a formality. A document file is what the
retrieval pipeline loads. If the label rides along inside it, the detection layer can
reach it through any code path that touches the document dict — and the leak need not be
deliberate. A field that is populated on poisoned documents and null on clean ones is a
perfect classifier available for free to anything downstream.

The subtler half is **schema symmetry**. It is not enough to remove the label; the two
partitions must expose the *identical* set of keys, or the shape of the record separates
them just as reliably. The validator enforces this by comparing key sets across
partitions.

Two consequences worth internalising:

- Poisoned documents are rendered by the **same renderers** as clean documents, imported
  directly from `build_clean_corpus.py`. If poisoned documents had their own rendering
  code they would acquire a stylistic signature, and the detectors would learn the
  signature rather than the attack.
- The ground-truth manifests carry a `WARNING` field stating that no pipeline component
  may read them. That is a convention, not an enforced boundary — the enforcement that
  matters is that the evaluation harness is the only module that imports the manifest
  path, and that should be asserted in a test when the harness is built.

---

## The poisoned partition

**Defensive security research.** These documents exist solely to provide ground-truth
positives for evaluating this project's own detection layer, following the published
PoisonedRAG methodology (Zou, Geng, Wang & Jia, 34th USENIX Security Symposium, 2025).
They are synthetic, contain no real indicators, are never inserted into any live
retrieval system, and are never directed at any third-party system. Every factual
assertion in them is deliberately false by construction, which is what makes them useful
as labelled positives and useless as intelligence.

### Composition

12 documents against 10 target queries, spanning six attack families and all three tiers.

| Tier | Count | Rationale |
|---|---|---|
| **1** | 2 | Simulates a compromised or spoofed authoritative channel — the case the taxonomy ranks highest (C4/C5). Without Tier-1 poisoned instances the `is_tier1 x signal` interaction coefficients are unidentifiable and those cases can never be validated. |
| **2** | 5 | Ordinary poisoning of trusted-but-open feeds |
| **3** | 5 | The expected attack path |

| Attack family | Count | What it does |
|---|---|---|
| `ioc_reputation_flip` | 3 | Asserts a known-malicious indicator is benign, or that a listing was withdrawn |
| `authority_spoof` | 2 | Impersonates a Tier 1 channel — an advisory "update" reversing isolation guidance |
| `severity_downgrade` | 2 | Concedes the vulnerability but understates reachability so remediation is deprioritised |
| `remediation_misdirection` | 2 | Concedes the finding but recommends an action that weakens the defensive position |
| `attribution_fabrication` | 2 | Invents confident attribution that displaces defensive effort |
| `direct_prompt_injection` | 1 | Embeds instruction text addressed to the generating model rather than a human reader |

Six families matters for evaluation, not variety: leave-one-attack-family-out (design
§3.6) holds out an entire family to measure generalisation to unseen attack strategies,
and that needs several to hold out.

### Construction: S + I

Each document is built as PoisonedRAG specifies:

- **S — the retrieval-optimising segment.** In the black-box setting the attacker cannot
  query the embedding model, so the document is conditioned on the target query text
  itself. `_build_retrieval_segment()` restates the query and its salient terms as a
  natural subject line rather than pasting the question verbatim — a document containing
  a literal question is detectable by inspection and would make the benchmark too easy.
- **I — the corruption payload.** The attacker's intended false conclusion, rendered in
  the house style of its source type by the clean corpus's own renderers.

The exact S generated for each document is recorded in the ground-truth manifest, so the
attack is auditable after the fact.

### Retrieval pre-check, and its limits

The builder scores every poisoned document against the entire clean corpus for its target
query using BM25, and reports rank. All 12 currently rank 1st or 2nd.

**This is a pre-check, not verification.** Retrieval in the pipeline is dense, not
lexical. A document that fails here is certainly too weak; one that passes is *not*
thereby confirmed retrievable. The real measurement is rank@k against the actual
embedding index, and it is an open item until the pipeline exists.

### Two honest limitations

- **Poisoned Tier-1 documents carry `reference_verified: false`.** A spoofing attacker
  can supply a plausible URL — and these do — but cannot make *our* ingestion-time
  verifier return true, so the flag stays false. This is faithful to the threat model and
  leaves a legitimate detection signal in place, but it does mean a detector could learn
  "Tier 1 + unverified" as a shortcut. Worth watching in the results: if Tier-1 detection
  is near-perfect while Tier-2 and Tier-3 lag, that shortcut is the likely reason.
- **12 documents is small.** The design targets ~200 poisoned *query instances*, which is
  a different unit — one document supports several instances once the query set is built.
  These 12 are the attack surface, not the training set.

### Extending

Add an entry to `sources/poison_seeds.json` with a `target_query_id`, a
`poison_family_id`, an `intended_false_claim`, and `facts` matching the renderer for its
source type. Rebuild and revalidate. To add a family, add it to `poison_families` and use
it — nothing else needs changing.
