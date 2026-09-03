# Session Log — Building the Clean Document Corpus

**Date:** 2 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main outputs:** `corpus/build_clean_corpus.py`, `corpus/validate_corpus.py`, `corpus/schema.py`, `corpus/sources/`, and 72 generated documents in `corpus/clean/`

---

## What this session was for

The system needs a body of realistic healthcare threat-intelligence documents to retrieve
from. This session built that, plus the two scripts that make it repeatable: one that
assembles the corpus, and one that checks it is complete before anything downstream
touches it.

---

## What we built

**72 documents**, each stored as its own JSON file with full metadata, plus an
`index.json` that lists them all. Spread across the three source trust tiers we defined
last session:

- **Tier 1 (40 documents)** — CISA medical device advisories, CISA cybersecurity
  advisories, MITRE ATT&CK technique entries, CVE records for medical devices and
  healthcare software, HHS HC3 threat briefs, and device manufacturer security bulletins.
- **Tier 2 (21 documents)** — Health-ISAC member bulletins, security vendor research
  write-ups, and curated open-source intelligence feed entries.
- **Tier 3 (11 documents)** — unattributed threat reports, community forum threads, and
  uploaded analyst working notes.

Every document carries: a unique document ID, the source it came from, its trust tier, the
source's name, the date we ingested it, a short summary, tags, and a checksum of its
content.

---

## Three decisions worth explaining

### 1. We added Tier 2 and Tier 3 documents, which weren't in the original ask

The task named CISA, MITRE, CVE and HC3 — and all four of those are Tier 1 sources. A
corpus made entirely of Tier 1 documents would have broken our own design.

Two reasons. First, four of the eleven cases in our taxonomy are defined at Tier 2 and
Tier 3, and they can't be tested with documents that don't exist. Second, and more
important: our design says the thresholds that decide "clean vs. suspicious vs. malicious"
are calculated *per tier*, from clean documents in that tier. With no clean Tier 3
documents, there is nothing to compare a Tier 3 document against — the whole calibration
step has no input.

Worth being clear on something the tiers make easy to muddle: **a Tier 3 document is not
a bad document.** Low source trust and malicious content are two separate axes, which is
exactly why the taxonomy crosses them. All 11 Tier 3 documents here are clean. They
represent the "unverified but unremarkable" case.

### 2. We wrote the documents rather than downloading them, and we say so in the data

We tried to pull real advisories. CISA's site refuses automated fetching, and neither the
build environment nor the project's network policy can reach the NVD or MITRE data feeds.

So the document bodies are written for this benchmark. They follow the structure, register
and field conventions of the source type they model, but they are not copies. Every
document records this in a `content_origin` field.

Separately, 27 of the 72 documents are anchored to **real, verified identifiers** — 8
genuine CISA medical advisory IDs, 12 genuine MITRE ATT&CK technique IDs, and 7 genuine
CVE records — with the real URL stored alongside. A flag called `reference_verified`
marks these, and it means the *identifier and title* were confirmed. It does not claim the
body text is a copy of the real thing.

Being precise about this is not pedantry. A research artifact that presents invented text
as a real government advisory is not defensible, and a mentor or examiner is entitled to
ask which parts are real. Now the data answers that question itself. It also avoids
republishing licensed third-party content in a student repository, and it means the corpus
stays fixed while the real advisories keep changing.

All IP addresses and domains in the corpus are fabricated and use the ranges reserved for
documentation, so nothing points at real infrastructure.

### 3. The build is deterministic and the network is never touched during it

Run the builder twice with the same inputs and you get byte-identical files. This matters
because a benchmark that changes between runs can't support reproducible evaluation — you
could never tell whether a metric moved because the model changed or because the corpus
did.

We've documented how to add live fetching later, and the key rule for it: fetch into a
cache as a separate step, and build from the cache. Never fetch during a build.

---

## The validator, and why it does more than check for blank fields

`validate_corpus.py` must be run before any embedding or retrieval work. The reason is
that corpus faults don't crash anything — they quietly distort a number, which is far
worse than an error.

It checks the obvious things: every required field present and non-empty, valid dates,
document IDs matching filenames and unique, index and files agreeing in both directions,
and content checksums matching.

Three checks are less obvious and matter more:

**Tier agreement with the registry.** Trust tiers are assigned in exactly one place — a
source registry file. Documents inherit their tier from their source, and the validator
fails any document whose tier has drifted from what the registry says. Tier is the
foundation of the entire case taxonomy; if a document's tier is wrong, every case
assignment and every per-tier threshold built from it is wrong too, and nothing would ever
announce it.

**Tier coverage.** The validator errors if any tier has no documents, and warns if a tier
is too thin for its thresholds to be stable.

**Near-duplicate detection.** This one guards against a mistake we could easily have made.
Because the builder renders documents from templates, documents from the same source type
could come out too similar to each other. If they did, they'd bunch tightly together when
converted to embeddings, and our anomaly detector would look excellent — not because it
works, but because we handed it an unrealistically tidy baseline. That would be an
evaluation artifact masquerading as a result.

So the builder deliberately varies the phrasing of each document, and the validator
measures whether that worked. Current maximum overlap between any two documents is **0.34**
on a 0–1 scale, against a warning line at 0.70. Comfortably clear, and it needs re-checking
whenever documents are added.

We tested the validator by deliberately breaking seven things in a copy of the corpus —
wrong tier, tampered content, missing field, verified-but-uncitable reference, a file
missing from the index, an impossible date, and a clean document tagged as poisoned. It
caught all seven and exited with a failure code. A validator nobody has tried to fool is
just decoration.

---

## One naming trap to know about

Our design document calls the grouping key `source_doc_id`. In the corpus it's called
`doc_id`. There is also a `source_id`, and it means something different — it identifies the
*feed*, not the document, and many documents share one.

When we get to splitting data for training, **group by `doc_id`.** Grouping by `source_id`
would put all 12 MITRE documents into a single group and wreck the split. This is written
into the corpus README so nobody has to remember it.

---

## What's open

1. The poisoned corpus is next, and the design puts two hard requirements on it: poisoned
   documents must exist at **all three tiers, including Tier 1** (without Tier 1 poisoned
   examples, the two most important cases in our taxonomy can never be validated), and each
   one needs an attack-template ID for data splitting. The validator already rejects
   poisoned documents missing that ID.
2. 72 clean documents is right for now, but the design targets roughly 600 clean and 200
   poisoned *query instances*. Those are different units — one document supports several
   query instances — so we need to confirm how many queries we can build per document
   before deciding whether to write more documents.
3. Whether the templated writing style is diverse enough will only be properly answerable
   once we can see the documents in embedding space. The 0.34 overlap figure is a good
   sign, not a guarantee.
4. If we ever get network access to NVD or MITRE, the fetch-to-cache path is documented and
   worth adding, because real advisory text would be better than ours.

---

## Next session

Build the poisoned corpus, following the PoisonedRAG method. As always, that work is
defensive research: the documents are synthetic, they exist only to test our own detection
layer, and they are never pointed at any real system.
