# Baseline RAG Pipeline

Retrieve → generate → log. **No security layer.** This is the comparison baseline the
trust layer will be measured against, so it stays naive by design: no provenance
weighting, no filtering, no refusal behaviour, and no trust language in the prompt.
Adding any of those here would contaminate the comparison the whole evaluation rests on.

---

## Setup

```bash
pip install -r pipeline/requirements.txt
export GROQ_API_KEY=...                  # free key: https://console.groq.com
python -m pipeline.check_backends        # verify before any batch run
```

Groq is the project default. Local Ollama is supported as an alternative
(`--generation-backend ollama`).

`torch` is the large download. For CPU-only:
`pip install torch --index-url https://download.pytorch.org/whl/cpu` first.

## Run

```bash
python -m pipeline.build_index
python -m pipeline.run_query "Is 198.51.100.47 associated with ransomware infrastructure?"
python -m pipeline.run_query --queries-file eval/target_queries.txt -k 5
python -m pipeline.test_pipeline
```

## Use as a module

```python
from pipeline import BaselineRAG

rag = BaselineRAG.from_disk()          # or .build() to index in memory

retrieval  = rag.retrieve(query, k=5)              # structured records
generation = rag.generate(query, retrieval.records)
rag.log(retrieval, generation)

result = rag.answer(query)             # all three at once
```

The three stages are independently callable on purpose. Later instrumentation needs
retrieval without generation (to compute detector signals over a retrieval set) and
generation without re-retrieval (to replay a logged set).

| Function | Returns |
|---|---|
| `embed_query(query)` | L2-normalised `np.ndarray`, shape `(dim,)` |
| `retrieve_top_k(query, k=5)` | `RetrievalResult` — `.records` is a list of `RetrievedRecord` |
| `generate_answer(query, retrieved_docs)` | `GenerationResult` |
| `log(retrieval, generation)` | the log record written |

---

## The retrieval record

`retrieve_top_k()` returns **structured records, never bare strings**. The report
generator, the audit log and the Level 2 detectors all read these fields, so the shape
is a contract — see `records.py`.

```python
RetrievedRecord(
    rank=1,
    doc_id="osint-feed-ransomware-c2-indicators",
    similarity=0.7413,               # cosine, in [-1, 1]
    raw_score=0.7413,
    title=..., summary=..., content=...,
    provenance=Provenance(
        source_id="curated_osint",
        source_name="Curated Open-Source Intelligence Feed",
        source_tier=2,
        source_tier_label="trusted_open",
        source_type="osint_feed",
        publisher=..., published_date=..., ingestion_date=...,
        reference_url=..., reference_verified=False,
        attestation=..., content_sha256=...,
    ),
    tags=[...], cve_ids=[...], attack_techniques=[...],
    healthcare_relevance="high", vendor=..., product=...,
)
```

`RetrievalResult` adds the set-level quantities the detectors need: `n_retrieved`,
`similarities`, `tier_min`, `top_tier`, `latency_ms`, `embedding_model`, `index_id`.

**`top_tier` is not the design's `tier_governing`.** That is the tier of the
highest-*attribution* cited document (design §2.2), which needs the generation step.
`top_tier` is the retrieval-time approximation; the fusion layer should recompute it.

---

## Logging (Level 1)

Every query and every record it retrieved, with scores and provenance, appended to
`logs/retrieval_log.jsonl` — one JSON object per line, append-only, flushed and
`fsync`ed so a crash mid-run cannot lose the record of what the pipeline saw.
`--per-query-file` additionally writes `logs/queries/<run_id>.json`.

**Passive means passive.** Nothing here scores, filters, flags or reorders. The
detectors do not exist yet and this stage must not anticipate them.

Each line carries `_schema`, `run_id`, `logged_at`, the query and its hash, `k`,
`embedding_model`, `index_id`, retrieval latency, the set-level similarity geometry
(`similarity_top`, `similarity_min`, `similarity_spread`, `tier_min`, `top_tier`), the
full retrieved list with per-document similarity and provenance, and the generation
result when one was produced.

Why JSONL rather than the SQLite `query_events` table from design §5.2: that table
carries detector signals, case identifiers and both track proposals, none of which exist
yet. Writing rows with those columns null would give the audit trail a large block of
meaningless history. This log is the input the audit writer will consume; `_schema` lets
that migration key off a version rather than guess.

---

## Two properties this package guarantees

### It is partition-blind

Clean and poisoned documents are indexed together and the pipeline is **never told which
is which**. `corpus_loader.load_corpus()` discards the directory of origin, emits only
an allowlist of fields, and **raises `GroundTruthLeakError`** if any document file
carries an answer-key field — so a regression in the corpus builders fails loudly at
index time rather than silently inflating a score.

Ground truth lives in `corpus/ground_truth/` and is joined by `doc_id` by the evaluation
harness, which is the only component permitted to read it. A test asserts that no module
in this package opens that directory.

Note also that `build_prompt()` deliberately does **not** put source tier in the prompt.
Telling the baseline which sources are authoritative would be a trust signal, and the
baseline is meant to have none.

### It does not compute perplexity

Not anywhere. This is a scoped-out decision from the literature review, not an oversight:
clean and adversarial text overlap in perplexity (design references P1 and P5), and no
perplexity term appears in the composite score (design §3.2). A test asserts the string
never appears in a log record. **Do not add one.**

---

## Backends

Each layer resolves a real backend first and falls back with a visible warning, so the
pipeline runs — and is testable — in an environment without model weights or network.

| Layer | Real | Fallback | Fallback is |
|---|---|---|---|
| Embeddings | `sentence-transformers`, default `BAAI/bge-small-en-v1.5` | hashing embedder | **not semantic.** Character-n-gram matching. Structurally valid, quality figures meaningless |
| Index | FAISS `IndexFlatIP` | exact numpy search | **identical results.** Both are exact inner-product search |
| Generation | Ollama (`llama3.1:8b`) or Groq free tier | extractive stub | **not a language model.** Returns leading passages; labels itself in its own output |

Force a backend with `--embedding-backend` / `--generation-backend`, or
`RAG_EMBEDDING_BACKEND` / `RAG_GENERATION_BACKEND`.

### Generator choice: Groq for evaluation, Ollama for iteration

**The headline evaluation uses Groq `llama-3.1-8b-instant`.** Attack success rate is
model-dependent — a different generator is differently steerable by poisoned context — so
**the baseline arm and the trust-layer arm must use the same one**, or the single
comparison the project rests on is confounded. Pick once, record it, don't mix.

Local Ollama is for development iteration, where speed matters and exact answers don't.
The default local model is `llama3.2:3b` rather than an 8B, because 8B does not fit in
4GB of VRAM (see below). Do not report figures from a mixed set of generators.

#### Groq free-tier rate limits, and why they bite

30 requests/min, **6,000 tokens/min**, 1,000 requests/day. For RAG the *token* limit binds
first by a wide margin: at k=5 a prompt is roughly 1.6k input plus 0.3k output, so the
sustainable rate is about **three queries per minute, not thirty**. A few hundred query
instances is therefore an hour or more, and 1,000 requests/day caps a full two-arm
evaluation at roughly 500 queries per arm per day.

`GroqGenerator` retries on 429 and 5xx with exponential backoff, honours `Retry-After`,
and fails fast on 4xx (a bad key or unknown model should not burn the daily quota on
retries). For unattended batches set `RAG_GROQ_MIN_INTERVAL=20` to pace requests
client-side rather than discovering the limit through repeated 429s.

#### Running Ollama on 4GB VRAM

| Model | Q4_K_M size | Fits 4GB VRAM? | Rough speed |
|---|---|---|---|
| `llama3.2:3b` | ~2.0 GB | yes, fully | 40–60 tok/s |
| `qwen2.5:3b` | ~1.9 GB | yes, fully | 40–60 tok/s |
| `phi3.5` (3.8B) | ~2.2 GB | yes, fully | 35–50 tok/s |
| `llama3.1:8b` | ~4.9 GB | **no** — partial offload | 5–9 tok/s |
| `qwen2.5:7b` | ~4.7 GB | **no** — partial offload | 5–9 tok/s |

An 8B model still *runs* on 4GB: Ollama puts what fits on the GPU and the rest on the CPU.
It is just slow — roughly 35–60 seconds for a single RAG answer, which makes a batch run
impractical. 16GB of system RAM is comfortable for the CPU-offloaded portion and is not
the constraint; VRAM is.

Two design notes worth keeping:

- **`bge-small-en-v1.5` over `all-MiniLM-L6-v2`** — same 384 dimensions, materially better
  retrieval. bge expects an instruction prefix on the **query side only**; applying it to
  documents as well degrades retrieval, which is why the prefix is applied conditionally
  in the embedder rather than by the caller.
- **Flat index, not IVF or HNSW** — at 84 documents an approximate index is slower to
  build, no faster to query, and introduces recall error into a benchmark whose entire
  purpose is measuring what gets retrieved. Revisit above ~100k vectors.
- **Index and query model must match.** `Retriever.from_disk()` refuses to load an index
  built with a different embedding model, because query and document vectors would live
  in different spaces and every similarity would be quietly meaningless.

---

## Files

```
pipeline/
  __init__.py          public API
  config.py            paths, models, env overrides
  records.py           Provenance, RetrievedRecord, RetrievalResult, GenerationResult
  corpus_loader.py     partition-blind loading + leak guard
  embeddings.py        sentence-transformers / hashing fallback
  vector_index.py      FAISS / exact numpy fallback
  retrieval.py         embed_query, retrieve_top_k
  generation.py        Ollama / Groq / extractive stub
  retrieval_log.py     passive JSONL logging
  rag.py               BaselineRAG facade
  build_index.py       CLI: build and persist the index
  run_query.py         CLI: run queries
  check_backends.py    CLI: verify embeddings / index / generation before a batch
  test_pipeline.py     smoke tests (no pytest dependency)
  index/               generated: persisted index + metadata
```
