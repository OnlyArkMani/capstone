# Session Log — Building the Baseline RAG Pipeline

**Date:** 3 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main output:** the `pipeline/` package — 15 files, all tests passing

---

## What this session was for

We now have documents. This session built the thing that actually uses them: take a
question, find the most relevant documents, feed them to a language model, get an answer.
That's the whole baseline.

Crucially, **this version has no security layer at all**. That's deliberate. It is the
"before" picture. Everything we build afterwards gets measured against it, so if we
sneaked any protection in here we would be comparing our system against itself and the
headline result would mean nothing.

---

## What we built

Three functions, callable separately:

- `embed_query(query)` — turns a question into a vector
- `retrieve_top_k(query, k=5)` — finds the 5 closest documents
- `generate_answer(query, retrieved_docs)` — writes an answer from them

Plus `rag.answer(query)` which runs all three and logs the result.

We kept them separate on purpose. Later sprints need to run retrieval *without*
generation (to compute detector signals on a set of documents) and generation *without*
re-retrieval (to replay a set we already logged). If they were welded together, both
would be awkward.

**Tech:** sentence-transformers with `bge-small-en-v1.5` for embeddings, FAISS for
search, and either Ollama running Llama 3.1 8B locally or Groq's free tier for
generation. All open-source, nothing paid.

---

## The retrieval output is structured, not text

This was the specific requirement and it's worth explaining why it matters.

A naive retriever hands back a list of strings. Ours hands back a list of records, each
carrying:

- its **rank** and **similarity score** to the query
- the **document text**
- full **provenance**: which source it came from, that source's trust tier and tier
  label, its type, publisher, publication date, whether we verified its reference, and a
  content checksum
- tags, CVE IDs, ATT&CK techniques, vendor, product

Three later components read these fields — the report generator, the audit log, and all
four detectors. If the pipeline only returned text, every one of them would have to go
back to disk and look the metadata up again, and they would inevitably drift out of sync
on how they did it. Getting the shape right now means it only has to be right once.

We also return set-level numbers alongside the list: how many documents came back, the
spread of similarity scores, the worst tier present. The anomaly detector normalises
against the retrieval set rather than the whole corpus, and the confidence measure reads
evidence volume — both need these, including for queries replayed from the log later.

**One naming caution.** We return `top_tier`, the tier of the highest-scoring document.
That is *not* the same as the design's `tier_governing`, which is the tier of the document
the answer actually leaned on. Working that out needs the generation step. Ours is the
retrieval-time approximation and the fusion layer should recompute it properly — noted in
the code so nobody assumes otherwise.

---

## Logging

Every query and everything it retrieved, with scores and provenance, gets appended to
`logs/retrieval_log.jsonl` — one line per query. Nothing is scored, filtered or flagged;
this is passive recording only, which is what this stage calls for.

Two small decisions worth recording:

**We write to a JSON lines file, not the SQLite audit table from the design.** That table
has columns for detector signals, case IDs and both track proposals — none of which exist
yet. Filling it with rows where most columns are empty would leave the audit trail with a
big block of meaningless history. Every log line carries a schema version so the audit
writer can migrate them later instead of guessing.

**We flush and sync each line to disk immediately.** If the process dies mid-run, the
record of what the pipeline retrieved is the only account of what it saw. Losing it to a
buffer would be losing the evidence.

---

## Perplexity is deliberately not here

Per the literature review, perplexity does not reliably separate clean from adversarial
text — clean and malicious writing overlap in it — and no perplexity term appears anywhere
in our composite score. So it is not computed, not logged, and not referenced.

This is a scoped-out decision, not something we forgot. It's stated in the module
documentation, in the logging module, and there's a test that fails if the string ever
turns up in a log record.

---

## Keeping the pipeline honest about what it can see

Same principle as last session, now enforced in code. The pipeline indexes clean and
poisoned documents **together and is never told which is which**:

- The loader throws away which folder a document came from.
- It only passes through an explicit allowlist of fields, so if someone adds a new
  answer-key field to the corpus later it is excluded by default rather than leaking until
  somebody notices.
- It **crashes** if a document file carries an answer-key field. A regression in the corpus
  builders now fails loudly when you build the index, instead of quietly inflating a score
  months later.
- A test checks that no file in the pipeline package even mentions the ground-truth folder.

One more thing we caught while writing the prompt builder: we do **not** tell the language
model which tier a source is. Saying "this one is from CISA" would be a trust signal, and
the baseline is supposed to have none.

---

## A practical problem, and what we did about it

Neither the build environment nor the project's network policy can reach PyPI or Hugging
Face, so we could not install sentence-transformers or download the model here.

Rather than ship code nobody had run, each layer got a fallback that works with no
downloads:

| Layer | Real | Fallback | What the fallback is |
|---|---|---|---|
| Embeddings | bge-small-en-v1.5 | keyword-hashing vectors | **Not semantic.** Structure works, quality numbers meaningless |
| Search | FAISS | plain numpy | **Identical results** — both are exact search |
| Generation | Llama 3.1 / Qwen2.5 | extract leading passages | **Not a language model.** Labels itself in its own output |

Each falls back with a visible warning, and the index metadata records which was used, so
a result can never be quietly mistaken for a real one.

The numpy fallback is genuinely fine — with 84 documents, exact search computes the same
answer FAISS would, just without the dependency. The other two need the real thing before
any number is worth reporting, and the code says so.

**You will need to run `pip install -r pipeline/requirements.txt` on your own machine to
get real results.** That's the one thing this session couldn't do for you.

---

## Testing

`python -m pipeline.test_pipeline` — 45 checks, all passing, on both the build environment
and yours. It covers the corpus loading being partition-blind, the leak guard actually
raising, embeddings being normalised and the right size, the retrieval record shape and
ordering, the prompt not leaking tiers, the log containing everything it should and
nothing it shouldn't, and a saved index reloading to identical results.

We also ran real queries end to end. Two things stood out even with the placeholder
embedder:

- Asking about the ransomware IP returned our poisoned "withdrawn indicator" feed entry at
  **rank 1**, above the genuine one.
- Asking whether the Contec patient monitor is safe returned our **fake CISA advisory at
  rank 1**, above the real advisory at rank 2.

That is exactly what this benchmark exists to demonstrate — the attack works against an
unprotected pipeline. Treat it as encouraging rather than conclusive, since the real
embedder may rank things differently.

---

## What's open

1. Install the real dependencies and rebuild the index. Every number so far is
   provisional until then.
2. Re-run the poisoned-document retrieval check properly — this is the measurement we
   flagged as outstanding last session, and now there's something to run it against.
3. Build the query set. We have 10 target questions from the poisoned corpus; the
   evaluation design wants several hundred query instances.
4. Decide Ollama or Groq. Ollama means no rate limits and no key but needs local compute;
   Groq is faster but rate-limited on the free tier. Either works — the code supports both
   and picks whichever is available.

---

## Next session

Level 2 — the four detectors: embedding anomaly, prompt injection, claim-evidence
entailment, and evidence conflict. They read the retrieval records this session produces.
