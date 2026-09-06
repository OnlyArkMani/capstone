# Archived results — hashing-fallback index (superseded)

These are the evaluation outputs of 6 September 2026, 13:04, kept only as a record.

They were produced against `pipeline/index/`, which `corpus_meta.json` shows was
built on 3 September with `embedding_model: hashing-fallback-384d` and
`embedding_is_semantic: false`. The semantic embedder the design specifies,
`BAAI/bge-small-en-v1.5`, was not present on the machine at the time and was
downloaded for the first time on 6 September while profiling latency;
`get_embedder()` had been falling back to the hashing embedder, which matches on
character n-grams and carries no semantics.

`pipeline/embeddings.py` states the consequence directly: "Retrieval quality
measured with this backend is not a result." Every figure in these files that
depends on which documents were retrieved — attack success rate, false positive
and false negative rates, per-family and per-case detection, disposition mix — is
therefore a measurement of a lexical matcher, not of the system as designed.

Superseded by the results at `eval/results/`, produced against an index rebuilt
with bge-small-en-v1.5. Retained so the correction is visible rather than silent.
