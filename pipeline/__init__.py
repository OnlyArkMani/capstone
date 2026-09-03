"""
Baseline retrieval-augmented generation pipeline (Level 0).

No security layer. This is the comparison baseline for the evaluation: retrieve,
generate, log. The trust layer is measured against it, so it must remain naive.

Quick start
-----------
    from pipeline import BaselineRAG

    rag = BaselineRAG.build()
    result = rag.answer("Is 198.51.100.47 associated with ransomware infrastructure?")
    for r in result["retrieval"].records:
        print(r.rank, round(r.similarity, 3), r.doc_id, "tier", r.source_tier)

Independent stages, for later instrumentation:
    retrieval  = rag.retrieve(query, k=5)
    generation = rag.generate(query, retrieval.records)
    rag.log(retrieval, generation)

Two properties this package guarantees
--------------------------------------
* **Partition-blind.** Clean and poisoned documents are indexed together and the
  pipeline is never told which is which. `corpus_loader` raises if a document
  file carries an answer-key field.
* **No perplexity.** Not computed anywhere. Scoped out on the literature review
  (clean and adversarial text overlap in perplexity), and absent from the
  composite score by design. Its absence is a decision, not an oversight.
"""

from .config import PipelineConfig, DEFAULT_CONFIG
from .corpus_loader import load_corpus, embedding_text, GroundTruthLeakError
from .embeddings import Embedder, get_embedder
from .generation import Generator, get_generator, build_prompt
from .rag import BaselineRAG
from .records import GenerationResult, Provenance, RetrievalResult, RetrievedRecord
from .retrieval import Retriever, query_hash
from .retrieval_log import log_query, read_log, build_log_record, LOG_SCHEMA_VERSION
from .vector_index import VectorIndex, make_index, load_index

__all__ = [
    "BaselineRAG", "Retriever", "PipelineConfig", "DEFAULT_CONFIG",
    "RetrievedRecord", "RetrievalResult", "GenerationResult", "Provenance",
    "Embedder", "get_embedder", "Generator", "get_generator", "build_prompt",
    "VectorIndex", "make_index", "load_index",
    "load_corpus", "embedding_text", "GroundTruthLeakError",
    "log_query", "read_log", "build_log_record", "LOG_SCHEMA_VERSION",
    "query_hash",
]

__version__ = "0.1.0"
