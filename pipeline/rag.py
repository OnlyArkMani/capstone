"""
The baseline RAG pipeline: retrieve, generate, log.

No security layer. This is the comparison baseline the trust layer will be
measured against, so it must stay naive: no provenance weighting, no filtering,
no refusal, no trust language in the prompt.

The three stages are independently callable, because later instrumentation needs
to run retrieval without generation (to compute detector signals over a
retrieval set) and generation without re-retrieval (to replay a logged set):

    rag = BaselineRAG.build()
    retrieval  = rag.retrieve(query, k=5)          # structured records
    generation = rag.generate(query, retrieval.records)
    rag.log(retrieval, generation)

    answer = rag.answer(query)                      # all three, convenience
"""

from __future__ import annotations

import uuid
from typing import Any

import numpy as np

from .config import PipelineConfig, DEFAULT_CONFIG
from .generation import Generator, get_generator
from .records import GenerationResult, RetrievalResult, RetrievedRecord
from .retrieval import Retriever
from .retrieval_log import log_query


class BaselineRAG:
    def __init__(
        self,
        retriever: Retriever,
        generator: Generator | None = None,
        config: PipelineConfig | None = None,
    ) -> None:
        self.config = config or retriever.config or DEFAULT_CONFIG
        self.retriever = retriever
        self._generator = generator

    # ---------------- construction ----------------

    @classmethod
    def build(cls, config: PipelineConfig | None = None, verbose: bool = True) -> "BaselineRAG":
        """Build the index in memory. Use for one-off runs and tests."""
        return cls(Retriever.build(config, verbose=verbose), None, config)

    @classmethod
    def from_disk(cls, config: PipelineConfig | None = None) -> "BaselineRAG":
        """Load a persisted index. Use for repeated runs; avoids re-embedding."""
        return cls(Retriever.from_disk(config), None, config)

    @property
    def generator(self) -> Generator:
        # Resolved lazily so that retrieval-only work never probes Ollama or
        # requires a Groq key.
        if self._generator is None:
            self._generator = get_generator(self.config)
        return self._generator

    # ---------------- stage 1: embedding ----------------

    def embed_query(self, query: str) -> np.ndarray:
        return self.retriever.embed_query(query)

    # ---------------- stage 2: retrieval ----------------

    def retrieve_top_k(self, query: str, k: int | None = None) -> RetrievalResult:
        return self.retriever.retrieve_top_k(query, k)

    # Alias so later sprints can call `retrieve()` as specified.
    def retrieve(self, query: str, k: int | None = None) -> RetrievalResult:
        return self.retrieve_top_k(query, k)

    # ---------------- stage 3: generation ----------------

    def generate_answer(self, query: str, retrieved_docs: list[RetrievedRecord]) -> GenerationResult:
        return self.generator.generate_answer(query, retrieved_docs, self.config)

    def generate(self, query: str, retrieved_docs: list[RetrievedRecord]) -> GenerationResult:
        return self.generate_answer(query, retrieved_docs)

    # ---------------- logging ----------------

    def log(
        self,
        retrieval: RetrievalResult,
        generation: GenerationResult | None = None,
        run_id: str | None = None,
        per_query_file: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return log_query(retrieval, generation, self.config, run_id, per_query_file, extra)

    # ---------------- convenience ----------------

    def answer(
        self,
        query: str,
        k: int | None = None,
        generate: bool = True,
        log: bool = True,
        per_query_file: bool = False,
    ) -> dict[str, Any]:
        """Run the full pipeline for one query and return both results."""
        run_id = uuid.uuid4().hex
        retrieval = self.retrieve_top_k(query, k)
        generation = self.generate_answer(query, retrieval.records) if generate else None
        if log:
            self.log(retrieval, generation, run_id=run_id, per_query_file=per_query_file)
        return {"run_id": run_id, "retrieval": retrieval, "generation": generation}
