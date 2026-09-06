"""
Pipeline configuration.

Every path and model name the baseline needs, in one place, overridable by
environment variable so that later instrumentation can point the same code at a
different index or a different generator without editing it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class PipelineConfig:
    # ---- corpus ----
    # Both partitions are indexed together. The pipeline is not told which is
    # which; see corpus_loader.load_corpus().
    corpus_dirs: list[Path] = field(default_factory=lambda: [
        PROJECT_ROOT / "corpus" / "clean",
        PROJECT_ROOT / "corpus" / "poisoned",
    ])

    # ---- embeddings ----
    # bge-small-en-v1.5 is the default: 384-dim, ~130MB, and it materially
    # outperforms all-MiniLM-L6-v2 on retrieval benchmarks at the same
    # dimensionality. MiniLM stays available as the lighter alternative.
    embedding_model: str = _env("RAG_EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
    embedding_backend: str = _env("RAG_EMBEDDING_BACKEND", "auto")  # auto|sentence_transformers|hashing
    embedding_dim_fallback: int = 384

    # bge models are trained with an instruction prefix on the QUERY side only.
    # Omitting it costs several points of retrieval quality; applying it to
    # documents as well also hurts. Hence query_prefix, not a general prefix.
    query_prefix: str = _env(
        "RAG_QUERY_PREFIX",
        "Represent this sentence for searching relevant passages: ",
    )

    # ---- compute device ----
    # "auto" resolves to CUDA when torch can actually reach a device, CPU
    # otherwise; see pipeline/device.py. Before this existed the device was
    # whatever sentence-transformers happened to choose and nothing recorded the
    # choice, which is how every model in the system came to run on CPU on a
    # machine with a GPU. RAG_DEVICE=cpu forces CPU, which is how a
    # like-for-like CPU/GPU comparison is run.
    device: str = _env("RAG_DEVICE", "auto")

    # ---- index ----
    index_backend: str = _env("RAG_INDEX_BACKEND", "auto")  # auto|faiss|numpy
    index_dir: Path = PROJECT_ROOT / "pipeline" / "index"

    # ---- retrieval ----
    default_k: int = int(_env("RAG_TOP_K", "5"))

    # ---- generation ----
    # Groq is the project default. Rationale in pipeline/README.md: the headline
    # evaluation must use ONE generator across both arms, and Groq gives an 8B
    # model at consistent speed without depending on local hardware.
    # "auto" rather than a fixed backend, because the generator is now on the
    # INFERENCE path (design 6 step 2, and pipeline/hypothesis.py) and not only in
    # training. auto prefers Groq where a key is present -- which is the Docker
    # environment the fitted artefacts came from, so that path is unchanged -- and
    # falls through to a local Ollama otherwise, which is what a developer machine
    # with a GPU and no exported key actually has. A fixed default meant the
    # console silently had no generator at all on such a machine.
    generation_backend: str = _env("RAG_GENERATION_BACKEND", "auto")  # groq|ollama|extractive|auto
    ollama_model: str = _env("RAG_OLLAMA_MODEL", "llama3.2:3b")
    ollama_host: str = _env("OLLAMA_HOST", "http://localhost:11434")
    # Verified against this account's /v1/models listing on 5 September 2026.
    # llama-3.1-8b-instant, the previous default, has been decommissioned and is
    # no longer offered -- a configured model name is a perishable thing on a free
    # tier, so `python -m pipeline.check_backends` tests it rather than assuming.
    # gpt-oss-20b is open-weight (Apache 2.0), which the tech-stack constraint
    # requires. qwen/qwen3.6-27b is the alternative if this one is retired next.
    groq_model: str = _env("RAG_GROQ_MODEL", "openai/gpt-oss-20b")
    groq_api_key_env: str = "GROQ_API_KEY"
    generation_timeout_s: int = int(_env("RAG_GEN_TIMEOUT", "120"))

    # Groq free tier: 30 requests/min, 6000 tokens/min, 1000 requests/day.
    # At k=5 a RAG prompt is ~1.6k input + ~0.3k output tokens, so TOKENS bind
    # long before requests -- roughly 3 queries/minute sustained, not 30. An
    # evaluation run will hit this, so the backend retries rather than failing.
    groq_max_retries: int = int(_env("RAG_GROQ_MAX_RETRIES", "5"))
    groq_backoff_base_s: float = float(_env("RAG_GROQ_BACKOFF", "2.0"))
    groq_min_interval_s: float = float(_env("RAG_GROQ_MIN_INTERVAL", "0.0"))
    max_context_chars: int = int(_env("RAG_MAX_CONTEXT_CHARS", "12000"))
    temperature: float = float(_env("RAG_TEMPERATURE", "0.0"))
    # Cap the answer length. The free tier's binding limit is 6000 tokens/MINUTE,
    # so an unbounded reply from a reasoning-capable model burns the budget for
    # the queries behind it and turns a batch run into a queue of 429s. A SOC
    # answer that cannot be said in this many tokens is too long to be read in a
    # triage queue anyway.
    max_output_tokens: int = int(_env("RAG_MAX_OUTPUT_TOKENS", "512"))

    # ---- logging ----
    log_dir: Path = PROJECT_ROOT / "logs"
    retrieval_log_file: str = "retrieval_log.jsonl"
    per_query_dir: str = "queries"
    log_content_in_jsonl: bool = _env("RAG_LOG_CONTENT", "0") == "1"

    @property
    def index_path(self) -> Path:
        return self.index_dir / "corpus.index"

    @property
    def meta_path(self) -> Path:
        return self.index_dir / "corpus_meta.json"


DEFAULT_CONFIG = PipelineConfig()
