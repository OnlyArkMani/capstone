#!/usr/bin/env python3
"""
Report which backends are actually usable here, and make one real call to each.

    python -m pipeline.check_backends

Run this before an evaluation batch. It is much cheaper to find out now that the
key is unset or the model name is wrong than 40 minutes into a run.
"""

from __future__ import annotations

import os
import sys
import time

from .config import PipelineConfig


def _line(label: str, ok: bool | None, detail: str = "") -> None:
    mark = {True: "  OK  ", False: " FAIL ", None: " ---- "}[ok]
    print(f"[{mark}] {label:<34} {detail}")


def main() -> int:
    cfg = PipelineConfig()
    print(f"Configured generation backend: {cfg.generation_backend}\n")

    print("Embeddings")
    try:
        from sentence_transformers import SentenceTransformer  # noqa: F401
        _line("sentence-transformers", True, "installed")
        try:
            from .embeddings import SentenceTransformerEmbedder
            emb = SentenceTransformerEmbedder(cfg)
            _line(f"model {cfg.embedding_model}", True, f"dim {emb.dim}")
        except Exception as exc:
            _line(f"model {cfg.embedding_model}", False, f"{type(exc).__name__}: {exc}")
            print("        (first run downloads ~130MB; needs network once)")
    except ImportError:
        _line("sentence-transformers", False, "pip install -r pipeline/requirements.txt")
        _line("fallback", None, "hashing embedder — NOT semantic, results not meaningful")

    print("\nVector index")
    try:
        import faiss  # noqa: F401
        _line("faiss-cpu", True, "installed")
    except ImportError:
        _line("faiss-cpu", False, "not installed")
        _line("fallback", None, "exact numpy search — identical results at this corpus size")

    print("\nGeneration")
    from .generation import GroqGenerator, OllamaGenerator

    if os.environ.get(cfg.groq_api_key_env):
        _line(f"{cfg.groq_api_key_env}", True, "set")
        try:
            gen = GroqGenerator(cfg)
            t0 = time.perf_counter()
            reply = gen._post("Reply with the single word: ready")
            _line(f"groq {cfg.groq_model}", True,
                  f"{(time.perf_counter() - t0) * 1000:.0f} ms, replied {reply[:24]!r}")
        except Exception as exc:
            _line(f"groq {cfg.groq_model}", False, f"{type(exc).__name__}: {exc}")
    else:
        _line(f"{cfg.groq_api_key_env}", False, "not set — get a free key at console.groq.com")

    if OllamaGenerator.available(cfg):
        _line("ollama server", True, cfg.ollama_host)
        try:
            gen = OllamaGenerator(cfg)
            t0 = time.perf_counter()
            reply = gen.complete("Reply with the single word: ready")
            _line(f"ollama {cfg.ollama_model}", True,
                  f"{(time.perf_counter() - t0) * 1000:.0f} ms, replied {reply[:24]!r}")
        except Exception as exc:
            _line(f"ollama {cfg.ollama_model}", False,
                  f"{type(exc).__name__}: {exc} — try `ollama pull {cfg.ollama_model}`")
    else:
        _line("ollama server", False, f"not reachable at {cfg.ollama_host}")

    print("\nReminder: the baseline arm and the trust-layer arm of the evaluation must use")
    print("the SAME generator. Attack success rate is model-dependent, so mixing them")
    print("would confound the one comparison the project rests on.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
