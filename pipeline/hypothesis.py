"""
The entailment hypothesis, resolved once for every inference path.

Why this exists
---------------

Design §3.1 specifies the generated answer as the hypothesis the entailment
detector scores evidence against, and design §6 orders the pipeline accordingly:
step 2 generates, step 3 runs the detectors. The training set follows that
specification -- `eval/fusion_metrics.json` records `hypothesis_source:
generated_answer` for all 98 queries.

Neither inference path did. The analyst console ran retrieve -> score -> report
and the evaluation harness ran retrieve -> score, and neither ever called the
generator, so both fell back to the query text and stamped every row
`hypothesis_source=query_proxy`. The consequence is not a cosmetic
inconsistency: §9A.4 measured the query proxy at AUC 0.248 against the same
labels, INVERTED, because PoisonedRAG documents restate the target query in
order to be retrieved and therefore look better supported than genuine ones when
scored against it. The fitted coefficient on unsupport was estimated from one
quantity and applied to another that behaves differently.

This module closes that gap in one place rather than twice, so the console and
the harness cannot drift apart again.

What it refuses to do
---------------------

The extractive stub is **not** an acceptable hypothesis, and this module returns
the query proxy rather than use it. §9A.4 states the reason: the stub returns
leading sentences of the retrieved documents, so scoring evidence against it asks
whether a document entails a quotation of itself. That is circular, and worse
than the proxy it would replace. A backend that is not a language model is
therefore rejected explicitly rather than accepted because it happened to return
a string.

Degradation is per-query and recorded, never silent and never per-run. A
generator that fails on one query yields the proxy for that query alone, and the
row says so, so a mixed run is visible in the audit trail rather than averaged
over.

Caching
-------

Answers are cached in-process, keyed by the query and the identities of the
documents retrieved for it -- the same key the training path uses on disk. Two
reasons, and the second matters more than the first. A repeated query costs no
second generation, which keeps the console responsive; and a language model is
not a pure function, so scoring the same query twice against two different
answers would make a re-run disagree with itself for reasons that have nothing to
do with detection.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Sequence

from .config import PipelineConfig, DEFAULT_CONFIG

QUERY_PROXY = "query_proxy"
GENERATED = "generated_answer"

# Bounded so a long-lived console cannot grow it without limit.
_CACHE_MAX = 2048
_CACHE: dict[str, str] = {}


def cache_key(query: str, doc_ids: Sequence[str]) -> str:
    """Same construction as the training path's on-disk cache."""
    payload = query.strip() + "|" + "|".join(doc_ids)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def clear_cache() -> None:
    _CACHE.clear()


def is_language_model(generator: Any) -> bool:
    """Whether this backend may supply a hypothesis at all.

    The extractive stub names itself; §9A.4 refuses it. Anything else that
    reached us through `get_generator` is a language model.
    """
    backend = str(getattr(generator, "backend", "") or "").lower()
    name = str(getattr(generator, "name", "") or "").lower()
    return "extractive" not in backend and "stub" not in name and "extractive" not in name


def resolve(
    rag: Any,
    query: str,
    records: Sequence[Any],
    config: PipelineConfig | None = None,
) -> dict[str, Any]:
    """Produce the entailment hypothesis for one query.

    Returns a dict carrying the hypothesis, where it came from, how long it took
    and -- when the generated answer could not be used -- why. The caller passes
    `hypothesis` to `score_query(..., generated_answer=...)` when `source` is
    `generated_answer`, and passes nothing when it is `query_proxy`.
    """
    cfg = config or getattr(rag, "config", None) or DEFAULT_CONFIG
    doc_ids = [getattr(r, "doc_id", "") for r in records]
    out: dict[str, Any] = {
        "hypothesis": query,
        "source": QUERY_PROXY,
        "generator": None,
        "cached": False,
        "elapsed_ms": 0.0,
        "reason": None,
    }

    key = cache_key(query, doc_ids)
    if key in _CACHE:
        out.update(hypothesis=_CACHE[key], source=GENERATED, cached=True,
                   generator=getattr(getattr(rag, "_generator", None), "name", None))
        return out

    started = time.perf_counter()
    try:
        generator = rag.generator
    except Exception as exc:
        out["reason"] = (f"no generation backend ({type(exc).__name__}: {exc}); "
                         f"scoring against the query text, which design 9A.4 measured "
                         f"as inverted")
        return out

    out["generator"] = getattr(generator, "name", type(generator).__name__)
    if not is_language_model(generator):
        out["reason"] = ("the resolved backend is the extractive stub, which design 9A.4 "
                         "refuses as a hypothesis: it returns sentences of the retrieved "
                         "documents, so entailment would score a document against a "
                         "quotation of itself")
        return out

    try:
        answer = generator.generate_answer(query, list(records), cfg).answer
    except Exception as exc:
        out["reason"] = f"generation failed ({type(exc).__name__}: {exc})"
        out["elapsed_ms"] = (time.perf_counter() - started) * 1000
        return out

    out["elapsed_ms"] = (time.perf_counter() - started) * 1000
    if not answer or not answer.strip():
        out["reason"] = "the generator returned an empty answer"
        return out

    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = answer
    out.update(hypothesis=answer, source=GENERATED)
    return out
