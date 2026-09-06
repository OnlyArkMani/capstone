#!/usr/bin/env python3
"""
Latency attribution for the trust-and-risk layer.

    python -m eval.profile_latency
    python -m eval.profile_latency --n 10 --k 5 --tag baseline

Answers four questions with numbers rather than inspection, and writes them to
`eval/results/latency_profile.json` so successive runs can be compared:

  (a) DEVICE PLACEMENT -- which torch device each model actually sits on, and
      whether this build of torch can see a GPU at all. A CPU-only wheel on a
      machine with a GPU is the failure this section exists to make visible:
      nothing errors, nothing warns, everything is simply ten times slower.

  (b) MODEL RELOADING -- how many times a transformer is constructed during the
      run. Constructors are counted by patching them before any project module
      is imported, so a load hidden inside a factory is still counted. Anything
      above one per model means weights are being read from disk on the query
      path.

  (c) COMPARISON STRUCTURE -- how many NLI pairs are actually submitted, split
      into the claim-entailment set and the pairwise-conflict set. Design 0.4
      specifies `d_conflict` over every ordered pair of retrieved documents, so
      the expected counts at k are k for entailment and k*(k-1) for conflict.
      A number below that is a silent change to the signal, not a speedup.

  (d) BATCHING -- how many forward passes those pairs are submitted in. One call
      carrying many pairs is batched; many calls carrying one pair each is the
      pathological case.

Method
------
A warm-up query runs first and is reported separately: it carries every lazy
model load, and averaging it into the steady-state figure hides both the load
cost and the per-query cost. Component stages are then timed individually on a
warm process, and `score_query` is timed end to end; the difference between the
two is reported as the fusion/bookkeeping residual rather than being attributed
to any stage that was not measured directly.

This script measures. It changes nothing.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# (b) Constructor counters -- installed BEFORE any project import
# ---------------------------------------------------------------------------

CONSTRUCTIONS: dict[str, list[float]] = {}


def _install_constructor_counters() -> list[str]:
    """Patch the transformer constructors so every load is counted, wherever it happens."""
    patched: list[str] = []

    def wrap(cls: Any, label: str) -> None:
        original = cls.__init__

        def counted(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            t0 = time.perf_counter()
            original(self, *args, **kwargs)
            CONSTRUCTIONS.setdefault(label, []).append((time.perf_counter() - t0) * 1000)

        cls.__init__ = counted
        patched.append(label)

    try:
        from sentence_transformers import CrossEncoder, SentenceTransformer

        wrap(SentenceTransformer, "SentenceTransformer")
        wrap(CrossEncoder, "CrossEncoder")
    except Exception as exc:
        print(f"[profile] sentence-transformers not importable ({type(exc).__name__}); "
              f"model-load counting is unavailable and the run will use fallback backends.")
    try:
        from transformers import AutoModelForSequenceClassification

        wrap(AutoModelForSequenceClassification, "AutoModelForSequenceClassification")
    except Exception:
        pass
    return patched


PATCHED = _install_constructor_counters()

from detectors import entailment as ent_mod  # noqa: E402
from detectors import injection as inj_mod  # noqa: E402
from detectors.anomaly import embedding_anomaly_score  # noqa: E402
from eval.run_evaluation import load_queries  # noqa: E402
from fusion.scorer import FusionScorer  # noqa: E402
from pipeline.embeddings import get_embedder  # noqa: E402
from pipeline.rag import BaselineRAG  # noqa: E402
from reports import build_report  # noqa: E402

OUT_DIR = PROJECT_ROOT / "eval" / "results"


# ---------------------------------------------------------------------------
# (a) Device placement
# ---------------------------------------------------------------------------

def torch_environment() -> dict[str, Any]:
    info: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
    }
    try:
        import torch

        info["torch_version"] = torch.__version__
        # A wheel built without CUDA reports None here. That is the single most
        # useful field in this whole report: it separates "no GPU on this
        # machine" from "a GPU this build of torch cannot address".
        info["torch_cuda_build"] = torch.version.cuda
        info["cuda_available"] = bool(torch.cuda.is_available())
        info["device_count"] = int(torch.cuda.device_count()) if torch.cuda.is_available() else 0
        info["threads"] = int(torch.get_num_threads())
        if torch.cuda.is_available():
            props = torch.cuda.get_device_properties(0)
            info["gpu_name"] = props.name
            info["gpu_total_mem_gb"] = round(props.total_memory / 1024**3, 2)
            info["gpu_capability"] = f"{props.major}.{props.minor}"
        else:
            info["gpu_name"] = None
            info["diagnosis"] = (
                "torch reports no usable CUDA device. If this machine has one, the "
                "installed wheel is the CPU-only build (torch.version.cuda is null) "
                "and every model below is running on CPU."
                if info.get("torch_cuda_build") is None else
                "torch was built with CUDA but cannot see a device (driver, or no GPU present)."
            )
    except Exception as exc:
        info["torch_version"] = None
        info["error"] = f"{type(exc).__name__}: {exc}"
    for mod in ("sentence_transformers", "transformers", "sklearn", "numpy"):
        try:
            info[f"{mod}_version"] = __import__(mod).__version__
        except Exception:
            info[f"{mod}_version"] = "absent"
    return info


def _module_device(obj: Any) -> str | None:
    """The device of the first parameter of whatever torch module `obj` wraps."""
    seen: set[int] = set()
    stack = [obj]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        params = getattr(cur, "parameters", None)
        if callable(params):
            try:
                return str(next(params()).device)
            except StopIteration:
                pass
            except Exception:
                pass
        for attr in ("model", "_model", "auto_model", "_first_module", "0"):
            nxt = getattr(cur, attr, None)
            if callable(nxt) and attr == "_first_module":
                try:
                    nxt = nxt()
                except Exception:
                    nxt = None
            if nxt is not None:
                stack.append(nxt)
    return None


def model_placement(embedder: Any, nli_backend: Any, inj_backend: Any) -> dict[str, Any]:
    return {
        "embedder": {
            "name": getattr(embedder, "name", None),
            "is_semantic": bool(getattr(embedder, "is_semantic", False)),
            "device": _module_device(embedder),
        },
        "entailment_nli": {
            "name": getattr(nli_backend, "name", None),
            "is_model": bool(getattr(nli_backend, "is_model", False)),
            "device": _module_device(nli_backend),
        },
        "injection": {
            "name": getattr(inj_backend, "name", None),
            "is_model": bool(getattr(inj_backend, "is_model", False)),
            "device": _module_device(inj_backend),
            "note": ("pattern backend is the measured primary (design 9A.1); no tensor "
                     "work on the query path" if not getattr(inj_backend, "is_model", False)
                     else "transformer backend active"),
        },
    }


# ---------------------------------------------------------------------------
# (c) + (d) NLI call accounting
# ---------------------------------------------------------------------------

class NLICallRecorder:
    """Wraps the resolved NLI backend and records every call it receives."""

    def __init__(self, backend: Any) -> None:
        self.backend = backend
        self.calls: list[dict[str, Any]] = []
        self._orig_batch = backend.score_batch
        self._orig_single = backend.score

        def score_batch(pairs, _o=self._orig_batch):  # type: ignore[no-untyped-def]
            t0 = time.perf_counter()
            out = _o(pairs)
            self.calls.append({"kind": "batch", "pairs": len(pairs),
                               "ms": round((time.perf_counter() - t0) * 1000, 3)})
            return out

        def score(premise, hypothesis, _o=self._orig_single):  # type: ignore[no-untyped-def]
            t0 = time.perf_counter()
            out = _o(premise, hypothesis)
            self.calls.append({"kind": "single", "pairs": 1,
                               "ms": round((time.perf_counter() - t0) * 1000, 3)})
            return out

        backend.score_batch = score_batch
        backend.score = score

    def restore(self) -> None:
        self.backend.score_batch = self._orig_batch
        self.backend.score = self._orig_single

    def reset(self) -> None:
        self.calls = []

    def summary(self) -> dict[str, Any]:
        return {
            "n_calls": len(self.calls),
            "n_batched_calls": sum(1 for c in self.calls if c["kind"] == "batch"),
            "n_single_calls": sum(1 for c in self.calls if c["kind"] == "single"),
            "n_pairs": sum(c["pairs"] for c in self.calls),
            "ms": round(sum(c["ms"] for c in self.calls), 3),
            "calls": self.calls,
        }


# ---------------------------------------------------------------------------
# One query, fully attributed
# ---------------------------------------------------------------------------

def profile_query(query: str, rag: Any, scorer: Any, recorder: NLICallRecorder,
                  k: int) -> dict[str, Any]:
    timings: dict[str, float] = {}

    t = time.perf_counter()
    result = rag.retrieve_top_k(query, k=k)
    timings["retrieval"] = (time.perf_counter() - t) * 1000
    records = result.records

    recorder.reset()
    t = time.perf_counter()
    embedding_anomaly_score(records, embedder=scorer.embedder)
    timings["detector_anomaly"] = (time.perf_counter() - t) * 1000
    anomaly_nli = recorder.summary()["n_pairs"]

    recorder.reset()
    t = time.perf_counter()
    inj_mod.injection_probabilities(records)
    timings["detector_injection"] = (time.perf_counter() - t) * 1000

    recorder.reset()
    t = time.perf_counter()
    ent_mod.entailment_scores(query, records)
    timings["detector_entailment"] = (time.perf_counter() - t) * 1000
    entailment_calls = recorder.summary()

    recorder.reset()
    t = time.perf_counter()
    ent_mod.pairwise_conflict(records)
    timings["detector_conflict"] = (time.perf_counter() - t) * 1000
    conflict_calls = recorder.summary()

    # End to end, the way the dashboard and the evaluation harness call it.
    recorder.reset()
    t = time.perf_counter()
    score = scorer.score_query(query, records)
    timings["score_query_total"] = (time.perf_counter() - t) * 1000
    end_to_end_calls = recorder.summary()

    t = time.perf_counter()
    build_report(query, score, records)
    timings["report_build"] = (time.perf_counter() - t) * 1000

    detector_sum = (timings["detector_anomaly"] + timings["detector_injection"]
                    + timings["detector_entailment"] + timings["detector_conflict"])
    timings["fusion_residual"] = timings["score_query_total"] - detector_sum
    timings["end_to_end"] = timings["retrieval"] + timings["score_query_total"] + timings["report_build"]

    n = len(records)
    return {
        "query": query,
        "n_retrieved": n,
        "timings_ms": {key: round(val, 2) for key, val in timings.items()},
        "nli": {
            "entailment": {"pairs": entailment_calls["n_pairs"],
                           "calls": entailment_calls["n_calls"],
                           "expected_pairs": n},
            "conflict": {"pairs": conflict_calls["n_pairs"],
                         "calls": conflict_calls["n_calls"],
                         "expected_pairs": n * (n - 1),
                         "design_reference": "design 0.4: ordered pairs, both directions, max-symmetrised"},
            "per_score_query": {"pairs": end_to_end_calls["n_pairs"],
                                "calls": end_to_end_calls["n_calls"],
                                "single_pair_calls": end_to_end_calls["n_single_calls"]},
            "anomaly_pairs": anomaly_nli,
        },
        "outcome": {"action": score.action, "case_id": score.case_id,
                    "headline": score.headline,
                    "trust_percent": (None if score.trust_percent != score.trust_percent
                                      else score.trust_percent)},
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Latency attribution for the security layer.")
    ap.add_argument("--n", type=int, default=10, help="queries to profile (targets first)")
    ap.add_argument("--k", type=int, default=5, help="documents retrieved per query")
    ap.add_argument("--tag", default="baseline", help="label for this run in the JSON output")
    ap.add_argument("--out", type=Path, default=OUT_DIR / "latency_profile.json")
    args = ap.parse_args()

    print("=" * 78)
    print("LATENCY ATTRIBUTION — trust-and-risk layer")
    print("=" * 78)

    env = torch_environment()
    print("\n(a) ENVIRONMENT")
    for key in ("python", "torch_version", "torch_cuda_build", "cuda_available",
                "gpu_name", "gpu_total_mem_gb", "threads", "sentence_transformers_version"):
        if key in env:
            print(f"    {key:32s} {env[key]}")
    if env.get("diagnosis"):
        print(f"    DIAGNOSIS: {env['diagnosis']}")

    t_cold = time.perf_counter()
    rag = BaselineRAG.from_disk()
    scorer = FusionScorer.load(embedder=rag.retriever.embedder, verbose=False)
    nli_backend = ent_mod.get_backend()
    inj_backend = inj_mod.get_backend()
    startup_ms = (time.perf_counter() - t_cold) * 1000

    placement = model_placement(rag.retriever.embedder, nli_backend, inj_backend)
    print("\n(a) DEVICE PLACEMENT")
    for role, info in placement.items():
        print(f"    {role:18s} {info['name']}  ->  device={info['device']}")

    recorder = NLICallRecorder(nli_backend)

    queries = [text for _, text, is_target in load_queries() if is_target][: args.n]
    if not queries:
        print("no queries loaded")
        return 1

    # Warm-up: carries every lazy load, reported separately rather than averaged in.
    warm = profile_query(queries[0], rag, scorer, recorder, args.k)

    print("\n(b) MODEL LOADING")
    print(f"    startup (index + artefacts + backends)   {startup_ms:9.1f} ms")
    for label, loads in CONSTRUCTIONS.items():
        print(f"    {label:40s} {len(loads):3d} construction(s), "
              f"{sum(loads):9.1f} ms total")
    if not CONSTRUCTIONS:
        print("    no transformer constructors were called (fallback backends in use)")
    loads_before = {label: len(v) for label, v in CONSTRUCTIONS.items()}

    rows = [profile_query(q, rag, scorer, recorder, args.k) for q in queries]
    loads_after = {label: len(v) for label, v in CONSTRUCTIONS.items()}
    reloads = {label: loads_after[label] - loads_before.get(label, 0) for label in loads_after}
    print(f"    constructions during {len(rows)} steady-state queries: "
          f"{reloads or 'none'}  <- must be zero")

    def med(path: str) -> float:
        return statistics.median([r["timings_ms"].get(path, 0.0) for r in rows])

    stages = ["retrieval", "detector_anomaly", "detector_injection",
              "detector_entailment", "detector_conflict", "fusion_residual",
              "report_build"]
    total = med("end_to_end")

    print("\n(c)+(d) NLI CALL STRUCTURE  (median query, k=%d)" % args.k)
    r0 = rows[0]
    print(f"    entailment   {r0['nli']['entailment']['pairs']:4d} pairs in "
          f"{r0['nli']['entailment']['calls']} call(s)   (design expects "
          f"{r0['nli']['entailment']['expected_pairs']})")
    print(f"    conflict     {r0['nli']['conflict']['pairs']:4d} pairs in "
          f"{r0['nli']['conflict']['calls']} call(s)   (design expects "
          f"{r0['nli']['conflict']['expected_pairs']}, ordered pairs)")
    print(f"    per score_query: {r0['nli']['per_score_query']['pairs']} pairs, "
          f"{r0['nli']['per_score_query']['calls']} call(s), "
          f"{r0['nli']['per_score_query']['single_pair_calls']} unbatched")

    print("\nPER-QUERY BREAKDOWN (median of %d queries, ms)" % len(rows))
    print("    %-24s %10s   %s" % ("stage", "ms", "share"))
    for stage in stages:
        value = med(stage)
        share = (value / total * 100) if total else 0.0
        print("    %-24s %10.1f   %5.1f%%  %s" % (stage, value, share, "#" * int(share / 2)))
    print("    %-24s %10.1f" % ("END TO END", total))
    print("\n    warm-up (first) query end to end: %.1f ms" % warm["timings_ms"]["end_to_end"])

    payload = {
        "tag": args.tag,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "k": args.k,
        "environment": env,
        "device_placement": placement,
        "startup_ms": round(startup_ms, 2),
        "model_constructions": {label: {"count": len(v), "total_ms": round(sum(v), 2)}
                                for label, v in CONSTRUCTIONS.items()},
        "reloads_during_steady_state": reloads,
        "warmup_query": warm,
        "medians_ms": {stage: round(med(stage), 2) for stage in stages + ["score_query_total",
                                                                          "end_to_end"]},
        "queries": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nwritten: {args.out}")

    recorder.restore()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
