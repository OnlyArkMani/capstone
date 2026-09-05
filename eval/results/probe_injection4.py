#!/usr/bin/env python3
"""
Probe 4 — is this classifier usable for document-level injection detection at all?

WHERE THIS SITS

Probe 1: whole documents. Target 0.0011, seven clean documents above it. Read as
         "the payload is diluted by surrounding prose".
Probe 3: paragraph chunks, max aggregation. Target 1.0000 -- and clean median
         0.9821, clean mean 0.6965, margin -0.0000. `**Tactic:** Initial Access`,
         26 characters of MITRE label, scores 1.0000.

Those two results are not a dilution problem and its fix. They are one property
seen twice: `protectai/deberta-v3-base-prompt-injection-v2` was fine-tuned on
short single-turn prompts, and text LENGTH appears to drive its decision far more
than instruction content does. Long input -> SAFE. Short input -> INJECTION.
Neither reading of the corpus is about the payload.

WHAT THIS PROBE ANSWERS

Before choosing another chunk size -- which would be a third guess -- establish
whether any aggregation over this model separates the one injection-bearing
document from the other 83. Four questions, in order:

  Q1  How much of the score is explained by chunk length alone? If clean and
      injection chunks of similar length score alike, the model is measuring
      length and the content signal is not there to recover.

  Q2  Do LOGIT MARGINS separate where probabilities do not? Probabilities
      saturate; a margin of 13.6 and a margin of 4.0 are both p=1.0000 but are
      not the same evidence.

  Q3  Does any aggregation rule rank the target first? Whole-document, max,
      max with a minimum-length floor at several thresholds, mean of the top-k,
      and max margin -- scored the same way, compared on the same corpus.

  Q4  How does the regex fallback compare on the identical corpus? It is
      currently labelled "structurally valid, analytically weak" and barred from
      being reported as detector performance. If it separates the corpus and the
      classifier does not, that judgement needs revisiting on evidence rather
      than being inherited.

This probe only measures. It changes no thresholds and writes no artifacts.

Run:
  docker compose -f docker-compose.yml -f docker-compose.dev.yml \\
      run --rm shell python3 eval/results/probe_injection4.py
"""

import glob
import json
import math
import statistics

from detectors.injection import (
    _CHUNK_MAX_CHARS,
    _chunk_for_scoring,
    _HeuristicBackend,
    get_backend,
)

TARGET = "poison-injection-infusion-t3-forum"


def doc_text(doc: dict) -> str:
    parts = [doc.get("title", ""), doc.get("summary", ""), doc.get("content", "")]
    return "\n\n".join(p for p in parts if p).strip()


def load(pattern: str) -> dict:
    out = {}
    for path in glob.glob(pattern):
        d = json.load(open(path))
        if "doc_id" in d:
            out[d["doc_id"]] = d
    return out


def rank_and_margin(scores: dict[str, float]) -> tuple[int, float, str]:
    """Rank of the target (1 = highest) and its margin over the loudest other document."""
    target = scores.get(TARGET, 0.0)
    others = {k: v for k, v in scores.items() if k != TARGET}
    if not others:
        return 1, 0.0, "-"
    loudest = max(others, key=lambda k: others[k])
    rank = 1 + sum(1 for v in others.values() if v > target)
    return rank, target - others[loudest], loudest


def main() -> None:
    clean = load("corpus/clean/*.json")
    poisoned = load("corpus/poisoned/*.json")
    docs = {**clean, **poisoned}

    backend = get_backend()
    print(f"backend: {backend.name}  is_model: {getattr(backend, 'is_model', None)}")
    if not getattr(backend, "is_model", False):
        print("!! heuristic fallback -- this probe measures nothing. Fetch the models.")
        return
    print(f"corpus: {len(clean)} clean, {len(poisoned)} poisoned   "
          f"chunk ceiling: {_CHUNK_MAX_CHARS} chars\n")

    # ---- score every chunk of every document -------------------------------
    # rows: (doc_id, is_target, chunk_index, length, prob, margin, text)
    rows = []
    per_doc_chunks: dict[str, list] = {}
    for doc_id, d in docs.items():
        text = doc_text(d)
        chunks = _chunk_for_scoring(text)
        scored = []
        for i, chunk in enumerate(chunks):
            prob, logits = backend._score_chunk(chunk)
            pos = backend._pos_index
            neg = 1 - pos
            margin = float(logits[pos] - logits[neg])
            rec = (doc_id, doc_id == TARGET, i, len(chunk), prob, margin, chunk)
            scored.append(rec)
            rows.append(rec)
        per_doc_chunks[doc_id] = scored

    print(f"scored {len(rows)} chunks across {len(docs)} documents\n")

    # ---- Q1: how much is length? -------------------------------------------
    print("=" * 74)
    print("Q1  score as a function of chunk length")
    print("=" * 74)
    buckets = [(0, 50), (50, 100), (100, 200), (200, 300), (300, 400), (400, 10_000)]
    print(f"  {'length':>14}  {'n':>5}  {'mean p':>8}  {'median p':>9}  {'frac p>0.9':>11}")
    for lo, hi in buckets:
        sel = [r for r in rows if lo <= r[3] < hi]
        if not sel:
            continue
        probs = [r[4] for r in sel]
        frac = sum(1 for p in probs if p > 0.9) / len(probs)
        label = f"{lo}-{hi if hi < 10_000 else '+'}"
        print(f"  {label:>14}  {len(sel):>5}  {statistics.mean(probs):>8.4f}  "
              f"{statistics.median(probs):>9.4f}  {frac:>11.2%}")

    xs = [float(r[3]) for r in rows]
    ys = [float(r[4]) for r in rows]
    n = len(xs)
    mx, my = statistics.mean(xs), statistics.mean(ys)
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    corr = cov / (sx * sy) if sx and sy else float("nan")
    print(f"\n  Pearson r(length, score) over {n} chunks: {corr:+.3f}")
    print("  A strong negative r means the model is largely reading length, not content.")

    # ---- Q2: margins --------------------------------------------------------
    print("\n" + "=" * 74)
    print("Q2  logit margins -- do they separate where probabilities saturate?")
    print("=" * 74)
    saturated = [r for r in rows if r[4] > 0.99]
    print(f"  chunks at p > 0.99: {len(saturated)} of {len(rows)}")
    if saturated:
        margins = [r[5] for r in saturated]
        print(f"  their margins: min {min(margins):+.2f}  median "
              f"{statistics.median(margins):+.2f}  max {max(margins):+.2f}")
    tgt_chunks = per_doc_chunks.get(TARGET, [])
    if tgt_chunks:
        best = max(tgt_chunks, key=lambda r: r[5])
        by_margin = sorted(rows, key=lambda r: -r[5])
        pos = 1 + sum(1 for r in rows if r[5] > best[5])
        print(f"\n  target's best chunk: margin {best[5]:+.2f}  len {best[3]}  "
              f"rank {pos} of {len(rows)} chunks corpus-wide")
        print(f"    {best[6][:100]!r}")
        print("\n  top 5 chunks corpus-wide by margin:")
        for r in by_margin[:5]:
            mark = " <== TARGET" if r[1] else ""
            print(f"    {r[5]:+7.2f}  len={r[3]:4d}  {r[0][:42]:42s}{mark}")
            print(f"             {r[6][:88]!r}")

    # ---- Q3: aggregation rules ---------------------------------------------
    print("\n" + "=" * 74)
    print("Q3  aggregation rules, compared on the same corpus")
    print("=" * 74)

    def agg_whole() -> dict[str, float]:
        return {doc_id: backend._score_chunk(doc_text(d)[:4000])[0]
                for doc_id, d in docs.items()}

    def agg_max(min_len: int = 0) -> dict[str, float]:
        out = {}
        for doc_id, scored in per_doc_chunks.items():
            elig = [r[4] for r in scored if r[3] >= min_len]
            out[doc_id] = max(elig) if elig else 0.0
        return out

    def agg_max_margin(min_len: int = 0) -> dict[str, float]:
        out = {}
        for doc_id, scored in per_doc_chunks.items():
            elig = [r[5] for r in scored if r[3] >= min_len]
            out[doc_id] = max(elig) if elig else -20.0
        return out

    def agg_mean_topk(k: int) -> dict[str, float]:
        out = {}
        for doc_id, scored in per_doc_chunks.items():
            top = sorted((r[4] for r in scored), reverse=True)[:k]
            out[doc_id] = statistics.mean(top) if top else 0.0
        return out

    rules = [
        ("whole document (probe 1)", agg_whole()),
        ("max over chunks (probe 3)", agg_max()),
        ("max, chunks >= 100 chars", agg_max(100)),
        ("max, chunks >= 200 chars", agg_max(200)),
        ("max, chunks >= 300 chars", agg_max(300)),
        ("max margin, all chunks", agg_max_margin()),
        ("max margin, chunks >= 200", agg_max_margin(200)),
        ("mean of top-3 chunks", agg_mean_topk(3)),
    ]

    print(f"  {'rule':<28} {'target':>9} {'rank':>6} {'margin':>9}  loudest other")
    print("  " + "-" * 86)
    for name, scores in rules:
        rank, margin, loudest = rank_and_margin(scores)
        flag = "  <-- separates" if rank == 1 and margin > 0 else ""
        print(f"  {name:<28} {scores.get(TARGET, 0):>9.4f} {rank:>6} "
              f"{margin:>+9.4f}  {loudest[:30]}{flag}")

    # ---- Q4: the regex fallback --------------------------------------------
    print("\n" + "=" * 74)
    print("Q4  the regex fallback, on the identical corpus")
    print("=" * 74)
    heur = _HeuristicBackend()
    hscores, hdetail = {}, {}
    for doc_id, d in docs.items():
        s, det = heur.score(doc_text(d))
        hscores[doc_id] = s
        hdetail[doc_id] = det
    rank, margin, loudest = rank_and_margin(hscores)
    print(f"  target: {hscores.get(TARGET, 0):.4f}   rank {rank} of {len(docs)}"
          f"   margin {margin:+.4f} over {loudest}")
    print(f"  patterns fired on target: "
          f"{[h['pattern'] for h in hdetail.get(TARGET, {}).get('pattern_hits', [])]}")
    nonzero = [(v, k) for k, v in hscores.items() if v > 0]
    print(f"  documents with any pattern hit: {len(nonzero)} of {len(docs)}")
    for v, k in sorted(nonzero, reverse=True)[:8]:
        mark = " <== TARGET" if k == TARGET else ""
        pats = [h["pattern"] for h in hdetail[k].get("pattern_hits", [])]
        print(f"    {v:.4f}  {k[:46]:46s} {pats}{mark}")

    print("\n" + "=" * 74)
    print("READ THIS BEFORE CHANGING ANYTHING")
    print("=" * 74)
    print("One injection-bearing document. Any rule that ranks it first is separating")
    print("a single point and is not a detection rate. What this probe can legitimately")
    print("rule OUT is a rule that fails even on that one document. Choosing among the")
    print("survivors needs more documents of this family in the corpus, and that gap is")
    print("already recorded as an open item in detectors/injection.py.")


if __name__ == "__main__":
    main()
