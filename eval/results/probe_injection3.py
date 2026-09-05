#!/usr/bin/env python3
"""
Probe 3 — does paragraph chunking fix the injection detector without
inventing false positives on the clean corpus?

Probes 1 and 2 established the problem: the injection payload scores 1.000 in
isolation and 0.001 inside its own document, because the classifier pools a
2.2k-character document down to one representation and several paragraphs of
ordinary report prose drown out one paragraph of instruction text.

`detectors/injection.py` now scores paragraph-sized chunks and reports the max.
That necessarily raises every document's score, clean ones included, because a
max over twelve chunks can only be >= the score of the whole. So the fix is
only worth keeping if the separation between the injection-bearing document and
the clean corpus gets *wider*, not just if the target's own score goes up.

This prints, for the whole corpus:
  - the target document's score and which chunk won it
  - the clean-corpus distribution (max, 95th, 99th percentile)
  - the margin between the target and the loudest clean document
  - the top clean documents, so a false positive can be read rather than guessed

Run:  docker compose run --rm shell python3 eval/results/probe_injection3.py
"""

import glob
import json
import statistics

from detectors.injection import get_backend

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


def main() -> None:
    clean = load("corpus/clean/*.json")
    poisoned = load("corpus/poisoned/*.json")

    backend = get_backend()
    print(f"backend: {backend.name}  is_model: {getattr(backend, 'is_model', None)}")
    if not getattr(backend, "is_model", False):
        print("\n!! Running on pattern heuristics, not the classifier. These numbers say")
        print("!! nothing about the chunking fix. Run `docker compose run --rm fetch-models`.")
    print()

    rows = []
    for group, docs in (("clean", clean), ("poisoned", poisoned)):
        for doc_id, d in docs.items():
            score, detail = backend.score(doc_text(d))
            rows.append((score, group, doc_id, detail))

    clean_scores = [r[0] for r in rows if r[1] == "clean"]
    target_row = next((r for r in rows if r[2] == TARGET), None)

    print(f"corpus: {len(clean)} clean, {len(poisoned)} poisoned")
    print("\n--- clean-corpus distribution (this is the false-positive question) ---")
    if clean_scores:
        srt = sorted(clean_scores)
        pct = lambda p: srt[min(len(srt) - 1, int(round(p / 100 * (len(srt) - 1))))]  # noqa: E731
        print(f"  max          {max(srt):.4f}")
        print(f"  99th pct     {pct(99):.4f}")
        print(f"  95th pct     {pct(95):.4f}")
        print(f"  median       {statistics.median(srt):.4f}")
        print(f"  mean         {statistics.mean(srt):.4f}")

    print("\n--- injection-bearing document ---")
    if target_row is None:
        print(f"  {TARGET} not found in corpus")
    else:
        score, _, _, detail = target_row
        print(f"  {TARGET}: {score:.4f}")
        print(f"  chunks scored: {detail.get('n_chunks')}   winning chunk: "
              f"#{detail.get('winning_chunk_index')}")
        print(f"  winning chunk text: {detail.get('winning_chunk_preview')!r}")
        if clean_scores:
            margin = score - max(clean_scores)
            print(f"\n  margin over loudest clean document: {margin:+.4f}")
            print("  (probe 1, scoring whole documents, had this at -0.1660 — the detector"
                  "\n   ranked seven clean documents above the poisoned one.)")

    print("\n--- top 8 documents overall ---")
    for score, group, doc_id, detail in sorted(rows, reverse=True)[:8]:
        mark = " <== TARGET" if doc_id == TARGET else ""
        print(f"  {score:.4f}  [{group:8s}] {doc_id}{mark}")
        if group == "clean" and score > 0.5 and detail.get("winning_chunk_preview"):
            print(f"           false positive? winning chunk: "
                  f"{detail['winning_chunk_preview'][:110]!r}")

    print("\nNOTE: one injection-bearing document in the corpus. This confirms the signal")
    print("fires and is separable; it is not a detection rate and must not be reported as")
    print("one. Threshold fitting reads the clean distribution above, so `verify` must be")
    print("re-run after this change — the old fitted thresholds were fitted on whole-")
    print("document scores and are no longer the right scale.")


if __name__ == "__main__":
    main()
