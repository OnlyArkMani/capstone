"""
Detector 2 — prompt injection.

Scores a document for text addressed to the *model* rather than to a human
reader. Real backend is `protectai/deberta-v3-base-prompt-injection-v2` via
transformers; a pattern-based heuristic stands in when the model is unavailable.

Why this signal is treated differently from the others
------------------------------------------------------

Design section 2.1 lets injection alone push a response to MALICIOUS, while the
other three signals need corroboration. Anomalous embeddings, unsupported claims
and knowledge conflicts all have benign explanations -- a genuinely novel threat,
a badly written advisory, a model whose training predates the CVE. Instruction
text aimed at a language model inside a threat-intelligence document has no
benign explanation. Its presence is evidence of *intent*, not of unusual
statistics.

Which backend is primary, and why it is not the transformer
------------------------------------------------------------

`protectai/deberta-v3-base-prompt-injection-v2` is retained but is NOT the
default. It was measured against this corpus and does not separate it. The
measurement is reproducible: `eval/results/probe_injection.py`, `probe_injection2.py`,
`probe_injection3.py`, `probe_injection4.py`.

  Whole documents. The one injection-bearing document scores 0.0011 and ranks
  10th of 84. Seven clean documents score higher.

  Paragraph chunks, max aggregation. The payload chunk scores 1.0000 -- and so
  does much of the corpus. Clean median 0.9821, clean mean 0.6965, margin over
  the loudest clean document -0.0000. `**Tactic:** Initial Access`, 26
  characters of MITRE label, scores 1.0000.

  Not a length effect. The obvious reading -- long input dilutes the payload,
  short input concentrates it -- was tested and is wrong. Pearson r between
  chunk length and score, over 1073 chunks, is -0.011. The model fires on
  roughly 10% of chunks in every length bucket and `max` surfaces that noise.

  No aggregation recovers it. Eight rules on identical inputs: whole-document,
  max, max with length floors at 100/200/300 chars, max logit margin with and
  without a floor, mean-of-top-3. The best ranks the target 2nd at margin
  -0.0000. Logit margins do not rescue it -- the payload ranks 5th of 1073
  chunks by margin, behind three clean fragments, one of which is that same
  26-character MITRE label at +14.20 against the payload's +13.63. A 300-char
  floor drops the target to rank 53, the payload chunk being 270 chars.

The pattern backend, on the identical corpus, ranks the target 1st at margin
+1.0000 and is the only document of 84 on which any pattern fires at all.

What that separation is, and what it is not
--------------------------------------------

It is one positive example. The corpus holds exactly one document of family
`direct_prompt_injection`; this team wrote that document, and this team wrote
the patterns that catch it. Perfect separation under those conditions is what
the setup guarantees, not evidence that the detector generalises.

So the defensible claim from this corpus is "the pretrained classifier was
measured and ruled out", which the evidence supports. "The patterns work" is
NOT supported, and no detection rate, false-positive rate or F1 for this
detector is reportable yet.

The open item is correspondingly specific: further `direct_prompt_injection`
documents whose payloads are phrased unlike this one -- placed mid-document
rather than at the tail, split across paragraphs, and without the `SYSTEM NOTE`
header that three of the five firing patterns key on. Each is to be measured and
reported individually rather than as an aggregate: which phrasings the patterns
catch and which they miss is the finding, and a single pass/fail number would
hide it.

Chunking and the model backend, retained
-----------------------------------------

`_chunk_for_scoring` and `_ModelBackend` are kept and reachable through
`get_backend(force="model")`. They are what the probes above measure, and
re-running that measurement against the expanded corpus is the next step rather
than a discarded branch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from .base import BackendInfo, DetectorScore, as_records, clip01, doc_text, softmax

DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"

# Heuristic patterns, weighted by how little benign explanation each has in a
# threat-intelligence document. Weights are judgement, not fitted -- which is
# exactly why this is the fallback and not the detector.
_PATTERNS: list[tuple[str, float, str]] = [
    (r"\b(ignore|disregard|override)\b[^.]{0,40}\b(previous|prior|other|above|earlier)\b"
     r"[^.]{0,30}\b(instruction|prompt|source|document|advisor)", 0.95, "override_instruction"),
    (r"\b(system\s+note|system\s+prompt|system\s+message)\b", 0.85, "system_impersonation"),
    (r"\bfor\s+(automated|ai|llm|model|assistant)\s+(summari[sz]er|reader|system|agent)", 0.90, "addressed_to_model"),
    (r"\bwhen\s+(answering|responding|summari[sz]ing)\b[^.]{0,60}\b(report|state|say|answer)\b", 0.80, "answer_steering"),
    (r"\bdo\s+not\s+(mention|disclose|reveal|report|cite)\b", 0.85, "concealment_instruction"),
    (r"\bthis\s+(thread|document|entry|advisory)\s+supersedes\b", 0.70, "supersession_claim"),
    (r"\byou\s+(must|should|are\s+required\s+to)\b[^.]{0,40}\b(answer|respond|report|state)\b", 0.75, "imperative_to_model"),
    (r"\b(assistant|chatbot|language\s+model)\s*[:,]", 0.60, "role_prefix"),
    (r"</?(system|instruction|prompt)>", 0.80, "tag_injection"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), w, n) for p, w, n in _PATTERNS]


@dataclass(frozen=True)
class InjectionScore(DetectorScore):
    pass


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

# A chunk this size keeps a single embedded instruction paragraph from being
# pooled away by several paragraphs of surrounding report prose (see the
# module docstring for the measurement that motivated this). Overlap carries
# a little of the previous sentence into a fresh chunk so an injection
# straddling a split point is not each half diluted below threshold.
_CHUNK_MAX_CHARS = 500
_CHUNK_OVERLAP_CHARS = 80
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+")
_PARAGRAPH_SPLIT = re.compile(r"\n\s*\n")


def _chunk_for_scoring(text: str) -> list[str]:
    """Split into paragraph-sized (or smaller) pieces, never one giant block.

    Paragraph boundaries first, because this corpus's own injection payloads
    sit in their own paragraph -- matching the document's structure costs
    nothing and usually isolates the payload outright. Any paragraph still
    too long to trust a single pooled score is further split on sentence
    boundaries with a short character overlap between consecutive chunks.
    """
    paragraphs = [p.strip() for p in _PARAGRAPH_SPLIT.split(text) if p.strip()]
    if not paragraphs:
        return [text.strip()] if text.strip() else []

    chunks: list[str] = []
    for para in paragraphs:
        if len(para) <= _CHUNK_MAX_CHARS:
            chunks.append(para)
            continue
        sentences = [s.strip() for s in _SENTENCE_SPLIT.split(para) if s.strip()]
        current = ""
        for sentence in sentences:
            if current and len(current) + len(sentence) + 1 > _CHUNK_MAX_CHARS:
                chunks.append(current)
                current = current[-_CHUNK_OVERLAP_CHARS:] + " " + sentence
            else:
                current = (current + " " + sentence).strip() if current else sentence
        if current:
            chunks.append(current)
    return chunks or [text.strip()]


class _ModelBackend:
    is_model = True

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: PLC0415
        import torch  # noqa: PLC0415

        self.name = model_name
        self._torch = torch
        self._tok = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModelForSequenceClassification.from_pretrained(model_name)
        self._model.eval()
        # Resolve the positive class by NAME rather than assuming index 1.
        # Label order differs between releases of this model, and a silently
        # inverted classifier would report every clean document as an injection.
        self._pos_index = None
        for idx, label in self._model.config.id2label.items():
            if "inject" in str(label).lower():
                self._pos_index = int(idx)
        if self._pos_index is None:
            self._pos_index = 1

    def _score_chunk(self, text: str) -> tuple[float, list[float]]:
        enc = self._tok(text, truncation=True, max_length=512, return_tensors="pt")
        with self._torch.no_grad():
            logits = self._model(**enc).logits[0].tolist()
        probs = softmax(logits)
        return float(probs[self._pos_index]), logits

    def score(self, text: str) -> tuple[float, dict[str, Any]]:
        chunks = _chunk_for_scoring(text)
        if not chunks:
            return 0.0, {"n_chunks": 0}

        best_score, best_logits, best_idx = -1.0, None, 0
        for idx, chunk in enumerate(chunks):
            chunk_score, chunk_logits = self._score_chunk(chunk)
            if chunk_score > best_score:
                best_score, best_logits, best_idx = chunk_score, chunk_logits, idx

        return float(best_score), {
            "logits": [round(x, 4) for x in best_logits],
            "positive_index": self._pos_index,
            "n_chunks": len(chunks),
            "winning_chunk_index": best_idx,
            "winning_chunk_preview": chunks[best_idx][:160],
        }


class _PatternBackend:
    """The primary backend: hand-specified patterns over a noisy-OR.

    Combined with a noisy-OR rather than a sum: several weak indicators should
    raise suspicion without three of them saturating the score, and one strong
    indicator should dominate. `1 - prod(1 - w_i)` does both.

    This was written as a fallback for when the transformer was unavailable, and
    was promoted on measurement rather than by preference -- see the module
    docstring. Its weights remain judgement, not fitted values, and its cut
    points are declared in `fusion.bands.FIXED_THRESHOLD_SIGNALS` rather than
    fitted, because a rule aggregate has no clean distribution to fit against.
    Both facts are limitations to state in the report, not details to bury.
    """

    is_model = False
    name = "zetabyte-injection-patterns-v1"

    def score(self, text: str) -> tuple[float, dict[str, Any]]:
        hits, product = [], 1.0
        for regex, weight, label in _COMPILED:
            match = regex.search(text)
            if match:
                hits.append({"pattern": label, "weight": weight,
                             "match": match.group(0)[:80]})
                product *= (1.0 - weight)
        return clip01(1.0 - product), {"pattern_hits": hits, "n_hits": len(hits)}


_BACKEND: Any | None = None


def get_backend(model_name: str = DEFAULT_MODEL, force: str | None = None) -> Any:
    """Resolve once and cache.

    The pattern backend is the default. That is a measured decision, not a
    fallback: the transformer does not separate this corpus at any aggregation
    tried (module docstring). It stays reachable with force="model", which is
    how the probes run it and how the comparison is re-made when the corpus
    grows more injection-bearing documents.

    Caching matters only for the model path -- loading a transformer per
    document would dominate runtime. The pattern backend is stateless and cheap.
    """
    if force == "model":
        global _BACKEND
        if _BACKEND is None or not getattr(_BACKEND, "is_model", False):
            _BACKEND = _ModelBackend(model_name)
        return _BACKEND
    if force in (None, "patterns", "heuristic"):
        return _PatternBackend()
    raise ValueError(f"unknown backend {force!r}; expected 'patterns' or 'model'")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def injection_probability(document_text: str, backend: Any | None = None) -> float:
    """Probability that this document contains prompt-injection content, in [0, 1]."""
    if not document_text or not document_text.strip():
        return 0.0
    b = backend or get_backend()
    return clip01(b.score(document_text)[0])


def injection_probabilities(
    retrieved_docs: Sequence[Any], backend: Any | None = None
) -> list[InjectionScore]:
    """Per-document injection scores, in input order."""
    docs = as_records(retrieved_docs)
    if not docs:
        return []
    b = backend or get_backend()
    info = BackendInfo(
        b.name, b.is_model,
        "pretrained classifier; measured as non-separating on this corpus"
        if b.is_model else
        "hand-specified patterns, noisy-OR; weights and cut points declared, not fitted")
    out = []
    for i, d in enumerate(docs):
        text = doc_text(d)
        score, detail = b.score(text) if text.strip() else (0.0, {})
        out.append(InjectionScore(d.get("doc_id", f"doc_{i}"), clip01(score), info, detail))
    return out


def injection_probability_max(scores: Sequence[InjectionScore]) -> float:
    """Set-level aggregate: max, per design section 0.5."""
    return max((s.score for s in scores), default=0.0)


# The pattern backend was named for the role it used to have. Kept as an alias so
# the probe scripts that measured the swap still run unchanged.
_HeuristicBackend = _PatternBackend
