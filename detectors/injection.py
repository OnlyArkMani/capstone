"""
Detector 2 — prompt injection.

Scores a document for text addressed to the *model* rather than to a human
reader. Real backend is `protectai/deberta-v3-base-prompt-injection-v2` via
transformers; a pattern-based heuristic stands in when the model is unavailable.

Why this signal is treated differently from the others
------------------------------------------------------

Design section 2.1 lets injection alone push a response to MALICIOUS, while the
other three signals need corroboration. The reason is that anomalous embeddings,
unsupported claims and knowledge conflicts all have benign explanations -- a
genuinely novel threat, a badly written advisory, a model whose training predates
the CVE. Instruction text aimed at a language model inside a threat-intelligence
document has no benign explanation. Its presence is evidence of *intent*, not of
unusual statistics.

What this detector cannot tell us yet
-------------------------------------

The corpus contains exactly **one** document carrying an injection payload
(`poison-injection-infusion-t3-forum`, family `direct_prompt_injection`). One
positive is enough to check the signal fires and is nowhere near enough to
estimate a threshold, a false-positive rate, or anything else. Any per-detector
performance figure for injection is not reportable until the poisoned corpus
carries substantially more of this family. Recorded as an open item rather than
discovered later.
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

    def score(self, text: str) -> tuple[float, dict[str, Any]]:
        enc = self._tok(text, truncation=True, max_length=512, return_tensors="pt")
        with self._torch.no_grad():
            logits = self._model(**enc).logits[0].tolist()
        probs = softmax(logits)
        return float(probs[self._pos_index]), {
            "logits": [round(x, 4) for x in logits],
            "positive_index": self._pos_index,
        }


class _HeuristicBackend:
    """Pattern matching. Structurally valid, analytically weak.

    Combined with a noisy-OR rather than a sum: several weak indicators should
    raise suspicion without three of them saturating the score, and one strong
    indicator should dominate. `1 - prod(1 - w_i)` does both.
    """

    is_model = False
    name = "heuristic-patterns"

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
    """Resolve once and cache: loading a transformer per document would dominate runtime."""
    global _BACKEND
    if force == "heuristic":
        return _HeuristicBackend()
    if _BACKEND is None:
        try:
            _BACKEND = _ModelBackend(model_name)
        except Exception as exc:
            print(f"[detectors] WARNING: prompt-injection model unavailable "
                  f"({type(exc).__name__}); using pattern heuristics. Scores are indicative "
                  f"only and must not be reported as detector performance.", flush=True)
            _BACKEND = _HeuristicBackend()
    return _BACKEND


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
    info = BackendInfo(b.name, b.is_model,
                       "pretrained classifier" if b.is_model else "regex patterns, not fitted")
    out = []
    for i, d in enumerate(docs):
        text = doc_text(d)
        score, detail = b.score(text) if text.strip() else (0.0, {})
        out.append(InjectionScore(d.get("doc_id", f"doc_{i}"), clip01(score), info, detail))
    return out


def injection_probability_max(scores: Sequence[InjectionScore]) -> float:
    """Set-level aggregate: max, per design section 0.5."""
    return max((s.score for s in scores), default=0.0)
