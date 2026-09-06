"""
Detector 3 — claim-evidence entailment.

Does the retrieved evidence actually support the generated claim? Real backend is
`cross-encoder/nli-deberta-v3-base` via sentence-transformers; a lexical-overlap
proxy stands in when the model is unavailable.

Direction of this signal
------------------------

`entailment_score` runs opposite to every other detector: **higher is safer**.
Design section 0.3 defines the risk-oriented form once, `unsupport = 1 -
entailment`, and uses it everywhere thereafter. Both are returned so nobody has
to remember which way round it goes.

The derived signal this module also provides
--------------------------------------------

Design section 0.4 needs a document-vs-document contradiction measure
(`d_conflict`) that the four named detectors do not supply: `conflict_score`
compares evidence against the *model's* knowledge, not against other evidence.
Case C10 -- two Tier-1 sources contradicting each other, which is a distinct
failure mode from poisoning -- is defined entirely by that quantity, and the
confidence measure's agreement component needs it too.

It is provided here rather than as a fourth detector because it is the *same
model applied pairwise*: no new dependency, no new weights, one extra function.
It earns its place twice and costs nothing new.

Cost note: pairwise comparison is O(k^2) NLI calls, which is 10 calls at k=5 and
28 at k=8. Restrict to cited documents if that proves too slow (design open
question 2).
"""

from __future__ import annotations

import itertools
import os
import re
from dataclasses import dataclass
from typing import Any, Sequence

from .base import BackendInfo, DetectorScore, as_records, clip01, doc_text, softmax

DEFAULT_MODEL = "cross-encoder/nli-deberta-v3-base"

# Pairs per forward pass. A retrieval at k=5 produces 5 entailment pairs and 20
# conflict pairs, so 32 keeps each call to a single batch while staying small
# enough that padding to the longest sequence in the batch does not dominate.
BATCH_SIZE = int(os.environ.get("RAG_NLI_BATCH_SIZE", "32"))
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "to", "of", "for",
    "on", "in", "and", "or", "not", "no", "it", "this", "that", "with", "as", "at",
    "by", "from", "has", "have", "had", "which", "should", "would", "can", "may",
}


@dataclass(frozen=True)
class EntailmentScore(DetectorScore):
    """`score` is the RISK-oriented value (unsupport). `detail` carries the rest."""

    @property
    def entailment(self) -> float:
        return float(self.detail.get("entailment", 1.0 - self.score))

    @property
    def contradiction(self) -> float:
        return float(self.detail.get("contradiction", 0.0))


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

class _CrossEncoderBackend:
    is_model = True

    def __init__(self, model_name: str = DEFAULT_MODEL) -> None:
        from sentence_transformers import CrossEncoder  # noqa: PLC0415

        self.name = model_name
        self._model = CrossEncoder(model_name)
        # Resolve label positions by NAME. This model family has shipped with
        # different orderings, and silently swapping entailment for
        # contradiction would invert the single most important signal in the
        # system while still producing plausible-looking numbers.
        cfg = getattr(self._model.model, "config", None)
        id2label = dict(getattr(cfg, "id2label", {}) or {})
        self._idx = {"contradiction": 0, "entailment": 1, "neutral": 2}
        if id2label:
            for idx, label in id2label.items():
                key = str(label).lower()
                for target in ("contradiction", "entailment", "neutral"):
                    if target.startswith(key[:5]) or key.startswith(target[:5]):
                        self._idx[target] = int(idx)

    def _from_logits(self, logits: Any) -> dict[str, float]:
        probs = softmax(list(logits))
        return {
            "entailment": float(probs[self._idx["entailment"]]),
            "contradiction": float(probs[self._idx["contradiction"]]),
            "neutral": float(probs[self._idx["neutral"]]),
        }

    def score(self, premise: str, hypothesis: str) -> dict[str, float]:
        return self.score_batch([(premise, hypothesis)])[0]

    def score_batch(self, pairs: Sequence[tuple[str, str]]) -> list[dict[str, float]]:
        """Score many premise/hypothesis pairs in ONE forward pass.

        This is the difference between minutes and tens of minutes on CPU.
        Scoring one pair at a time was costing 25 separate forward passes per
        query -- 5 for entailment plus 10 document pairs scored in both
        directions -- and 94 queries during training meant roughly 2,350 of
        them. Worse, a batch of one is the pathological case for CPU inference:
        PyTorch spreads a tiny matrix multiply across every available thread and
        the synchronisation costs more than the arithmetic. Measured on this
        machine, the run pinned 15 cores and still crawled.

        The arithmetic per pair is unchanged -- same model, same pairs, same
        softmax over the same logits -- so scores are identical to the unbatched
        path up to float ordering. That equivalence is worth preserving: the
        speedup must not become a silent change to the numbers.
        """
        if not pairs:
            return []
        raw = self._model.predict(list(pairs), batch_size=BATCH_SIZE,
                                  show_progress_bar=False)
        return [self._from_logits(row) for row in raw]


class _LexicalBackend:
    """Token-overlap proxy. Not inference -- it cannot detect contradiction.

    A negated restatement of a claim shares nearly all its tokens, so this
    backend scores "the device is safe" and "the device is not safe" as strongly
    entailing. That failure is precisely the thing the real model exists to
    catch, so any entailment figure from this backend is structural evidence
    only. It reports a fixed low contradiction probability rather than
    pretending to estimate one.
    """

    is_model = False
    name = "lexical-overlap"

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOP and len(t) > 2}

    def score(self, premise: str, hypothesis: str) -> dict[str, float]:
        p, h = self._tokens(premise), self._tokens(hypothesis)
        if not h:
            return {"entailment": 0.0, "contradiction": 0.0, "neutral": 1.0}
        coverage = len(p & h) / len(h)          # how much of the claim the evidence covers
        ent = clip01(coverage)
        return {"entailment": ent, "contradiction": 0.0, "neutral": clip01(1.0 - ent)}

    def score_batch(self, pairs: Sequence[tuple[str, str]]) -> list[dict[str, float]]:
        """Same interface as the real backend, so callers need no branch.

        There is nothing to batch here -- token overlap is not a forward pass --
        but a caller written against score_batch must work on both backends or
        the fallback path silently stops being exercised.
        """
        return [self.score(p, h) for p, h in pairs]


_BACKEND: Any | None = None


def get_backend(model_name: str = DEFAULT_MODEL, force: str | None = None) -> Any:
    global _BACKEND
    if force == "lexical":
        return _LexicalBackend()
    if _BACKEND is None:
        try:
            _BACKEND = _CrossEncoderBackend(model_name)
        except Exception as exc:
            print(f"[detectors] WARNING: NLI cross-encoder unavailable ({type(exc).__name__}); "
                  f"using lexical overlap. This proxy CANNOT detect contradiction -- a negated "
                  f"claim scores as entailed. Structural checks only.", flush=True)
            _BACKEND = _LexicalBackend()
    return _BACKEND


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def entailment_score(generated_claim: str, evidence_text: str, backend: Any | None = None) -> float:
    """Probability that `evidence_text` entails `generated_claim`, in [0, 1].

    Higher = better supported = safer. The risk-oriented complement is
    `1 - entailment_score(...)`, which design section 0.3 calls `s_uns`.
    """
    if not generated_claim.strip() or not evidence_text.strip():
        return 0.0
    b = backend or get_backend()
    return clip01(b.score(evidence_text, generated_claim)["entailment"])


def entailment_scores(
    generated_claim: str, retrieved_docs: Sequence[Any], backend: Any | None = None
) -> list[EntailmentScore]:
    """Per-document entailment of one claim, in input order.

    `.score` is the RISK value (unsupport); `.entailment` and `.contradiction`
    expose the underlying probabilities.
    """
    docs = as_records(retrieved_docs)
    if not docs:
        return []
    b = backend or get_backend()
    info = BackendInfo(b.name, b.is_model,
                       "cross-encoder NLI" if b.is_model else "token overlap, cannot detect contradiction",
                       # The lexical backend IS a degraded stand-in: it cannot
                       # detect contradiction at all, which is the thing the real
                       # model exists for. This one should be flagged loudly.
                       is_fallback=not b.is_model)
    # One batched call for every document, rather than one call per document.
    # Empty-evidence documents are held out of the batch and given the neutral
    # result directly, so the model is never asked to score an empty premise.
    evidences = [doc_text(d) for d in docs]
    scorable = [(i, e) for i, e in enumerate(evidences) if e.strip()]
    NEUTRAL = {"entailment": 0.0, "contradiction": 0.0, "neutral": 1.0}
    probs_by_index: dict[int, dict[str, float]] = {i: NEUTRAL for i in range(len(docs))}
    if scorable:
        batched = b.score_batch([(e, generated_claim) for _, e in scorable])
        for (i, _), probs in zip(scorable, batched):
            probs_by_index[i] = probs

    out = []
    for i, d in enumerate(docs):
        probs = probs_by_index[i]
        out.append(EntailmentScore(
            doc_id=d.get("doc_id", f"doc_{i}"),
            score=clip01(1.0 - probs["entailment"]),   # risk-oriented
            backend=info,
            detail={
                "entailment": round(probs["entailment"], 6),
                "contradiction": round(probs["contradiction"], 6),
                "neutral": round(probs["neutral"], 6),
                "unsupport": round(1.0 - probs["entailment"], 6),
            },
        ))
    return out


def unsupport_max(scores: Sequence[EntailmentScore]) -> float:
    """Weakest support across the set, as a risk value."""
    return max((s.score for s in scores), default=0.0)


def best_entailment(scores: Sequence[EntailmentScore]) -> float:
    """Strongest support any single document gives the claim.

    This is usually the right response-level quantity: a claim supported by one
    document *is* supported, even if four others are silent on it.
    """
    return max((s.entailment for s in scores), default=0.0)


# ---------------------------------------------------------------------------
# Derived: intra-evidence conflict (design section 0.4)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PairwiseConflict:
    doc_id_a: str
    doc_id_b: str
    contradiction: float
    tier_a: int | None = None
    tier_b: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "doc_id_a": self.doc_id_a, "doc_id_b": self.doc_id_b,
            "contradiction": round(self.contradiction, 6),
            "tier_a": self.tier_a, "tier_b": self.tier_b,
        }


def pairwise_conflict(
    retrieved_docs: Sequence[Any], backend: Any | None = None
) -> list[PairwiseConflict]:
    """Contradiction between every pair of retrieved documents.

    Symmetrised by taking the max of both directions: NLI is directional, but
    "these two documents disagree" is not.
    """
    docs = as_records(retrieved_docs)
    if len(docs) < 2:
        return []
    b = backend or get_backend()

    tiers = {}
    for i, original in enumerate(retrieved_docs):
        did = docs[i].get("doc_id", f"doc_{i}")
        prov = getattr(original, "provenance", None)
        tiers[did] = getattr(prov, "source_tier", None) if prov else (
            original.get("source_tier") if isinstance(original, dict) else None)

    # Collect every pair first, score them in ONE call, then reassemble. At k=5
    # this is 20 forward passes (10 pairs, both directions) collapsed into one
    # batch. Both directions are still scored and still symmetrised by max --
    # NLI is directional, "these two documents disagree" is not -- so the
    # contradiction values are unchanged, only the number of calls differs.
    pending: list[tuple[str, str, str, str]] = []   # (doc_id_a, doc_id_b, text_a, text_b)
    for (i, a), (j, bdoc) in itertools.combinations(enumerate(docs), 2):
        ta, tb = doc_text(a), doc_text(bdoc)
        if not ta.strip() or not tb.strip():
            continue
        pending.append((a.get("doc_id", f"doc_{i}"), bdoc.get("doc_id", f"doc_{j}"), ta, tb))

    if not pending:
        return []

    forward = [(ta, tb) for _, _, ta, tb in pending]
    backward = [(tb, ta) for _, _, ta, tb in pending]
    scored = b.score_batch(forward + backward)
    n = len(pending)

    out = []
    for idx, (ida, idb, _, _) in enumerate(pending):
        c = max(scored[idx]["contradiction"], scored[idx + n]["contradiction"])
        out.append(PairwiseConflict(ida, idb, clip01(c), tiers.get(ida), tiers.get(idb)))
    return out


def per_document_conflict(conflicts: Sequence[PairwiseConflict]) -> dict[str, float]:
    """Turn pairwise contradictions into a per-DOCUMENT conflict value.

    A document's conflict is the strongest contradiction it takes part in. The
    set-level `d_conflict_max` answers "does this evidence set disagree with
    itself"; the fusion layer needs the per-document form, because a band and a
    trust score are assigned to a document, not to a set.

    Max rather than mean, for the same reason the rest of the system uses max
    across a set: one crafted document among clean neighbours is the mechanism
    being defended against, and averaging it against agreeable neighbours is
    exactly how it hides. A document contradicted by nothing scores 0.0, which
    here is a real measurement -- it was compared and did not disagree -- rather
    than an absent signal.

    IMPORTANT -- this is NOT what design section 2.1 calls `conflict`. The design
    defines that signal as retrieved evidence versus the MODEL'S PARAMETRIC
    KNOWLEDGE, which needs a probe this system does not have. What is wired here
    is INTRA-EVIDENCE conflict: retrieved documents against each other, which is
    design section 0.4's derived quantity. The substitution is deliberate and is
    recorded per row as `conflict_source`, exactly as `hypothesis_source` records
    the entailment substitution. It must be written into docs/design/ before any
    figure that depends on it is quoted, and it should not be silently read as
    the parametric-conflict signal the design specifies.
    """
    out: dict[str, float] = {}
    for c in conflicts:
        for did in (c.doc_id_a, c.doc_id_b):
            out[did] = max(out.get(did, 0.0), float(c.contradiction))
    return out


def d_conflict_max(conflicts: Sequence[PairwiseConflict]) -> float:
    """Design section 0.4's `d_conflict_max`."""
    return max((c.contradiction for c in conflicts), default=0.0)


def tier1_conflict_max(conflicts: Sequence[PairwiseConflict]) -> float:
    """Highest contradiction between two Tier-1 documents specifically.

    This is the quantity case C10 turns on. A Tier-1/Tier-3 disagreement is
    ordinary; two authorities disagreeing with each other is the distinct
    failure mode the taxonomy separates out (design section 2.5).
    """
    return max((c.contradiction for c in conflicts if c.tier_a == 1 and c.tier_b == 1), default=0.0)
