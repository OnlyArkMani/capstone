# Level 2 — Independent Detectors

Three detectors over the retrieval set. Deliberately **independent**: no detector sees
another's output, and fusion happens later. P1, P4 and P6 all reach the same conclusion —
no single detector should be trusted alone — and independence is what makes the
combination worth more than its parts.

```bash
pip install -r detectors/requirements.txt
python -m detectors.test_detectors -v
```

```python
from detectors import embedding_anomaly_score, injection_probability, entailment_score

anomaly = embedding_anomaly_score(retrieval.records)       # per-document
inject  = injection_probability(doc.content)               # single document
support = entailment_score(claim, evidence_text)           # HIGHER = SAFER
```

---

## The three contracts

| Detector | Signature | Returns |
|---|---|---|
| **1. Embedding anomaly** | `embedding_anomaly_score(retrieved_docs, embedder=None, vectors=None)` | `list[AnomalyScore]`, one per doc |
| **2. Prompt injection** | `injection_probability(document_text)` → `float`<br>`injection_probabilities(retrieved_docs)` → `list[InjectionScore]` | probability of injection content |
| **3. Entailment** | `entailment_score(generated_claim, evidence_text)` → `float`<br>`entailment_scores(claim, retrieved_docs)` → `list[EntailmentScore]` | support for the claim |

Every score is in **[0, 1]** and every detector returns **per-document** values, never only
an aggregate. Aggregation belongs to fusion, which takes the **max** over cited documents,
not the mean (design §0.5) — one crafted document among four clean ones is the entire
attack, and averaging it away is how the attack survives. `*_max()` helpers are provided
for that.

**Direction.** `entailment_score` is the one signal where *higher is safer*.
`entailment_scores(...)` returns the risk-oriented complement `unsupport = 1 - entailment`
in `.score`, with both probabilities in `.detail`, so the convention isn't something anyone
has to remember (design §0.3).

---

## Detector 1 — embedding anomaly

K-means over the retrieved documents' embeddings; each document scores its normalised
distance from its nearest cluster centre. Normalisation is a median/MAD robust z-score
computed **within the query's own retrieval set** (design §3.2), which makes the signal
scale-free across embedding models and corpus sizes. `.detail["robust_z"]` is what the
fusion feature encoding actually consumes; `.score` is the squashed [0, 1] view.

**Clustering five points is barely clustering.** Below four documents the detector doesn't
cluster at all — it measures distance from the set centroid and reports
`method="centroid_distance"`. At n=1 it returns 0.0, because a singleton retrieval carries
no outlier evidence and inventing some would manufacture a signal from nothing. Cluster
count is capped at three: with few points, more clusters means more singleton clusters, and
a point that is its own cluster has distance zero — the outlier would score as the most
normal document in the set.

**Why not min-max normalisation.** Min-max over a retrieval set always assigns exactly one
document 1.0 and one 0.0, whether or not anything is anomalous. It would manufacture a
maximum-severity outlier in every clean set the system ever sees. Scaling by *dispersion*
instead means a clean set scores near zero throughout, which is the correct answer.

**Expect this to be the weakest of the three, and that is a finding.** PoisonedRAG
documents are constructed to sit *near* the query in embedding space — that is the attack.
A document engineered for retrieval proximity can land comfortably inside the cluster it
was aimed at. A low anomaly score on a poisoned document is a true observation about the
attack, not a defect in the detector. Reading it as failure would be misreading the
experiment.

## Detector 2 — prompt injection

`protectai/deberta-v3-base-prompt-injection-v2` via transformers.

The positive class is resolved **by label name**, not by assuming index 1. Label order
differs between releases of this model, and a silently inverted classifier would report
every clean document as an injection while looking entirely plausible.

Design §2.1 lets this signal alone push a response to MALICIOUS while the other three need
corroboration. Anomalous embeddings, unsupported claims and knowledge conflicts all have
benign explanations; instruction text aimed at a language model inside a threat-intelligence
document does not. Its presence is evidence of *intent*, not of unusual statistics.

**The corpus has exactly one document with an injection payload.** One positive confirms
the signal fires and is nowhere near enough to estimate a threshold or a false-positive
rate. No per-detector performance figure for injection is reportable until the poisoned
corpus carries more of the `direct_prompt_injection` family.

## Detector 3 — entailment (and the derived conflict signal)

`cross-encoder/nli-deberta-v3-base` via sentence-transformers. Label positions are resolved
**by name** for the same reason as above — swapping entailment for contradiction would
invert the single most important signal in the system while still producing plausible
numbers.

This module also provides the derived intra-evidence conflict the design needs (§0.4).
The four named detectors have no doc-vs-doc measure — `conflict_score` compares evidence
against the *model's* knowledge, not against other evidence — but case C10 (two Tier-1
sources contradicting each other, a distinct failure mode from poisoning) is defined
entirely by that quantity, and the confidence measure's agreement component needs it too.

```python
conflicts = pairwise_conflict(retrieval.records)   # symmetrised, max of both directions
d_conflict_max(conflicts)                          # design §0.4
tier1_conflict_max(conflicts)                      # the quantity case C10 turns on
```

It lives here rather than as a fourth detector because it is the *same model applied
pairwise*: no new dependency, no new weights. Cost is O(k²) — 10 calls at k=5, 28 at k=8.
Restrict to cited documents if that proves too slow (design open question 2).

---

## Backends

Each detector resolves a real pretrained model and falls back to a heuristic when one is
unavailable. `BackendInfo.is_model` travels with every result, and `test_detectors.py`
refuses to call a run conclusive without it.

| Detector | Real | Fallback | The fallback |
|---|---|---|---|
| Anomaly | sklearn KMeans + real embeddings | numpy k-means++ | **same algorithm**; only the *embedder* matters, and a non-semantic one invalidates the result |
| Injection | `protectai/deberta-v3-base-prompt-injection-v2` | weighted regex patterns, noisy-OR | indicative only; weights are judgement, not fitted |
| Entailment | `cross-encoder/nli-deberta-v3-base` | token overlap | **cannot detect contradiction** — a negated claim scores as entailed, which is exactly what the real model exists to catch |

---

## The sanity check

`test_detectors.py` is not a performance evaluation. It answers one question before fusion
gets built on top of these signals: given documents we already know the answer for, does
each detector move in the direction it is supposed to move? A detector wired backwards
produces confident, plausible, wrong numbers, and catching that after three signals have
been fused is far more expensive.

It checks the output contract (per-document, [0, 1], singleton and empty-input behaviour,
consistent `doc_id`s across all three), then the direction of each detector, then the
Tier-1 conflict pair.

The entailment check is the informative one. For each of the 10 target queries it scores
the *attacker's intended answer* against the poisoned document and against the genuine
anchor. The poisoned document should support the attacker's claim more than the real
document does, and that gap is the signal the verifier exists to expose.

**This script reads `corpus/ground_truth/`, and that is the boundary.** The detectors are
the system under test and never see the answer key; test and evaluation code do. A check in
the script asserts, via AST inspection, that no module in `detectors/` or `pipeline/` reads
the manifest. It inspects executable code rather than doing a string search, because both
packages *document* that they do not read ground truth — a naive search flags exactly the
modules being most careful.

---

## Files

```
detectors/
  __init__.py           public API
  base.py               BackendInfo, robust_z, squash, input normalisation
  anomaly.py            detector 1
  injection.py          detector 2
  entailment.py         detector 3 + derived pairwise conflict
  isolation_check.py    AST assertion that a package never reads the answer key
  test_detectors.py     sanity check
  requirements.txt
```
