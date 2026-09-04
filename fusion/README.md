# Level 3 — Fusion, Confidence and Adaptive Response

This package turns the three independent Level 2 detector signals into one
analyst-facing decision: **how trustworthy is this answer, how sure are we of
that, what kind of situation is this, and what should be done about it.**

```python
from fusion import score_query

result = score_query("ransomware targeting hospital imaging systems", records)

result.headline             # "ORANGE" — the three-state band an analyst reads first
result.headline_label       # "Mid-Suspicious, Review Recommended"
result.headline_subtype     # None, or ATTACK_DETECTED / TRUSTED_SOURCE_COMPROMISE on RED
result.trust_percent        # 87.4   — 0-100
result.confidence           # 0.62   — how much to trust that number, 0-1
result.confidence_interval  # (79.1, 92.8)
result.case_id              # "C6"   — Open-Feed Irregularity
result.action               # "REVIEW"
result.documents            # per-document scores, cases, headlines and signals
```

`records` is the list of `RetrievedRecord` objects that `pipeline.retrieve_top_k`
returns. Nothing else is required.

---

## Why three parts and not one number

A single risk score is not enough to act on, for two reasons.

**A number does not tell you what kind of thing you are looking at.** "Two
authoritative sources disagree with each other" and "an unverified blog is
lying" can carry the same risk score and require completely different responses.
Part A assigns a named *case*, and the case carries the action.

**A number does not tell you how much to believe it.** A risk of 0.85 from five
agreeing documents across three independent sources is a finding. The same 0.85
from one document, with the detectors contradicting each other, is a guess.
Reporting them as the same figure would hide the difference from the analyst, so
Part C reports confidence separately and never folds it into the score.

---

## Part A — the case classifier (`bands.py`, `cases.py`)

Two steps: detector scores become a **band**, then band × source tier becomes a
**case**.

### Bands

Each signal is compared against thresholds fitted on the **clean** documents
only — `theta_suspicious = Q95(clean)`, `theta_malicious = Q99(clean)`. They are
not hand-picked. This makes the false-positive rate a design input rather than
something discovered after deployment, and the thresholds move automatically
when a detector is replaced with a better one.

```
MALICIOUS   injection alone above its malicious threshold
            or two or more signals above theirs
            or one, plus two others above their suspicious thresholds
SUSPICIOUS  at least one signal above its suspicious threshold
CLEAN       otherwise
```

**Injection alone is sufficient; the others are not.** Anomalous embeddings,
unsupported claims and knowledge conflicts all have innocent explanations — a
genuinely novel advisory, a badly written one, a model whose training predates
the CVE. Instruction text aimed at a language model, sitting inside a
threat-intelligence document, has none. It is evidence of intent, not of unusual
statistics.

Two protections live here:

- A **missing** signal is excluded, not treated as zero. Zero is an assertion
  that there is no conflict, which is a claim we have no evidence for, and it
  would bias every band toward CLEAN.
- A **degenerate** signal — one whose clean distribution has essentially no
  spread, which is what a fallback detector backend produces — is marked
  `unusable` and excluded entirely. Its quantiles are not thresholds, they are
  that constant, and using them would make either every document malicious or
  the signal permanently dead.

### Cases

Nine cases from crossing three tiers with three bands, plus two cross-cutting
cases defined on the shape of the retrieval set. Assignment is deterministic
under a fixed precedence order; the first match wins.

| Precedence | Case | Situation | Priority | Action |
|---|---|---|---|---|
| 1 | **C5** Authoritative Channel Compromise | Tier 1 × Malicious | P0 | Escalate |
| 2 | **C4** Trusted-Source Anomaly | Tier 1 × Suspicious | P1 | Escalate |
| 3 | **C11** Isolated Retrieval Outlier | set-level | P1 | Escalate |
| 4 | **C10** Authoritative Divergence | Tier 1 vs Tier 1 | P2 | Review |
| 5 | **C7** Open-Feed Poisoning | Tier 2 × Malicious | P2 | Reject |
| 6 | **C9** Expected-Path Poisoning | Tier 3 × Malicious | P2 | Reject |
| 7 | **C6** Open-Feed Irregularity | Tier 2 × Suspicious | P3 | Review |
| 8 | **C8** Unverified Irregularity | Tier 3 × Suspicious | P3 | Reject |
| 9 | **C3** Unverified but Unremarkable | Tier 3 × Clean | P3 | Review |
| 10 | **C2** Community Corroboration | Tier 2 × Clean | P4 | Accept |
| 11 | **C1** Authoritative Confirmation | Tier 1 × Clean | P5 | Accept |

**Reject and Escalate are not degrees of the same thing.** Reject protects *this
answer* — the query is the unit of concern. Escalate protects *the system* — a
source or the pipeline is the unit of concern, and this query is merely how we
noticed.

Two entries in that table are the design's actual claims, and both are testable:

**C4 outranks C9.** A merely *suspicious* Tier-1 document is ranked above an
outright *malicious* Tier-3 one. This looks backwards and is deliberate. The
tier is a prior: anomalous behaviour is improbable from Tier 1 by construction,
so observing it carries far more information than the same observation from
Tier 3, where we already assumed it. Tier-1 sources are trusted by everything
downstream, so the blast radius is larger. And every plausible explanation —
source compromise, an intercepted fetch path, a provenance mislabel, an insider
edit — is a finding about *our own system*, which is exactly why the action is
Escalate rather than Reject.

**C10 is not an attack.** Two Tier-1 sources contradicting each other, with the
attack indicators quiet, is an advisory revision, a scope difference or genuine
analytic disagreement. The system is bound never to silently pick a winner:
there is no principled basis for choosing between two authorities, and doing so
would conceal from the analyst the single most decision-relevant fact available.
The "quiet indicators" clause matters — a contradiction accompanied by a live
injection signal is a possible compromise wearing the costume of a disagreement,
and C5 catches it instead.


### The headline band — GREEN / ORANGE / RED

Eleven cases and four actions are operationally precise but are not what an analyst reads
first. The headline collapses them into three states, **derived** from the reconciled action
and the governing tier — never stored as an independent judgement, so it cannot disagree with
the disposition the system actually took.

| Band | Label | Reached when |
|---|---|---|
| **GREEN** | Good to Go | Accept **and** governing tier is 1 |
| **ORANGE** | Mid-Suspicious, Review Recommended | Review, **or** any governing tier other than 1 |
| **RED** · `ATTACK_DETECTED` | Reject / Escalate — Attack Detected | Reject or Escalate from a source we had not vouched for |
| **RED** · `TRUSTED_SOURCE_COMPROMISE` | Reject / Escalate — Trusted Source Compromise Suspected | Reject or Escalate where the governing tier is 1 |

**Why RED is sub-typed.** A malicious document from an unverified blog and an anomaly in a
CISA advisory can produce the same action and the same risk score while needing completely
different responses: the first is closed by quarantining a document, the second is a finding
about our own trust infrastructure that outlives the query. An undifferentiated RED would
throw away the most decision-relevant fact in the taxonomy. The sub-type keys on the governing
tier rather than a case list, so it tracks the taxonomy automatically — C4 and C5 are its
principal members, and C11 joins them whenever the isolated outlier is carried by a Tier-1
source.

**Why Tier 2 and Tier 3 can never be GREEN.** Unverified provenance with quiet signals is
unremarkable, not trustworthy — the absence of evidence against a document is not evidence
for it. A moderated but community-writable feed is trusted enough to retrieve from, not
trusted enough to return unexamined. Together these reduce GREEN to a single case, **C1**.
The overlap is intentional; both rules are enforced and tested independently because they
encode different commitments, and either could be revisited without the other.

**The fail-safe.** GREEN is reachable only by an affirmative conjunction: an explicit Accept
*and* Tier 1. Every other path terminates at ORANGE — an unrecognised action, a missing tier,
a response the classifier could not resolve. There is no `else: GREEN` branch anywhere in the
implementation, and the truth table is asserted exhaustively in `test_fusion.py`. An
implementation that returns GREEN when it does not know what else to return has inverted the
guarantee.

*Current coverage:* the Tier-3 governing cases are C3, C8 and C9, mapping to ORANGE, RED and
RED. None reaches GREEN, so the Tier-3 rule is presently a no-op — kept as an enforced
invariant, and tested against the case table rather than a hard-coded list, because only two
cases route to Accept at all and a future edit is exactly how that guarantee would be lost.

---

## Part B — the composite score (`features.py`, `model.py`, `evaluate.py`)

Logistic regression over the detector signals plus dummy-coded source tier,
producing a calibrated probability that is reported as a trustworthiness
percentage. Per Sprint 0, the weights are **fitted, not chosen**.

**Bounded signals get a logit transform.** Injection and unsupport are
probabilities that pile up near the endpoints; a linear model on raw
probabilities spends nearly all its resolution on a region containing no data.
The anomaly signal arrives as a within-set robust z-score and is used as-is.

**Source tier is dummy-coded, never ordinal.** This is the most consequential
encoding decision in the project. Encoding tier as 1/2/3 forces the model to
assume risk moves monotonically with tier — the exact opposite of the C4/C9
inversion. An ordinal encoding would make that relationship *structurally
unrepresentable*: the model would be incapable of learning the one thing it was
built to learn. Tier 2 is the reference level.

**Tier × signal interactions carry the inversion.** Dummies alone shift the
intercept per tier; they cannot change a signal's *slope* per tier. Without
interactions the model can say "Tier 1 is safer overall" but never "an anomaly
means more when it comes from Tier 1".

**The feature set shrinks when the corpus cannot support it.** Logistic
regression wants roughly 10–15 minority-class events per predictor, so
`choose_feature_spec` picks a rung automatically: full (≥150 positives), reduced
(60–149, keeping only the two interactions that carry the inversion), or
base-only (<60, flagged **underpowered** in every report it appears in).

Other decisions worth knowing before reading a number out of this package:

- Class imbalance is handled by cost-weighting at `C_FN/C_FP = 10`, not by
  resampling, and the reported summary statistic is **F₃**, which weights recall
  accordingly. **PR-AUC** is the headline curve, not ROC-AUC, because ROC-AUC
  flatters a detector on an imbalanced problem.
- Splits are **grouped** by `poison_family_id` (poisoned) and `doc_id` (clean),
  so no attack family appears on both sides of the split. An ungrouped random
  split would let near-duplicate variants of one attack leak across and inflate
  every figure.
- The scaler is fitted on the training fold only. Fitting it before splitting is
  the most common leakage bug in small-corpus work and would invalidate every
  number reported.
- Calibration is Platt scaling; isotonic overfits below roughly 200 positives.
- Response-level risk is the **maximum** over retrieved documents, never the
  mean. PoisonedRAG's mechanism is one crafted document among several clean
  ones, and averaging it against four clean neighbours is exactly how the attack
  survives.
- The reported interval takes its **width** from a 200-sample bootstrap and its
  **location** from the calibrated point estimate. The bootstrap ensemble is
  uncalibrated, so quoting its raw quantiles produced intervals that did not
  contain the number they were attached to.

---

## Part C — confidence (`confidence.py`)

Five components, combined by **geometric** mean:

| Component | Asks | Why |
|---|---|---|
| `volume` | How much effective evidence? | Kish effective sample size, saturating — the tenth corroborating document adds far less than the second |
| `agreement` | Does the evidence agree? | Five documents that contradict each other are less informative than two that agree |
| `independence` | How many real witnesses? | Five documents from one feed is one witness quoted five times; cross-tier agreement is harder to manufacture |
| `coherence` | Do the detectors concur? | Disagreeing detectors mean the estimate rests on an unresolved internal contradiction |
| `model_stability` | Is the fit stable here? | Sparse regions of the training distribution give wide intervals, and predictions near p=0.5 are inherently uncertain |

The geometric mean is the point. Confidence is **conjunctive** — we are confident
only if there is enough evidence *and* it agrees *and* it is independent *and*
the detectors concur *and* the model is stable. An arithmetic mean lets four
strong components mask one fatal weakness, which is precisely the behaviour we
cannot afford. Any component at zero drives the composite to zero, correctly.

Two caps and one floor:

- A **single-document** answer caps at 0.30 however clean it looks.
- `n_eff ≤ 1` caps at 0.40, which catches five near-duplicates from one feed.
- Below **0.35**, the minimum disposition is Review regardless of the score.

Low confidence may only ever make a disposition *more* conservative. A wide
interval is not a reason to relax.

---

## How the final action is reached

Two tracks run over the same signals and the more conservative wins.

```
RULE TRACK         the case taxonomy — semantics a model fitted on a few
                   hundred instances cannot learn, notably the Tier-1
                   inversion and treating authoritative divergence as not
                   an attack
STATISTICAL TRACK  the fitted score against derived thresholds — better than
                   hand-written rules on patterns present in training, but
                   opaque during an incident and silent on unseen attacks

                        escalation_dominance(rule, statistical)
```

**Escalation dominance** guarantees that adding the statistical track can never
make the system less safe than the rules alone — worth having when the model is
fitted on a corpus we built ourselves. Only the rule track can produce
**Escalate**, because escalation is a claim about the *system* and needs the
semantic structure of a case, not a scalar.

Two further constraints, both one-directional: confidence below the floor forces
at least Review, and thresholds are applied to the **upper bound** of the risk
interval rather than the point estimate, so low confidence pushes borderline
cases toward Review automatically with no extra rule.

---

## Files

| File | What it does |
|---|---|
| `bands.py` | Fits Q95/Q99 thresholds on clean data; assigns Clean/Suspicious/Malicious; degeneracy guard |
| `cases.py` | The eleven cases, the precedence order, `escalation_dominance`, and the GREEN/ORANGE/RED headline derivation |
| `features.py` | Logit transform, dummy coding, tier × signal interactions, the events-per-variable ladder |
| `model.py` | `TrustModel` — fit, calibrate, bootstrap, predict, save/load |
| `confidence.py` | Kish n_eff, the five components, the caps and the review floor |
| `evaluate.py` | Metrics, threshold derivation, and the attack-success-rate comparison |
| `dataset.py` | Builds the labelled instance table by running retrieval + detectors, joining ground truth |
| `train.py` | The seven-step training CLI; writes everything in `artifacts/` |
| `scorer.py` | `FusionScorer` / `score_query` — Parts A, B and C wired into one call |
| `test_fusion.py` | Contract tests: does the machinery match the design? |

`artifacts/` holds `band_thresholds.json`, `trust_model.joblib` (+ a readable
`.json` sidecar) and `operating_thresholds.json`. The `.joblib` is a build
product and is git-ignored; the JSON files are not, so a reviewer can read the
fitted thresholds and coefficients without loading a pickle.

---

## Running it

```bash
pip install -r fusion/requirements.txt

python -m fusion.train                 # fit, evaluate, write artifacts/
python -m fusion.test_fusion           # contract tests
python -m fusion.test_fusion --verbose # with intermediate values

python -c "from fusion import score_query"   # inference needs no training run
```

`score_query` degrades rather than failing if training has not been run: the case
taxonomy runs alone, which is a valid configuration and is reported as such in
`result.detail`.

**`train.py` and `dataset.py` read `corpus/ground_truth/`. Nothing else in this
package does, at any point.** `test_fusion.py` asserts that on the parsed AST of
every inference-time module, so the boundary cannot erode quietly.

---

## What these numbers currently mean

Read this before quoting any figure from this package.

The **fusion mechanics are correct and validated**; the **detector inputs are
not yet real**. This environment has no network egress, so all three Level 2
detectors run on fallback backends — pattern heuristics instead of the
prompt-injection classifier, lexical overlap instead of the NLI cross-encoder, a
hashing embedder instead of sentence-transformers. Every accuracy figure the
training run prints is therefore *structural evidence that the layer works*, not
a measurement of how well it detects poisoning.

`train.py` says so at the top of its output and prints a VERDICT block when every
signal's AUC sits within 0.10 of chance, so no fallback number can be quoted as a
result by accident.

Two findings from the current run are worth carrying forward regardless:

**Two signals came out anti-correlated with the label.** On training data
`unsupport` scored AUC 0.381 and `anomaly` 0.466 — both pointing the wrong way.
`train.py` now reports per-signal separation and drops inverted signals before
fitting, rather than letting the model quietly learn a negative coefficient. The
likely cause for `unsupport` is structural rather than a bug: PoisonedRAG's
retrieval segment restates the target query almost verbatim, so a poisoned
document *appears to entail the query better than a genuine one does*. Using the
generated answer as the hypothesis, instead of the query as a stand-in, is the
fix, and that requires generation in the loop.

**The attack-success-rate comparison had to be made fair.** The naive baseline
("any single detector signal ≥ 0.5") blocks 80% of clean documents to catch 29%
of attacks. Compared at operating points, that flatters the baseline, so
`evaluate.py` also reports a matched-false-block-rate comparison: at the
baseline's own 80% block rate, the fusion score reaches ASR 0.000 versus the
baseline's 0.294. That is the honest comparison, and it is labelled as such in
the output.

---

*Design reference: `docs/design/TRUST_RISK_DESIGN.md` — §2 taxonomy, §3 scoring,
§4 confidence, §9 constants.*
