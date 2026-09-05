# Trust & Risk Layer — Core Decision Logic Design

**Project:** Hallucinations in AI-Driven Cybersecurity Systems (Healthcare Sector)
**Team:** Zetabyte — Deloitte Capstone Program 2026, Manipal University Jaipur
**Document:** `docs/design/TRUST_RISK_DESIGN.md`
**Document version:** `design-v1.2`
**Status:** Authoritative. Per project convention, this document is the source of truth
for case definitions, feature encoding, and threshold-derivation procedure. Later work
must not redefine these ad hoc; changes require a version bump and a note in §10.
**Scope:** Design only. No implementation code is specified here beyond schema
definitions (DDL/JSON), which are contracts rather than application logic.

---

## 0. Reader's Orientation

### 0.1 What this document decides

The trust layer sits between retrieval and answer delivery. For each SOC analyst query
it must answer three separate questions, and this document specifies all three plus the
record-keeping that follows them:

| Question | Mechanism | Section |
|---|---|---|
| *What kind of situation is this?* | Case taxonomy (Source Trust Tier × Content Signal Outcome) | §2 |
| *How likely is it that this response is attacker-influenced?* | Composite risk score, fitted logistic regression | §3 |
| *How much should we trust that estimate?* | Confidence measure | §4 |
| *What did the human actually do about it?* | `analyst_decision` audit schema | §5 |

These are deliberately **four separate outputs, not one number**. Collapsing them loses
information the SOC needs: a high-risk/low-confidence case and a high-risk/high-confidence
case demand different human responses, and a case identifier tells an analyst *why*
something fired in a way a scalar never can.

### 0.2 The two-track design and why both tracks exist

The system runs a **rule track** (the taxonomy, §2) and a **statistical track** (the
fitted score, §3) over the same inputs, then reconciles them (§3.9).

This is intentional redundancy, not indecision:

- The **statistical track** is data-driven, calibrated, and will outperform hand-written
  rules on the attack patterns present in our training corpus. It is also opaque, will
  fail silently on attack families it has never seen, and cannot be audited by an analyst
  mid-incident.
- The **rule track** encodes security semantics that the statistical track cannot learn
  from a small corpus — most importantly the inversion in §2.4 (a trusted source behaving
  strangely is *more* alarming, not less) and the Tier-1-conflict failure mode (§2.5,
  case C10), which is not an attack at all and must not be scored as one.

The reconciliation rule is **escalation dominance**: where the two tracks disagree, the
more conservative disposition wins. This guarantees that adding the statistical track can
never make the system *less* safe than the rules alone — a property worth having when the
statistical track is fitted on a corpus we built ourselves and may not represent reality.

### 0.3 Notation and signal conventions

Four detector signals are computed per query, as given:

| Symbol | Signal | Range | Direction |
|---|---|---|---|
| `s_ent` | `entailment_score` — NLI support for the generated claim by retrieved evidence | [0, 1] | **higher = safer** |
| `s_ano` | `anomaly_score` — embedding-cluster outlier distance | [0, ∞) raw | higher = riskier |
| `s_inj` | `injection_probability` — prompt-injection classifier output | [0, 1] | higher = riskier |
| `s_cnf` | `conflict_score` — retrieved evidence vs. LLM parametric knowledge | [0, 1] | higher = riskier |

`s_ent` runs opposite to the others. To make every threshold statement in this document
read the same direction, we define the **risk-oriented unsupport signal** once and use it
everywhere thereafter:

```
s_uns = 1 - s_ent        # "unsupport": higher = riskier
```

All four risk-oriented signals are therefore `{s_uns, s_ano, s_inj, s_cnf}`, and every
"above threshold" statement below means "riskier".

### 0.4 One derived signal we must add: intra-evidence conflict

The four given signals do not contain a doc-vs-doc measure. `s_cnf` compares evidence
against the *model's* knowledge, not evidence against *other evidence*. But case C10
(two Tier-1 sources contradicting each other) is defined entirely by doc-vs-doc
disagreement, and the confidence measure in §4 needs the same quantity.

We therefore define a **derived** quantity — not a fifth detector, and no new model:

```
d_conflict(i, j) = P_contradiction(doc_i, doc_j)      # same NLI model as s_ent, applied pairwise
d_conflict_max   = max over all retrieved pairs (i, j), i ≠ j
```

**Justification for the addition:** it costs no new dependency (the NLI/entailment model
is already in the stack for `s_ent`), it is required by an explicitly requested case, and
it is reused by the confidence measure, so it earns its place twice. Cost is O(k²) NLI
calls per query at k ≤ 8, which is bounded and acceptable.

For k documents, k(k−1)/2 pairs; at k=5 that is 10 additional NLI calls per query. If
this proves too slow in evaluation, restrict pairs to documents that the answer actually
cites (§2.2), which is typically 2–3 documents.

### 0.5 Level of analysis: document vs. response

Signals are computed at different granularities, and conflating them causes real bugs.
We fix the convention now:

- `s_ano` and `s_inj` are **per-document** quantities. Each retrieved document has its own.
- `s_uns` and `s_cnf` are **per-response** quantities. They concern the generated claim.
- `d_conflict_max` is a **per-set** quantity.

Two dispositions are produced per query and both are logged:

1. **Document disposition** — per retrieved document; drives quarantine and corpus hygiene.
2. **Response disposition** — for the answer as a whole; drives what the analyst sees.

Where the taxonomy needs a single scalar for a per-document signal, we use the **maximum
over documents that the answer actually cites** (see §2.2), not the mean. Mean is wrong
here: PoisonedRAG's entire mechanism is that *one* crafted document among several clean
ones steers the answer. Averaging that document against four clean neighbours is exactly
how the attack evades detection.

```
s_ano* = max over cited docs of s_ano(doc)
s_inj* = max over cited docs of s_inj(doc)
```

Starred quantities are used in the taxonomy and in feature construction.

---

## 1. Source Trust Tiers

| Tier | Definition | Examples | Assumed prior of adversarial content |
|---|---|---|---|
| **Tier 1** | Verified, authoritative, cryptographically or institutionally attested | CISA advisories, MITRE ATT&CK / CVE, HHS 405(d), vendor PSIRT bulletins | Very low |
| **Tier 2** | Trusted but open — reputable, moderated, but community-writable or non-attested | Curated OSINT feeds, established security vendor blogs, moderated ISAC/ISAO sharing | Low–moderate |
| **Tier 3** | Unverified or unknown provenance | Scraped pastes, forum posts, unattributed threat reports, uploaded analyst notes | Elevated |

Tier is assigned at ingestion time by the provenance tagger (Level 1) and stored with the
document. It is a property of the **source**, not of the content, and is never modified by
detector output — otherwise the tiers would stop being an independent axis and the whole
cross-tabulation in §2 would collapse.

### 1.1 Tier is a prior, not a verdict

The tier expresses our prior belief before we look at the content. The detectors express
the evidence. The taxonomy is the posterior. Stating this explicitly matters because it is
what makes §2.4 defensible rather than counter-intuitive.

---

## 2. Task 1 — Case Taxonomy

### 2.1 Deriving the Content Signal Outcome

The taxonomy's second axis, **Content Signal Outcome ∈ {Clean, Suspicious, Malicious}**,
is derived from the risk-oriented signals by band thresholds.

**Thresholds are not hand-picked.** For each signal `s`, thresholds are set as quantiles
of that signal's distribution over the **clean-only** portion of the calibration split
(§3.6). This makes the bands mean something concrete and stable across embedding models
and detector versions:

```
θ_s^sus = Q_0.95( s over clean calibration documents )   # top 5% of normal behaviour
θ_s^mal = Q_0.99( s over clean calibration documents )   # top 1% of normal behaviour
```

Interpretation: "Suspicious" means *this looks like the strangest 5% of legitimate
traffic*. "Malicious" means *this looks like the strangest 1%*. A false-positive rate is
therefore designed in and known, rather than discovered after deployment.

`s_ano` is normalised before thresholding (§3.2) so these quantiles are comparable across
queries with different retrieval-set geometry.

**Band assignment rule** (evaluated in order, first match wins):

```
MALICIOUS  if  s_inj* ≥ θ_inj^mal
           or  at least 2 of {s_uns, s_ano*, s_inj*, s_cnf} ≥ their θ^mal
           or  (at least 1 signal ≥ its θ^mal  AND  at least 2 others ≥ their θ^sus)

SUSPICIOUS if  at least 1 of the four ≥ its θ^sus

CLEAN      otherwise
```

**Why `s_inj` alone is sufficient for MALICIOUS while the others are not.** Anomalous
embeddings, unsupported claims and knowledge conflicts all have benign explanations — a
genuinely novel threat, a poorly-written advisory, a model whose training data predates
the CVE. Prompt-injection text has no benign explanation in a threat-intelligence corpus.
Its presence is direct evidence of *intent*, not of unusual statistics. The other three
signals therefore require corroboration; injection does not.

### 2.2 Determining the governing tier

A retrieval set is usually mixed-tier. The taxonomy needs one tier per response.

```
cited_docs      = documents the generation step actually attributed the claim to
                  (if attribution is unavailable, fall back to the top-3 by similarity)
attribution_w_i = softmax over cited_docs of retrieval similarity
tier_governing  = tier of argmax_i(attribution_w_i)
tier_min        = worst (numerically highest) tier present in the full retrieval set
```

`tier_governing` drives the response disposition. `tier_min` is logged and drives
document-level dispositioning, so that a Tier-3 document with bad signals is quarantined
even when the answer was actually built from Tier-1 evidence.

### 2.3 The eleven cases

Priority scale: **P0 highest → P5 lowest.** Actions are defined in §2.6.

| ID | Case name | Tier | Outcome | Trigger (precise) | Priority | Action |
|---|---|---|---|---|---|---|
| **C1** | Authoritative Confirmation | T1 | Clean | `tier_governing=1` and band=CLEAN and `d_conflict_max < θ_dcf^sus` | P5 | **Accept** |
| **C2** | Community Corroboration | T2 | Clean | `tier_governing=2` and band=CLEAN | P4 | **Accept** (provenance shown) |
| **C3** | Unverified but Unremarkable | T3 | Clean | `tier_governing=3` and band=CLEAN | P3 | **Review** (lightweight) |
| **C4** | **Trusted-Source Anomaly** | T1 | Suspicious | `tier_governing=1` and band=SUSPICIOUS | **P1** | **Escalate** |
| **C5** | **Authoritative Channel Compromise** | T1 | Malicious | `tier_governing=1` and band=MALICIOUS | **P0** | **Escalate** (+ Reject answer) |
| **C6** | Open-Feed Irregularity | T2 | Suspicious | `tier_governing=2` and band=SUSPICIOUS | P3 | **Review** |
| **C7** | Open-Feed Poisoning | T2 | Malicious | `tier_governing=2` and band=MALICIOUS | **P2** | **Reject** + Escalate (source-level) |
| **C8** | Unverified Irregularity | T3 | Suspicious | `tier_governing=3` and band=SUSPICIOUS | P3 | **Reject** (answer), Review (document) |
| **C9** | Expected-Path Poisoning | T3 | Malicious | `tier_governing=3` and band=MALICIOUS | P2 | **Reject** + quarantine document |
| **C10** | **Authoritative Divergence** | T1 ⟂ T1 | — | ≥2 Tier-1 docs cited, `d_conflict_max ≥ θ_dcf^mal` between two Tier-1 docs, **and** `s_inj* < θ_inj^sus` **and** `s_ano* < θ_ano^sus` | P2 | **Review** (dual-evidence presentation) |
| **C11** | **Isolated Retrieval Outlier** | any | — | exactly one document with similarity ≥ Q_0.99 of the query's similarity distribution, **and** `s_ano ≥ θ_ano^mal` for that same document, **and** `n_eff ≤ 2` (§4.3), **and** no corroborating document entails the claim | **P1** | **Escalate** |

### 2.4 Why C4 and C5 outrank Tier-3 malicious cases

This is the most counter-intuitive decision in the taxonomy and the one most likely to be
challenged, so the argument is set out fully.

**The information-theoretic argument.** The tier is a prior (§1.1). An anomalous signal is
*surprising* in proportion to how unlikely it was under that prior. The surprise carried by
observing an anomaly `A` from a source of tier `t` is `−log P(A | t)`. Because
`P(A | T1) ≪ P(A | T3)` by construction of the tiers, the same observed anomaly carries
substantially more information when it comes from Tier 1. A Tier-3 document behaving badly
tells us almost nothing we did not already assume. A Tier-1 document behaving badly tells us
that one of our foundational assumptions is wrong.

**The blast-radius argument.** Tier-1 sources are, by design, trusted by everything
downstream — this pipeline, other tooling, and the analysts themselves. A compromise, spoof,
or supply-chain manipulation of a Tier-1 channel contaminates every consumer, not just the
query in front of us. Tier-3 poisoning is contained: it is the attack path we already
defend against, and rejecting the answer largely resolves it.

**The hypothesis-set argument.** For a Tier-3 malicious document the leading hypothesis is
"someone put junk on the internet" — routine. For a Tier-1 malicious document the leading
hypotheses are all serious: the source was compromised; our fetch path was
man-in-the-middled; our provenance tagger mislabelled a document; or an insider modified the
corpus. **Every one of these is a finding about our own system, not about this query.**
That is precisely the distinction between Reject and Escalate (§2.6).

**The consequence.** C4 (merely *suspicious*, from Tier 1) is priority P1 — higher than C9
(outright *malicious*, from Tier 3, P2). The taxonomy deliberately ranks a weaker signal from
a stronger source above a stronger signal from a weaker source. Anyone implementing this must
not "fix" that as though it were a mistake.

**Guarding against the obvious objection.** This inversion generates false positives on
legitimately unusual Tier-1 content — a genuinely novel CISA advisory will look anomalous
because it *is* novel. Three mitigations:

1. C4's action is **Escalate**, which routes to the threat-intel owner for source
   verification, not to the analyst as an answer-blocking alarm. The analyst still receives
   the answer, marked.
2. `θ_ano^sus` is calibrated on clean Tier-1 documents specifically (§3.6), so "novel but
   legitimate" advisories are part of the reference distribution rather than outliers to it.
3. The `override_reason_code` vocabulary (§5.5) includes
   `FALSE_POSITIVE_BENIGN_ANOMALY` precisely so this failure mode is measurable rather than
   argued about.

### 2.5 Why C10 is a distinct case and not poisoning

Two Tier-1 sources contradicting each other is a **different failure mode** with a different
correct response, and merging it into the poisoning cases would be a design error.

**Signature.** Contradiction is high (`d_conflict_max ≥ θ_dcf^mal`) while the attack
indicators are quiet (`s_inj*` and `s_ano*` both below their suspicious thresholds).
Poisoning that survives to Tier 1 would be expected to leave at least one attack artefact;
pure disagreement leaves none. The trigger in §2.3 encodes exactly this: high contradiction
**with** low injection **and** low anomaly.

**Leading benign explanations**, in rough order of likelihood:

- **Temporal staleness** — a CVSS score revised, an advisory superseded, an IOC de-listed.
  Both documents were correct when written.
- **Scope difference** — one advisory covers a product version or deployment configuration
  the other does not.
- **Genuine analytic disagreement** — attribution and threat-actor naming legitimately differ
  between authoritative bodies.

**Required response.** The system must **never silently pick a winner.** Auto-selecting one
Tier-1 source over another is unjustifiable — we have no basis for the choice, and doing so
would hide from the analyst the single most decision-relevant fact available, which is that
the authorities disagree. The response is therefore a **dual-evidence presentation**: both
claims, both sources, both publication dates, the specific contradicting spans, and an
explicit "authoritative sources disagree" banner. Priority P2 reflects operational urgency
(an analyst may be about to act on stale guidance), not attack suspicion.

**Precedence interaction.** If one of the two Tier-1 documents *is* anomalous, the trigger's
`s_ano* < θ_ano^sus` clause fails, C10 does not fire, and C4/C5 catch it instead — correctly,
because that situation is a possible compromise wearing the costume of a disagreement.

### 2.6 Action semantics

The four actions are frequently confused; these definitions are binding.

| Action | Answer returned? | Who is notified | Purpose |
|---|---|---|---|
| **Accept** | Yes, automatically | No one | Normal operation. Provenance panel always attached. |
| **Review** | Yes, marked *unverified* | Analyst queue | The answer may be fine but must not be relied upon for a downstream action until a human confirms. |
| **Reject** | No — replaced by "insufficient trustworthy evidence" + full evidence trail | Analyst queue | **Protects this answer.** The query is the unit of concern. |
| **Escalate** | No (or marked, per case) | Threat-intel / corpus owner, as a security event | **Protects the system.** The *pipeline or a source* is the unit of concern; this query is merely how we noticed. |

**Reject vs. Escalate is the axis the whole taxonomy turns on.** Reject says *this answer is
untrustworthy*. Escalate says *our trust infrastructure may be untrustworthy*. C4 and C5
Escalate because a Tier-1 anomaly is evidence about the source, which outlives the query.
C9 merely Rejects because a bad Tier-3 document is evidence about that document, and
quarantining it closes the matter.

Rejection never deletes a document. Following P1's (TrustRAG) explicit caution against naive
deletion, flagged documents are **quarantined** — flagged, excluded from retrieval, retained
for review and for the evaluation corpus. Deletion would destroy the evidence needed to
determine whether the flag was correct.

### 2.7 Case precedence

Cases can co-fire. Assignment is deterministic: evaluate in this order, first match wins.

```
1.  C5   Tier-1 malicious                (P0)
2.  C4   Tier-1 suspicious               (P1)
3.  C11  Isolated retrieval outlier      (P1)
4.  C10  Authoritative divergence        (P2)
5.  C7   Tier-2 malicious                (P2)
6.  C9   Tier-3 malicious                (P2)
7.  C6   Tier-2 suspicious               (P3)
8.  C8   Tier-3 suspicious               (P3)
9.  C3   Tier-3 clean                    (P3)
10. C2   Tier-2 clean                    (P4)
11. C1   Tier-1 clean                    (P5)
```

Ordering rationale: Tier-1 compromise cases first because they are the most consequential and
the least self-evident; C11 next because it is the canonical PoisonedRAG signature and must
not be masked by a mild tier-based case; C10 before the Tier-2/3 attack cases because
misreading authoritative divergence as poisoning produces a wrong analyst response.

All co-firing case IDs are recorded in `all_matched_cases` even though only the winner drives
the action — the secondary matches are diagnostic information the analyst wants.

### 2.8 Coverage check

The nine grid cells (3 tiers × 3 outcomes) are C1–C9. C10 and C11 are cross-cutting cases
defined on set-level structure rather than the grid. Every (tier, outcome) pair therefore has
exactly one owning case, and the precedence order in §2.7 makes assignment total and
deterministic.

---

### 2.9 Headline classification — GREEN / ORANGE / RED

The four actions of §2.6 are operationally precise but are not what an analyst reads first.
This section defines a **three-state headline band** derived from the final action and the
governing tier. It is a presentation layer over §2.6, not a replacement: the action still
determines what the system *does*; the band determines what the analyst *sees at a glance*.

The band is **derived, never stored as an independent judgement.** No code path sets it
directly, and it cannot disagree with the action it was derived from.

#### 2.9.1 The rule

Evaluated in this order, first match wins:

```
RED     if final_action in (Reject, Escalate)
          sub-type: tier_governing == 1  ->  TRUSTED_SOURCE_COMPROMISE
                    otherwise            ->  ATTACK_DETECTED

ORANGE  if final_action == Review
        or tier_governing != 1                    (§2.9.3 — the tier overrides)

GREEN   if final_action == Accept and tier_governing == 1

ORANGE  otherwise                                 (§2.9.4 — the fail-safe default)
```

| Band | Label | Meaning |
|---|---|---|
| **GREEN** | Good to Go | Verified authoritative source, clean signals, automatic Accept. Normal operation. |
| **ORANGE** | Mid-Suspicious, Review Recommended | Answer returned marked *unverified* and queued for an analyst. |
| **RED** — `ATTACK_DETECTED` | Reject / Escalate — Attack Detected | Malicious or irregular content from a source we had not already vouched for. **The document is the unit of concern.** |
| **RED** — `TRUSTED_SOURCE_COMPROMISE` | Reject / Escalate — Trusted Source Compromise Suspected | A source we had already verified is behaving anomalously. **The source is the unit of concern.** |

#### 2.9.2 Why RED is sub-classified

The sub-type carries the Reject/Escalate distinction of §2.6 into the headline. A malicious
document from an unverified blog and an anomaly in a CISA advisory can produce the same action
and the same risk score while requiring completely different responses: the first is closed by
quarantining a document; the second is a finding about our own trust infrastructure that
outlives the query. Collapsing both into an undifferentiated RED would discard the most
decision-relevant fact available — the same argument that motivates C4 outranking C9 (§2.4).

The sub-type keys on `tier_governing == 1` rather than on a fixed case list, so it tracks the
taxonomy automatically. C4 and C5 are its principal members; C11 joins them whenever the
isolated outlier is itself carried by a Tier-1 source, which is the correct reading of that
situation.

#### 2.9.3 The tier overrides — GREEN is affirmative, not residual

Two constraints narrow GREEN beyond the action alone. Both are one-directional: they can only
move a response *away* from GREEN, never toward it.

**Tier 3 can never be GREEN.** An unverified source with quiet signals is unremarkable, not
trustworthy. The absence of evidence against a document is not evidence for it, and Tier 3 is
precisely the population where there is no provenance to fall back on.

**Tier 2 can never be GREEN.** A moderated but community-writable feed is trusted enough to
retrieve from, not trusted enough to return unexamined. This demotes C2 (Community
Corroboration) from its Accept action to an ORANGE headline — a deliberate acceptance of
review load in exchange for a narrower automatic-pass surface.

Together these reduce GREEN to a single case, **C1**. The redundancy is intentional and both
rules are enforced and tested independently, because they encode different commitments: the
Tier-3 rule is a property of unverified provenance; the Tier-2 rule is a policy choice about
review capacity. Either could be revisited without disturbing the other.

*Coverage check at design-v1.2.* The Tier-3 governing cases are **C3, C8 and C9**. Under the
action rule alone they map to ORANGE, RED and RED respectively — **none reaches GREEN**, so
the Tier-3 override is presently a no-op. It is retained as an enforced invariant rather than
a comment because only two cases (C1, C2) route to Accept at all, and a future case or a
relaxed trigger is exactly how the guarantee would be lost silently. A test asserts it
directly against the case table rather than against a hard-coded list.

#### 2.9.4 Fail-safe

**GREEN is reachable only by an affirmative conjunction** — an explicit Accept action *and* a
governing tier of 1. Every other path terminates at ORANGE, including an unrecognised action,
an unknown or missing governing tier, and a response the classifier could not resolve. There
is no `else: GREEN` branch anywhere in the implementation.

This is the same structural commitment as escalation dominance (§3.9): a degraded or
incompletely-specified input may cost the system precision, but it may never cost it safety.
An implementation that returns GREEN when it does not know what else to return has inverted
the guarantee.

---

## 3. Task 2 — Data-Driven Composite Risk Score

### 3.1 Model and target

**Model.** Regularised binary logistic regression.

**Target.** `y = 1` if the response was materially influenced by at least one poisoned
document, `y = 0` otherwise. Ground truth is available because we construct the corpus
(§3.5). "Materially influenced" means the poisoned document appears in `cited_docs` **and**
the generated answer matches the attacker's intended answer — a poisoned document that was
retrieved but did not change the answer is labelled `y = 0` and flagged
`poison_present_but_ineffective`, because a detector that fires on harmless retrievals is
producing false alarms by our own operational definition.

**Why logistic regression rather than something stronger.** Three reasons, in order of
weight: (i) the corpus is small, and a linear model in an engineered feature space is the
right capacity for a few hundred labelled instances; (ii) coefficients are directly
inspectable, which matters when an analyst asks *why* the system flagged something and when a
mentor asks whether the model learned anything sensible; (iii) it emits calibrated
probabilities natively, which §4 requires. Tree ensembles are a documented ablation, not the
primary model.

### 3.2 Feature encoding — exact specification

**Step 1 — Bounded signals: logit transform.**
`s_uns`, `s_inj`, `s_cnf` are probabilities on [0, 1] and are heavily mass-concentrated near
the endpoints (an injection classifier outputs 0.001 or 0.98, rarely 0.5). A linear model on
raw probabilities wastes almost all of its resolution on a region that contains no data.
Apply the logit with clipping:

```
ε = 1e-3
x_uns = log( clip(s_uns, ε, 1-ε) / (1 - clip(s_uns, ε, 1-ε)) )
x_inj = log( clip(s_inj*, ε, 1-ε) / (1 - clip(s_inj*, ε, 1-ε)) )
x_cnf = log( clip(s_cnf, ε, 1-ε) / (1 - clip(s_cnf, ε, 1-ε)) )
```

Clipping at 1e-3 bounds each transformed feature to ±6.9, which prevents a single saturated
detector output from dominating the linear predictor.

**Step 2 — Unbounded signal: per-query robust normalisation.**
`s_ano` is a raw distance whose scale depends on the embedding model, the corpus, and `k`.
Normalise it *within the query's own retrieval set*, which makes it scale-free and
model-agnostic:

```
D          = { s_ano(doc) : doc in retrieval set }
x_ano_doc  = ( s_ano(doc) - median(D) ) / ( 1.4826 * MAD(D) + 1e-6 )
x_ano      = max over cited docs of x_ano_doc
```

Median/MAD rather than mean/SD because the quantity we are detecting *is* the outlier — a
mean-based normaliser is dragged by the very document it is meant to expose. The 1.4826
factor makes MAD a consistent estimator of σ under normality, so `x_ano` reads as a robust
z-score.

**Edge case, and it matters:** when `k = 1` there is no dispersion, `MAD(D) = 0`, and
`x_ano` is undefined. Set `x_ano = 0` and set the indicator `is_singleton = 1`. A singleton
retrieval carries no anomaly evidence at all, and pretending otherwise (by, say, comparing
against a global corpus mean) manufactures a signal that is not there. The confidence
measure (§4) is what handles the singleton case, and it caps confidence hard.

**Step 3 — Source tier: dummy coding, NOT ordinal.**

```
is_tier1 = 1 if tier_governing == 1 else 0
is_tier3 = 1 if tier_governing == 3 else 0
# Tier 2 is the reference level (both dummies = 0)
```

**This is the single most important encoding decision in the document.** Encoding tier as the
integer 1/2/3 would force the model to assume risk moves monotonically and linearly with
tier. Our taxonomy asserts the opposite (§2.4): the *same* anomaly is more alarming from
Tier 1 than from Tier 3. An ordinal encoding makes that relationship literally unrepresentable
— the model would be structurally incapable of learning the thing we built it to learn.
Tier 2 is the reference level because it is the middle and modal category, so the `is_tier1`
and `is_tier3` coefficients read as interpretable deviations from the common case.

**Step 4 — Tier × signal interactions.**
Dummies alone shift the intercept per tier. They cannot change the *slope* of a signal per
tier — which is exactly what §2.4 requires. Without interaction terms the model can say
"Tier 1 is safer overall" but never "an anomaly means more when it comes from Tier 1".

```
is_tier1 × {x_uns, x_ano, x_inj, x_cnf}      (4 terms)
is_tier3 × {x_uns, x_ano, x_inj, x_cnf}      (4 terms)
```

Expected sign, and this doubles as a sanity check on the fit: the coefficient on
`is_tier1 × x_ano` should be **positive**, meaning anomaly is penalised *more* steeply for
Tier-1 sources. If the fitted model produces a negative coefficient there, either the corpus
does not contain the Tier-1-compromise scenario in sufficient number, or the labelling is
wrong. Do not ship a model that disagrees with the taxonomy on this point without
understanding why.

**Step 5 — Standardisation.**
Z-score all continuous features. **Fit the scaler on the training fold only**, persist it,
and apply the stored parameters to validation and test. Fitting the scaler on the full
dataset before splitting is the most common leakage bug in small-corpus work and would
invalidate every number we report.

**Full feature vector (14 features + intercept):**

| # | Feature | Type |
|---|---|---|
| 1 | `x_uns` | continuous |
| 2 | `x_ano` | continuous |
| 3 | `x_inj` | continuous |
| 4 | `x_cnf` | continuous |
| 5 | `is_tier1` | binary |
| 6 | `is_tier3` | binary |
| 7–10 | `is_tier1 × {x_uns, x_ano, x_inj, x_cnf}` | continuous |
| 11–14 | `is_tier3 × {x_uns, x_ano, x_inj, x_cnf}` | continuous |

`is_singleton` and `d_conflict_max` are **deliberately excluded from the risk model** and
routed to the confidence measure (§4) and the taxonomy (C10) respectively. Rationale: a
singleton retrieval is an *uncertainty* fact, not a *risk* fact, and Tier-1 divergence is
explicitly not an attack — feeding either into the risk score would teach the model to
score benign situations as attacks.

### 3.3 The events-per-variable constraint and the feature ladder

Fourteen features is a lot for a capstone corpus. The standard guidance for logistic
regression is roughly 10–15 events (minority-class instances) per predictor; 14 features
therefore implies **≈150–200 poisoned instances** before the full model is statistically
defensible.

Rather than discover this problem after building the corpus, fix the rule now. Let
`n_pos` = number of poisoned instances in the training split:

| `n_pos` | Feature set | Count |
|---|---|---|
| ≥ 150 | Full model (all 14) | 14 |
| 60 – 149 | Base 6 + `is_tier1 × {x_ano, x_cnf}` only | 8 |
| < 60 | Base 6 only; report as underpowered and treat the taxonomy as the primary control | 6 |

The reduced interaction set keeps `is_tier1 × x_ano` and `is_tier1 × x_cnf` because those two
carry the §2.4 inversion; the other six interactions are refinements we can afford to lose.

**Corpus target:** ≥ 200 poisoned and ≥ 600 clean query instances, which supports the full
model. This is now a requirement on corpus construction, not an aspiration — record it in the
corpus work plan.

### 3.4 Regularisation

L2 (ridge) penalty. `C` swept over `{0.01, 0.03, 0.1, 0.3, 1, 3, 10}` on a log grid, selected
by inner cross-validation (§3.6). L2 rather than L1 because the interaction terms are
correlated with their parent features by construction, and L1 selects arbitrarily among
correlated predictors — which would make the coefficients unstable across folds and destroy
the interpretability that motivated the model choice. Elastic-net is a documented ablation.

Solver: `lbfgs`. `max_iter = 2000` to ensure convergence on standardised features.

### 3.5 Corpus construction requirements this design imposes

Stated here because they constrain §3.6 and must be honoured during corpus work:

- Every poisoned document carries `poison_family_id` — the attack template/strategy it was
  generated from (e.g. `corpus_injection_ioc_flip`, `authority_spoof_cisa`,
  `semantic_drift_cve_severity`).
- Every document carries `source_doc_id` and `source_tier`.
- Every query instance carries `query_topic_id` so that paraphrases of the same underlying
  question stay together.
- **Poisoned documents must be constructed at all three tiers**, including Tier 1. If the
  corpus contains no Tier-1 poisoned instances, the `is_tier1 × ·` interaction coefficients
  are unidentifiable and cases C4/C5 can never be validated. This is easy to overlook and
  fatal to the central claim.

**Defensive-research framing.** Poisoned document construction follows the published
PoisonedRAG methodology (P5, USENIX Security 2025) and exists solely to build a labelled
benchmark for evaluating our own defensive layer. The corpus is synthetic, internal, never
deployed to any live retrieval system, and never directed at any third-party system. This
framing must be restated in the corpus module's own documentation and in the generator's
header, not left implicit here.

### 3.6 Split strategy for a small corpus

**The failure to avoid.** Poisoned documents are generated from a small number of templates.
If a template's instances land in both train and test, the model memorises the template's
surface statistics and every metric is inflated — sometimes dramatically. Random
instance-level splitting is therefore not acceptable here.

**Grouping.** Group key = `poison_family_id` for poisoned instances, `source_doc_id` for
clean instances, with `query_topic_id` as a secondary constraint so paraphrases of one
question never straddle the split. All instances sharing a group go to the same side of
every split.

**Three-stage protocol.**

1. **Locked test set — 20%.** One `StratifiedGroupKFold`-derived holdout, drawn once with a
   fixed seed (`RANDOM_SEED = 20260915`), written to `eval/splits/test_ids.json`, and then
   **not looked at** until the final evaluation. Every threshold, hyperparameter and feature
   decision is made without it. It is evaluated once; if we evaluate it more than once we
   report that we did.

2. **Model selection — repeated stratified group 5-fold CV on the remaining 80%.**
   `RepeatedStratifiedGroupKFold`, 5 folds × 5 repeats = 25 fits. Repetition matters at this
   sample size: a single 5-fold estimate on ~150 positives has a standard error large enough
   to select the wrong hyperparameter on noise alone. We report mean ± SD across repeats,
   never a single fold's number.

3. **Honest performance estimate — nested CV.** Outer 5-fold group CV for the estimate; inner
   5-fold group CV inside each outer training fold for `C` and threshold selection. Selecting
   hyperparameters and reporting performance on the same folds is optimistically biased, and
   nested CV is the standard correction. The nested estimate is the one quoted in the report;
   the locked test set is the final confirmation that nothing went wrong.

**Calibration split.** The clean-only quantiles that define `θ_s^sus` and `θ_s^mal` (§2.1) are
computed on the *training* portion of each fold only, never on validation or test, for the
same leakage reason as the scaler.

**Secondary evaluation — Leave-One-Attack-Family-Out (LOAFO).** Hold out one entire
`poison_family_id` at a time, train on the rest, evaluate on the held-out family. This
measures the thing a security reviewer will actually ask about: *does the detector generalise
to an attack strategy it has never seen?* Expect LOAFO scores to be materially lower than
grouped-CV scores. **Report both.** The gap between them is an honest measurement of how much
of our performance is pattern-matching on known attacks versus genuine detection, and it is
one of the more scientifically interesting numbers this project can produce.

### 3.7 Metric selection

**Not accuracy.** With a skewed corpus, a model that predicts "clean" for everything scores
well on accuracy and is worthless. Accuracy is not reported except inside a full confusion
matrix.

**Cost assumption, stated explicitly so it can be challenged.** A missed attack (FN) admits a
poisoned conclusion into a healthcare SOC workflow, with downstream clinical and operational
consequences. A false alarm (FP) costs analyst attention — real, but recoverable. We assume:

```
C_FN / C_FP = 10
```

This ratio is an assumption, not a measurement. It is recorded in §9 as a tunable constant
and should be revisited once §5's `time_to_decision_ms` gives us an empirical estimate of
what a false alarm actually costs in analyst-minutes.

**Model selection metric (threshold-free): PR-AUC (average precision).** Chosen over ROC-AUC
because ROC-AUC's false-positive-rate axis is normalised by the large negative class and
therefore looks flattering under imbalance; precision-recall keeps the minority class in the
denominator where it belongs. ROC-AUC is still reported for comparability with the literature.

**Headline scalar: F-beta with β = 3.** F_β weights recall β² times more heavily than
precision, and the principled choice is `β = sqrt(C_FN / C_FP) = sqrt(10) ≈ 3.16`, rounded to
3 for reporting. This makes the headline number a direct consequence of the stated cost
assumption rather than an arbitrary choice.

**Operating-point metric: recall at a fixed alert budget.** Maximising recall alone is
degenerate (flag everything, recall = 1.0). The operationally meaningful question is *how much
can we catch within the alert volume a SOC can absorb*:

```
primary operating metric = max recall subject to FPR ≤ 0.10
```

**Full reporting set** (all of these, every time):

| Metric | Why it is reported |
|---|---|
| PR-AUC (average precision) | Primary model-selection metric |
| Recall @ FPR ≤ 0.10 | Primary operating metric |
| F₃ | Headline cost-weighted scalar |
| Precision, Recall, F1 | Comparability |
| ROC-AUC | Comparability with the literature |
| Brier score + reliability curve | Calibration — §4 depends on the probabilities being meaningful |
| Expected cost `10·FN + 1·FP` | Direct decision-theoretic quantity |
| Full confusion matrix | Everything else is derived from it |
| Per-case recall (C4, C5, C10, C11) | A good aggregate can hide total failure on the cases we care most about |

The last row deserves emphasis. Cases C4, C5 and C11 are rare by construction and could each
be missed entirely without moving the aggregate metrics. Per-case recall is what stops that
from going unnoticed.

### 3.8 Class imbalance

**First: treat imbalance as a design variable, not a fact of nature.** We construct the
corpus, so the training-time class ratio is our choice. Target ≈ 25% poisoned (§3.3's 200/800
target), which is enough signal to fit 14 features without heroic reweighting.

**Second: cost-sensitive weighting, not resampling.**

```
class_weight = {0: 1.0, 1: 10.0}      # equal to C_FN / C_FP
```

Explicit cost weights rather than `class_weight='balanced'` (which uses inverse frequency) —
because the weight *should* encode our stated decision cost, not an artefact of how many
poisoned documents we happened to write. Inverse-frequency weighting silently makes the
corpus composition into a policy decision. Report `'balanced'` as an ablation.

**Third: do not use SMOTE as the default.** In a 14-dimensional engineered feature space with
a few hundred positives, interpolating between minority points creates instances that satisfy
no real attack's geometry — particularly across the interaction terms, where a synthetic point
can have `is_tier1 = 0.5`, which is meaningless. Worse, SMOTE applied before splitting leaks
test information into training through the interpolation neighbourhoods. If evaluated at all,
it must sit inside an `imblearn.Pipeline` so it is refit within each training fold only, and
it is reported as an ablation, never as the primary configuration.

**Fourth, and most important operationally: correct for deployment prevalence.** Our corpus
is ~25% poisoned. Real SOC traffic is perhaps 1–5%. A detector with 90% precision at 25%
prevalence can have well under 20% precision at 2% prevalence — the base-rate problem that
makes real alerting systems unusable. Two obligations follow:

1. **Report prevalence-corrected precision** alongside raw precision, at π = 0.05 and
   π = 0.01, computed from the fold's sensitivity and specificity:
   ```
   precision(π) = (TPR · π) / (TPR · π + FPR · (1 − π))
   ```
2. **Prior-correct the score before thresholding in deployment.** Weighted fitting shifts the
   intercept; shifting from training prevalence π_t to deployment prevalence π_d is an
   intercept adjustment:
   ```
   logit_deploy = logit_train + ln( (π_d / (1 − π_d)) · ((1 − π_t) / π_t) )
   ```
   Store both the raw and prior-corrected score in the audit log so this correction is
   auditable rather than buried.

**Calibration.** After weighted fitting the raw probabilities are distorted by design. Fit a
calibrator (Platt scaling; isotonic only if `n_pos ≥ 200`, as isotonic overfits below that) on
held-out inner folds via `CalibratedClassifierCV`. §4 requires calibrated probabilities — an
uncalibrated score cannot support a meaningful uncertainty interval.

### 3.9 From score to action, and reconciliation with the taxonomy

**Two thresholds** partition the calibrated score into three bands, both derived from the
validation folds rather than chosen:

```
τ_review = the lowest threshold at which recall ≥ 0.95 on validation folds
           (catch nearly everything; the cost is human review, which is what Review means)
τ_reject = the lowest threshold at which precision ≥ 0.90 on validation folds
           (only suppress an answer automatically when we are confident)
```

If `τ_review ≥ τ_reject` the bands are inconsistent, which means the model is too weak to
support automated rejection at these tolerances. **The correct response is to disable the
auto-Reject band and route everything above `τ_review` to Review**, not to loosen the
precision requirement. Record which regime is in effect in `threshold_set_version`.

```
score < τ_review              → Accept
τ_review ≤ score < τ_reject   → Review
score ≥ τ_reject              → Reject
```

**Reconciliation (escalation dominance).** The rule track (§2) and the statistical track each
propose an action. The final disposition is the more conservative of the two, on the ordering
`Accept < Review < Reject < Escalate`.

- Only the taxonomy can produce **Escalate** — Escalate is a claim about the *system*, which
  requires the semantic structure of a case, not a scalar.
- The score can promote a taxonomy-Accept to Review or Reject when the fitted model sees a
  pattern the rules miss.
- The taxonomy can promote a low score to Escalate when a Tier-1 anomaly fires.

Both proposed actions and the final disposition are logged separately (§5.2). **Their
disagreement rate is a headline evaluation result**, not an inconvenience: it tells us how much
each track contributes and where the rules or the model need work.

---

## 4. Task 3 — Confidence Measure

### 4.1 What confidence is, and what it is not

**Risk** answers *how likely is it that this response is attacker-influenced?*
**Confidence** answers *how much should we trust that risk estimate?*

These are orthogonal. A risk score of 0.85 computed from five agreeing documents across three
independent sources, with all four detectors pointing the same way, is a finding. A risk score
of 0.85 computed from one document, with detectors contradicting each other, is a guess that
happens to be numerically identical. Reporting them as the same number would be a
misrepresentation, and it is exactly the misrepresentation a single-scalar design commits.

Confidence `∈ [0, 1]` is reported alongside the risk score, never folded into it.

### 4.2 Components

Five components, each on [0, 1], each measuring a distinct way our estimate can be shaky.

---

**(1) Evidence volume — `C_vol`**

More evidence, with diminishing returns:

```
C_vol = 1 − exp( − n_eff / κ ),    κ = 2.0
```

`n_eff` (§4.3) is the *effective* number of independent documents, not the raw count.
With κ = 2: n_eff=1 → 0.39, n_eff=2 → 0.63, n_eff=3 → 0.78, n_eff=5 → 0.92, n_eff=8 → 0.98.
Saturating rather than linear because the tenth corroborating document adds far less than the
second, and a linear form would let volume dominate the composite.

---

**(2) Evidence agreement — `C_agr`**

Volume without agreement is not confidence. Five documents that contradict each other are
*less* informative than two that agree, and this component is what encodes that. Reusing
`d_conflict` from §0.4:

```
C_agr = 1 − d_conflict_max
```

This directly answers the motivating question: one document → low `C_vol`; five *agreeing*
documents → high `C_vol` and high `C_agr`; five *disagreeing* documents → high `C_vol` but low
`C_agr`, and the geometric mean (§4.4) ensures the composite stays low.

---

**(3) Source independence — `C_ind`**

Five documents from one feed are one witness quoted five times. Correlated evidence must not
multiply confidence:

```
n_sources = number of distinct source_doc_id values among cited docs
            (near-duplicates with pairwise cosine > 0.95 collapsed into one)
n_tiers   = number of distinct source tiers represented
C_ind     = 0.7 · min(n_sources / 3, 1)  +  0.3 · min(n_tiers / 2, 1)
```

Three distinct sources saturate the first term; corroboration across at least two tiers
saturates the second. Cross-tier corroboration is weighted in deliberately: an attacker who
has poisoned one feed has not necessarily poisoned CISA *and* a community feed, so agreement
that spans tiers is harder to manufacture than agreement within one.

---

**(4) Detector coherence — `C_coh`**

If the four detectors disagree with each other, our risk estimate rests on an unresolved
internal contradiction. Map each risk-oriented signal to a [0, 1] "risk vote" via its own
clean-calibration CDF (§2.1), so the four are on a common scale, then:

```
v = [ F_uns(s_uns), F_ano(x_ano), F_inj(s_inj*), F_cnf(s_cnf) ]      # each in [0,1]
C_coh = 1 − ( SD(v) / 0.5 ),   clipped to [0, 1]
```

0.5 is the maximum standard deviation attainable by four values on [0, 1] (two at each
extreme), so the ratio is a proper normalisation.

---

**(5) Model epistemic uncertainty — `C_mdl`**

How stable is the fitted model's output for this particular input? Estimated by bootstrap:
refit the logistic regression on `B = 200` bootstrap resamples of the training set (done once,
offline; the 200 coefficient vectors are persisted), then at inference score the input under
all 200 and take the empirical interval.

```
p̂_b for b = 1..200
CI_width = percentile(p̂, 97.5) − percentile(p̂, 2.5)
C_mdl    = 1 − CI_width
```

Inference cost is 200 dot products over a 14-dimensional vector — negligible. This captures
two distinct problems at once: inputs in sparse regions of the training distribution produce
unstable coefficients and wide intervals, and predictions near p = 0.5 are inherently
uncertain. Both correctly lower confidence.

---

### 4.3 Effective sample size

```
For cited documents with attribution weights w_i (normalised, Σ w_i = 1):
n_eff = 1 / Σ (w_i²)                                    # inverse Simpson / Kish ESS
then:   n_eff = min( n_eff, n_sources_after_dedup )     # independence cap
```

The Kish form means that one document carrying 90% of the attribution weight yields
`n_eff ≈ 1.2` even if five documents were retrieved — correctly, because the answer really
rested on one document. The independence cap then prevents five near-duplicates from the same
feed from inflating it further.

### 4.4 Composition

```
Confidence = ( C_vol^1.0 · C_agr^1.5 · C_ind^1.0 · C_coh^1.0 · C_mdl^1.0 ) ^ (1 / 5.5)
```

**Geometric mean, not arithmetic.** A weakness in any single component must drag the composite
down, because confidence is conjunctive: we are confident only if we have enough evidence
*and* it agrees *and* it is independent *and* the detectors concur *and* the model is stable.
An arithmetic mean lets four strong components mask one fatal weakness — precisely the
behaviour we cannot afford. Any component at 0 drives Confidence to 0, which is correct.

`C_agr` carries exponent 1.5 because contradictory evidence is the most direct evidence that
our estimate is unreliable. All other weights are 1.0.

**Hard caps** applied after composition:

```
if n_eff ≤ 1:     Confidence = min(Confidence, 0.40)
if is_singleton:  Confidence = min(Confidence, 0.30)
```

A single-document answer can never be high-confidence regardless of how clean it looks. This
also aligns with P1's (TrustRAG) explicit caution about isolated singleton documents, which is
the same structural situation viewed from the corpus-hygiene side.

### 4.5 How confidence changes the action

Confidence must not be decorative. It affects the disposition through a **conservative
decision rule**: threshold on the upper bound of the risk interval, not the point estimate.

```
p_upper = percentile( bootstrap p̂, 97.5 )      # from §4.2 component 5
```

Apply the §3.9 bands to `p_upper` rather than `p̂`. Low confidence widens the interval, raises
`p_upper`, and pushes borderline cases toward Review — automatically, with no extra rule.

Two further constraints:

- **Low confidence may never downgrade a disposition.** It can only make the outcome more
  conservative. A wide interval is not a reason to relax.
- **`Confidence < 0.35` forces a minimum disposition of Review**, whatever the score says. If
  we do not know what we are looking at, a human should.

### 4.6 Validating the confidence measure

Confidence has no ground-truth label, which makes it easy to ship something that looks
principled and measures nothing. It must therefore be **empirically falsifiable**, and the
test is straightforward:

> If the confidence measure is meaningful, prediction error must be lower in high-confidence
> bins than in low-confidence bins.

**Procedure.** Bin test predictions into confidence deciles. Compute Brier score and error
rate per bin. Requirements:

1. **Monotonicity** — Spearman correlation between confidence decile and error rate must be
   negative and significant (target ρ ≤ −0.6).
2. **Separation** — error rate in the top confidence tercile must be at least 2× lower than in
   the bottom tercile.
3. **Component ablation** — removing each component in turn must degrade (1) or (2); a
   component that can be removed with no effect is not earning its place and should be dropped.

If these fail, the weights in §4.4 are wrong and must be refitted (by grid search against
criterion 1) or the failing component removed. **The measure is not shipped on the strength of
its rationale alone.** This is the one place where hand-set weights appear anywhere in the
design, and this test is the price of admission for them.

---

## 5. Task 4 — `analyst_decision` Schema and Audit Trail

### 5.1 Purpose and stance

Every analyst action on a flagged case is recorded now, so that a future team can recalibrate
thresholds, retrain the fusion model on real analyst judgement, and measure whether the system
actually helped. Nothing here is used for retraining during this capstone. The design
obligation is therefore to **capture enough context that the record is still interpretable
after the model and thresholds have changed** — a decision logged without its scoring context
is unusable within one version bump, and that is the single most common way audit data is
wasted.

The log is **append-only and hash-chained**. Corrections are new rows that supersede old ones;
no row is ever updated or deleted.

### 5.2 Parent table — `query_events`

Sketched because `analyst_decisions` is meaningless without it.

```sql
CREATE TABLE query_events (
    event_id                TEXT PRIMARY KEY,          -- UUIDv4
    created_at              TEXT NOT NULL,             -- ISO-8601 UTC
    query_text              TEXT NOT NULL,
    query_hash              TEXT NOT NULL,             -- SHA-256, for dedup without storing text twice
    retrieved_doc_ids       TEXT NOT NULL,             -- JSON array
    cited_doc_ids           TEXT NOT NULL,             -- JSON array
    generated_answer        TEXT,

    -- raw detector signals
    entailment_score          REAL,
    anomaly_score_max         REAL,
    injection_probability_max REAL,
    conflict_score            REAL,
    d_conflict_max            REAL,

    -- encoded features, for exact reproduction of the score
    feature_vector          TEXT NOT NULL,             -- JSON object, named features

    -- tier context
    tier_governing          INTEGER NOT NULL,          -- 1 | 2 | 3
    tier_min                INTEGER NOT NULL,
    n_retrieved             INTEGER NOT NULL,
    n_eff                   REAL    NOT NULL,

    -- outputs of both tracks
    case_id                 TEXT NOT NULL,             -- winning case, 'C1'..'C11'
    all_matched_cases       TEXT NOT NULL,             -- JSON array of every case that fired
    taxonomy_action         TEXT NOT NULL,             -- rule track proposal
    risk_score              REAL NOT NULL,             -- calibrated p-hat
    risk_score_prior_corrected REAL,                   -- §3.8
    risk_p_upper            REAL NOT NULL,             -- §4.5
    score_action            TEXT NOT NULL,             -- statistical track proposal
    confidence              REAL NOT NULL,
    confidence_components   TEXT NOT NULL,             -- JSON: C_vol, C_agr, C_ind, C_coh, C_mdl
    final_action            TEXT NOT NULL,             -- after escalation dominance
    risk_priority           TEXT NOT NULL,             -- 'P0'..'P5'

    -- version pinning: without these the row is uninterpretable later
    model_version           TEXT NOT NULL,
    threshold_set_version   TEXT NOT NULL,
    taxonomy_version        TEXT NOT NULL,
    detector_versions       TEXT NOT NULL,             -- JSON: model id per detector

    -- verification sampling (§5.6)
    is_verification_sample  INTEGER NOT NULL DEFAULT 0
);
```

### 5.3 `analyst_decisions`

```sql
CREATE TABLE analyst_decisions (
    decision_id             TEXT PRIMARY KEY,          -- UUIDv4
    event_id                TEXT NOT NULL REFERENCES query_events(event_id),
    analyst_id              TEXT NOT NULL,             -- pseudonymous stable hash, never a name
    analyst_role            TEXT,                      -- 'tier1_soc'|'tier2_soc'|'threat_intel'|'other'

    -- what the system said, snapshotted so the row stands alone
    system_recommended_action TEXT NOT NULL,           -- 'ACCEPT'|'REVIEW'|'REJECT'|'ESCALATE'
    system_case_id          TEXT NOT NULL,
    system_risk_score       REAL NOT NULL,
    system_confidence       REAL NOT NULL,

    -- the decision itself
    analyst_decision        TEXT NOT NULL,             -- 'ACCEPT'|'REJECT'|'OVERRIDE'
    override_action         TEXT,                      -- required iff decision='OVERRIDE'
    override_reason_code    TEXT,                      -- required iff decision='OVERRIDE'
    override_reason_text    TEXT,                      -- free text, optional, always alongside a code

    -- document-level ground truth: the most valuable field in this table
    per_document_verdicts   TEXT,                      -- JSON [{doc_id, verdict, note}]

    -- calibration and cost inputs
    analyst_confidence      INTEGER,                   -- 1..5 self-reported, optional
    time_to_decision_ms     INTEGER,                   -- measures what a false alarm actually costs

    decided_at              TEXT NOT NULL,             -- ISO-8601 UTC
    logged_at               TEXT NOT NULL,

    -- append-only integrity
    supersedes_decision_id  TEXT REFERENCES analyst_decisions(decision_id),
    prev_row_hash           TEXT NOT NULL,
    row_hash                TEXT NOT NULL,

    CHECK (analyst_decision IN ('ACCEPT','REJECT','OVERRIDE')),
    CHECK (analyst_decision != 'OVERRIDE'
           OR (override_action IS NOT NULL AND override_reason_code IS NOT NULL))
);

CREATE INDEX idx_ad_event   ON analyst_decisions(event_id);
CREATE INDEX idx_ad_code    ON analyst_decisions(override_reason_code);
CREATE INDEX idx_ad_decided ON analyst_decisions(decided_at);
```

`per_document_verdicts` entries take the form
`{"doc_id": "...", "verdict": "CLEAN"|"POISONED"|"UNCERTAIN", "note": "..."}`.
Document-level verdicts are the highest-value field in the table: response-level labels are
weak supervision, but the detectors operate on documents, so document-level judgement is what
a future retraining pass actually needs.

`row_hash` is `SHA-256` over the canonical JSON serialisation of all other columns plus
`prev_row_hash`, giving a tamper-evident chain at no dependency cost.

> **This table definition is amended in §5.8.** Three further columns (`decision_source`,
> `system_action_shown`, `review_started_at`) and the rule governing when `analyst_decision`
> may be written are specified there. Read §5.3 and §5.8 together.

### 5.4 Field semantics — the ambiguity that must be resolved

"Reject" is dangerously ambiguous: it could mean *the analyst rejects the answer* or *the
analyst rejects the system's recommendation*. If this is not pinned down before the dashboard
is built, the field becomes uninterpretable and the whole table is wasted. Binding
definitions:

| Value | Meaning — **always about the content, never about the system** |
|---|---|
| `ACCEPT` | The analyst judges the answer and its evidence **trustworthy and usable**. |
| `REJECT` | The analyst judges the answer or its evidence **untrustworthy**. |
| `OVERRIDE` | The analyst judges that the **system's recommended disposition is wrong** and substitutes a different one, named in `override_action`. |

Agreement with the system is **derived, never entered**. An analyst asked to record both their
verdict and whether they agree will eventually record the two inconsistently. Derive it:

```
agreement = (analyst_decision == 'ACCEPT' and system_recommended_action == 'ACCEPT')
         or (analyst_decision == 'REJECT' and system_recommended_action in ('REJECT','ESCALATE'))
         or (analyst_decision in ('ACCEPT','REJECT') and system_recommended_action == 'REVIEW')
```

The third clause reflects that `REVIEW` is a request for a human verdict, so either verdict
resolves it as intended rather than contradicting it.

`OVERRIDE` is by definition disagreement, and it is the label-rich case: an override with a
reason code is a *diagnosis of a specific system failure*, which is worth far more for future
recalibration than a bare disagreement flag.

### 5.5 Controlled vocabulary — `override_reason_code`

Free text alone cannot be used as a future training label. A closed vocabulary can, and each
code maps to a specific corrective action:

| Code | Meaning | What it implies for recalibration |
|---|---|---|
| `FALSE_POSITIVE_BENIGN_ANOMALY` | Anomalous but legitimately so (novel advisory, unusual formatting) | `θ_ano^sus` too tight, or the §2.4 inversion over-firing |
| `SOURCE_STALE_NOT_MALICIOUS` | Content outdated, not adversarial | Needs a recency feature, not a threshold change |
| `LEGITIMATE_TIER1_DISAGREEMENT` | C10 fired and the divergence is genuine and expected | C10 working as designed; measures its base rate |
| `TIER_MISLABELLED` | Provenance tagger assigned the wrong tier | Provenance bug — highest-severity code here, since tier is the taxonomy's foundation |
| `MISSED_ATTACK_SYSTEM_UNDERSCORED` | Analyst identified poisoning the system scored as low risk | **False negative — the costliest error class; every instance is a case study** |
| `INSUFFICIENT_EVIDENCE_TO_JUDGE` | Analyst cannot determine either way | Excluded from future label sets; do not treat as clean |
| `DETECTOR_ERROR_INJECTION` | Injection classifier plainly wrong | Detector-specific, not fusion-level |
| `DETECTOR_ERROR_ENTAILMENT` | NLI verdict plainly wrong | Detector-specific, not fusion-level |
| `CONFIDENCE_TOO_LOW_TO_ACT` | Score plausible but confidence too low to rely on | Feeds §4.6 validation |
| `POLICY_OVERRIDE` | Organisational policy overrides the technical verdict | Excluded from technical recalibration |
| `OTHER` | Anything else — `override_reason_text` then mandatory | Reviewed periodically; a growing `OTHER` share means the vocabulary needs extending |

### 5.6 Two things that make this data actually usable later

**(a) Version pinning.** Every decision row snapshots `model_version`,
`threshold_set_version`, `taxonomy_version` and `detector_versions` (via `query_events`, and
the score/confidence directly on the decision row). Without these, a decision logged under
thresholds v1 is meaningless once v2 ships, because we cannot reconstruct what the analyst was
actually shown. This is cheap to add now and impossible to reconstruct later.

**(b) Verification sampling — the selection-bias fix.** Only *flagged* cases reach an analyst.
A future team training on this table would therefore be training on a sample conditioned on
the current model's decisions — the classic selection-bias trap, which produces a successor
model that faithfully reproduces its predecessor's blind spots and cannot discover them.

**Mitigation:** route a **random 3% of auto-Accepted responses** to blind analyst review,
presented identically to flagged cases and with the system's disposition hidden. Flag them
`is_verification_sample = 1`. This costs a small, bounded amount of analyst time and buys three
things nothing else can provide: an unbiased estimate of the false-negative rate in the
auto-Accept region; labelled negatives from the region the model never doubts; and an early
warning when a new attack family starts slipping through. Blinding matters — an analyst who
knows the system said "Accept" is measurably more likely to agree.

### 5.7 Retention and privacy

Threat-intelligence queries can contain incident-sensitive material (hostnames, patient-system
identifiers, internal IPs). For this capstone the corpus is synthetic and no real PHI or
production data is involved. The schema nonetheless assumes: `analyst_id` is a pseudonymous
stable hash and never a name; `query_text` is hashed as well as stored so that the plaintext
column can be purged under a retention policy without breaking joins or the hash chain; and
retention defaults to 365 days with hash-chain continuity preserved across purges.

---

### 5.8 Decision lifecycle — when `analyst_decision` is set, and the invariant that it is never set by the system

§5.3 defines the field. This subsection defines **when it may be written**, which is a separate
question and the one that determines whether the table is worth anything later. A decision
column that the system can populate on its own is not a record of human judgement; it is a
record of the system's own output wearing a human's name, and no future recalibration can
separate the two after the fact.

#### The invariant

> `analyst_decision` is written **only** as the direct result of a human acting on a case in
> the dashboard. There is no code path in the pipeline that writes it, no default that supplies
> it, and no process that infers it.

This holds without exception, including for cases that are never reviewed.

#### Absence is the absence of a row, not a NULL and not a sentinel

An event that no analyst has acted on has **no row in `analyst_decisions` at all**.

This is a deliberate choice over the two obvious alternatives, and it is worth being explicit
about why both were rejected:

- **A nullable `analyst_decision` column** would mean every decision row could exist without a
  decision. Once a column is nullable, something eventually fills it — a migration default, a
  well-meaning backfill, an ORM's zero value. The `NOT NULL` constraint in §5.3 is what makes
  the invariant enforceable rather than aspirational.
- **A `PENDING` sentinel value** would sit in the same column as real verdicts. Every future
  aggregate query would then have to remember to exclude it, and the first query that forgets
  produces a silently wrong number rather than an error.

Representing "not yet reviewed" as the absence of a row makes the undecided state impossible to
confuse with a verdict, at the cost of one `LEFT JOIN` in the queue query. That is the right
trade.

#### Lifecycle states

| State | Representation | How it is reached |
|---|---|---|
| **Undecided** | No row in `analyst_decisions` for the `event_id` | Default for every event, including flagged ones. Persists indefinitely if no one reviews it. |
| **Decided** | Exactly one row, not superseded | An analyst submits a decision in the dashboard. |
| **Superseded** | A row that another row's `supersedes_decision_id` points at | An analyst corrects an earlier decision. The original is never edited or deleted. |
| **Current** | The head of a supersede chain | Derived, not stored — see `v_current_decisions` in §5.9. |

An unreviewed case **never times out into a decision.** A queue item that ages out of the
analyst queue remains Undecided forever. Aging a case into `ACCEPT` on a timer would manufacture
exactly the label a future model most wants to trust and least deserves to.

#### Enforcement — three layers, because one is not enough

A rule stated in a design document is not an invariant. Three independent mechanisms enforce it,
each catching a different class of violation:

1. **Schema.** `analyst_decision` is `NOT NULL` with a `CHECK` constraint and **no `DEFAULT`
   clause**. A row cannot be inserted without an explicit value, and the database will not
   invent one. The absence of a `DEFAULT` is load-bearing and must survive any future migration.

2. **Write-path separation.** Only the dashboard's decision handler may `INSERT` into
   `analyst_decisions`. The scoring pipeline writes `query_events` and holds no write grant on
   `analyst_decisions`. In a SQLite deployment this is enforced by module boundary rather than
   by database roles: the pipeline package must not import the decision writer, and this should
   be asserted in a test rather than left to convention.

3. **Provenance field.** Every row records how it came to exist:

   ```sql
   decision_source TEXT NOT NULL
       CHECK (decision_source IN ('analyst_ui','bulk_import','migration'))
   ```

   Only `analyst_ui` is produced during this capstone. The other two values exist so that if a
   future team ever does import decisions from elsewhere, those rows are distinguishable rather
   than silently mixed in. **Any row whose `decision_source` is not `analyst_ui` is excluded from
   recalibration by default** (§5.9). This is the layer that survives a mistake in the other two:
   even if something wrong is written, it is labelled as such.

#### Schema amendment to §5.3

Three columns are added to `analyst_decisions` to support this subsection. §5.3's definition
should be read together with this amendment.

```sql
-- Added in design-v1.1
decision_source      TEXT NOT NULL
    CHECK (decision_source IN ('analyst_ui','bulk_import','migration')),

-- Was the system's recommendation visible to the analyst when they decided?
-- 0 for blind verification samples (§5.6b), 1 for ordinary flagged-case review.
system_action_shown  INTEGER NOT NULL CHECK (system_action_shown IN (0,1)),

-- When the analyst opened the case. Makes time_to_decision_ms verifiable
-- rather than a number the client asserts.
review_started_at    TEXT
```

`system_action_shown` matters more than it looks. An analyst who was shown "the system says
Reject" and agrees has produced a weaker signal than one who decided blind, because automation
bias is real and measurable. Without this column a future team cannot tell the two apart, and
will treat them as equivalent evidence. Recording it costs one integer.

#### Timing constraints

```
query_events.created_at  <=  review_started_at  <=  decided_at  <=  logged_at
```

A decision whose `decided_at` precedes its event's `created_at` is impossible and must be
rejected at write time, not merely flagged in analysis. `logged_at` is set server-side;
`decided_at` comes from the client and may drift, which is why both exist.

#### Explicitly prohibited

Each of the following is a realistic temptation, and each poisons the future label set in a way
that cannot be detected once it is in the table:

| Prohibited | Why it is tempting | Why it is fatal |
|---|---|---|
| Defaulting an unreviewed case to `ACCEPT` after a timeout | Closes the queue; looks like throughput | Manufactures the majority-class label the model is already biased toward, at exactly the volume that would dominate a retraining set |
| Inferring a decision from downstream behaviour ("no one complained, so ACCEPT") | Free labels at scale | Absence of complaint is not judgement. This produces confident labels with no human behind them and no way to identify them later |
| Back-filling historical events once the schema ships | Makes the table look complete | A decision reconstructed after the fact was not made with the information the analyst had, and the version-pinned context is a fiction |
| Carrying a decision forward to a similar case | Saves analyst effort on near-duplicates | Duplicates one judgement into many rows, which inflates apparent agreement and breaks any independence assumption in later analysis |
| Pre-selecting a value in the dashboard UI | Reduces clicks | Anchors the analyst on the system's answer; the recorded verdict partly measures the default, not the human |

The dashboard's decision control must therefore open with **no option selected**, and submission
must be blocked until the analyst chooses one.

#### Idempotency

The dashboard generates `decision_id` client-side and sends it with the submission, so a
double-submit or a retried request writes one row rather than two. A repeated `decision_id` is
an `INSERT OR IGNORE`, not an error — the analyst pressing the button twice is not an incident.

---

### 5.9 Storage and query patterns for a future recalibration pass

Nothing here is used during this capstone. The obligation now is that the data can be extracted
correctly later by someone who was not in the room, which means the joins and the exclusion
rules are specified rather than left to be rediscovered.

#### Additional indexes

Beyond the three in §5.3:

```sql
CREATE INDEX idx_ad_supersedes ON analyst_decisions(supersedes_decision_id);
CREATE INDEX idx_ad_source     ON analyst_decisions(decision_source);
CREATE INDEX idx_ad_event_time ON analyst_decisions(event_id, decided_at);
CREATE INDEX idx_qe_case       ON query_events(case_id);
CREATE INDEX idx_qe_created    ON query_events(created_at);
CREATE INDEX idx_qe_vsample    ON query_events(is_verification_sample);
```

`idx_ad_supersedes` is not optional: the current-decision view below is a correlated
`NOT EXISTS` over that column, and without the index it degrades to a full scan per row.

#### The two views that are the only sanctioned entry point

Any future extraction goes through these. Hand-written joins against the base tables are how a
supersede chain gets silently mishandled and a corrected decision counted twice.

```sql
-- The head of each supersede chain: the decision that currently stands.
CREATE VIEW v_current_decisions AS
SELECT d.*
FROM analyst_decisions d
WHERE NOT EXISTS (
    SELECT 1 FROM analyst_decisions s
    WHERE s.supersedes_decision_id = d.decision_id
);

-- Decisions joined to the scoring context that produced them, restricted to
-- rows a human actually made. This is the recalibration extraction surface.
CREATE VIEW v_labelled_decisions AS
SELECT
    q.event_id,
    q.case_id,
    q.all_matched_cases,
    q.tier_governing,
    q.feature_vector,
    q.risk_score,
    q.risk_p_upper,
    q.confidence,
    q.confidence_components,
    q.taxonomy_action,
    q.score_action,
    q.final_action,
    q.is_verification_sample,
    q.model_version,
    q.threshold_set_version,
    q.taxonomy_version,
    q.detector_versions,
    d.decision_id,
    d.analyst_id,
    d.analyst_role,
    d.analyst_decision,
    d.override_action,
    d.override_reason_code,
    d.per_document_verdicts,
    d.analyst_confidence,
    d.time_to_decision_ms,
    d.system_action_shown,
    d.decided_at
FROM query_events q
JOIN v_current_decisions d ON d.event_id = q.event_id
WHERE d.decision_source = 'analyst_ui';
```

#### Label derivation — and a trap in it

**The response-level decision is not the risk model's target.** §3.1 defines `y = 1` as *the
response was materially influenced by a poisoned document*. An analyst rejects an answer for
several reasons, most of which are not poisoning: the evidence is stale, the claim is
unsupported, the sources disagree. Treating every `REJECT` as `y = 1` would train the successor
model to detect *analyst dissatisfaction*, which is a different and much broader target.

So the mapping is layered, and the document-level verdicts carry the load:

```
Preferred label (matches the model's target):
    per_document_verdicts[].verdict == 'POISONED'   -> that document is positive
    per_document_verdicts[].verdict == 'CLEAN'      -> that document is negative
    per_document_verdicts[].verdict == 'UNCERTAIN'  -> excluded

Fallback response-level label (weak supervision, use only where per-document
verdicts are absent, and record that it was a fallback):
    ACCEPT                                          -> y = 0
    OVERRIDE with override_action = 'ACCEPT'        -> y = 0
    REJECT                                          -> y = 1  (weak; see below)
    OVERRIDE with override_action in
        ('REJECT','ESCALATE')                       -> y = 1  (weak)
    OVERRIDE with override_action = 'REVIEW'        -> excluded, no verdict on content

Excluded from every label set regardless of decision value:
    override_reason_code = 'INSUFFICIENT_EVIDENCE_TO_JUDGE'
    override_reason_code = 'POLICY_OVERRIDE'
    decision_source != 'analyst_ui'
```

A fallback response-level `y = 1` should be recorded with a flag so that a future team can fit
with and without it and see whether it helped. It is the weakest evidence in the table and it
will also be the most plentiful, which is a bad combination to leave unmarked.

#### The queries that will actually be run

```sql
-- 1. Undecided flagged cases (the queue). Note the LEFT JOIN: absence of a row
--    is the undecided state (§5.8).
SELECT q.event_id, q.case_id, q.risk_priority, q.created_at
FROM query_events q
LEFT JOIN analyst_decisions d ON d.event_id = q.event_id
WHERE d.decision_id IS NULL
  AND q.final_action IN ('REVIEW','REJECT','ESCALATE')
ORDER BY q.risk_priority, q.created_at;

-- 2. Agreement rate by case, split by whether the analyst saw the system's
--    recommendation. The split is the point: the two columns are not comparable.
SELECT case_id,
       system_action_shown,
       COUNT(*) AS n,
       SUM(CASE WHEN analyst_decision != 'OVERRIDE' THEN 1 ELSE 0 END) * 1.0
           / COUNT(*) AS agreement_rate
FROM v_labelled_decisions
GROUP BY case_id, system_action_shown;

-- 3. False negatives found in the auto-Accept region, via blind sampling.
--    This is the only unbiased estimate of what the system misses (5.6b).
SELECT COUNT(*) AS missed
FROM v_labelled_decisions
WHERE is_verification_sample = 1
  AND final_action = 'ACCEPT'
  AND (analyst_decision = 'REJECT'
       OR override_reason_code = 'MISSED_ATTACK_SYSTEM_UNDERSCORED');

-- 4. Threshold recalibration input: score against realised analyst verdict,
--    pinned to one threshold set so the comparison is meaningful.
SELECT risk_score, confidence, analyst_decision, override_reason_code
FROM v_labelled_decisions
WHERE threshold_set_version = :version;

-- 5. Document-level training rows, the preferred label source.
SELECT v.event_id,
       json_extract(j.value, '$.doc_id')  AS doc_id,
       json_extract(j.value, '$.verdict') AS verdict
FROM v_labelled_decisions v,
     json_each(v.per_document_verdicts) j
WHERE v.per_document_verdicts IS NOT NULL
  AND json_extract(j.value, '$.verdict') IN ('CLEAN','POISONED');
```

#### JSON columns and when to stop using them

`per_document_verdicts`, `feature_vector` and `confidence_components` are stored as JSON text.
SQLite's `json_each` and `json_extract` make them queryable, as query 5 shows, and at capstone
volume that is the right trade — a child table for per-document verdicts would add a join and a
migration for no present benefit.

The threshold at which that stops being true: **once per-document verdicts exceed roughly
50,000 rows when expanded, or once any query needs to filter on a verdict rather than project
it**, normalise into `analyst_document_verdicts(decision_id, doc_id, verdict, note)` with an
index on `(doc_id, verdict)`. Recording the threshold now means the decision gets made on
evidence rather than when someone notices a slow query.

#### Interaction with retention

§5.7 permits purging `query_events.query_text` under the retention policy. Purging must set the
column to `NULL` and must not delete the row: `v_labelled_decisions` joins on `event_id`, and
the hash chain covers the row. A retention job that deletes `query_events` rows would orphan
every decision that references them and break the chain at that point. The retention job must
therefore null columns, never remove rows.

---

### 5.10 What this data cannot support, and why that must be written down now

The table's value depends on a future team understanding its limits. Three are structural and
cannot be fixed by collecting more of it:

**Analyst decisions are not ground truth.** They are expert judgement made under time pressure,
frequently on incomplete evidence. A future model fitted on them learns to predict *what an
analyst would say*, which correlates with but is not identical to *whether the response was
attacker-influenced*. That distinction should be stated in any write-up that uses this data,
not discovered by a reviewer.

**Agreement is inflated by automation bias.** Most decisions are made with the system's
recommendation visible, and people agree with a displayed recommendation more often than they
would judge independently. This is why `system_action_shown` exists (§5.8) and why the blind
verification sample (§5.6b) is the only unbiased slice in the table. **Any headline agreement
figure computed across the whole table is an overestimate**, and a future team should report the
blind-sample figure alongside it.

**There is no inter-rater reliability without deliberate double-review.** The schema permits
several decision rows per event by different analysts, but nothing in the workflow generates
them. Without a measure of how often two analysts agree with each other, there is no way to know
how much of the disagreement between analyst and system is signal rather than ordinary variance
between reviewers. A future team wanting to use this data seriously should double-review a small
random slice from the outset — it is cheap while volume is low and impossible to reconstruct
later.

---

## 6. End-to-End Decision Flow

```
1.  Retrieve top-k documents; attach source_tier, source_doc_id from provenance tags
2.  Generate answer; record cited_docs and attribution weights
3.  Compute detectors:  s_ent, s_ano (per doc), s_inj (per doc), s_cnf
4.  Compute derived:    s_uns, s_ano*, s_inj*, d_conflict_max, n_eff, n_sources
5.  Determine tier_governing and tier_min                                   (§2.2)
6.  Band the signals -> Content Signal Outcome                              (§2.1)
7.  RULE TRACK:  assign case by precedence -> taxonomy_action, risk_priority (§2.3, §2.7)
8.  Encode 14 features; apply persisted scaler                              (§3.2)
9.  STATISTICAL TRACK: calibrated p-hat, bootstrap interval, prior correction (§3.8)
10. Compute Confidence and its five components                              (§4)
11. Threshold p_upper against tau_review / tau_reject -> score_action       (§3.9, §4.5)
12. Apply confidence floor: Confidence < 0.35 -> at least Review            (§4.5)
13. Reconcile by escalation dominance -> final_action                       (§3.9)
14. Write query_events row (both proposals + final action + all versions)   (§5.2)
15. Derive headline band GREEN / ORANGE / RED (+ RED sub-type)              (§2.9)
16. Deliver to analyst per action semantics                                 (§2.6)
17. On analyst action: append analyst_decisions row, extend hash chain      (§5.3)
18. With probability 0.03 on auto-Accept: enqueue as verification sample    (§5.6)
```

---

## 7. Worked Examples

**Example A — Tier-1 anomaly (case C4).**
Query: "Is CVE-2026-XXXX being exploited against hospital imaging systems?" Retrieval returns
four documents, the top one tagged Tier 1 (CISA). Detectors:
`s_ent = 0.88` → `s_uns = 0.12` (below threshold); `s_ano* = 4.1σ` (above `θ_ano^sus`);
`s_inj* = 0.02`; `s_cnf = 0.31`. Band = **SUSPICIOUS** (one signal above its suspicious
threshold). `tier_governing = 1` → **C4**, priority **P1**, action **Escalate**. The fitted
score might well be modest here — three of four signals are quiet — but escalation dominance
means the taxonomy wins and the case is raised to the threat-intel owner as a possible
Tier-1 source-integrity issue. **This is the behaviour §2.4 exists to produce, and the case a
scalar-only design would miss.**

**Example B — Tier-1 divergence (case C10).**
Query about the severity of a medical-device vulnerability. Two Tier-1 documents are cited: a
vendor PSIRT bulletin rating it 9.8 and a CISA advisory rating it 7.5 after re-analysis.
`d_conflict_max = 0.91` (above `θ_dcf^mal`); `s_inj* = 0.01` and `s_ano* = 0.9σ` (both quiet).
C10 fires → priority **P2**, action **Review**, dual-evidence presentation with both ratings
and both dates. The system does not pick a winner. If the analyst confirms this is a genuine
revision, the logged `override_reason_code = LEGITIMATE_TIER1_DISAGREEMENT` lets us measure
C10's base rate over time.

**Example C — Classic poisoning (case C11).**
Query about a ransomware IOC. One Tier-3 document is retrieved with anomalously high
similarity (99th percentile), `s_ano = 5.6σ`, `s_inj = 0.71`, `s_ent = 0.34` → `s_uns = 0.66`,
and no other document supports the claim. `n_eff = 1.0`. Band = **MALICIOUS**. Precedence:
C5 no, C4 no, **C11 yes** → priority **P1**, action **Escalate** (the isolated-outlier
signature indicates a targeted corpus insertion, not merely a bad document; had the outlier
structure been absent, this would have fallen through to C9 as ordinary Tier-3 poisoning).
Confidence is capped at **0.30** by the singleton rule, so it is reported as *high risk, low
confidence* — which is the honest characterisation and the one an analyst can act on.

---

## 8. Open Questions

| # | Question | Blocks | Resolution path |
|---|---|---|---|
| 1 | Does the generation step expose usable per-document attribution, or must we fall back to top-3 by similarity? | `tier_governing`, `n_eff` | Test during baseline RAG build; fallback is specified in §2.2 |
| 2 | Is O(k²) pairwise NLI acceptable at k=5–8 on our hardware? | `d_conflict_max`, C10, `C_agr` | Benchmark during detector build; restrict to cited docs if not |
| 3 | Can we construct enough Tier-1 poisoned instances to identify the `is_tier1 × ·` interactions? | §3.3 feature ladder, C4/C5 validation | Corpus construction; feature ladder is the fallback |
| 4 | Is the assumed `C_FN/C_FP = 10` defensible? | β = 3, `class_weight` | Revisit with `time_to_decision_ms` data; documented as an assumption in §9 |
| 5 | Do the §4.4 confidence weights survive the §4.6 validation? | Confidence measure | Run §4.6; refit weights by grid search against criterion 1 if not |

---

## 9. Authoritative Constants

Two categories, and the distinction is important. **Fixed design constants** are authoritative
now and must not be changed without a version bump. **Fitted parameters** are placeholders —
what is authoritative about them is the *procedure* that produces them, not the current value.

### 9.1 Fixed design constants

| Constant | Value | Section |
|---|---|---|
| `RANDOM_SEED` | 20260915 | §3.6 |
| Logit clipping ε | 1e-3 | §3.2 |
| MAD scale factor | 1.4826 | §3.2 |
| Tier reference level | Tier 2 | §3.2 |
| Cost ratio `C_FN / C_FP` | 10 | §3.7 |
| F-beta β | 3 | §3.7 |
| `class_weight` | {0: 1.0, 1: 10.0} | §3.8 |
| Alert budget (max FPR) | 0.10 | §3.7 |
| Confidence κ | 2.0 | §4.2 |
| `C_agr` exponent | 1.5 | §4.4 |
| Confidence floor forcing Review | 0.35 | §4.5 |
| Singleton confidence cap | 0.30 | §4.4 |
| `n_eff ≤ 1` confidence cap | 0.40 | §4.4 |
| Bootstrap replicates `B` | 200 | §4.2 |
| Near-duplicate cosine threshold | 0.95 | §4.2 |
| Verification sampling rate | 0.03 | §5.6 |
| Minimum governing tier for a GREEN headline | Tier 1 | §2.9.3 |
| Default headline band (fail-safe) | ORANGE | §2.9.4 |
| Test holdout fraction | 0.20 | §3.6 |
| CV configuration | 5 folds × 5 repeats, nested | §3.6 |
| Target corpus | ≥200 poisoned, ≥600 clean | §3.3 |

### 9.2 Fitted parameters — procedure is authoritative, values are placeholders

| Parameter | Derivation | Status |
|---|---|---|
| `θ_s^sus` (per signal) | Q_0.95 of clean calibration distribution | Pending corpus |
| `θ_s^mal` (per signal) | Q_0.99 of clean calibration distribution | Pending corpus |
| `θ_dcf^sus`, `θ_dcf^mal` | Same procedure, applied to `d_conflict` | Pending corpus |
| `τ_review` | Lowest threshold with validation recall ≥ 0.95 | Pending fit |
| `τ_reject` | Lowest threshold with validation precision ≥ 0.90 | Pending fit |
| LR coefficients, intercept | Nested CV over the L2 grid | Pending fit |
| Regularisation `C` | Inner-CV selection over the log grid | Pending fit |
| Scaler parameters | Fit on training fold only | Pending fit |

---

## 9A. Implementation Amendments — Measured Deviations from §§0.4, 2.1 and 3.1

*Added as `design-v1.3`, 5 September 2026.*

This design is the authoritative source for thresholds, feature encoding and case
definitions, so where the implementation departs from it the departure is recorded here
rather than left in code comments. Four amendments, each forced by a measurement rather
than chosen for convenience. Every one narrows what may be claimed; none changes the
architecture, the case taxonomy, or the action semantics.

### 9A.1 The prompt-injection detector is a rule detector, not a pretrained classifier

**§2.1 unchanged. What implements `s_inj` has changed.**

`protectai/deberta-v3-base-prompt-injection-v2` was the intended backend. It was measured
against this corpus and does not separate it, at any aggregation attempted. The
measurement is reproducible as `eval/results/probe_injection.py` and `probe_injection2/3/4.py`:

| Aggregation | Injection-bearing doc | Rank of 84 | Margin over loudest clean |
|---|---|---|---|
| Whole document | 0.0011 | 10th | −0.1660 |
| Max over paragraph chunks | 1.0000 | 5th | −0.0000 |
| Max, chunks ≥ 100 chars | 1.0000 | 2nd | −0.0000 |
| Max, chunks ≥ 300 chars | 0.0019 | 53rd | −0.9980 |
| Max logit margin | 13.63 | 5th | −0.8495 |
| Mean of top-3 chunks | 0.6253 | 31st | −0.3746 |

No rule ranks the target first. The best ties it at 1.0000 with a clean HC3 brief, and a
tie cannot be thresholded. A plausible explanation — that the model reads input *length*
rather than content — was tested and **rejected**: Pearson r between chunk length and
score over 1,073 chunks is −0.011. The model fires on roughly 10% of chunks in every
length bucket. The 26-character MITRE label `**Tactic:** Initial Access` scores a higher
logit margin (+14.20) than the actual injection payload (+13.63).

The pattern backend, on the identical corpus, ranks the target first with margin +1.0000
and is the only document of 84 on which any pattern fires.

**What may be claimed:** the pretrained classifier was measured and ruled out for
document-level detection on this corpus. **What may not:** that the pattern detector
generalises. See §9A.4.

The transformer backend is retained and reachable via `get_backend(force="model")`, so the
comparison can be re-made against a larger corpus rather than being taken on trust.

### 9A.2 `s_inj` band thresholds are declared, not fitted

**Amends §2.1 for one signal only. The quantile rule of §2.1 continues to govern
`s_uns`, `s_ano` and `s_cnf`.**

§2.1 sets thresholds at Q₀.₉₅ / Q₀.₉₉ of the clean calibration distribution. That rule
assumes a signal with a distribution. The pattern detector is a noisy-OR over
hand-specified patterns with hand-assigned weights, and its clean distribution is a column
of zeros — no pattern fires on any clean document. Quantiles of that are not thresholds;
they are the constant.

Left alone this failed **silently and dangerously**. Q₀.₉₅ = 0.0 would make every document
exceed the threshold, so the degeneracy guard in `fusion/bands.py` correctly marked the
signal `unusable`, and `assign_band` excludes unusable signals — which made the
`injection_alone` rule, the one rule §2.1 permits to act on a single signal, unreachable
dead code while every test suite continued to pass.

Cut points are therefore declared in `fusion.bands.FIXED_THRESHOLD_SIGNALS`, derived from
the pattern weights rather than typed by preference:

```
θ_inj^sus = 0.60    the weakest single pattern in the set, so any one pattern firing
                    reaches SUSPICIOUS
θ_inj^mal = 0.90    reached by one pattern only if it is addressed_to_model (0.90) or
                    override_instruction (0.95) — the two with no benign reading — or by
                    any two mid-weight patterns combined
```

`system_impersonation` (0.85) alone deliberately lands SUSPICIOUS rather than MALICIOUS: a
legitimate advisory can contain the words "system note".

These are judgement, stated openly as judgement, and are to be revisited when the corpus
carries more evidence than §9A.4 describes.

### 9A.3 `s_cnf` carries intra-evidence conflict, which is not the signal §2.1 defines

**§2.1 defines `s_cnf` as retrieved evidence versus the model's PARAMETRIC KNOWLEDGE.**
That needs a probe of the model's own beliefs, which this system does not have, and the
signal was consequently absent from every row — excluded from banding rather than
zero-filled, per the `SignalSet` contract.

What is now wired is **§0.4's derived quantity**, `d_conflict`, reduced to a per-document
value: a document's conflict is the strongest contradiction it participates in, max rather
than mean for the reason §0.5 gives — one crafted document among clean neighbours is the
mechanism being defended against, and averaging is how it hides.

This fills a previously empty signal with a real measurement, and it answers a **different
question** than §2.1 specifies. It is recorded as `conflict_source =
intra_evidence_pairwise_nli` in the dataset metadata and must not be read as the
parametric-conflict signal. A document in a singleton retrieval has no pair and receives
`None` (absent), not `0.0` (compared, found not to disagree).

**Open:** either implement the parametric probe §2.1 describes, or amend §2.1 to define
`s_cnf` as the intra-evidence quantity. Until one or the other, no figure depending on
`s_cnf` is quotable without this caveat attached.

### 9A.4 The entailment hypothesis is the generated answer, and the proxy inverted the signal

**§3.1 always specified the generated answer. The implementation substituted the query
text, because no generator was in the loop.**

That substitution was not neutral. PoisonedRAG documents restate the target query in order
to be retrieved, so measured against the *query* they appear **better** supported than
genuine documents. Training measured `s_uns` at AUC 0.248 — inverted, worse than chance —
and dropped the strongest detector in the system as anti-correlated. The proxy did not
weaken the signal; it reversed it.

With generation available the hypothesis is the generated answer, per §3.1. Fallback to
the query proxy is per-QUERY rather than per-run, and every row records
`hypothesis_source` so a mixed dataset is visible rather than averaged over. The
extractive stub is explicitly **refused** as a hypothesis: it returns leading sentences of
the retrieved documents, so using it would score evidence on whether it entails a
quotation of itself — circular, and worse than the proxy it replaces.

Generated answers are cached on disk, keyed by `sha256(query ‖ retrieved doc ids)`, and
the cache is tracked. This is a methodological requirement, not an optimisation: a
language model is not a pure function, and refitting against freshly generated answers
would silently change the training set and confound every cross-run comparison.

### 9A.5 Corpus amendment: injection payload placement and phrasing

**Extends §3.5's corpus construction requirements.**

The first corpus version contained one `direct_prompt_injection` document. One document is
one group under the LOAFO split of §3.6, so the family lands wholly in train or wholly in
test and `x_inj` may fit at exactly zero — which it did. It also meant any detection figure
described a single point.

Two construction faults were also present, both artefacts of the builder rather than of
the attack:

1. **Placement.** Every payload was appended as the final paragraph, because that was all
   the builder could do. A corpus with one placement teaches a detector to look in one
   place. The builder now supports `injection_placement ∈ {tail, mid, split}`.
2. **Phrasing.** The single payload was written by the same team that wrote the patterns
   that catch it. Perfect separation under those conditions is guaranteed by the setup and
   is evidence of nothing.

The family now holds five documents spanning both axes, and is deliberately **graded** so
that the detector does not score perfectly:

| Document | Placement | Phrasing variant | Score | Band |
|---|---|---|---|---|
| `poison-injection-infusion-t3-forum` | tail | explicit SYSTEM NOTE, multi-signal | 1.0000 | MALICIOUS |
| `poison-injection-contec-t3-forum` | tail | override + concealment, reworded | 0.9925 | MALICIOUS |
| `poison-injection-log4shell-t3-note` | mid | markup tags + role prefix | 0.9840 | MALICIOUS |
| `poison-injection-dcmtk-t2-isac` | mid | answer steering only | 0.8000 | SUSPICIOUS |
| `poison-injection-carescape-t3-unattrib` | split | indirect, no trigger vocabulary | 0.0000 | **MISSED** |

The miss is intentional and is the most informative row in the table. It carries no
vocabulary the pattern set anticipates, and it establishes the honest limit of a rule
detector: it catches phrasings it was written for. Results are reported **per payload**,
never as an aggregate — an aggregate would conceal precisely this distinction.

**This does not restore `x_inj` to the statistical track.** All five documents remain one
LOAFO group by design, so the family still lands wholly on one side of the split. That is
correct and needs no fix: `s_inj` is a **rule-track** signal. §2.1 grants it its own
`injection_alone` rule with declared thresholds precisely because it is not something the
fitted model needs to learn. A zero coefficient on `x_inj` is the two-track architecture of
§0.2 working as intended, not a defect.

**Still not claimable:** a detection rate, a false-positive rate, or an F-score for this
detector against an adversary who has not seen the pattern list.

---

## 10. Version History

| Version | Date | Change |
|---|---|---|
| `design-v1.3` | 2026-09-05 | Added §9A (implementation amendments): the prompt-injection detector is a rule detector after the pretrained classifier was measured and ruled out (§9A.1); `s_inj` band thresholds are declared rather than fitted, because a rule aggregate has no clean distribution and the degeneracy guard was silently disabling the `injection_alone` rule (§9A.2); `s_cnf` now carries §0.4's intra-evidence quantity, which is NOT the parametric-knowledge signal §2.1 defines (§9A.3); the entailment hypothesis is the generated answer per §3.1, the query-text proxy having been measured as INVERTING `s_uns` to AUC 0.248 (§9A.4); corpus extended to five graded `direct_prompt_injection` documents across three payload placements, one of which the detector misses by design (§9A.5). No case definition, priority, action semantic or headline rule altered. |
| `design-v1.0` | 2026-09-02 | Initial design: case taxonomy (C1–C11), logistic-regression scoring methodology, five-component confidence measure, `analyst_decision` audit schema. |
| `design-v1.2` | 2026-09-04 | Added §2.9 (three-state headline classification GREEN/ORANGE/RED with RED sub-typed into `ATTACK_DETECTED` and `TRUSTED_SOURCE_COMPROMISE`, the Tier-2/Tier-3 GREEN exclusions, and the fail-safe default). Amends §6 step ordering and adds two constants to §9.1. No case definition, trigger, priority or action altered — §2.9 is derived from §2.6 and §2.2, not a redefinition of them. |
| `design-v1.1` | 2026-09-03 | Added §5.8 (decision lifecycle and the never-auto-populated invariant, plus three columns amending §5.3), §5.9 (storage and query patterns for future recalibration), §5.10 (limits of the analyst-decision data). No existing section altered other than a cross-reference added to §5.3. |

---

## 11. Glossary

- **Attribution weight** — normalised share of the generated claim traceable to a given
  retrieved document.
- **Band** — the Clean / Suspicious / Malicious classification of a response's signals (§2.1).
- **Case** — a (tier, band) situation type with a defined priority and action (§2.3).
- **Headline band** — the analyst-facing GREEN / ORANGE / RED classification derived from the
  final action and the governing tier (§2.9). Derived, never stored independently.
- **RED sub-type** — `ATTACK_DETECTED` or `TRUSTED_SOURCE_COMPROMISE`, distinguishing whether
  the document or the source is the unit of concern (§2.9.2).
- **Cited docs** — retrieved documents the generation step actually drew on.
- **Escalation dominance** — the reconciliation rule that the more conservative of the two
  tracks' proposed actions wins (§3.9).
- **Governing tier** — the trust tier of the highest-attribution cited document (§2.2).
- **LOAFO** — Leave-One-Attack-Family-Out evaluation (§3.6).
- **`n_eff`** — effective independent evidence count after attribution and duplicate
  correction (§4.3).
- **Poison family** — a template or strategy used to generate a class of poisoned documents.
- **Quarantine** — flag and exclude from retrieval while retaining the document (§2.6).
- **Rule track / statistical track** — the taxonomy and the fitted score, respectively (§0.2).
- **Verification sampling** — blind analyst review of a random slice of auto-Accepted
  responses (§5.6).
