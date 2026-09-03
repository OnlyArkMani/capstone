# Session Log — The Three Level 2 Detectors

**Date:** 3 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main output:** the `detectors/` package — three independent detectors plus a sanity-check harness

---

## What this session was for

We have a pipeline that retrieves documents. This session built the three things that
*look at* those documents and produce a number each:

1. **Embedding anomaly** — is this document an outlier compared to the others retrieved?
2. **Prompt injection** — does this document contain instructions written for the AI?
3. **Entailment** — does this document actually support the answer that was generated?

They are deliberately kept independent. None of them can see the others' output. Combining
them is the next sprint's job, and every paper we reviewed reaches the same conclusion —
no single detector should be trusted on its own — so keeping them separate is what makes
combining them worth anything.

---

## Housekeeping first

Three open items from earlier sessions got closed:

- **`eval/target_queries.txt` now exists.** Our own docs referenced it but nobody had
  written it. It's the 10 questions the poisoned documents were built to intercept, pulled
  straight from the ground-truth manifest so it can't drift.
- **The generator question is settled** — Groq for the headline evaluation, Ollama's 3B for
  local iteration, and both arms of the comparison must use the same one.
- **The "does anything read the answer key" check is now real.** More on that below.

Still open and genuinely blocked: installing the real models. Neither this environment nor
the project's network policy can reach PyPI or Hugging Face, so all three detectors ran on
fallbacks. That's your machine's job.

---

## What each detector does, and the decisions inside them

### 1. Embedding anomaly

Clusters the retrieved documents and scores each one by how far it sits from its nearest
cluster centre.

**Clustering five things is barely clustering.** With k=5 retrieved documents, k-means is
extremely unstable, and pretending otherwise produces confident noise. So below four
documents it doesn't cluster at all — it measures distance from the centre of the set and
says so. At one document it returns zero, because a single document can't be an outlier
relative to nothing.

**We deliberately did not use min-max scaling**, which is the obvious way to squeeze scores
into 0–1. Min-max always makes exactly one document score 1.0 and one score 0.0, whether or
not anything is actually odd — so it would invent a maximum-severity anomaly in every
perfectly clean set the system ever sees. We scale by how spread out the distances are
instead, so a clean set scores near zero across the board.

**We expect this to be the weakest of the three, and that is a result, not a bug.**
PoisonedRAG documents are *built* to sit close to the query in embedding space — that's the
attack. A document engineered to look relevant can land comfortably inside the cluster it
was aimed at. If this detector scores poisoned documents low, that tells us something true
about the attack. The test harness prints that explanation so nobody later reads it as a
failure and "fixes" it.

### 2. Prompt injection

Uses a pretrained classifier to spot text addressed to the model rather than to a person.

**One detail that would have been an invisible disaster:** we look up which output class
means "injection" *by its name*, not by assuming it's the second one. Different releases of
this model have shipped with the labels in different orders. Get it backwards and the
detector reports every clean document as an injection — while producing entirely
plausible-looking numbers that nobody would question until much later.

**A limit we're stating now rather than discovering later:** our corpus contains exactly
**one** document with an injection payload. That's enough to confirm the signal fires. It
is nowhere near enough to set a threshold or estimate how often it false-alarms. No
performance number for this detector is reportable until we write more of that attack type.

### 3. Entailment

Uses a natural-language-inference model to ask whether a claim is actually supported by a
piece of evidence.

Same by-name label lookup, for the same reason and with higher stakes — swapping
"entailment" for "contradiction" would invert the most important signal in the whole system
while still producing numbers that look fine.

This is also the one signal that runs *backwards* from the others: higher means safer, not
riskier. Rather than expect everyone to remember that, the function returns the risk-facing
version (`1 - entailment`) as its main score, with both numbers available underneath.

**We also added the doc-vs-doc conflict measure here.** Our design needs a way to detect
two Tier-1 sources contradicting *each other* — the "authorities disagree" case, which is
not an attack and must not be scored as one. None of the four named signals covers it. It
turned out to be the same NLI model applied to pairs of documents, so it costs no new
dependency and no new download. It sits in this module rather than being a fourth detector
because it is literally the same model call.

---

## The sanity check

`python -m detectors.test_detectors -v`

This is not a performance evaluation. It answers one question before we build fusion on
top: **given documents we already know the answer for, does each detector point the right
way?** A detector wired backwards produces confident, plausible, wrong numbers, and finding
that out after three signals have been combined is much more expensive.

Twenty structural checks pass — output shape, per-document scores, 0–1 range, singleton and
empty-input behaviour, all three detectors agreeing on document IDs.

The interesting part is the entailment test. For each of our 10 target questions it scores
*the attacker's intended answer* against the poisoned document and against the real one.
Even on the weak fallback, the gap is clear:

- attacker's claim, supported by the **poisoned** document: **0.67**
- attacker's claim, supported by the **clean** document: **0.30**
- true answer, supported by the clean document: **0.72**

That's the direction we need. Ten of our twelve poisoned documents support the attacker's
claim more than the genuine document does. Two don't — the Log4Shell severity downgrade and
one of the attribution fabrications — which is worth looking at again once the real model is
installed, because those two may simply be subtler attacks.

Injection: the one document with a payload scored 1.00 and everything else scored 0.00.
Clean separation, on a sample size of one.

Anomaly: 5 of 12 poisoned documents ranked most-anomalous in their set. Consistent with the
expectation above.

---

## A bug we found in our own tests

Last session's pipeline test had a check that "no module reads the ground-truth answer key",
implemented as a string search. It was wrong in both directions, and we only noticed because
we copied it into the new package.

The problem: both packages *document* the fact that they don't read ground truth. So
searching for the phrase flags exactly the modules that are being most careful about it.
Then when we tightened it, it flagged the corpus loader — which contains the string
`"ground_truth"` as the name of a field it **bans**, i.e. the guard itself.

The fix is a proper one: parse the code, ignore comments and docstrings entirely, and look
only for actual file paths and the specific constants that point at the manifest. Both
packages now pass honestly, and the corpus builders — which legitimately *write* the
manifest — are correctly identified as touching it.

Small thing, but a test that passes for the wrong reason is worse than no test.

---

## What's open

1. **Install the real models** (`pip install -r detectors/requirements.txt`) and re-run.
   Everything above is structural evidence only. The fallbacks are honest about this: the
   test harness prints "RUN IS NOT CONCLUSIVE" and lists which detectors were faked.
2. **Write more injection-family poisoned documents.** One example can't support a
   threshold.
3. **Watch the two poisoned documents that entailment didn't separate.** They may be subtler
   attacks worth studying, or the lexical fallback may simply be too crude to see them.
4. The pairwise conflict measure costs k² model calls. Fine at k=5; benchmark it before
   raising k.

---

## Next session

Level 3 — fusion. Take these three signals plus the evidence-conflict check, encode them per
the design, and produce the composite risk score and the case classification.
