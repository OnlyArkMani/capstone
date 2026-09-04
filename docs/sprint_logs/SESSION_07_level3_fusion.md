# Session Log — Level 3: Putting the Signals Together

**Date:** 4 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main output:** the `fusion/` package — one function that turns three detector scores into a trust percentage, a named situation, and a recommended action

---

## What this session was for

Up to now the project produced numbers that nobody could act on. Retrieval gave us five
documents with similarity scores. The three detectors each gave every document a score
between 0 and 1. That's a lot of numbers and no decision.

This session built the layer that answers the question an analyst actually has:

> **How much can I trust this answer, how sure are you of that, what kind of situation is
> this, and what should I do about it?**

One function call now returns all four.

```python
from fusion import score_query
result = score_query("ransomware targeting hospital imaging systems", records)

result.trust_percent        # 87.4    — how trustworthy, 0 to 100
result.confidence           # 0.62    — how much to trust that number
result.confidence_interval  # (79.1, 92.8)
result.case_id              # "C6"    — Open-Feed Irregularity
result.action               # "REVIEW"
result.headline             # "ORANGE" — the traffic-light an analyst reads first
```

---

## Three parts, and why it isn't just one number

### Part A — the case classifier

A risk score tells you *how worried* to be. It does not tell you *what kind of thing you are
looking at*, and that's what decides the response.

Two examples that could carry the identical risk score and need completely different
handling:

- Two government advisories contradict each other. Nobody attacked anything — one was
  probably revised. The right move is to show the analyst both and let them decide.
- An unverified blog is lying. The right move is to throw the answer away.

So the classifier assigns a **named case** first. Nine of them come from crossing the three
source trust tiers with three content outcomes (clean, suspicious, malicious), plus two more
that describe the shape of the whole retrieval set rather than any single document. Eleven
in total, each carrying a priority and an action.

The two entries that matter most:

**A slightly odd document from a government source outranks an outright malicious document
from a random blog.** This looks backwards. It is the design's central claim, and it comes
from three things. Odd behaviour from a verified source is improbable *by definition* — we
classified it as verified because we expected it to behave — so seeing it tells us far more
than the same oddity from a source we already distrusted. Everything downstream trusts the
government feed, so the damage spreads further. And every explanation for it — the source
was compromised, our fetch was intercepted, we mislabelled the provenance, someone edited it
internally — is a problem with **our own system**, not with this one question. That's why
the action is *escalate to the security team* rather than *reject this answer*.

**Two authorities disagreeing is not an attack.** The system is forbidden from quietly
picking a winner. There is no principled basis for choosing between CISA and HHS, and doing
so would hide from the analyst the single most useful fact available — that the authorities
disagree. There is one condition attached: if the contradiction comes with a live injection
signal, it's treated as a possible compromise wearing the costume of a disagreement, and
handled as the more serious case instead.

**Reject and Escalate are not degrees of the same thing.** Reject protects *this answer*.
Escalate protects *the system* — this question was merely how we noticed.

### The traffic light on top

Eleven cases and four actions are precise, but they are not what someone glances at first. So
the layer also produces a three-state headline:

- **GREEN — "Good to Go."** Verified authoritative source, clean signals, automatic accept.
- **ORANGE — "Mid-Suspicious, Review Recommended."** Return it, mark it unverified, put it in
  the analyst's queue.
- **RED — "Reject / Escalate,"** in two flavours: *Attack Detected* when the trouble comes
  from a source we never vouched for, and *Trusted Source Compromise Suspected* when it comes
  from one we did.

That last split is the whole reason RED isn't one thing. A malicious document from a random
blog and an anomaly in a CISA advisory can produce the same score. The first is closed by
quarantining a document. The second means something may be wrong with our own trust
infrastructure, and that outlives the question that surfaced it. Collapsing both into a single
red light would throw away the most useful fact we have.

**GREEN is deliberately hard to reach.** It requires two things at once: an explicit accept
*and* a verified Tier-1 source. Tier 3 can't be green because quiet signals from an unverified
source mean "nothing stood out", not "this is trustworthy" — the absence of evidence against a
document is not evidence for it. Tier 2 can't be green either, which is a policy choice: a
moderated but community-writable feed is trusted enough to search, not trusted enough to hand
back unexamined. That costs us review load and we accepted it knowingly.

Everything else — an action the code doesn't recognise, a missing tier, anything ambiguous —
falls to ORANGE. There is no branch anywhere that says "otherwise, green". A system that shows
green when it doesn't know what else to show has inverted the entire point.

One honest note: because green now requires Tier 1, the separate "Tier 3 is never green" rule
can't currently fire — Tier 1 already excludes it. We kept and tested both anyway. They say
different things (one is about unverified provenance, one is about review capacity), either
could be relaxed later, and only two of the eleven cases lead to an accept at all — which is
exactly how a guarantee like this gets lost quietly.

### Part B — the composite score

A logistic regression that learns how much each detector signal is worth, rather than us
picking weights and hoping. Four decisions inside it are worth recording.

**The source tier is encoded as separate yes/no columns, never as the numbers 1, 2, 3.**
This is the most consequential line of code in the project. Writing it as 1/2/3 forces the
model to assume risk rises steadily as tier number rises — which is the exact opposite of
the inversion described above. It wouldn't just make the model less accurate; it would make
that relationship *impossible to represent*. The model would be structurally incapable of
learning the one thing it exists to learn.

**The feature set shrinks automatically when the data can't support it.** Statistics has a
rough rule of about 10–15 examples of the rare class per input variable. Our corpus is
small, so the code counts the positives and picks the appropriate size of model, then
labels the result **underpowered** in every report where it appears. It is much better to
say "this is indicative" than to publish confident numbers from a model fitted on too
little.

**Splits are grouped by attack family.** All the variants of one attack go entirely into
training or entirely into testing, never both. A plain random split would put near-identical
copies of the same attack on both sides, and every accuracy number we reported would be
inflated by it.

**The response-level score is the worst document, not the average.** This attack works by
slipping one crafted document in among four genuine ones. Averaging it against its four
clean neighbours is precisely how it survives.

### Part C — confidence

Risk and confidence answer different questions, and we keep them as separate outputs.

A risk of 0.85 from five agreeing documents across three independent sources is a finding.
The same 0.85 from one document with the detectors contradicting each other is a guess.
Reporting them as the same number would hide that from the analyst.

Five components: how much evidence there is, whether it agrees, whether the sources are
genuinely independent, whether the detectors concur, and how stable the model's output is
for this particular input.

They're combined by multiplying rather than averaging. Confidence is an *and*, not an
average — we're confident only if there's enough evidence **and** it agrees **and** it's
independent **and** the detectors concur **and** the model is stable. Averaging lets four
strong components hide one fatal weakness, which is exactly the failure we can't afford.
Any component at zero takes the whole thing to zero, which is correct.

Three hard limits regardless of anything else: a one-document answer can never exceed 0.30
confidence; five near-duplicates from one feed are capped like one document; and below 0.35
a human looks at it whatever the score says. Low confidence can only ever make the outcome
*more* cautious, never less.

---

## How the two halves are reconciled

The case classifier and the fitted model both run, over the same signals, and **the more
cautious one wins**.

This guarantees that adding the statistical model can never make the system less safe than
the rules alone. That's worth having when the model was fitted on a corpus we built
ourselves. Only the rule side can trigger *escalate*, because escalation is a claim about
the system and needs the meaning of a case, not a number.

Two more one-way constraints: low confidence forces at least a review, and the thresholds
are applied to the **top** of the uncertainty range rather than the middle — so an uncertain
answer drifts toward review automatically, with no extra rule written for it.

---

## Four problems we found, and what we did about them

### 1. A detector that always returns zero would have marked the whole corpus malicious

The thresholds for "suspicious" and "malicious" are set at the 95th and 99th percentile of
how the *clean* documents score. That's deliberate — it makes our false-alarm rate a
decision we make up front rather than something we discover later.

But the injection detector is running on a fallback (no network to download the real model),
and the fallback returns exactly 0.00 for every clean document. The 95th percentile of a
column of zeros is zero. Which means *every* document scoring above zero would have been
flagged malicious — the entire corpus.

The mirror-image failure was also present: another signal's threshold came out at 1.00,
which nothing can ever exceed, silently killing the signal.

The fix is a check for whether a signal's clean scores have any spread at all. If they
don't, the signal is marked **unusable** and taken out of the decision entirely, with the
reason recorded. Having no threshold for a signal is much better than having a meaningless
one.

### 2. Two of our three signals were pointing the wrong way

When we measured how well each signal separates poisoned documents from clean ones, two came
out **backwards** — poisoned documents scored *lower* than clean ones.

We now measure this before fitting, print it, and drop any inverted signal rather than
letting the model quietly learn a negative weight and produce plausible nonsense.

The likely reason for one of them is genuinely interesting and not a bug. The published
attack method works by making the poisoned document restate the question almost word for
word, so it ranks highly in retrieval. Our entailment check currently asks "does this
document support the question?" — and a poisoned document, by construction, supports the
question *better than a real document does*. We are measuring the attack's own mechanism and
reading it as innocence.

The fix is to ask the right question: does the document support the **generated answer**,
not the query. That needs the answer generator in the loop, which is the next session's
work. Both the code and the reports say so explicitly so nobody quotes the current numbers
as final.

### 3. Our headline comparison was unfair to us in one direction and to the baseline in the other

We compare against a naive baseline: block anything where any single detector scores above
0.5.

That baseline blocks **80% of all clean documents** in order to catch 29% of attacks. It's
useless in practice, but comparing at each system's own operating point made it look
respectable. Any system can score well on "attacks blocked" by blocking nearly everything.

So the evaluation now also reports a matched comparison: at the baseline's own 80% false
block rate, our score catches **everything** the baseline missed. That's the honest
comparison and it's labelled as such in the output, right next to the note explaining why
the raw figures aren't.

### 4. (Found by the new tests) The uncertainty range didn't contain the number it described

The tests caught a real bug in our own code: the reported risk was 0.34 with an uncertainty
range of 0.73 to 0.88. The range didn't include the value.

Cause: the range came from 200 refits of a *raw* model, while the reported number came from
the *calibrated* one. Two different scales. Fixed by taking the *width* from the refits and
the *position* from the calibrated number, so the range always contains the value by
construction. This is exactly the kind of thing that ships silently if nobody writes the
test.

---

## Testing

`fusion/test_fusion.py` — 115 checks, all passing. These are **contract tests**, not accuracy
tests: they ask whether the machinery does what the design says, not how well it detects
anything. Accuracy comes from the training run.

The distinction matters because a fusion layer wired backwards still produces confident,
well-formatted, wrong numbers.

Among the things it checks: all nine grid cells map to the right case and action; the
tier-1 inversion survives end to end; the tier encoding is never ordinal; every combination of
action and source tier produces the right traffic-light colour, including nonsense inputs that
must fall to orange; combining two actions can never produce a *less* cautious one than either
input; a one-document answer can never be high confidence; the model saves and reloads to
identical predictions; and no module on the scoring path can read the answer key.

**A correction to yesterday's figure.** This log originally said 66 checks. That number was
wrong — it was written without counting. The real figure was 92 before today's additions and
115 now. Every other number in this log came from a run; that one didn't, and it has been
fixed everywhere it appeared.

That last one is checked by parsing the code rather than searching the text, so a module
that *documents* not reading the answer key isn't flagged for saying so. We got that wrong
in an earlier session and fixed it properly then; the same checker is reused here.

---

## What the current numbers actually mean

**The plumbing is correct and tested. The inputs are not real yet.**

This environment has no internet access, so all three detectors ran on stand-ins — pattern
matching instead of the trained injection classifier, word overlap instead of the language
model that judges entailment, a simple hash instead of the sentence embedder. Every accuracy
figure the training run prints is evidence that *the layer works*, not a measurement of *how
well it detects poisoning*.

The training script prints a warning block listing exactly which detectors were faked, and a
verdict block when every signal is statistically indistinguishable from chance, so a
stand-in number cannot be quoted as a result by accident.

What the run does establish: 470 labelled examples were built from 94 queries across 78
attack groups; the model fitted, calibrated and saved; thresholds derived; and every
structural property the design asserts held up under test.

---

## What's open

1. **Install the real detector models and refit.** Everything numerical above is provisional
   until this happens. This is your machine's job — it needs internet access we don't have
   here.
2. **Put the answer generator in the loop** so entailment scores the generated claim instead
   of the query. This is the fix for the inverted signal, and it is a design correction
   rather than a tuning exercise.
3. **Build the fourth signal** — the check for retrieved evidence contradicting what the
   model already knows. It's designed but not built, and it is currently *absent* rather
   than zero-filled, which is the correct handling.
4. **The corpus directory is not in version control.** `corpus/` shows as untracked in git —
   the clean and poisoned document sets from sessions 2 and 4 were never committed. That
   needs fixing before submission; the benchmark is the project.
5. More poisoned documents in the injection family. One example still can't support a
   threshold.

---

## Also this session

The headline classification described above was added after the main build, on request. It
touched the design document (new §2.9, bumped to `design-v1.2`), `fusion/cases.py`, the two
places in `score_query()` that assemble a result, and the tests. No case definition, trigger,
priority or action changed — the traffic light is *derived* from the action and the tier
rather than being a second opinion that could disagree with them.

Worth recording: the spec we were handed used a six-case numbering that didn't match our
eleven. Read literally, two of the mappings would have inverted important cases — putting the
Tier-1 anomaly case (our most urgent) into orange, and the harmless Tier-3-clean case into
red. We checked before writing anything and settled the mapping first.

---

## Next session

Level 4 — the analyst-facing report. Take what `score_query` returns and render the evidence
trail, the provenance panel and the case explanation into something a person can read and
act on, plus the analyst decision record that Session 3 designed.
