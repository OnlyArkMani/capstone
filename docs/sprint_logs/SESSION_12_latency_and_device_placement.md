# Session Log — Making a Query Fast Enough to Demonstrate

**Date:** 6 September 2026
**Team:** Zetabyte
**Session type:** Performance work, plus two configuration faults found on the way
**Main output:** `pipeline/device.py`, `eval/profile_latency.py`, and a query that went from about eight seconds to about one

> Short version: a query took roughly eight seconds, which reads as broken when
> somebody is watching. It turned out almost all of that was one model doing real
> work on the wrong processor. We moved it to the graphics card, stopped it
> re-answering questions it had already answered, and a query now takes about 1.2
> seconds the first time and under a tenth of a second if you ask it again. We
> also found two configuration faults that had nothing to do with speed and would
> have been much more embarrassing to find later. Nothing about what the system
> detects changed — we checked that field by field after every single step.

---

## Why we did this

Every query through the console took about eight seconds. Nothing was wrong with
the answers, but a wait that long with no explanation reads as a system that is
struggling, and we are going to run this live in front of a mentor and a panel.
The concern was not really the seconds. It was that the seconds make careful work
look shaky.

The rule we set before touching anything was that this had to be a **pure speed
change**. If any figure about what the system detects moved, we had made a
different change than the one we intended, no matter how much faster it was.

---

## We measured before we changed anything

It is tempting to guess at this kind of problem, and guessing is how people spend
a day optimising something that was never the bottleneck. So the first thing we
built was `eval/profile_latency.py`, which measures four specific things and
writes them to a file so runs can be compared later.

Two of those four questions were about things we suspected. The other two turned
out to be fine, and knowing that saved us the work of "fixing" them.

**Was anything loading a model from disk on every query?** No. We counted the
model constructions by intercepting the constructors before any of our own code
loads, and across ten queries the count was zero. The caching already in the code
was doing its job. Nothing to fix.

**Were the model calls being sent one at a time instead of together?** No. All 25
comparisons per query already travel as two batched calls, none of them singly.
Nothing to fix here either.

**Was the document comparison doing more work than the design asks for?** No, and
this one is worth stating carefully, because it was the obvious place to cut. At
five retrieved documents the system does 5 claim comparisons and 20 document-pair
comparisons. That is exactly what the design specifies — it compares every
document against every other one, in both directions. It is expensive on purpose.
The alternative, comparing each document only against a single reference answer,
would be about half the cost and would also delete the signal that case C10
depends on, which is how we spot two trusted sources contradicting each other.
We did not do that. Making something cheap by making it do less is not a speed
fix.

**Was anything running on the wrong processor?** Yes, and this was the whole
problem.

---

## The actual cause

Every model was running on the CPU while the machine's graphics card sat idle at
0%.

The interesting part is *why*, because it was not a missing line of code. The
version of PyTorch installed was the CPU-only build — a separate download that
physically does not contain the graphics-card support. No amount of telling it
"use the GPU" could have worked, because there was nothing there to use. Our own
`requirements.txt` was the culprit: it instructs a CPU-only install, which is the
right default for a machine without a card and exactly wrong for one with a card.

That is a nasty class of fault. Nothing errors. Nothing warns. The only symptom
is that everything is slow, and "slow" is the one symptom people blame on the
system being big rather than on the system being misconfigured.

---

## Two faults we found that had nothing to do with speed

**The search index had been built with the wrong model.** The pipeline is meant
to understand meaning, using a model called bge-small. When that model cannot be
downloaded, the code falls back to a much simpler method that matches on letter
patterns instead of meaning — and it says so in a warning, and its own source
comments say results from it are "not meaningful". The index on disk had been
built with that fallback back on 3 September, and the real model had never
successfully downloaded until this session. So every evaluation number we had was
produced by a spelling-similarity matcher rather than by the system we describe
in the report.

We rebuilt the index with the real model and re-ran everything. The archived
results are kept in `eval/results/archive_hashing_index/` with an explanation
attached, rather than quietly overwritten. The reassuring part: **every detection
figure came out identical.** The correction cost us nothing except the honesty of
being able to say what produced the numbers.

**The trust model was being loaded by a different version of the maths library
than the one that built it.** scikit-learn does not promise that a saved model
loads correctly across versions — it warns and then carries on anyway, which
means wrong numbers that look completely normal. Our code already checks for this
and was printing "the trust scores from this run may be invalid" on every single
run, including in front of anyone we demonstrated to. We matched the environment
back to the versions recorded in the file, the warning went away, and the results
came out identical — so the drift had been harmless. But that was not knowable
until we checked, which is the entire point of the check. We also pinned the two
libraries that were only loosely specified, so it cannot drift back.

---

## What we changed

**One place decides where models run.** A new file, `pipeline/device.py`, answers
"CPU or graphics card?" once, for everything. It never crashes: if a card is
asked for and cannot be reached, it says so plainly and falls back to the CPU. It
also distinguishes "this machine has no graphics card" from "this build of
PyTorch cannot see the card it has", because those look identical from outside
and need completely different fixes. The chosen device is written into the audit
trail, so a future slow run can be explained rather than guessed at.

While wiring this in we found a dormant bug in the injection detector: it would
have moved the model to the card but left its input data on the CPU, which
crashes. That path is not the one we use by default, so it would have surfaced
for whoever ran those experiments next. Fixed while we were in there.

**The system stopped re-answering identical questions.** The document-comparison
model gives the same answer for the same two pieces of text, always, and our
corpus of 88 documents never changes. So we remember the results. A remembered
result is the *same* answer the model would have given — same model, same weights,
same text — which is what makes this allowed under a no-change rule, where
reducing the number of comparisons would not be. Ask a question twice and the
second one is near-instant.

**The corpus is prepared at startup instead of during queries.** Same values,
computed while nobody is waiting.

**The console now says what it is doing.** Instead of one anonymous spinner, the
wait is now labelled: *Retrieving evidence → Running security checks → Building
the analyst report → Recording to the audit log*, with the security step naming
the four checks running underneath it. We would have done this even if we had
made no speed improvement at all. A labelled wait reads as a system working; an
unlabelled one reads as a system stuck.

---

## What it is worth

| | Before | After |
|---|---|---|
| One query, first time asked | 7.6 seconds | **1.2 seconds** |
| The same query asked again | — | **0.09 seconds** |
| Full 40-query evaluation | 313 seconds | **46 seconds** |

Inside that 1.2 seconds, the document-pair comparison is still about 78% of the
work. That is the design doing what it is supposed to do, and we have written the
measurement into the design document as the answer to a question it had left open
since the start: *is this quadratic comparison affordable?* Yes, at five
documents. We also wrote down where that stops being true, because it does.

---

## How we know we did not break anything

After every single change we re-ran the full evaluation and compared the results
field by field — not by looking at the table, which is easy to skim past, but by
comparing every value in the results file. Attack success rate, false positives,
false negatives, how many queries get accepted or blocked or sent to a human, and
the detection rate for every attack family, every trust tier and every case.

**Zero differences, every time.** The only things that changed were the timings,
the timestamps, and a note about which backend produced them.

---

## Two mistakes we caught in our own measurements

Worth recording, because both would have put a wrong number in front of a panel.

Our own profiler briefly lied to us. Once results were being remembered, it was
timing each step individually and then timing the whole thing — which meant the
whole thing was reading from memory that the individual steps had just filled. It
reported one step as taking 1,024% of the total, which is how we noticed. It now
measures each step with the memory switched off, and reports "first time asked"
and "asked again" as two separate numbers, because they genuinely are.

The evaluation harness also had a sentence claiming the run used fallback models
and that "real models would be substantially slower". That was true when it was
written and false the moment the real models were installed — and it understated
our own system's cost. It now names the model and the device it ran on.

---

## What is still open

- The pair-remembering helps in proportion to how much different queries retrieve
  the same documents. Over our 40-query evaluation that was 19.5%. A different
  query mix would give a different number.
- The measurement is one laptop graphics card, no other load, 88 documents,
  five documents retrieved per query. Retrieval depth is the thing that would
  hurt: eight documents instead of five is 56 pair comparisons instead of 20.
- Three test files fail under `pytest` on Windows for reasons unrelated to any of
  this: the audit tests leave database connections open, and Windows refuses to
  delete a file that something still has open. Every check inside them passes;
  it is the cleanup that fails. Worth fixing before anyone runs the suite in
  front of a mentor.
