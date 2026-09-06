# Session Log — Checking the Answer Instead of the Question

**Date:** 6 September 2026
**Team:** Zetabyte
**Session type:** Correctness fix, plus one small test repair
**Main output:** `pipeline/hypothesis.py`, a refitted model, and an uncomfortable finding we decided to write down

> Short version: our system was checking whether the evidence supported the
> *question* rather than the *answer* — which is backwards, and our own design
> document had said so for weeks without anyone noticing it applied to the live
> system. We fixed it. One broken thing got fixed (a coefficient that was
> pointing the wrong way), the safety guarantee held, false alarms went down,
> and slightly more bad documents got through. And while measuring all that we
> found something more serious that we had not been looking for, which is now
> written into the design document and the README rather than left in a JSON
> file nobody opens.

---

## What was wrong

The entailment detector asks: *does this retrieved document actually support the
claim being made?* The claim is supposed to be the answer the system generated.
Our design document says so in two places.

What the live system actually did was compare each document against the
**question the user typed**. And there is a specific reason that is worse than
merely being a bit off: a poisoned document is *written to look like the query*.
That is how the attacker gets it retrieved in the first place. So when you score
evidence against the question, poisoned documents look *better supported* than
genuine ones. The signal runs backwards.

We already knew this. Section 9A.4 of our design document measured it at AUC
0.248 — where 0.5 is a coin flip, so 0.248 is meaningfully worse than guessing.
What we had not noticed is that the fix described in that section had only been
applied to the **training** side. The model was trained on one thing and used on
another.

---

## The thing we checked before starting

We were asked to just pass the generated answer through, on the reasonable
assumption that generation already happens before detection. It doesn't. Neither
the console nor the evaluation harness called the answer generator at all —
they went straight from "retrieve documents" to "run detectors". So this was not
a matter of plugging in a value that was already sitting there. The generation
step had to be *added* to every query, which costs real time and needed a
decision rather than an assumption. We stopped and asked first.

We also checked whether refitting the model would fix the wrong-signed
coefficients, since that was the hoped-for outcome. It could not, and we said so
before running it: the training set was *already* using generated answers, so
that experiment had effectively been run. We were right about that, and it is
worth recording that we predicted it rather than discovered it afterwards.

---

## What we did

**One place now decides what the claim is.** A new file, `pipeline/hypothesis.py`,
produces the entailment hypothesis for both the console and the evaluation
harness, so the two cannot quietly drift apart again. It:

- refuses the extractive stub, which returns sentences copied out of the
  retrieved documents — using it would ask whether a document supports a
  quotation of itself, which is circular;
- falls back to the old behaviour **one query at a time** rather than for a whole
  run, and records on every row which was used and why, so a mixed run is visible
  instead of averaged away;
- remembers answers so asking the same question twice does not produce two
  different answers and therefore two different verdicts.

**Generation now runs locally.** We switched to Ollama with `llama3.2:3b` on the
graphics card, so training and inference use the same model, there are no API
rate limits, and the whole thing works offline. The default is now "use whatever
is available" rather than a fixed choice, which is why the console had ended up
with no generator at all on a developer machine.

**We refit the model** on the corrected setup, using the same grouped
cross-validation and calibration as before.

---

## What it changed

**Fixed:**

| | Before | After |
|---|---|---|
| Unsupport coefficient | −0.138 (backwards) | **+0.021** (right direction) |
| False alarms on genuine documents | 50.0% | **39.3%** |
| Documents blocked outright | 50.0% | 40.0% |

**Held — this is the one that matters:**

| | Before | After |
|---|---|---|
| **Attacks the system vouched for** | **0.0%** | **0.0%** |
| Attacks that reached the user at all | 60.0% | 60.0% |
| Genuine queries sent to a human | 100% | 100% |

**Got worse:**

| | Before | After |
|---|---|---|
| Bad documents reaching the user | 50.0% | 56.3% |
| `ioc_reputation_flip` caught | 16.7% | 0.0% |
| `severity_downgrade` caught | 80.0% | 60.0% |

Read together, this is the system becoming *less trigger-happy*: documents moved
out of "blocked" and into "send to a human". That buys eleven points of false
alarms and costs six points of exposure. The underlying ability to tell good from
bad did not improve — the held-out ranking scores were 0.1815 and are now 0.179.

So this was a **correctness fix, not an accuracy improvement**, and we have
written it up that way in the design document. It would have been easy to quote
the false-alarm improvement on its own and call it a win.

---

## The thing we found that we were not looking for

While comparing before and after, we looked properly at how well the fitted
model actually predicts on data it was not trained on. It scores **0.179**.

That number needs saying carefully. Below 0.5 is not "weak". It means the model
ranks poisoned documents as *safer* than genuine ones on data it has not seen.
The composite trust score, taken alone, is worse than a coin flip.

This is not something we broke today — it measured 0.1815 before this session —
but it had never been stated anywhere a reader would find it.

The reason the system still behaves safely is the part of the design nobody has
been paying attention to. There are two tracks: the rule track (our case
taxonomy) and the statistical track (this model). The design says the more
cautious of the two always wins. That rule was written as defence-in-depth
against a model that might be *opaque*. On our corpus it is doing something
stronger: it is protecting the system from a model that is *wrong*.

Three of the four signals explain it. The anomaly signal points the wrong way and
is dropped automatically at training time. The injection signal is **identically
zero on all 490 training rows** — it never fires once, so its coefficient is pure
noise, which is also why that coefficient is still wrong-signed and why no
amount of fixing the hypothesis could ever have changed it. Only the
document-versus-document contradiction signal separates the two classes at all.

We have written this into the design document as section 9A.8 and made it
Limitation 1 in the README. It is the most important open item in the project and
it deserves to be found by us rather than by a panel.

---

## Also fixed

The audit test suite failed three tests on Windows. Every check inside them
passed; the failure was in cleanup — the tests opened database connections and
never closed them, and Windows will not delete a file that something still has
open.

Worth recording that the obvious fix was wrong and the test suite caught it.
Closing the connections without committing first threw away the change one of
those tests deliberately makes — it edits a stored row to prove the tamper-proof
chain notices — so the tamper was undone, the chain verified, and the test failed
for the opposite reason. Both behaviours were needed. The explanation is in the
code so the next person to tidy it has the trap in front of them.

---

## The cost

A query now takes about 13 seconds, up from 1.1. Nearly 10 seconds of that is the
local language model writing the answer.

Two honest things about that number. It is *not* all security overhead: a real
deployment generates that answer anyway, because the answer is the thing the
analyst asked for. The detection layer's own cost is 3.2 seconds. But that is
still up from 1.1 seconds, because the thing being checked is now a full
paragraph instead of a one-line question, so every comparison is longer.

There is an obvious follow-up if 13 seconds is too slow for the demo: the console
currently generates an answer, uses it to check the evidence, and then throws it
away without showing it. It should display it. Right now we are paying for
something the analyst never sees.

---

## What is still open

- The composite score (above). This is the real one.
- The injection signal never fires on our training retrievals, so that feature is
  dead weight. That is a corpus problem, not a model problem.
- Answer-level attack success is still unmeasured. We now generate an answer, but
  nothing reads it to decide whether it repeats the attacker's claim. We also
  fixed a reporting bug where this caveat *disappeared* from the output as soon as
  a generator was present — the report was quietly dropping its most important
  qualification at exactly the moment it looked most convincing.
- Figures are comparable within one generator, not across generators. Everything
  before today used Groq's 20B model; everything now uses a local 3B one.
