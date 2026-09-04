# Session Log — The Evaluation

**Date:** 4 September 2026
**Team:** Zetabyte
**Session type:** Measurement
**Main output:** `eval/run_evaluation.py` and the results in `eval/results/`

> **Read this section first.** These are the numbers, stated plainly. The
> qualifications below them are real and they matter, but they are qualifications,
> not excuses, and none of them changes what the table says.

---

## The headline numbers

Three configurations, the same 84-document corpus, 40 queries (10 that the poisoned
documents were specifically written to intercept, 30 clean controls).

| | **A** — no retrieval | **B** — plain RAG | **C** — our system |
|---|---|---|---|
| **Attack success — poisoned content reached the user** | 0% ‡ | **100%** | **90%** |
| **Attack success — system vouched for it** | 0% ‡ | **100%** | **0%** |
| False positives — clean docs blocked | 0% ‡ | 0% ‡ | **18.1%** |
| Clean queries pushed to a human | 0% ‡ | 0% ‡ | **93.3%** |
| Poisoned docs reaching the user | 0% ‡ | 100% ‡ | **86.2%** |
| Auto-accepted with no human needed | 100% | 100% | **5%** |
| Sent to human review | 0% | 0% | **77.5%** |
| Blocked outright | 0% | 0% | **17.5%** |
| Latency per query | — | 0.1 ms | **23.8 ms** |

‡ = true by the configuration's definition, not measured. A system with no
retrieval cannot be poisoned; a system with no security layer cannot flag anything.

---

## What that actually says

**The good result is narrow and real.** Our system never once returned a poisoned
document inside an answer it vouched for. The plain RAG baseline did so every single
time. On the specific question "does the system confidently assert the attacker's
claim", we go from 100% to 0%.

**The bad result is bigger and we should say it first.** Poisoned content still
reached the user in **9 out of 10** attack cases. It arrived flagged as unverified
and queued for review — but it arrived. Our attack-success rate only drops from 100%
to 90% on the measure that asks "did the bad content get in front of a person at
all".

**And the cost is severe.** The system auto-accepts **5%** of queries. It sends
**93% of clean queries** to a human. In its current state it is not a filter; it is a
machine for generating review work.

Put bluntly: **the system currently achieves its safety number by refusing to decide.**
It declines to vouch for almost anything, which is technically safe and operationally
close to useless.

### The number we nearly reported instead

Our first run of this evaluation printed **0.0% attack success** for our system, and
a clean 100% detection rate across every single attack family.

That was an artefact, and catching it is probably the most useful thing that happened
this session. We had defined "attack succeeded" as *the poisoned document came back
in an answer the system vouched for*. Since the system almost never vouches for
anything, almost nothing counted as a success — so the metric was quietly rewarding
the system for being indecisive.

But a "review" outcome still **returns the answer to the user**, marked unverified.
The poisoned document reached the reader in 9 of 10 cases. Only 1 of 10 was actually
blocked.

The evaluation now reports both definitions side by side, permanently, because
either one alone is misleading. It also reports the auto-accept and review rates
next to them, because an attack-success rate of zero is unreadable without knowing
what it cost.

---

## Where detection is weakest

This is the part worth studying, and it is bleak.

**By attack family** — how often the poisoned document was actually blocked:

| Attack family | Blocked | Rate |
|---|---|---|
| Direct prompt injection | 1 / 1 | **100%** |
| Authority spoofing | 2 / 5 | 40% |
| Remediation misdirection | 1 / 7 | 14% |
| Attribution fabrication | 0 / 3 | **0%** |
| IOC reputation flipping | 0 / 7 | **0%** |
| Severity downgrading | 0 / 6 | **0%** |

Three of our six attack families are caught **zero** times. The only family caught
reliably is the one with a literal "ignore previous instructions" string in it,
which the pattern-matching stand-in can see — and that is a sample size of one.

**By source tier**, blocking rates are 40% (Tier 1), 0% (Tier 2), 22% (Tier 3).

**The most damning detail:** every poisoned document that got retrieved was
classified into **C1, C2 or C3** — the three *clean* cases. Not one was assigned a
suspicious or malicious case. At the document level, the detectors did not flag a
single poisoned document as anomalous.

Which means the small amount of protection we do have is coming almost entirely from
the **tier and case rules** — the system being cautious about unverified sources —
and almost nothing from the detectors themselves.

---

## Why the detectors aren't detecting

This environment has no internet access, so none of the three detector models could
be downloaded. All three ran on stand-ins:

- the prompt-injection classifier → simple pattern matching
- the entailment model → word-overlap counting
- the sentence embedder → a hash function

Word overlap **cannot detect contradiction at all**, which is precisely what a
severity-downgrade or reputation-flip attack is. A document saying "this CVE is low
severity" and one saying "this CVE is critical" share nearly all their words. Our
stand-in scores them as agreeing.

So the honest reading is: **this evaluation measures whether the machinery works, not
whether the detection works.** The plumbing is correct — signals flow, cases are
assigned, actions are reconciled, the audit log records it, the dashboard shows it.
Whether the system can actually *detect* poisoning is genuinely unknown and cannot be
determined until the real models are installed.

The script prints this in a block titled "what this run could not measure", and every
figure in the saved output carries its measurement status.

---

## Two things we could not measure at all

**Answer-level attack success.** The proper definition of the metric is *the
generated answer asserted the attacker's claim*. With no language model there is no
answer to read. What we measure instead is whether the poisoned document reached the
answer surface — which is a **necessary condition** for the attack, so our figures
are an upper bound on the true rate. That cuts in our favour and against the
baseline, and the output says so.

**Whether configuration A is useless.** The no-retrieval configuration scores a
perfect zero on every risk metric, for the trivial reason that it does nothing. Its
real cost is that it cannot answer a question about current threat intelligence at
all. Demonstrating that also needs a generator, so we report its zeros as
*structural* and refuse to present them as a security result.

---

## The latency picture

The security layer adds about **24 ms per query** on top of retrieval. That is
comfortably fast — but it is 24 ms of *pattern matching*. Three transformer forward
passes per retrieved document will be substantially slower. Treat this as a lower
bound, not a result.

---

## What this means for the final presentation

Three honest claims we can make:

1. The architecture is complete and works end to end: retrieval → detection →
   fusion → case classification → analyst report → audit trail → dashboard.
2. On the specific question of *confidently asserting an attacker's claim*, the
   system goes from 100% to 0% against the plain-RAG baseline.
3. The evaluation is built to detect its own flattery. It caught our own metric
   definition rewarding indecision, and it reports the weaknesses in a table sorted
   worst-first.

Three claims we cannot make, and should say so before we're asked:

1. That the detectors detect poisoning. Untested — they were never loaded.
2. That the system is deployable. A 5% auto-accept rate is not an operating point.
3. That 90% of attacks still reaching the user is acceptable. It isn't.

---

## What's open

1. **Install the three detector models and re-run this script.** Everything above is
   provisional until then, and this is the single highest-value remaining action on
   the project.
2. **Put the generator in the loop** — needed both for answer-level attack success
   and to fix the entailment signal, which currently scores against the *question*
   instead of the *answer*.
3. **Revisit the operating thresholds.** A 5% auto-accept rate means the thresholds
   are calibrated far too conservatively for real use, and that is a tuning problem
   we can address once the detector scores are real.
4. **More poisoned documents in the injection family.** One example cannot support
   any claim about the one family we appear to catch.
5. **`corpus/` is still untracked in git.**

---

## Next session

Compile the whole project log and finish the documentation for submission.
