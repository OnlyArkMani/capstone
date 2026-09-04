# Session Log — The Analyst Report

**Date:** 4 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main output:** the `reports/` package — turns a scored query into the thing a security analyst actually reads

---

## What this session was for

Everything built so far produces numbers. This session built the part a person
sees.

That makes it the most important output in the system, and also the most dangerous
one. Every earlier layer can be wrong quietly — a detector score that's off by a
bit gets averaged in with others. A report is different: whatever it says, an
analyst believes and acts on. So the whole session was organised around one
question — **can we prove the report never says anything the system didn't
actually compute?**

---

## The headline goes first, and here's why that matters

Every report opens like this, before anything else:

```
==============================================================================
[ RED ]  REJECT / ESCALATE
          Trusted Source Compromise Suspected
==============================================================================
Action: ESCALATE  Risk tier: CRITICAL       Case: C4 Trusted-Source Anomaly
```

The colour first, alone. Score, case, evidence and reasoning are below it — the
detail someone opens when it isn't green, or when they want to check one that is.

It would have been natural to lead with the trust score instead. One of our own
test cases shows why that would have been a mistake:

- The fitted model scored that response **93.5% trustworthy**.
- The case rules spotted a trusted government source behaving oddly and escalated.
- The more cautious of the two won, so the system escalated.

A report leading with **93.5%** would have handed an analyst a reassuring number
sitting on top of a suspected source compromise. The colour can't do that, because
it comes from what the system *decided*, not from the score.

**Red is split in two**, and the split is visible in the first four lines:

- **RED — Attack Detected.** Bad content from a source we never vouched for. The
  document is the problem; quarantining it more or less closes the matter.
- **RED — Trusted Source Compromise Suspected.** A source we *had* verified is
  behaving strangely. The source is the problem, and it outlives this one question.

Someone scanning twenty red flags has to tell those apart without opening any of
them. They aren't equally common and they aren't equally urgent.

---

## The reasoning text, and the promise we had to keep

The brief was explicit: the reasoning must be grounded in the actual computed
values, never freely generated. We took that seriously enough to make it
*checkable* rather than just promised.

### Why not just have an AI write the explanation

It's the obvious approach and it reads beautifully. It's also the one thing this
system cannot afford.

A model asked to "explain why this was flagged" is right most of the time. When
it's wrong, it's wrong in the worst possible way — a believable number attached to
a real detector, in a report that looks exactly like a correct one. The analyst has
no way to tell. That's the precise failure this entire project exists to prevent,
and it would be silly to reintroduce it in the last mile.

There's a second reason that's easy to miss. The text we'd be feeding the model is
a document we may already suspect is poisoned. Asking a model to read attacker-
written text and describe it is the attack surface, not the defence.

### How it works instead

Every number that appears in the text arrives as a small object carrying the value
*and* a pointer to exactly where in the report that value lives. Sentences are
fill-in-the-blank templates — they contain slots, never numbers. So:

> Flagged because `claim_unsupport_score` = 1.000 on document cisa-adv-9, exceeding
> the malicious threshold of 0.990 by +0.010, on a Tier 1 source.

Every figure in that sentence — the score, the threshold, the margin, the tier — is
substituted from a value elsewhere in the report, and each one knows its own
address. If a template is asked to render without the values it needs, it refuses
rather than producing a sentence with a hole in it.

### How we prove it

The test takes the **finished, rendered text** — the actual prose, not the internal
data — pulls out every number in it, and demands that each one be findable in the
report object. A sentence with a number that can't be traced fails the build.

We check the rendered text rather than the internal objects on purpose. Checking
the objects would only prove they agree with themselves. Three things slip past
that and are caught by reading the output: a number typed directly into a template,
a formatting bug that prints a value differently from how it's stored, and someone
later writing a sentence by hand instead of using a template.

And because a test that can't fail isn't a test, there are two **deliberate
sabotage checks**: we inject a made-up number into the text and confirm the checker
catches it, and we point a value at a field that doesn't exist and confirm that
fails too. Without those, a checker that silently approved everything would look
exactly like a passing test suite.

### It caught two real bugs immediately

**A number citing the wrong source.** When a detector crossed its *malicious*
threshold, the sentence correctly worked out the margin against that threshold — but
recorded its address as the *suspicious* margin field, which holds a different
number. The sentence read perfectly. Its provenance was wrong. This is exactly the
class of error the design is meant to prevent, and no check that only looked at the
internal data would ever have seen it.

**A renderer doing its own arithmetic.** The markdown output counted the number of
override reason codes itself rather than reading a stored count. Small, but it's the
start of a renderer becoming a second copy of the logic — and second copies drift.
The count is now carried in the report and the renderer just prints it.

Both were found in the first run. That's the test paying for itself before it
shipped.

---

## Indicators: pattern matching, no AI

IPs, domains, URLs, file hashes and CVE numbers, extracted by pattern rules only.

Analysts *pivot* on these values — pasting an IP into a search, looking a hash up,
checking a CVE against their inventory. An extractor that occasionally invents a
believable-looking indicator sends someone chasing something that was never in the
document. A pattern rule can't be talked into anything; a model reading a poisoned
document can.

The cost is that we miss indicators written in prose ("the attacker used the same
subnet as last quarter"). That's the right trade: a miss is visible to whoever reads
the document, an invention isn't.

Most of the work went into *not* extracting things. Each of these is a real false
positive we now suppress, and each has a test:

- `version 10.2.3.1 and prior` — looks exactly like an IP address. Suppressed by
  reading the words in front of it.
- `report.pdf` — looks exactly like a domain. `.pdf` isn't a real top-level domain.
- `cisa.gov` — a real domain, but it appears as a citation in nearly every advisory.
  Listing it as an indicator teaches analysts to skim the list.
- `evil-domain[.]com` — threat intel deliberately breaks indicators so nobody clicks
  them. We repair it before matching and keep both forms.
- A URL's own host isn't also listed separately as a domain.

Each indicator also records which documents it appeared in. One found only in the
document the detectors flagged is a very different thing from one corroborated
across four sources.

---

## Four answers, not two

For every document and every detector, the report distinguishes:

- **fired** — over threshold, with the value, the threshold and the gap all quoted
- **below** — measured, and under threshold
- **couldn't be calibrated** — the detector's normal-document scores were too flat
  to set a threshold at all
- **didn't run** — absent, and specifically *not* recorded as zero

Squashing these into "not flagged" would claim checks we didn't perform. The last
two mean *we don't know*, and a report that displays them like a clean result is
lying by omission.

---

## The analyst decision box

Every report carries an empty decision block for the dashboard to fill in — the
allowed verdicts, the eleven standard override reasons from Session 3, and a slot
for a per-document verdict on each retrieved document.

There was a genuine tension to resolve here. Session 3's design says an unreviewed
case must have **no database row at all** — not a blank one, and specifically not one
marked "pending" — because a "pending" value sitting in the same column as real
verdicts means every future query has to remember to exclude it, and the first one
that forgets is quietly wrong.

The resolution: this block is a **form**, not a record. It tells the dashboard what
to show. It is never written to the decisions table, no row exists until a human
presses submit, and the block carries a flag and a written warning saying so, in case
anyone later tries to save it as if it were a decision. What the *system* recommended
is copied in, so that a submitted decision makes sense on its own later.

---

## Testing

`reports/test_reports.py` — 100 checks, all passing.

Beyond the grounding tests: the headline really is first in both output formats; the
two kinds of red are distinguishable from the first four lines alone; a version
number is never extracted as an IP; the decision block is never pre-filled; nothing
in the report serialises as "NaN" (an unset number is null, because zero would read
as a measurement); and a report with nothing to extract says so explicitly instead of
dropping the section.

---

## What these reports currently mean

The report machinery is correct and tested. **The detector numbers inside them are
still not real** — all three detectors are running on stand-ins because this
environment can't download the actual models.

The reports say so themselves rather than trusting anyone to remember. Every one
carries a caveats list naming each stand-in detector, and the reasoning always ends
with a line stating how many were faked. Reports built before the model is trained
also say their thresholds are provisional.

That's the same rule the rest of the project follows: a number that can't be quoted
as a result shouldn't be presentable as one — and the report is the last place that
rule can be enforced.

---

## What's open

1. **Install the real detector models and regenerate.** Same blocker as the last two
   sessions, same fix, still your machine's job.
2. **The dashboard.** These reports are built to be rendered by one and to receive a
   decision back from one. That's the next piece.
3. **Wire the audit log.** The report is a rendering; the permanent record is the
   `query_events` table from Session 3, which doesn't exist yet.
4. **`corpus/` is still untracked in git** — third session running. The benchmark is
   the project's main artefact and it isn't in version control.

---

## Next session

The dashboard: render these reports, let an analyst act on one, and write the
decision back — which is the first time anything in this system writes to the
audit trail.
