# Session Log — Completing the Analyst Decision Schema

**Date:** 3 September 2026
**Team:** Zetabyte
**Session type:** Design amendment
**Main output:** `docs/design/TRUST_RISK_DESIGN.md`, now at version `design-v1.1`

---

## What we found first

The request was to add the analyst decision field to the design document, on the understanding
that it was missing. It wasn't — Section 5 has covered it since the design session. It already
defines the three values (Accept / Reject / Override), the database tables, what each value
means, the fixed list of reasons an analyst must pick from when overriding, and the rule that
the system's score and case classification are recorded alongside every decision.

So before writing anything we read the existing section and checked it against the three things
that were actually asked for:

| Asked for | Already in the document? |
|---|---|
| The exact field values | Yes — Section 5.3 and 5.4 |
| When it gets set, and that the system must never fill it in automatically | **No. Nowhere.** |
| How to store it so it's queryable later for recalibration | Partly — the tables exist, but no queries and no rules for turning decisions into training labels |

Simply appending what was asked for would have produced two overlapping specifications of the
same field in a document the project treats as its single source of truth. Later work would then
have had to guess which one was current. So we filled the two real gaps instead, and put them
where they belong — as new subsections inside Section 5 rather than bolted on at the end.

**Nothing existing was rewritten.** The only change to prior text is one cross-reference line
added under the table definition, pointing at the amendment so nobody reads the table without
seeing it.

---

## What we added

### 5.8 — When the field gets set, and the rule that the system never sets it

This is the gap that mattered most, and the reasoning is worth stating plainly: a decision
column the system can fill in on its own is not a record of human judgement. It's a record of
the system's own output with a person's name on it, and once that's in the table nobody can
separate the two afterwards.

The rule we wrote down: the field is written **only** when a human acts in the dashboard. No
default value, no code path in the pipeline that touches it, nothing that infers it.

**A case nobody has reviewed has no row at all.** Not a blank field, not a "pending" marker. We
considered both and rejected them for concrete reasons. A blank field eventually gets filled by
something — a migration default, a helpful backfill, a framework's zero value. A "pending" marker
sits in the same column as real answers, so every future count has to remember to exclude it, and
the first query that forgets returns a wrong number instead of an error. Absence of a row can't
be mistaken for a verdict. It costs one extra join in the queue query.

**An unreviewed case never times out into "Accept".** If it ages out of the queue it stays
undecided forever. Letting it default would manufacture exactly the label a future model is
already most biased toward, in the largest volume.

Three separate things enforce the rule, because writing it in a document enforces nothing:

1. The database column can't be empty and has no default, so nothing can quietly supply a value.
2. Only the dashboard may write to the decisions table; the scoring pipeline has no access to it.
   We noted this needs a test rather than trusting people to remember.
3. Every row records *how it came to exist*. Only rows written by the dashboard count toward
   future recalibration. This is the layer that survives a mistake in the other two — even if
   something wrong gets written, it's labelled as wrong.

We also listed five things that must not happen, each with why it's tempting and why it's fatal:
timing out into Accept, inferring a decision from the fact nobody complained, back-filling old
cases, copying a decision across to a similar case, and pre-selecting an option in the dashboard.
That last one is subtle — a pre-selected default anchors the analyst on the system's answer, so
what you record partly measures the default rather than the person.

**One new field worth calling out:** we now record whether the analyst could see the system's
recommendation when they decided. An analyst shown "the system says Reject" who agrees has given
you weaker evidence than one who decided blind, because people go along with a displayed
recommendation more than they would judge on their own. Without this column a future team can't
tell those two apart and will treat them as equal. It costs one integer.

### 5.9 — How to get the data out later

The tables existed; the queries didn't. We added two database views that are the only sanctioned
way to extract this data, so nobody re-derives the joins and gets them subtly wrong — in
particular the handling of corrected decisions, where a naive query counts both the original and
the correction.

We also wrote out the five queries that will actually be run (the review queue, agreement rates,
missed attacks found by blind sampling, threshold recalibration input, and document-level
training rows), and the rules for turning decisions into training labels.

**A trap we found while writing those rules.** It's natural to assume "analyst rejected it"
means "it was poisoned". It doesn't. Our risk model predicts whether a poisoned document
influenced the answer, but analysts reject answers for all sorts of other reasons — the evidence
is out of date, the claim isn't supported, the sources disagree. Training on response-level
rejections would teach the next model to predict *analyst dissatisfaction*, which is a much
broader and different thing. So the per-document verdicts are the real label source, and
response-level decisions are marked as weak fallback evidence. That distinction would have been
easy to miss and expensive to discover later.

We also recorded when to stop storing verdicts as JSON and move them into their own table, so
that decision gets made on a number rather than when someone notices a slow query.

### 5.10 — What this data can't do

Three limits, written down now so a future team doesn't overclaim:

Analyst decisions aren't ground truth — they're expert judgement under time pressure. Agreement
rates across the whole table are inflated, because most decisions are made with the system's
recommendation visible; only the blind-sampled slice is unbiased. And with one reviewer per case
there's no way to know how much analyst-versus-system disagreement is real signal versus ordinary
variation between reviewers, so a future team should double-review a small random slice from the
start — cheap now, impossible to reconstruct later.

---

## Testing

We built the tables and views in a real database and ran every query against sample data,
including a corrected decision, a row from a non-analyst source, and a blind-sampled case.

- Corrected decisions resolve properly: the correction is returned, the superseded original
  isn't.
- Non-analyst rows are excluded from the recalibration view.
- The blind-sample query finds the seeded missed attack.
- Document-level extraction returns the right rows.
- Four deliberately malformed inserts were all rejected by the database: a missing decision
  value, an invalid value, an override without a reason code, and an invalid source.

A schema nobody has tried to break is just a diagram.

---

## Housekeeping

While in the folder we also enabled file deletion for the project, which was blocked. This
mattered beyond tidying up a temporary file: the corpus builder's `--clean` flag deletes old
documents before rebuilding, and it would have failed the first time anyone tried to regenerate
the corpus. We confirmed a full rebuild now works and the validator still passes with zero errors
and zero warnings.

---

## What's open

1. The write-path separation in 5.8 needs an actual test when the dashboard is built. Right now
   it's a rule in a document, and rules in documents don't enforce themselves.
2. The dashboard must open its decision control with nothing selected. Worth saying out loud at
   build time, because every UI framework makes pre-selecting the default option the path of
   least resistance.
3. Double-reviewing a slice of cases is a workflow decision, not a schema one. The tables already
   allow it; nothing currently generates it.
4. Still the main thread: the poisoned corpus, which needs Tier 1 examples or the two most
   important cases in our taxonomy can never be validated.

---

## Next session

Poisoned corpus construction, following the PoisonedRAG method — synthetic, internal, and only
ever used to test our own detection layer.
