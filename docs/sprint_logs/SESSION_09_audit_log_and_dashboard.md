# Session Log — The Audit Log and the Dashboard

**Date:** 4 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main output:** `logs/` — a permanent record of every scored query; `dashboard/` — the screen an analyst actually uses

---

## What this session was for

Two things that turn a scoring engine into a system somebody can operate.

**The audit log** writes down everything the system did — the question, what it
retrieved, every detector's score, the composite, the colour, the case, and what it
recommended — into a small database file, each entry with a timestamp and a unique
reference number. Nothing is thrown away.

**The dashboard** is the screen. Type a question, get an answer with a large colour
banner at the top, drill into the evidence if you want to, and press Accept, Reject
or Override. The decision goes straight back into the log.

---

## The banner, and why it's a requirement rather than a design preference

The results screen opens with a full-width coloured block:

```
==============================================================
  ✕  RED
     REJECT / ESCALATE
     Trusted Source Compromise Suspected
==============================================================
```

Green, orange or red, in very large type, before anything else. No scrolling. No
clicking. When it's red, the sub-type sits directly underneath — *Attack Detected*
or *Trusted Source Compromise Suspected* — because those two need completely
different responses and someone scanning a list of red flags has to tell them apart
without opening any of them.

The trust score sits directly below the banner, then the case and the recommended
action, then the reasoning, then an expandable panel per retrieved document, then
the extracted indicators.

We deliberately did **not** lead with the trust score, and one of our own test cases
shows why. A response came back scored **93.5% trustworthy** — while the case rules
had spotted a trusted government source behaving oddly and escalated it. A screen
that opened with "93.5%" would have handed an analyst a reassuring number sitting on
top of a suspected source compromise. The banner can't do that, because it's derived
from what the system actually decided rather than from the score.

### Testing a screen we couldn't run

Streamlit isn't installed in the environment this was built in, and a UI test that
only runs where the UI runs is a test that quietly stops running.

So the tests swap in a fake Streamlit that records every call in order. That turns
"the banner must be visible without scrolling or clicking" into something
mechanically checkable — it's a claim about *call order*, and the test asserts the
banner is the first thing drawn, with nothing above it. It would fail the moment
somebody adds a heading, a spinner or a metric above the banner.

**What this can't check:** whether it actually looks right. Colours, font sizes and
layout still need a person to run `streamlit run dashboard/app.py` and look at it.
Please do that before the mentor demo.

---

## The audit log, and the one rule it exists to protect

Two tables. The first records what the *system* did, automatically, on every query.
The second records what a *human* concluded — and it is written only when a person
presses a button.

Session 3 set a rule we've now had to actually enforce: **the analyst's decision is
never filled in by the system.** A decision column the system can populate isn't a
record of human judgement; it's a record of the system's own output wearing a
person's name, and no future retraining can separate the two afterwards.

Three independent things enforce it, because one wouldn't survive a careless edit:

1. **The database refuses.** The decision column is mandatory with no default value.
   That absence is doing real work — the database will not invent a verdict, and a
   test checks the "no default" is still there.
2. **The code can't reach it.** There are two separate classes. The one the scoring
   pipeline holds has *no method* that writes a decision. Only the dashboard's class
   does. A test asserts the first one has no way in.
3. **Every row records who wrote it.** A decision imported or backfilled is stored
   but excluded from the set that could ever become training data.

**An unreviewed query has no decision row at all** — not a blank one, and
specifically not one marked "pending". A "pending" value sitting in the same column
as real verdicts means every future count has to remember to exclude it, and the
first query that forgets is quietly wrong instead of failing loudly. The cost is one
extra join when building the review queue. Worth it.

### Corrections don't overwrite

If an analyst changes their mind, the new decision is a **new row** pointing back at
the old one. The original is never edited or deleted. A future recalibration that
can't see analysts changing their minds is missing the most informative signal in
the table.

### Tamper-evidence, for free

Each decision row carries a hash of its own contents plus the previous row's hash.
Change any historical row and every hash after it stops matching. It costs one hash
per write and no extra dependency, and it turns the decision history from data into
evidence. The audit viewer runs the check and shows the result; a test tampers with
a row deliberately and confirms the break is detected.

---

## The audit viewer

A second page listing every query with its colour, case, scores and decision.
Filter by colour, by case, by analyst decision — including "not reviewed", which is
offered as a filter but is *not* a stored value; it asks for the absence of a
decision row rather than a status string.

Open any row to see the full detail, including which of the two tracks proposed
what, and whether the detectors were running as real models or as stand-ins.

---

## What's open

1. **Look at it.** The structure is tested; the appearance is not. Run it before the
   demo.
2. **Install the real detector models.** The dashboard prominently displays a
   warning whenever the detectors are running on stand-ins, which in this
   environment is always.
3. **`corpus/` is still untracked in git** — fourth session running.

---

## Next session

The evaluation: run the whole labelled corpus through three configurations and find
out whether any of this actually works.
