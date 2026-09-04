# Final Project Log

## Hallucinations in AI-Driven Cybersecurity Systems — A Healthcare Sector Perspective

**Team Zetabyte** — Deloitte Capstone Programme 2026, Manipal University Jaipur
**Compiled:** 4 September 2026
**Covers:** ten working sessions, 2–4 September 2026

---

# Executive Summary

## The problem

Hospitals are starting to use AI assistants to triage security threat intelligence.
These assistants work by *retrieving* documents from a knowledge base and then
writing an answer based on them. That creates a specific vulnerability that ordinary
"AI makes things up" research does not address: **an attacker who can get a
document into the knowledge base can make the assistant confidently give a chosen
wrong answer.**

This is different from an honest mistake. It is engineered. And in a hospital
security context a wrong answer can mean a missed ransomware indicator or a delayed
response to a compromised clinical system.

Every commercial tool we surveyed treats this as a data-quality question — *did the
model make something up?* None of them asks the security question: *did somebody
arrange for this answer, and can the system tell the difference?*

## What we built

A trust-and-risk layer that sits between retrieval and the answer. Working code,
across nine packages:

| Piece | What it does |
|---|---|
| **Corpus** | 72 genuine and 12 deliberately poisoned healthcare threat-intel documents, across three source trust tiers, with the answer key held outside the documents |
| **Pipeline** | The baseline retrieve-and-answer system, with no security — the control condition everything is measured against |
| **Detectors** | Three independent checks on retrieved documents: is it a statistical outlier, does it contain instructions aimed at the AI, does it actually support the claim |
| **Fusion** | Combines those signals into a trust percentage, a named situation type, a confidence figure, and a recommended action |
| **Reports** | The analyst-facing output, with a colour headline and reasoning text that can be traced back to real computed numbers |
| **Audit log** | A tamper-evident record of every query and every human decision |
| **Dashboard** | The screen: ask a question, see the verdict, act on it |
| **Evaluation** | Runs the whole corpus through three configurations and compares them |

The organising idea is **three colours**. Green means good to go. Orange means
review recommended. Red means reject or escalate — split into *Attack Detected*
(an untrusted source is lying) and *Trusted Source Compromise Suspected* (a source
we had already verified is behaving strangely, which is a much more serious and much
rarer thing).

## What the evaluation found

Three configurations, 84 documents, 40 queries.

| | No retrieval | Plain RAG | **Our system** |
|---|---|---|---|
| Poisoned content **reached the user** | 0%* | 100% | **90%** |
| System **vouched for** poisoned content | 0%* | 100% | **0%** |
| Clean documents blocked | 0%* | 0%* | **18.1%** |
| Clean queries pushed to a human | 0%* | 0%* | **93.3%** |
| Auto-accepted, no human needed | 100% | 100% | **5%** |
| Added latency per query | — | — | **~24 ms** |

\* true by that configuration's definition, not measured.

**The honest reading, in three sentences.** Our system never once returned poisoned
content inside an answer it vouched for, where plain RAG did so every single time.
But poisoned content still reached the reader in 9 of 10 attack cases — flagged as
unverified, but there. And it achieves that by auto-accepting only 5% of queries and
sending 93% of clean traffic to a human, which is not an operating point anybody
would deploy.

**Why the detectors aren't detecting.** The development environment had no internet
access, so none of the three detector models could ever be downloaded. All three ran
on crude stand-ins. Word-overlap counting, which is what stood in for the entailment
model, *cannot detect contradiction at all* — and contradiction is exactly what a
"this vulnerability is actually low severity" attack is. Three of our six attack
families were caught zero times. Every poisoned document that got retrieved was
classified into one of the three *clean* case types.

So the defensible claim is: **the architecture is complete and works end to end, and
whether it can actually detect poisoning is still unknown.** The remaining protection
comes from the tier and case rules being cautious about unverified sources, not from
detection.

## What remains — Level 4 and beyond

We scoped this capstone at Levels 0–3 of a five-level architecture. Beyond it:

- **Cross-model verification** — a second, independent model gives an opinion, but
  only on the cases Level 3 already flagged as high risk, so the cost is spent where
  it matters.
- **Secondary retrieval** — when the evidence contradicts itself, go and look again
  with a different strategy rather than reporting the conflict and stopping.
- **Smarter handling of lone suspicious documents** — currently they are quarantined;
  the literature warns that blunt deletion removes genuine documents and misses
  isolated poisoned ones.
- **Tool and action firewalls** — if the system is ever allowed to *do* things rather
  than answer questions, those actions need their own gate.
- **A full human review workflow**, and using the collected analyst decisions to
  retrain the scoring model. The database schema for this exists already and is
  deliberately unused.

**The immediate next step is not Level 4.** It is installing the three detector
models on a machine with internet access and re-running the evaluation. Every
number above is provisional until that happens, and it is the single highest-value
action left on the project.

---

# The Sessions

---

## Session 1 — Designing the decision logic

*2 September · Design only, no code*

Before writing anything we settled what the system would decide and why. The output
is `docs/design/TRUST_RISK_DESIGN.md`, which stayed authoritative for the whole
project and ended at version 1.2.

**Source trust tiers.** Every document carries a tier: 1 for verified authorities
(CISA, HHS), 2 for moderated but community-writable feeds, 3 for unverified. The tier
is a property of the *source*, assigned when the document is ingested, and no
detector may ever change it. It is a prior, not a verdict.

**Eleven named situations, not one score.** A number tells an analyst how worried to
be. It does not tell them *what kind of thing they are looking at*, and that is what
decides the response. "Two government agencies disagree with each other" and "an
unverified blog is lying" can carry the same risk score and need opposite handling.

Two entries in that table carry the design's real claims:

- **A slightly odd document from a verified source outranks an outright malicious
  one from a random blog.** This looks backwards and is deliberate. Odd behaviour
  from a source we classified as trustworthy is improbable *by definition*, so it
  carries far more information. Everything downstream trusts that feed, so the damage
  spreads further. And every explanation — the source was compromised, our fetch was
  intercepted, we mislabelled it, someone edited it internally — is a problem with
  **our own system** rather than with this one question. That is why the response is
  *escalate to the security team*, not *reject this answer*.
- **Two authorities contradicting each other is not an attack.** It is usually an
  advisory being revised. The system is forbidden from quietly picking a winner:
  there is no principled basis for choosing between CISA and HHS, and doing so hides
  the single most useful fact available.

**Reject and Escalate are not degrees of the same thing.** Reject protects *this
answer*. Escalate protects *the system* — this query is merely how we noticed.

**Two tracks, and the more cautious one wins.** A rule track (the named cases) and a
statistical track (a fitted model) both run over the same signals. This guarantees
that adding the model can never make the system less safe than the rules alone —
worth having when the model is fitted on a corpus we built ourselves.

**Weights are learned, not chosen.** The composite score is a logistic regression,
with the split strategy, evaluation metric and class-imbalance handling all fixed in
advance so they cannot be selected after seeing results.

**Confidence is reported separately from risk.** A risk of 0.85 from five agreeing
sources is a finding; the same 0.85 from one document with the detectors
contradicting each other is a guess. Folding them into one number hides the
difference.

---

## Session 2 — The clean corpus

*2 September · 72 documents*

A benchmark needs documents that are genuine, varied, and honestly attributed.

**Everything is deterministic.** Same inputs, same 72 documents, byte for byte. A
benchmark that changes between runs cannot support a before-and-after comparison.

**Tier is assigned in exactly one place** — a source registry — and never in a
document file. If tier could be set per document, someone would eventually set it to
whatever made a result look better.

**The validator runs before anything downstream** and refuses to pass a corpus with
structural problems. It checks more than blank fields: it checks that documents
across tiers are not accidentally distinguishable by shape, because if they are, a
detector can learn the shape instead of the content.

---

## Session 3 — The analyst decision lifecycle

*3 September · Design amendment (v1.1)*

A late but important addition: **the analyst's decision field is never populated by
the system.**

A decision column the system can fill in is not a record of human judgement. It is a
record of the system's own output wearing a person's name, and no future retraining
can separate the two afterwards.

**An unreviewed case has no row at all** — not a blank one, and specifically not one
marked "pending". A "pending" value sitting in the same column as real verdicts means
every future count has to remember to exclude it, and the first query that forgets is
quietly wrong instead of loudly broken. The cost is one extra join. Worth it.

**Corrections never overwrite.** A changed decision is a new row pointing at the old
one. A recalibration that cannot see analysts changing their minds is missing the
most informative signal available.

**No case ever times out into "accepted."** Aging an unreviewed case into approval
would manufacture exactly the label a future model most wants to trust and least
deserves to.

---

## Session 4 — The poisoned corpus

*3 September · 12 documents, six attack families*

Adversarial documents built following the published PoisonedRAG method (USENIX
Security 2025), purely to test our own defences. They are synthetic, contain no real
indicators, and are never pointed at any live system.

Six attack families: flipping an indicator's reputation, downgrading a severity,
spoofing an authority, misdirecting remediation, fabricating attribution, and one
containing a direct instruction aimed at the AI.

**The mistake we caught before it cost us the project.** Our first version put a
`"label": "clean"` field inside every clean document. Every detector would then have
had the answer key sitting in its input. Any accuracy figure produced afterwards
would have been meaningless — and it would have looked *excellent*.

The fix was structural. The answer key moved to a separate manifest that only
evaluation code reads. The validator now *fails* if any document contains an
answer-key field. Poisoned and clean documents are built by the same code so their
structure carries no signal. And an automated check inspects the code of the
retrieval and detector packages to confirm none of them can read the manifest.

---

## Session 5 — The baseline pipeline

*3 September · The control condition*

Plain retrieve-and-answer, with no security layer. This is what we measure against,
so it has to be a fair representation of what people actually build.

**Retrieval returns structured records, not text.** Each retrieved document arrives
with its similarity score and its full provenance — source, tier, dates,
verification status — attached. Every later layer depends on that.

**Perplexity is deliberately absent.** It is the obvious signal and the literature is
clear that it does not separate clean from adversarial text. We recorded the decision
as a scoped-out choice rather than an oversight, and a test asserts it never appears.

---

## Session 6 — The three detectors

*3 September · Independent by design*

Three checks, each producing a 0-to-1 score per document, none able to see the
others' output. Combining them is a later job; keeping them independent is what makes
combining them worth anything.

1. **Embedding anomaly** — is this document an outlier among the retrieved set?
2. **Prompt injection** — does it contain instructions written for the AI?
3. **Entailment** — does it actually support the claim being made?

**We expected the anomaly detector to be the weakest, and said so in advance.**
Poisoned documents are *built* to sit close to the query — that is the attack. A low
anomaly score on a poisoned document is a true observation about the attack, not a
defect to be fixed.

**A test that passed for the wrong reason.** Our "does anything read the answer key"
check was a text search, and it flagged exactly the modules that were being most
careful — because they *documented* not reading it. The fix parses the code properly
and ignores comments. A test that passes for the wrong reason is worse than no test.

---

## Session 7 — Fusion, confidence, and the traffic light

*4 September · The decision layer*

One function that turns three detector scores into a trust percentage, a named
situation, a confidence figure and a recommended action.

**Thresholds are set from the clean documents, not by hand** — the 95th and 99th
percentile of how genuine documents score. This makes the false-alarm rate something
we choose in advance rather than discover later.

**Source tier is encoded as separate yes/no columns, never as the numbers 1, 2, 3.**
This is the most consequential line of code in the project. Writing it as 1/2/3 forces
the model to assume risk rises steadily with tier number — the exact opposite of the
inversion above. It would not merely make the model less accurate; it would make that
relationship *impossible to represent*.

**The traffic light.** Eleven cases and four actions are precise but are not what
someone glances at first, so the layer also produces green, orange or red — derived
from the decision actually taken, so it can never contradict it. Red splits into
*Attack Detected* and *Trusted Source Compromise Suspected*.

**Green is deliberately hard to reach.** It needs an explicit accept *and* a verified
Tier-1 source. Everything else — an unrecognised action, a missing tier, anything
ambiguous — falls to orange. There is no branch anywhere that says "otherwise,
green". A system that shows green when it does not know what else to show has
inverted the entire point.

**Four problems this session surfaced:**

- A detector returning a constant would have made the *whole corpus* read as
  malicious, because the 95th percentile of a column of zeros is zero. Signals whose
  clean scores have no spread are now excluded entirely, with the reason recorded.
- **Two of our three signals came out pointing backwards.** Poisoned documents scored
  *lower* than clean ones. The likely cause for the entailment signal is structural
  and interesting: the attack works by making the poisoned document restate the
  question almost word for word, so it appears to support the *question* better than
  a genuine document does. We are measuring the attack's own mechanism and reading it
  as innocence. The fix is to score against the generated *answer* instead, which
  needs the generator in the loop.
- Our comparison against a naive baseline was unfair in both directions, so the
  evaluation now also compares at a matched false-alarm rate.
- The contract tests found a real bug: a reported risk of 0.34 with an uncertainty
  range of 0.73–0.88. The range did not contain the value.

---

## Session 8 — The analyst report

*4 September · The user-facing output*

Turns a scored query into what a person reads. Headline first, then the score, then
the case, then the evidence, then the reasoning.

**Why not have an AI write the explanation.** It reads beautifully and it is the one
thing this system cannot afford. A model asked to explain a flag is right most of the
time; when it is wrong it produces a believable number attached to a real detector,
in a report indistinguishable from a correct one. That is the precise failure this
whole project exists to prevent. And the text it would be reading is a document we
may already suspect is poisoned — asking a model to read attacker-written text and
describe it is the attack surface, not the defence.

**So every number in the reasoning carries its own address.** Sentences are
fill-in-the-blank templates containing slots, never numbers. The test takes the
finished text, pulls out every number, and demands each be findable in the report. It
includes deliberate sabotage checks — inject a made-up number, point a value at a
field that does not exist — because a checker that silently approves everything looks
exactly like a passing test suite.

**It caught two real bugs on its first run**, including a sentence whose number was
correct and whose stated source was wrong.

**Indicators are extracted by pattern matching, never by a model.** Analysts *pivot*
on these values. Most of the work is in *not* extracting things: `version 10.2.3.1`
is not an IP address, `report.pdf` is not a domain, `cisa.gov` is a citation rather
than an indicator.

---

## Session 9 — The audit log and the dashboard

*4 September · Making it operable*

**The audit log** records every query with a timestamp and a reference number, and
separately records human decisions.

Session 3's rule is now enforced three independent ways: the database refuses a
decision row with no verdict and has no default; the class the scoring pipeline holds
has *no method* that could write one; and every row records who wrote it, with
non-human sources excluded from anything that could become training data.

Each decision row carries a hash of its own contents plus the previous row's. Change
any historical row and every hash after it stops matching. One hash per write, no new
dependency, and the decision history becomes evidence rather than merely data.

**The dashboard** opens with a large colour banner before anything else — no
scrolling, no clicking. When it is red the sub-type sits directly underneath.

We deliberately did not lead with the trust score, and our own test data shows why: a
response scored **93.5% trustworthy** while the case rules had spotted a trusted
source behaving oddly and escalated it. A screen opening with "93.5%" would have
handed an analyst a reassuring number sitting on a suspected compromise.

Streamlit could not be installed in the build environment, so the tests swap in a
fake that records every call in order. That turns "visible without scrolling" into a
checkable claim about call order. It cannot check that it *looks* right — that still
needs a person to run it and look.

---

## Session 10 — The evaluation

*4 September · The evidence*

Covered in full in the Executive Summary above. Three points bear repeating.

**We nearly reported a much better number than we deserved.** Our first run printed
0.0% attack success and 100% detection across every attack family. It was an
artefact: we had defined success as *the poisoned document came back in an answer the
system vouched for*, and since the system almost never vouches for anything, almost
nothing counted. But a "review" outcome still returns the answer to the user. The
poisoned document reached the reader in 9 of 10 cases. The evaluation now reports
both definitions side by side, permanently, plus the auto-accept rate — because an
attack-success rate of zero is unreadable without knowing what it cost.

**Three of six attack families were caught zero times**, and every retrieved poisoned
document was classified into one of the three *clean* case types. At the document
level, the detectors did not flag a single one.

**All of that is on stand-in detectors.** The evaluation measures whether the
machinery works, not whether the detection works. That distinction is printed in the
output and carried in every saved result file.

---

# Standing Limitations

Stated plainly, because a reviewer will find them anyway and it is better that they
find them in our own writing.

1. **The detectors have never run.** No internet access in any development
   environment, so all three models ran as crude stand-ins throughout. Every accuracy
   figure in this project is structural evidence that the layer works, not a
   measurement of detection.
2. **No language model was ever in the loop.** Generation falls back to an extractive
   stub, so answer-level attack success could not be measured and the entailment
   signal scores against the question rather than the answer.
3. **The corpus is small.** 12 poisoned documents across six families. The statistical
   model is at what the design calls its "underpowered" setting, and its coefficients
   are indicative rather than reliable.
4. **The operating point is not deployable.** 5% auto-accept and 93% of clean queries
   routed to a human is a review-generating machine, not a filter.
5. **The fourth detector was never built.** The check comparing retrieved evidence
   against the model's own knowledge is designed but not implemented, and is treated
   throughout as *absent* rather than as zero.

---

# What We Would Tell the Next Team

**Protect the benchmark's ability to disappoint you.** The most valuable decisions in
this project all cost us something. Holding the answer key outside the documents made
the corpus harder to build. Splitting by attack family made the accuracy numbers
lower. Reporting both definitions of attack success replaced a 0% with a 90%. Each
one preserved the benchmark's ability to tell us we were wrong, which is the only
thing that makes it worth running.

**Write the test that can fail.** Our grounding test found two real bugs on its first
run because it included deliberate sabotage checks. A test that cannot fail looks
identical to a passing one.

**Say what you could not measure.** Every script in this project prints what it could
not determine and why. That habit is the reason this log can be read without
cross-checking every claim.

---

*Design specification: `docs/design/TRUST_RISK_DESIGN.md` (`design-v1.2`).
Full technical report: `docs/PROJECT_REPORT.md`.
Individual session logs: `docs/sprint_logs/`.
Evaluation results: `eval/results/`.*
