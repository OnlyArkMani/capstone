# Session Log — Design of the Trust & Risk Decision Logic

**Date:** 2 September 2026
**Team:** Zetabyte
**Session type:** Design only — no code written
**Main output:** `docs/design/TRUST_RISK_DESIGN.md`

---

## What this session was for

Before writing any code for the trust layer, we needed to decide *how it thinks*. That
means answering three separate questions for every query the system handles, and deciding
what we record when a human gets involved.

We deliberately kept these as separate answers instead of one number, because they are
genuinely different questions:

1. **What kind of situation is this?** — a named case, e.g. "a trusted source is behaving
   oddly" vs. "two trusted sources disagree with each other".
2. **How likely is it that an attacker influenced this answer?** — a risk score.
3. **How sure are we about that risk score?** — a confidence value.
4. **What did the analyst actually do about it?** — the audit record.

Everything in this session was about pinning those four things down precisely enough that
someone else on the team could build them without asking us questions.

---

## What we decided

### 1. A named list of situations (the case taxonomy)

We wrote out eleven situations the system can be in, built by crossing how much we trust
the **source** (Tier 1 = official bodies like CISA, Tier 2 = reputable open feeds, Tier 3 =
unverified) against what the **detectors** say about the content (Clean / Suspicious /
Malicious). Each situation gets a name, a priority from P0 (most urgent) to P5, and one of
four actions: Accept, Review, Reject, or Escalate.

**Two of these deserve calling out, because they are the interesting ones:**

**A trusted source behaving strangely is treated as MORE serious, not less.** This looks
backwards at first. The reasoning is that we already assume Tier-3 junk might be bad, so a
bad Tier-3 document tells us almost nothing new. But a Tier-1 source going strange means
one of our foundational assumptions is broken — maybe the source got compromised, maybe
someone tampered with our fetch path, maybe we mislabelled the document. All of those are
problems with *our system*, not with one query. And because everything downstream trusts
Tier 1 by default, the damage spreads much further. So it gets escalated to whoever owns
our threat-intel sources, not just flagged on screen.

**Two Tier-1 sources contradicting each other is its own separate case.** This is not an
attack. Usually it means one advisory was revised, or the two cover slightly different
product versions, or two authorities genuinely disagree on attribution. The critical rule
we wrote down: **the system must never quietly pick a winner.** We have no basis to choose
between CISA and a vendor bulletin, and hiding the disagreement would remove the single
most useful fact the analyst has. So both get shown, side by side, with their dates.

We also wrote down a strict order for deciding which case applies when several could fit,
so two people implementing this independently get the same answer every time.

### 2. How the risk score gets computed (and why it isn't a set of weights we made up)

The score comes from a logistic regression trained on our own labelled corpus, not from
weights we picked by hand. The important choices:

- **Source tier is encoded as separate yes/no flags, not as the numbers 1, 2, 3.** This
  matters more than it sounds. Using 1/2/3 would force the model to assume risk changes
  smoothly as tier gets worse — which is the exact opposite of what we decided in the
  taxonomy. It would make the model structurally incapable of learning the thing we built
  it for.
- **We include "tier × signal" combination terms**, which is what lets the model learn
  "an anomaly means more when it comes from Tier 1" rather than just "Tier 1 is safer
  overall".
- **We measure success by catching attacks, not by overall accuracy.** Accuracy is useless
  here — a model that says "everything is fine" would score well and be worthless. We
  wrote down an explicit assumption that a missed attack is roughly 10× worse than a false
  alarm, and then derived every metric choice from that number rather than picking metrics
  by taste.
- **Splitting the data is done by attack template, not randomly.** Our poisoned documents
  come from a handful of templates. If the same template shows up in both training and
  testing, the model just memorises it and our results look far better than they are. We
  also added a harder test: hold out an entire attack strategy and see whether the system
  catches an attack type it has never seen. We expect that number to be worse, and we are
  going to report it anyway — the gap between the two is an honest measure of how much of
  our performance is real.
- **A warning we wrote down now so we don't get surprised later:** our test corpus will be
  around 25% poisoned, but real traffic would be maybe 1–5%. A detector that looks precise
  at 25% can be swamped by false alarms at 2%. We specified how to report the corrected
  number so we don't overclaim.

### 3. How sure the system is (confidence)

Risk and confidence are kept as two separate outputs. A risk score of 0.85 built from five
agreeing documents is a finding. The same 0.85 built from one document is a guess. Showing
them as the same number would be misleading.

Confidence is built from five things: how much evidence there was, whether the evidence
agrees with itself, whether the sources are actually independent (five documents from one
feed is really one source repeated five times), whether the four detectors agree with each
other, and how stable the trained model's output is for this particular input.

These are combined by multiplying rather than averaging, so one weak component drags the
whole thing down — which is right, because confidence is conjunctive. And a single-document
answer can never be high confidence, no matter how clean it looks.

**We also wrote down a test that can prove the confidence measure is worthless.** If
confidence means anything, then high-confidence predictions must actually be wrong less
often than low-confidence ones. We specified how to check that, and committed to dropping
or refitting any part of it that fails. This is the only place in the whole design where
we set numbers by hand, and this test is the price of doing so.

### 4. What we record when an analyst acts

We designed the database tables now, even though nothing gets retrained from them this
capstone, because you cannot go back and collect this data later.

Key points:

- **"Reject" is ambiguous and we killed the ambiguity.** It could mean "I reject the
  answer" or "I reject what the system recommended". We defined the field to always mean
  the first, with a separate "Override" value for the second. If we had not fixed this
  before building the dashboard, the whole table would have been uninterpretable.
- **Overrides need a reason code from a fixed list**, not just free text. Free text can't
  be used as a training label later; a fixed list can, and each code points at a specific
  thing to fix.
- **Every record snapshots which model version and thresholds were in effect.** Without
  this, a decision logged today becomes meaningless the moment we change a threshold,
  because we can't reconstruct what the analyst was looking at.
- **The log is append-only and hash-chained** — corrections are new rows, nothing is ever
  edited or deleted. It's a security system; the audit trail has to be tamper-evident.
- **We send a random 3% of "everything looks fine" answers to an analyst anyway**, without
  telling them what the system decided. Otherwise we only ever collect data on cases the
  system already flagged, which means a future model would inherit all of today's blind
  spots and never be able to find them.

---

## Why the design has two parallel tracks

The system runs the case rules **and** the trained score at the same time, then takes
whichever answer is more cautious.

This is on purpose. The trained score will be better than rules at spotting attack patterns
it has seen before, but it goes quiet on attacks it has never seen and can't explain itself
to an analyst mid-incident. The rules encode security judgement the model can't learn from
a few hundred examples — particularly the "trusted source acting strange is worse" rule and
the "two authorities disagreeing isn't an attack" rule.

Taking the more cautious of the two means adding the trained model can never make the
system less safe than the rules alone. And how often the two disagree is itself a result
worth reporting.

---

## What this now requires from the corpus work

The design puts real constraints on the corpus, so these need to be in the corpus plan:

- Aim for at least **200 poisoned and 600 clean** query instances. Below that, the model
  has too many knobs for too little data, and we specified a reduced version to fall back
  to.
- **Poisoned documents must exist at all three tiers, including Tier 1.** If we only
  poison Tier-3 documents, the two most interesting cases in the whole taxonomy can never
  be tested and the central claim of the project goes unvalidated. Easy to overlook.
- Every document needs to be tagged with which attack template it came from, so the
  data splitting works.

---

## What's open

1. Does our RAG setup tell us which retrieved document the answer actually came from? If
   not, we fall back to "top 3 by similarity" — already specified, but worth checking early.
2. Comparing every retrieved document against every other one costs extra model calls. Need
   to benchmark whether that's fast enough on our hardware, and we have a cheaper fallback
   written down if it isn't.
3. Can we realistically build enough Tier-1 poisoned examples? This one gates the headline
   result.
4. Is "a missed attack is 10× worse than a false alarm" the right assumption? It's written
   down as an assumption rather than buried, so it can be argued with.
5. Do the confidence weights survive their own test? We'll know once there's data.

---

## Next session

Corpus construction — clean and poisoned healthcare threat-intel documents, tagged as this
design requires. Note that all poisoned-document work follows the published PoisonedRAG
method and exists purely to build a labelled benchmark for testing our own defence. It is
synthetic, internal, and never pointed at any real system.
