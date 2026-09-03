# Session Log — Building the Poisoned Corpus

**Date:** 3 September 2026
**Team:** Zetabyte
**Session type:** Build
**Main outputs:** `corpus/build_poisoned_corpus.py`, `corpus/sources/poison_seeds.json`, 12 poisoned documents in `corpus/poisoned/`, and the new `corpus/ground_truth/` manifests

---

## What this session was for

We now have a clean corpus. To test whether our detection layer actually works, we need
documents we *know* are poisoned — otherwise there is nothing to measure against. This
session built those, following the method from the PoisonedRAG paper, which is the
published attack our whole defence is designed to withstand.

Everything here is defensive research. The documents are synthetic, every claim in them is
deliberately false, all the IP addresses and domains are from ranges reserved for
documentation, and they exist only to be fed to our own detection pipeline. They are never
put into a real system.

---

## The problem we found before writing anything

Reading back over the clean corpus from last session, we noticed something that would have
quietly ruined the entire benchmark.

**Every clean document had `"label": "clean"` written inside it.** We had put it there for
tidiness. But the document file is exactly what the retrieval pipeline loads. If we had
carried on and written `"label": "poisoned"` into the poisoned documents, then our
detection system would have been sitting on the answer key the whole time. Any part of the
pipeline that reads document fields could have found it.

And it is worse than the obvious version. Even without a `label` field, we had a
`poison_family_id` field that would have been filled in on poisoned documents and empty on
clean ones. That is a perfect classifier, available for free, with nobody having to write a
line of cheating code. Our detector would have scored beautifully and measured nothing.

So before building the poisoned documents we fixed it:

- **Labels moved out of the documents entirely**, into separate answer-key files under
  `corpus/ground_truth/`. The pipeline loads documents; the evaluation harness loads the
  answer key; the two never meet.
- **The validator now fails any document carrying an answer-key field** — not warns, fails.
- **Clean and poisoned documents must have exactly the same set of fields.** Removing the
  label is not enough if the *shape* of the record still gives it away. The validator
  compares field names across the two sets and errors if they differ.
- **Poisoned documents are written by the same code that writes clean ones.** We import the
  clean corpus's own formatting functions. If poisoned documents had their own formatting
  code they would end up with a house style of their own, and our detectors would learn to
  spot the style instead of the attack.

That last one is the subtlest and probably the most important. It is very easy to build a
poisoned corpus that is trivially separable for reasons that have nothing to do with
poisoning.

---

## What we built

**12 poisoned documents** targeting **10 real questions** a SOC analyst would ask of the
clean corpus — things like "is this IP associated with ransomware infrastructure", "how
severe is this medical device CVE", "should we apply this firmware update".

**Six different attack styles**, because our evaluation plan holds out an entire attack
style at a time to test whether the detector generalises to attacks it has never seen. That
needs several styles to hold out:

| Attack style | How many | What it does |
|---|---|---|
| Reputation flip | 3 | Claims a known-bad indicator is actually harmless, or that the listing was withdrawn |
| Authority spoof | 2 | Pretends to be an official advisory update that reverses earlier safety guidance |
| Severity downgrade | 2 | Admits the vulnerability exists but understates it so nobody prioritises fixing it |
| Remediation misdirection | 2 | Accepts the finding but recommends an action that actually makes things worse |
| Attribution fabrication | 2 | Invents a confident "this was group X" claim that sends defensive effort the wrong way |
| Prompt injection | 1 | Contains instructions written to the AI rather than to a human reader |

**Spread across all three trust tiers:** 2 at Tier 1, 5 at Tier 2, 5 at Tier 3.

The two Tier 1 ones matter most. They simulate a *compromised trusted source* — a fake CISA
advisory update saying a dangerous patient monitor is safe to reconnect, and a fake vendor
bulletin saying an exposed encryption key was quietly rotated. Both instruct the reader to
remove the protective controls that are actually holding the risk down. This is exactly the
case our design ranks as highest priority, and without these two documents that claim could
never have been tested at all.

---

## How the poisoning actually works

The PoisonedRAG method builds each document in two parts.

**Part one gets the document retrieved.** The attacker cannot see inside our embedding
model, so the best they can do is write the document around the target question itself. Our
builder generates this automatically from the question text. We deliberately do *not* paste
the question in verbatim — a document with a question sitting in it would be spotted by
eye, and that would make the benchmark too easy. It gets rewritten into a natural-sounding
subject line.

**Part two carries the lie.** The false conclusion, written in the ordinary house style of
whatever kind of source it is pretending to be.

We record the exact retrieval text generated for each document in the answer key, so we can
audit afterwards what the attack actually consisted of.

---

## Checking that they would actually be retrieved

A poisoned document that never gets retrieved is harmless and also useless as a test case.
We cannot properly check this yet — that needs the embedding model, which isn't installed
and can't be downloaded here. So we built a rough keyword-based ranking check instead: score
each poisoned document against all 72 clean documents for its target question.

**All 12 come out 1st or 2nd.** That is encouraging but we are being careful about what it
proves: keyword matching is not the same thing as the semantic search the real pipeline
uses. A document that failed this check would definitely be too weak; passing it does not
guarantee anything. The real check gets re-run once the pipeline exists, and it's on the
open list.

---

## Two things we are being upfront about

**The Tier 1 fakes are marked as unverified.** Our clean Tier 1 documents carry a flag
saying we confirmed their identifier against the real published source. The poisoned ones
can't have that flag, because an attacker can supply a convincing URL but cannot make *our*
verification step return true. That's realistic — but it does mean a detector could learn
the shortcut "Tier 1 and unverified equals fake". Something to watch: if Tier 1 detection
comes out near-perfect while Tier 2 and 3 lag, that shortcut is probably why.

**12 documents is not many.** Our design targets around 200 poisoned *query instances*,
which is a different unit — one document produces several instances once we build the query
set. These 12 are the attack surface, not the training set.

---

## Testing

Both corpora rebuild cleanly and the validator passes with zero errors and zero warnings.

We also tried to break the new leak protections deliberately: we added a `label` field to
one poisoned document, a `poison_family_id` to another, and a stray extra field to a third.
All three were caught, and the validator exited with a failure code. We also fixed a bug the
test exposed — the validator was reporting only the first schema mismatch instead of all of
them.

One other bug fixed along the way: the "minimum documents per tier" rule was firing on the
poisoned corpus, which was wrong. That rule exists because our detection thresholds are
calculated from the *clean* documents at each tier. The poisoned set doesn't calculate
anything, so it doesn't need the same minimum.

---

## What's open

1. Re-run the retrieval check properly against the real embedding index once the pipeline
   exists. The keyword check is a stand-in.
2. Build the query set. That's what turns 84 documents into the hundreds of query instances
   the evaluation design actually calls for, and it's the next real blocker.
3. The rule that the pipeline must never read the answer key is currently just a warning
   written in the file. It should be a test — the evaluation harness should be the only
   module that can import that path.
4. Watch for the Tier 1 shortcut described above when the first results come in.

---

## Next session

The baseline RAG pipeline: embeddings, retrieval, generation. That's what finally lets us
check whether these poisoned documents actually get retrieved, and whether they change the
answer.
