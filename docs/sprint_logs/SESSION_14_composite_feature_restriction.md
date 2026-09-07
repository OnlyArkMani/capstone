# Session Log — Taking the Broken Signals Out of the Score

**Date:** 7 September 2026
**Team:** Zetabyte
**Session type:** Statistical-layer change, plus one measurement we could not take
**Main output:** `fusion/features.py` restricted feature set, `eval/refit_verify.py`, design §9A.10

> Short version: our trust score was being fitted on four signals, three of which
> carry no usable information. We took those three out of the score. We did **not**
> take them out of the system — they still run, and they still drive the case
> rules that are actually catching things. We could not run the refit tonight,
> because the machine this session can reach does not have the real models on it,
> and a number produced without them would have been a lie. So we built the thing
> that runs the refit safely and wrote down exactly what to expect.

---

## What was wrong

Our composite trust score is a small statistical model. It was being fitted on four
inputs. Three of them are useless, each for a completely different reason, and we
have measured all three:

- **Anomaly** points the *wrong way*. Poisoned documents score as less strange than
  ordinary ones. This is not a bug — poisoned documents are deliberately written to
  look like the question so they get retrieved, which also makes them look normal.
  It is the wrong tool for this job, not a broken tool.
- **Unsupport** is a coin flip. The model we use to check "does this evidence
  support this answer" is built to compare *one sentence to one sentence*. We hand
  it a whole document and a whole answer. It cannot do that, so it says "not
  supported" to almost everything. On documents we *know* are clean, the middle
  reading is 99.74% unsupported.
- **Injection** never varies. It is zero on all 490 training rows, so the model
  cannot learn anything from it at all. Again, not a broken detector: tested
  directly against our five injection documents it scores 1.0000, 0.9925 and 0.9840
  as malicious, 0.8000 as suspicious, and misses one on purpose. It just never
  fires during the retrievals we train on, which is about which documents our
  corpus contains.

Leaving all three in the fit means the model spends its limited statistical power
on noise.

---

## What we did

**Took the three out of the score's feature list.** There is now an explicit list in
the code, `COMPOSITE_SIGNALS`, naming which signals the score is allowed to use. It
contains one entry: conflict. The fitted inputs are now conflict plus the two
source-tier flags.

**Left all four detectors running, untouched.** This is the part that matters and the
part easiest to get wrong. The case rules (C1–C11) — which are what is actually
producing our safety behaviour — read each detector's **raw score** against its own
thresholds. They have never looked at the statistical model's coefficients. We
checked this rather than assuming it: the case file imports only the banding file,
and neither imports the model or the feature code. The case rules are structurally
incapable of noticing this change.

**Wrote a guarded runner** for the refit, `eval/refit_verify.py`, because running the
training script directly is dangerous the night before a demo (see below).

---

## The thing we could not do, and why we did not fake it

We could not run the refit. The environment this session reaches is a Linux
sandbox with the project folder mounted — it is not the Windows machine with the
graphics card. It has no PyTorch, no scikit-learn, no sentence-transformers, no way
to install them, and no Ollama.

We found this out the hard way. We ran the training script and it *succeeded* — on
the fallback keyword-matching retriever, the fallback lexical entailment stand-in,
the query-text hypothesis instead of a generated answer, and a plain numpy fit with
no calibration. It produced numbers. Those numbers were meaningless, and it had
already overwritten our shipped model to produce them.

We had taken a backup first, and restored it immediately. The shipped model, the
0.179 figure and the thresholds are all exactly as they were.

This is the same trap we already fell into once, and recorded as Limitation 9 —
a whole evaluation resting on a fallback retriever without anyone noticing. Quoting
a ROC-AUC from tonight's run would have repeated it, so we did not.

---

## A real bug we found on the way

`fusion/train.py` accepts a `--out` flag that looks like it writes results somewhere
safe. It does not work. The script creates that directory and then saves to the
normal fixed locations anyway. Anyone using `--out` to try the refit without risking
the live model will lose the live model. Our runner script works around it with an
explicit backup and restore; the flag itself should be either fixed or removed.

---

## The part to think about before tomorrow

Two of the instructions for this work pull against each other, and it is worth
understanding why rather than discovering it mid-demo.

We were asked to confirm the headline numbers do not change. But the review
threshold that produces those numbers is **calculated from the model we are
refitting**. It sits at zero today only because the current score is so bad that no
cut-off can hit the required recall. That is exactly why nothing is ever
auto-accepted, and why "0% of attacks were vouched for" holds.

So if the reduced model is genuinely better, the threshold may move off zero — and
the disposition mix changes, and auto-accept may reopen. We already know what
happens then, because we measured it: three of ten attacks became vouched-for
answers.

Which means the honest outcome might be: **the refit works, and precisely because it
works we do not ship it tonight.** Recalibration is gated on fixing the entailment
problem first. The runner treats a moved threshold as a finding to report and a
reason not to adopt, rather than as either a pass or a failure.

---

## How to run it tomorrow

On the Windows machine, with the normal environment active:

```
python -m eval.refit_verify            # measures, reports, ships nothing
python -m eval.refit_verify --adopt    # ships only if every check passes
```

It backs everything up, refits, re-runs the evaluation, compares every field against
the backup, prints a pass/fail line per field, and puts the old model back unless
everything holds.

---

## What is still open

- The refit itself is unmeasured. Until it runs, 0.179 stays the number of record.
- Removing dead features cannot create discrimination on its own. Conflict alone
  measured 0.653. Whether three features beat a coin flip is a real question and we
  should not assume the answer.
- The entailment fix (splitting answers into individual claims) is still the item
  that actually matters. This session cleaned up around it; it did not do it.
- We dropped the tier-interaction term along with the three signals, since with one
  signal left it adds nothing. If we want that decision revisited, the runner can
  measure both versions side by side.
