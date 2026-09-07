# Archived results — score track abstaining on the review axis (REJECTED, not shipped)

The experiment: `tau_review` had collapsed to 0.0, so the fitted score track proposed
REVIEW for every query ever scored and nothing could be auto-accepted. The change made the
score track abstain on the review axis while leaving its reject band at `tau_reject`
untouched.

It worked, and it cost too much.

| | Before | With the change |
|---|---|---|
| Clean documents cleared without a human | 0.0% | **45.8%** |
| Clean queries cleared end to end | 0.0% | **50.0%** |
| Clean queries sent to a human | 100.0% | **50.0%** |
| False positive rate | 39.3% | 39.3% |
| Attack success — reached the user | 60.0% | 60.0% |
| **Attack success — system VOUCHED FOR it** | **0.0%** | **30.0%** |
| False negative — vouched for | 0.0% | 31.2% |

Three of ten attacks became answers the system presented as trustworthy. The change was
reverted. The evaluation outputs at `eval/results/` correspond to the reverted code.

What this measurement establishes is worth more than the change would have been: the
0%-vouched-for result was **structural, not detective**. It held because the system
auto-accepted nothing at all, and the moment it was allowed to accept anything, the case
taxonomy and the confidence floor let three attacks through unflagged. The guarantee was
never evidence that the detectors identify poisoned documents; it was evidence that the
system had no Accept disposition. Design §9A.8 already recorded that the composite score
is anti-predictive; this records that the rule track alone does not carry the guarantee
either.
