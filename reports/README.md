# SOC Analyst Report Generator

Turns a scored query into the thing an analyst actually reads.

```python
from fusion import score_query
from reports import build_report, render_markdown, render_text

score  = score_query("ransomware targeting hospital imaging systems", records)
report = build_report(query, score, records)

print(render_text(report))          # terminal / ticket paste
print(render_markdown(report))      # docs, dashboard
report.to_dict()                    # JSON, for the audit log
```

```bash
python -m reports.test_reports            # 100 checks
python -m reports.test_reports --sample   # print a full example report
```

---

## The headline is the report

```
==============================================================================
[ RED ]  REJECT / ESCALATE
          Trusted Source Compromise Suspected
==============================================================================
Action: ESCALATE  Risk tier: CRITICAL       Case: C4 Trusted-Source Anomaly
```

The band comes first, alone, before the score, the case, the evidence and the
reasoning. That ordering is a design decision (§2.9), not a layout preference. An
analyst working a queue reads the band and stops there when it is GREEN;
everything below is the detail they open when it is not, or when they want to
verify a GREEN.

Leading with the composite score would be actively worse, and the system produces
cases that show why. Here is a real one from the test fixtures:

```
Trust score : 93.5%   ← the fitted model
Action      : ESCALATE
Headline    : RED — Trusted Source Compromise Suspected
```

The statistical track scored this response as 93.5% trustworthy. The case taxonomy
recognised a Tier-1 source behaving anomalously and escalated, and escalation
dominance took the more conservative of the two. A report that led with **93.5%**
would have handed an analyst a reassuring number attached to a possible source
compromise. The band cannot do that, because it is derived from the reconciled
action rather than from the score.

**RED is sub-typed**, and the sub-type is visible in the first four lines:

| Sub-type | When | Unit of concern |
|---|---|---|
| **Attack Detected** | Reject/Escalate from a Tier 2 or Tier 3 source | The **document** — quarantining it largely closes the matter |
| **Trusted Source Compromise Suspected** | Reject/Escalate where the governing tier is 1 | The **source** — a finding about our own trust infrastructure that outlives this query |

An analyst scanning twenty red flags needs to tell those apart without opening any
of them. They are not equally common and they are not equally urgent.

---

## Template-grounded reasoning

This is the part of the report most tempting to generate with a language model,
and the one place where doing so would be most damaging.

A model asked to "explain why this was flagged" produces fluent, confident prose
that is right most of the time. When it is wrong it is wrong in the worst possible
way: a plausible number attached to a real detector, in a report that looks
identical to a correct one. An analyst has no way to tell them apart, and the
whole system exists to stop exactly that class of failure from reaching them.

There is a second reason. The input to that generation step would be a document we
may already believe is adversarial. Handing poisoned text to a model and asking it
to describe itself is the attack surface, not the defence.

### How it works

Every number reaches the narrative as a `Fact` carrying three things: the value, a
**JSON pointer** to where that value lives in the report, and a format.

```python
Fact(key="value", value=0.8231, path="/documents/0/readings/0/value", fmt="score")
```

Templates contain slots, never literals:

```
"Flagged because {signal} = {value} on document {doc_id}, exceeding the
 malicious threshold of {threshold} by {margin}, on a Tier {tier} source."
```

renders as

> Flagged because `claim_unsupport_score` = 1.000 on document cisa-adv-9,
> exceeding the malicious threshold of 0.990 by +0.010, on a Tier 1 source.

Rendering a template without its facts raises rather than emitting a sentence with
a gap in it. `check_templates_have_no_literals()` asserts no template hard-codes a
number, because a literal would render as a real-looking figure that no fact backs.

### How it is proved

`test_reports.py` pulls every numeric token out of the **rendered text** — not the
fact list, the actual prose — and requires each one to resolve to a real value at a
real path in the report.

Checking the rendered output rather than the facts is deliberate. Checking the
facts would only prove the facts are self-consistent. Three failures the fact list
would miss are all caught by parsing the output: a literal baked into a template, a
formatting bug that renders a value differently from how it is stored, and a future
edit that inserts prose directly instead of going through a template. It also means
the test survives someone swapping the narrative engine for a different one.

Two **negative controls** prove the check can fail. A fabricated figure injected
into the prose must be detected as ungrounded, and a fact pointing at a
non-existent path must fail to resolve. A test that cannot fail is not a test, and
a matcher that quietly accepted everything would look identical to a passing suite.

### What this cost, and what it caught

The prose is more rigid than a model's. Sentences come from a fixed inventory, so
reports read repetitively. That is an acceptable price — an analyst reading twenty
reports a day benefits from sentences that always mean exactly the same thing, and
predictability is a virtue in an audit trail.

The grounding test earned its place immediately by catching two real defects:

**A margin cited against the wrong pointer.** When a signal crossed its *malicious*
threshold, the narrative computed `value − malicious_threshold` but pointed the
fact at `margin_to_suspicious`, which holds a different number. The sentence read
correctly and its provenance was wrong — the exact failure mode this design exists
to prevent, and invisible to any check that only looked at the facts. Both margins
are now stored and the citation points at the one it actually used.

**A renderer computing its own figure.** The markdown renderer printed
`len(override_reason_codes)` rather than reading a stored count. A renderer that
derives figures is a second implementation of the logic, and the two drift; the
count is now carried in the report.

---

## Indicator extraction — regex, never a model

IPs, domains, URLs, file hashes and CVE IDs, by pattern matching only.

An analyst *pivots* on these. They paste the IP into a SIEM query, look the hash up
in VirusTotal, check the CVE against an asset inventory. An extractor that
occasionally invents a plausible indicator sends someone chasing something that was
never in the document. A regex cannot be prompt-injected; a model reading a
poisoned document can.

The cost is recall: this misses indicators written in prose ("the attacker used the
same subnet as last quarter"). That trade is right. A recall failure is visible to
an analyst reading the document; an invented indicator is not.

Precision comes from the suppression rules, each of which is a real false positive
the tests pin down:

| Input | Extracted as | Why |
|---|---|---|
| `evil-domain[.]com` | `evil-domain.com` | Defanged indicators are re-fanged before matching; both forms kept |
| `version 10.2.3.1 and prior` | *nothing* | Version strings look exactly like dotted quads — suppressed by preceding context |
| `report.pdf` | *nothing* | Filename suffixes are not TLDs |
| `cisa.gov` | *nothing* | Citation domains appear in every advisory; listing them trains analysts to skim |
| `https://cisa.gov/a/b` | one URL | A URL's host is not also reported as a bare domain |
| 32 / 40 / 64 / 128 hex chars | md5 / sha1 / sha256 / sha512 | Classified longest-first so a SHA-256 is not reported as an MD5 prefix |

Each indicator records **which documents it appeared in**, which is
decision-relevant: an IP found only in the one document the detectors flagged is a
different thing from one corroborated across four sources.

---

## Signal readings — four outcomes, not two

Per document, per detector, the report distinguishes:

| Status | Meaning |
|---|---|
| `over_malicious` / `over_suspicious` | Fired. The narrative cites the value, the threshold and the margin |
| `below` | Measured, and under threshold |
| `unusable` | The detector could not be calibrated at all — its clean distribution was too degenerate to threshold |
| `missing` | Never ran. Treated as absent, **not** as zero |

Collapsing these into "not flagged" would overstate what the system checked.
`unusable` and `missing` mean the system does not know, and a report that renders
them the same as a measured quiet signal is claiming a check it did not perform.

---

## The analyst decision block

The report carries an `analyst_decision` block with `decision: null` and
`status: AWAITING_REVIEW`, plus the form specification the dashboard renders —
allowed values, the eleven-code override vocabulary from §5.5, and a per-document
verdict slot for every retrieved document.

**It is not a database row, and the block says so.** Design §5.8 requires that an
unreviewed event has *no row* in `analyst_decisions` — not a NULL, and specifically
not a `PENDING` sentinel, because a sentinel sitting in the same column as real
verdicts means every future aggregate has to remember to exclude it, and the first
query that forgets is silently wrong rather than an error.

This block does not contradict that. It is a **form specification inside a
rendering artefact**: `status` describes the report, not a stored decision. Nothing
here is written to `analyst_decisions`; a row exists only once a human submits, and
only the dashboard's decision handler may write it. `is_database_row: False` and an
`_invariant` string are carried in the payload so anything tempted to persist this
object has to override an explicit flag.

What the system said *is* snapshotted — recommended action, case, risk score,
confidence, headline — so that a submitted row stands alone without a join.

---

## Risk tier

A queue-sortable severity label, derived from **both** the case priority and the
final action, taking the more severe.

Priority alone is not enough. The two tracks are reconciled by escalation
dominance, so the statistical track can raise the final action above what the case
priority implies. A C2 (priority P4, nominally "low") whose fitted score pushed it
to Review is not a low-severity queue item, and labelling it LOW is how it sinks to
the bottom of a sorted list and never gets read. Unknown priorities and unknown
actions both map to HIGH, never LOW — the same fail-safe as the headline band.

---

## Files

| File | What it does |
|---|---|
| `entities.py` | Regex indicator extraction, defanging, and the false-positive suppression rules |
| `narrative.py` | `Fact`, the template inventory, and the substitution engine that makes grounding checkable |
| `schema.py` | Report parts, risk-tier derivation, and the pending analyst-decision block |
| `generator.py` | `build_report` — assembles everything and builds the narrative against the finished report |
| `render.py` | Markdown and terminal renderings. Computes nothing |
| `test_reports.py` | 100 checks, including the grounding test and its negative controls |

---

## What these reports currently mean

The report machinery is correct and tested. **The detector inputs are not yet
real** — all three Level 2 detectors run on fallback backends in this environment,
so the scores a report cites are structural indicators rather than measurements.

The reports say so themselves rather than relying on you to remember: every report
carries a `caveats` list naming each fallback backend, and the narrative ends with
a `CAVEAT:` sentence stating how many detectors were faked. A report built before
`fusion.train` has run also says its band thresholds are provisional.

That is the same commitment the rest of the project makes. A number that cannot be
quoted as a result should not be presentable as one, and the place to enforce that
is the artefact an analyst actually reads.

---

*Design reference: `docs/design/TRUST_RISK_DESIGN.md` — §2.6 action semantics,
§2.9 headline band, §5.3 and §5.5 the decision schema and its vocabulary,
§5.8 the never-auto-populated invariant.*
