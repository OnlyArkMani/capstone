# Project Audit Report

**Project:** Hallucinations in AI-Driven Cybersecurity Systems — A Healthcare Sector Perspective
**Team:** Zetabyte — Deloitte Capstone Programme 2026, Manipal University Jaipur
**Audit date:** 4 September 2026
**Audited tree:** `C:\Projects\Capstone`
**Type:** Read-only verification. See *Audit side effects* below for the one exception.

---

## Method

Every status below was established by reading the files on disk or by executing
existing code against them. Where a claim is made about behaviour, the check that
established it is named. Scripts were run with bytecode writing disabled so the audit
left no artefacts.

Three things this audit does **not** do: it does not assign severity, it does not
recommend fixes, and it does not evaluate whether the design decisions were correct —
only whether the artefacts the checklist names exist and are internally consistent.

### A note on sprint numbering

The checklist numbers sprints 0–9. The repository's session logs are numbered 01–10
and do not map one-to-one, because one working session (03) produced a design
amendment rather than a sprint deliverable. **This is a naming difference, not a
missing artefact.** The mapping used throughout this report:

| Checklist | Repository session log | Deliverable |
|---|---|---|
| Sprint 0 — Design | `SESSION_01_trust_risk_design.md` | `docs/design/TRUST_RISK_DESIGN.md` |
| — | `SESSION_03_analyst_decision_lifecycle.md` | Design amendment (v1.1), Task 4 lifecycle |
| Sprint 1 — Clean corpus | `SESSION_02_clean_corpus.md` | `corpus/clean/` |
| Sprint 2 — Poisoned corpus | `SESSION_04_poisoned_corpus.md` | `corpus/poisoned/` |
| Sprint 3 — Baseline RAG | `SESSION_05_baseline_pipeline.md` | `pipeline/` |
| Sprint 4 — Detectors | `SESSION_06_level2_detectors.md` | `detectors/` |
| Sprint 5 — Fusion | `SESSION_07_level3_fusion.md` | `fusion/` |
| Sprint 6 — Report generator | `SESSION_08_report_generator.md` | `reports/` |
| Sprint 7 — Audit log & dashboard | `SESSION_09_audit_log_and_dashboard.md` | `logs/`, `dashboard/` |
| Sprint 8 — Evaluation | `SESSION_10_evaluation.md` | `eval/` |
| Sprint 9 — Final docs | *(no session log)* | `docs/FINAL_PROJECT_LOG.md`, `README.md` |

---

## Summary

| # | Sprint | Status |
|---|---|---|
| 0 | Design | **Complete** |
| 1 | Clean corpus | **Complete** |
| 2 | Poisoned corpus | **Complete** |
| 3 | Baseline RAG | **Complete** |
| 4 | Detectors | **Complete** |
| 5 | Fusion | **Complete** |
| 6 | Report generator | **Complete** |
| 7 | Audit log & dashboard | **Complete** |
| 8 | Evaluation | **Partial** — configuration (a) produced no measured values |
| 9 | Final documentation | **Partial** — `docs/PROJECT_REPORT.md` contradicts the current build |
| X | Cross-cutting (logs, README, diagram) | **Partial** — ten count, consistency and version-control defects |

**21 gaps found.** All are listed in the consolidated table at the end, each attributed
to a sprint.

---

# Sprint 0 — Design

**Status: Complete**

`docs/design/` contains one file, `TRUST_RISK_DESIGN.md`, at version **`design-v1.2`**,
1,699 lines. Every Sprint 0 item is present in it.

### Case taxonomy — **exactly 11 cases**

Defined in §2.3. The exact count and each definition:

| ID | Name | Tier | Outcome | Priority | Action |
|---|---|---|---|---|---|
| C1 | Authoritative Confirmation | T1 | Clean | P5 | Accept |
| C2 | Community Corroboration | T2 | Clean | P4 | Accept |
| C3 | Unverified but Unremarkable | T3 | Clean | P3 | Review |
| C4 | Trusted-Source Anomaly | T1 | Suspicious | P1 | Escalate |
| C5 | Authoritative Channel Compromise | T1 | Malicious | P0 | Escalate |
| C6 | Open-Feed Irregularity | T2 | Suspicious | P3 | Review |
| C7 | Open-Feed Poisoning | T2 | Malicious | P2 | Reject |
| C8 | Unverified Irregularity | T3 | Suspicious | P3 | Reject |
| C9 | Expected-Path Poisoning | T3 | Malicious | P2 | Reject |
| C10 | Authoritative Divergence | T1 ⟂ T1 | — | P2 | Review |
| C11 | Isolated Retrieval Outlier | any | — | P1 | Escalate |

Nine are the 3×3 grid of trust tier × content outcome; C10 and C11 are cross-cutting
cases defined on the shape of the retrieval set. A fixed precedence order is specified
in §2.7. §2.8 contains a coverage check confirming every (tier, outcome) pair has
exactly one owning case.

### Scoring methodology — present, §3

- **Feature encoding** — §3.2. Logit transform on bounded signals; anomaly used as a
  within-set robust z-score; **source tier dummy-coded, not ordinal**, with Tier 2 as
  reference; tier × signal interaction terms specified.
- **Split strategy** — §3.6. Grouped splits by attack family, locked test set, nested
  cross-validation, leave-one-attack-family-out.
- **Metric choice** — §3.7. PR-AUC for model selection, F₃ as headline scalar, recall
  at a fixed alert budget, precision corrected to deployment prevalence.
- **Class imbalance** — §3.8. Cost weighting at C_FN/C_FP = 10, `class_weight
  {0: 1.0, 1: 10.0}`, Platt calibration.
- **Events-per-variable constraint and feature ladder** — §3.3.

### Confidence measure — present, §4

Five components (§4.2), effective sample size (§4.3), geometric-mean composition
(§4.4), effect on the action (§4.5), and a falsification test for the measure itself
(§4.6).

### `analyst_decision` schema (Task 4) — present, §5

Parent table `query_events` (§5.2), `analyst_decisions` DDL (§5.3), field semantics
(§5.4), an 11-code controlled override vocabulary (§5.5), the decision lifecycle and
never-auto-populated invariant (§5.8), recalibration query patterns (§5.9), and the
stated limits of the data (§5.10).

### 3-class headline mapping — present, §2.9

- The rule, in clause order, §2.9.1.
- **RED sub-typing**, §2.9.2 — `ATTACK_DETECTED` versus `TRUSTED_SOURCE_COMPROMISE`.
  Note the checklist refers to these as "Case 3 vs. Case 5-equivalent". The design does
  not use that numbering; it keys the sub-type on `tier_governing == 1` rather than on
  a case list, so C4 and C5 are its principal members and C11 joins them when the
  outlier is carried by a Tier-1 source. The semantics match the checklist's
  description; only the numbering differs.
- **Tier-3 fail-safe override**, §2.9.3 — stated explicitly, together with a Tier-2
  exclusion, and §2.9.4 states GREEN is reachable only by affirmative conjunction with
  no `else: GREEN` branch.

---

# Sprint 1 — Clean Corpus

**Status: Complete**

- `corpus/clean/` contains **72 JSON documents** plus `index.json`. Within the
  50–80 range.
- **Metadata completeness:** all five required fields — `source_id`, `source_tier`,
  `source_name`, `ingestion_date`, `summary` — are present and non-empty on **all 72
  documents**. Verified by reading every file. Documents carry 27 fields in total.
- **Tier distribution:** Tier 1 = 40, Tier 2 = 21, Tier 3 = 11.
- **Validation script:** `corpus/validate_corpus.py` exists.
  `python corpus/validate_corpus.py --corpus clean --strict` → **PASSED: 0 error(s),
  0 warning(s)**. Reports max pairwise lexical overlap 0.339, body length median 186
  words, 27 verified anchors.
- No answer-key field (`ground_truth`, `label`, `poison_family_id`, `is_poisoned`)
  appears inside any clean document. Labels live in `corpus/ground_truth/clean.json`
  (72 entries).

---

# Sprint 2 — Poisoned Corpus

**Status: Complete**

- `corpus/poisoned/` contains **12 JSON documents** plus `index.json`. Within the 8–12
  range.
- **Tier spread:** Tier 1 = 2, Tier 2 = 5, Tier 3 = 5. The Tier-1 requirement of "at
  least one edge case" is met with two: `poison-authority-carescape-t1-psirt` and
  `poison-authority-contec-t1-cisa`.
- **Ground-truth label:** present for all 12, in `corpus/ground_truth/poisoned.json`,
  with `ground_truth`, `poison_family_id`, `target_query_id`, `intended_false_claim`,
  `retrieval_segment`, `contains_injection_payload`, `source_tier`.
- **Internal-only:** confirmed. No poisoned document file contains a ground-truth
  field. Poisoned and clean documents carry an **identical 27-field schema**, so
  structure alone does not distinguish them.
- Six attack families: `attribution_fabrication` (2), `authority_spoof` (2),
  `direct_prompt_injection` (1), `ioc_reputation_flip` (3), `remediation_misdirection`
  (2), `severity_downgrade` (2).
- Validator: `--corpus poisoned --strict` → **PASSED: 0 error(s), 0 warning(s)**.

> **Gap 2-A.** `direct_prompt_injection` has a single instance. Sprint 8's results show
> this is the only family blocked at 100%, on n=1.

---

# Sprint 3 — Baseline RAG

**Status: Complete**

- **`embed_query()`** — `pipeline/retrieval.py:109`, re-exported `pipeline/rag.py:67`.
- **`retrieve_top_k()`** — `pipeline/retrieval.py:115`, re-exported `pipeline/rag.py:72`.
- **`generate_answer()`** — `pipeline/generation.py:71` and `:232`, re-exported
  `pipeline/rag.py:81`.

### Structured records — CONFIRMED

Executed `retrieve_top_k("ransomware targeting hospital imaging systems", k=3)`:

- Returns `RetrievalResult`, not a list of strings.
- Each element is a `RetrievedRecord`, **not `str`**.
- `similarity` present as a `float` (observed 0.349).
- `provenance` is a `Provenance` object carrying 12 fields including `source_id`
  (observed `cisa_advisory`), `source_tier` (observed 1), `source_name`,
  `source_tier_label`, `source_type`, `published_date`, `ingestion_date`,
  `reference_url`, `reference_verified`, `attestation`, `content_sha256`, `publisher`.

### Retrieval logging to `logs/` — CONFIRMED

`pipeline/config.py:77` sets `log_dir = PROJECT_ROOT / "logs"`;
`pipeline/config.py:78` sets `retrieval_log_file = "retrieval_log.jsonl"`;
`pipeline/retrieval_log.py:120,144` write there. `logs/retrieval_log.jsonl` exists on
disk at 6,292 bytes.

### Perplexity — NOT implemented, and documented as deliberate

No perplexity computation exists anywhere in the codebase. The string appears in four
files, in every case as an explicit statement of its absence:
`pipeline/records.py`, `pipeline/retrieval_log.py`, `pipeline/__init__.py`,
`pipeline/test_pipeline.py` (which asserts it never reaches a log record).

Documented in the Sprint 3 session log at
`docs/sprint_logs/SESSION_05_baseline_pipeline.md:96`, section headed
*"Perplexity is deliberately not here"*, stating: *"This is a scoped-out decision, not
something we forgot."* **Requirement met.**

---

# Sprint 4 — Detectors

**Status: Complete**

Three independent modules in `detectors/`:

| Module | Entry point | Verified range | Per-document |
|---|---|---|---|
| Embedding anomaly | `anomaly.py:116` `embedding_anomaly_score` | 0.000–0.838, in [0,1] | Yes |
| Prompt injection | `injection.py:155` `injection_probabilities` | 0.000–0.000, in [0,1] | Yes |
| Entailment / NLI | `entailment.py:163` `entailment_scores` | 1.000–1.000, in [0,1] | Yes |

Plus a derived fourth signal, `pairwise_conflict` (`entailment.py:230`), reusing the
NLI model.

**Normalisation confirmed** by executing all three against 8 real corpus documents:
every score in [0,1], one score per document.

**Sanity-check script:** `detectors/test_detectors.py` exists and runs against known
clean and poisoned documents. Output: *"Loaded 72 clean and 12 poisoned documents"*;
attacker's claim supported at **0.671** by the poisoned document versus **0.302** by
the clean anchor; 5/12 poisoned documents ranked most anomalous in their set; **All
structural checks passed** (20 checks).

> **Gap 4-A.** All three detectors resolved to fallback backends on this machine —
> `kmeans_numpy:hashing-fallback-384d`, `heuristic-patterns`, `lexical-overlap`, each
> reporting `is_model=False`. The harness prints *"RUN IS NOT CONCLUSIVE"* and names
> them.
> **Gap 4-B.** Under the fallbacks, injection returns a constant 0.000 across all
> sampled documents and entailment returns a constant 1.000. Both distributions are
> degenerate, which is what the fusion layer's degeneracy guard is responding to.

---

# Sprint 5 — Fusion

**Status: Complete**

### Components

| Required | Location |
|---|---|
| Case classifier | `fusion/cases.py` — `classify_document`, `classify_response` |
| Trained logistic regression | `fusion/artifacts/trust_model.joblib` + `.json` sidecar |
| Confidence estimator | `fusion/confidence.py` — `compute_confidence` |
| 3-class headline classifier | `fusion/cases.py` — `headline_band` |

Model sidecar reports: backend `sklearn`, C = 0.03, calibrated `True`, trained on
n = 373 (53 positive / 320 negative), features `['x_injection', 'is_tier1',
'is_tier3']`, `underpowered: True`, 1 warning.

### Reported validation metrics — present in `eval/fusion_metrics.json`

| Metric | Value |
|---|---|
| Precision | **0.0** |
| Recall | **0.0** |
| F1 | **0.0** |
| F₃ | **0.0** |
| PR-AUC | 0.2698 |
| ROC-AUC | 0.6938 |
| Brier | 0.1407 |

Attack Success Rate versus baseline, same file: `asr_baseline` 0.294118,
`asr_fusion` 1.0, `absolute_reduction` **−0.705882**, `relative_reduction` −2.4. A
matched-false-positive-rate comparison is also present in the file.

> **Gap 5-A.** The reported precision, recall, F1 and F₃ are all **0.000** on the
> held-out set. The metrics exist as the checklist requires; their values indicate the
> fitted model identified no positives at the chosen threshold.
> **Gap 5-B.** The ASR reduction recorded in `eval/fusion_metrics.json` is **negative**
> at the operating point — the fusion score performs worse than the naive baseline
> there. The file's own scope note states the figure is measured at retrieval
> containment and that a matched-rate comparison is the fair one.

## CRITICAL CHECK — design ↔ implementation

### Case count and definitions: **EXACT MATCH**

Parsed the §2.3 table from `docs/design/TRUST_RISK_DESIGN.md` and compared it
field-by-field against the `CASES` tuple in `fusion/cases.py`:

- Design case count: **11**. Implemented case count: **11**.
- Case ID sets identical.
- **Name, priority and action match on all 11 cases. Zero mismatches.**
- Precedence order matches design §2.7 exactly:
  `C5, C4, C11, C10, C7, C9, C6, C8, C3, C2, C1`.

### Tier-3 fail-safe override: **ENFORCED IN CODE**

Tested at two levels.

**Function level** — `headline_band()` called across 90 input combinations (9 action
values including `"UNKNOWN"`, `""`, `None`, `"accept"`, `"Accept"`; 10 tier values
including 0, 4, 99, −1, `None`, `"3"`, `"1"`):

- Combinations yielding GREEN: **exactly one — `('ACCEPT', 1)`**.
- **Tier 3 → GREEN: NEVER.**
- Tier 2 → GREEN: NEVER.
- Exceptions raised: none. Every degenerate input returned a band.

**Every case × every tier** — 33 combinations. No case reaches GREEN at Tier 3.

**End to end** — 36 full retrieval sets scored through `FusionScorer.score_query()`
across three threshold regimes (the fitted thresholds on disk, provisional thresholds,
and a regime where no signal can fire), with 1/2/3/5 documents at each tier:

- 9 GREEN outcomes, **all of them Tier 1, case C1, action ACCEPT**.
- **Tier 3 GREEN end-to-end: NONE. Tier 2 GREEN end-to-end: NONE.**

**No mismatch found between `docs/design/` and `fusion/`.**

---

# Sprint 6 — Report Generator

**Status: Complete**

Generated a report from a two-document retrieval set and inspected every required
field. All present:

| Required | Field | Observed |
|---|---|---|
| Query | `query` | present |
| Timestamp | `generated_at` | `2026-09-04T17:41:41+00:00` |
| Headline class | `headline` | `RED` |
| RED sub-type | `headline_subtype` | `ATTACK_DETECTED` |
| Case classification | `case_id` | `C7` |
| Score % | `trust_percent` | present (null in this run — see Gap 6-A) |
| Confidence interval | `trust_interval` | present |
| Risk tier | `risk_tier` | `HIGH` |
| Per-source breakdown | `documents` | present, one entry per retrieved document |
| Extracted entities | `entities` | present, CVE extracted |
| Reasoning narrative | `reasoning` | present |
| Recommended action | `recommended_action` | `REJECT` |
| Empty analyst_decision | `analyst_decision` | `decision=None`, `status=AWAITING_REVIEW`, `is_database_row=False` |

### Grounding unit tests — CONFIRMED

`reports/test_reports.py` contains 11 test functions, including
`test_narrative_grounding` and `test_grounding_test_actually_works`. Executed:

- *"a fabricated figure in the narrative is detected as ungrounded"* — PASS
- *"a fact pointing at a non-existent path fails to resolve"* — PASS
- **All report checks passed** (100 checks).

The suite extracts every numeric token from the rendered narrative and requires each to
resolve to a real value at a real JSON pointer in the report object, with two negative
controls proving the check can fail.

> **Gap 6-A.** `trust_percent` and `trust_interval` came back null in this run because
> the fitted model could not load — see Gap X-E. The fields exist and are populated
> when `sklearn` and `joblib` are installed.

---

# Sprint 7 — Audit Log & Dashboard

**Status: Complete**

### SQLite audit log

`logs/audit.py`. Schema instantiated and inspected:

- `query_events` — **45 columns**. Every checklist field present: `query_text`,
  `retrieved_doc_ids`, `documents` (all per-document detector scores), `trust_percent`,
  `headline`, `headline_subtype`, `case_id`, `final_action`, `created_at` (timestamp),
  `event_id` (unique reference ID). Also carries both track proposals separately,
  confidence components, entities, reasoning, and version pinning.
- `analyst_decisions` — **24 columns**, including `analyst_decision`.
- **Updatable after the fact:** `supersedes_decision_id` present; corrections append a
  new row rather than editing. Verified by test.
- Three views: `v_current_decisions`, `v_labelled_decisions`, `v_pending_review`.
- `python -m logs.test_audit` → **All audit log checks passed** (62 checks), including
  that the schema has no `DEFAULT` on `analyst_decision`, that the database refuses a
  decision row with no verdict, and that editing a historical row breaks the hash chain.

### Dashboard

`dashboard/` — `app.py`, `components.py`, `service.py`, `pages/1_Audit_Log.py`.

- **Banner first:** asserted at `test_dashboard.py:221` (*"nothing is rendered before
  the banner"*) and `:371` (*"no score, table or expander is rendered above the
  banner"*). Both PASS.
- **Accept / Reject / Override buttons:** `app.py:157`, `:160`, `:163`, wired to
  `_save()` at `:174` and `:191`.
- **Writes to `analyst_decision`:** via `get_decision_writer().record_decision()` at
  `app.py:224`. No dashboard module contains a direct `INSERT INTO analyst_decisions`.
- **Filterable audit viewer:** `pages/1_Audit_Log.py` — Class (`:47`), RED sub-type
  (`:49`), Case classification (`:57`), Analyst decision including `UNREVIEWED`
  (`:59–60`).
- `python -m dashboard.test_dashboard` → **All dashboard checks passed**.

> **Gap 7-A.** `streamlit` is **not installed** on this machine, so the dashboard cannot
> be launched here. The tests substitute a recording stub and verify call order and
> structure; they do not and cannot verify rendered appearance.

---

# Sprint 8 — Evaluation

**Status: Partial**

`eval/run_evaluation.py` exists and compares three configurations. Results saved to
`eval/results/`: `evaluation.json`, `comparison_table.txt`, `comparison.png`.

All four required metrics are computed per configuration: attack success rate, false
positive rate, false negative rate, latency.

| Configuration | ASR (exposure) | ASR (high-conf) | FPR | FNR | Latency | Status |
|---|---|---|---|---|---|---|
| `no_retrieval` | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 ms | **STRUCTURAL** |
| `vanilla_rag` | 1.0 | 1.0 | 0.0 | 1.0 | 0.15 ms | MEASURED |
| `full_system` | 0.9 | 0.0 | 0.1813 | 0.0 | 23.81 ms | MEASURED |

`generation_backend_available: false`. `fallback_detector_backends:
["anomaly", "entailment", "injection"]`.

> **Gap 8-A.** Configuration (a), the vanilla LLM with no retrieval, produced **no
> measured values**. Every metric for it is labelled `STRUCTURAL` — true by the
> configuration's definition rather than observed. No language model was queried,
> because none was reachable. The checklist asks for a comparison against a vanilla
> LLM; the configuration is implemented and reported, but contributes no measurement.
> **Gap 8-B.** The `vanilla_rag` FPR of 0.0 and FNR of 1.0 are also labelled
> `STRUCTURAL` — a configuration with no security layer cannot flag anything.
> **Gap 8-C.** Attack success is measured as a **containment proxy**, not at answer
> level, because no generation backend exists. The file records this and states the
> proxy is an upper bound.

---

# Sprint 9 — Final Documentation

**Status: Partial**

### Present and consistent

- `docs/FINAL_PROJECT_LOG.md` — 460 lines. Contains an executive summary, all ten
  sessions in order, standing limitations and Level 4 future scope.
- `docs/FINAL_PROJECT_LOG.docx` — present, 22,670 bytes.
- **Numbers cross-checked against `eval/results/evaluation.json`:** the log's 90%,
  0%, 18.1%, 93.3%, 5%, 77.5%, 17.5% and ~24 ms all match the saved evaluation output.
- `README.md` — current, 20 numbered sections, includes the evaluation results (§12)
  and the audit log and dashboard (§11).

> **Gap 9-A — the largest documentation inconsistency found.**
> `docs/PROJECT_REPORT.md` (880 lines) is **stale and contradicts the current build**:
> - line 50 — *"Decision-logic design (`design-v1.1`)"* — the design is now v1.2.
> - line 56 — *"Level 3 fusion and case classifier | Designed, not implemented"* —
>   `fusion/` is built, with 112–115 passing checks.
> - line 57 — *"Report generator, dashboard, audit log | Designed, not implemented"* —
>   all three are built.
> - line 791 — *"Designed in full; implementation next"*.
> - line 822 — *"reports/ dashboard/ to be implemented"*.
>
> `README.md` links this file at line 10 as *"the comprehensive report… Start there for
> the complete picture."* A reader following that instruction reaches a document
> stating that half the project does not exist. `docs/PROJECT_REPORT.docx` carries the
> same content.

---

# Cross-cutting checks

## Session log + .docx pairing — Complete

All ten session logs have a matching `.docx`. **No `.md` without a `.docx`, and no
`.docx` without a `.md`.**

> **Gap X-A.** No file named `SPRINT_LOG.md` exists. The convention in use is
> `SESSION_NN_<topic>.md`. Every sprint that shows work has a corresponding log under
> that convention (see the mapping table at the top); this is a naming difference from
> the checklist, not an absent artefact.
> **Gap X-B.** Sprint 9 (final documentation) has no session log of its own. Sessions
> 01–10 cover Sprints 0–8; the final-documentation work is recorded inside
> `FINAL_PROJECT_LOG.md` rather than in a session log.

## README tone and "sprint" mentions — Complete

`grep -ic sprint README.md` → **2 occurrences**, both structural rather than narrative:

- line 897 — a file path in a link, `docs/sprint_logs/SESSION_10_evaluation.md`
- line 987 — a directory name in the repository-layout listing, `sprint_logs/`

Neither refers to a sprint as a unit of work. Tone is formal throughout; no
first-person sprint narrative in the README.

## Mermaid diagram versus implementation — Complete

Parsed the diagram from `README.md`:

- **15 nodes claim "built"**: D1, D2, D3, DER, BAND, CASE, ENC, LR, CONF, HEAD, REP,
  AUDIT, DASH, AD, EVAL. **Every one corresponds to a directory that exists on disk.**
- **2 nodes are explicitly flagged as not built**: `GEN` — *"LLM Generates Conclusion —
  NOT WIRED IN"*; `D4` — *"Evidence Conflict Check — NOT BUILT"*. A third,
  verification sampling, is flagged *"DESIGNED, NOT BUILT"*.
- Syntax: 5 subgraphs, 5 matching `end` statements, balanced.

The diagram reflects what is implemented, including what is not.

## Test-count claims versus measured counts

| Suite | README claims | Measured on this machine | Static call sites |
|---|---|---|---|
| `pipeline.test_pipeline` | 45 | **55** | 46 |
| `detectors.test_detectors` | 20 | 20 | 23 |
| `fusion.test_fusion` | 115 | **112** | 115 |
| `reports.test_reports` | 100 | 100 | 71 |
| `logs.test_audit` | 62 | 62 | 58 |
| `dashboard.test_dashboard` | 61 | **55** | 43 |

All six suites report passing. Three counts do not match the README.

> **Gap X-C (Sprint 3).** README line 28 and `SESSION_05_baseline_pipeline.md:156` both
> state 45 pipeline checks. The measured count is **55**. The discrepancy is not
> environment-dependent — 46 static call sites exist, some inside loops.
> **Gap X-D (Sprint 5).** README states 115 fusion checks; **112** run here. The cause
> is verified: `fusion/test_fusion.py` contains exactly 3 checks gated behind
> `if result.risk is not None and not math.isnan(result.risk)`, which are skipped when
> the fitted model cannot load. 115 is correct on a machine with `sklearn` installed.
> **Gap X-E (Sprint 7).** README states 61 dashboard checks; **55** run here. Cause not
> established by this audit.

## Environment on this machine

> **Gap X-F.** `sklearn`, `joblib` and `streamlit` are **not installed** on this
> machine. Consequences verified:
> - `FusionScorer.load()` prints *"could not load model (ModuleNotFoundError); the rule
>   track will run alone"* and `model loaded: False`.
> - Composite trust scores are therefore absent from reports generated here
>   (Gap 6-A), and only the rule track contributes to dispositions.
> - The dashboard cannot be launched here (Gap 7-A).
>
> `numpy`, `matplotlib` and `pandas` are installed. Band thresholds load correctly
> (`bands fitted: True`).

## Two different attack-success figures in `eval/`

> **Gap X-G (Sprints 5 and 8).** Two files report attack success rates with different
> definitions, different baselines and **opposite directions**, and neither
> cross-references the other:
>
> | File | Baseline | System | Direction |
> |---|---|---|---|
> | `eval/fusion_metrics.json` | 0.294 (any single signal ≥ 0.5) | 1.000 | system **worse** |
> | `eval/results/evaluation.json` | 1.000 (vanilla RAG) | 0.900 exposure / 0.000 high-conf | system **better** |
>
> Both are internally documented — `fusion_metrics.json` carries a scope note and a
> matched-rate comparison; `evaluation.json` carries both ASR definitions. But a reader
> encountering them separately would see the fusion layer described as both worse and
> better than baseline.

## Version control

> **Gap X-H (all sprints).** The following are **untracked in git**: `corpus/`,
> `fusion/`, `reports/`, `logs/`, `dashboard/`, `eval/run_evaluation.py`,
> `eval/__init__.py`, `eval/fusion_metrics.json`, `eval/results/`,
> `docs/FINAL_PROJECT_LOG.md`, and session logs 07, 08, 09 and 10.
>
> Tracked top-level entries are only: `.gitignore`, `README.md`, `detectors`, `docs`,
> `eval`, `pipeline`, `requirements.txt`. `README.md`, `.gitignore` and
> `docs/design/TRUST_RISK_DESIGN.md` show as modified and uncommitted.
>
> The corpus is the project's benchmark and is not in version control.

## Stray directory

> **Gap X-I.** A directory named `Claude outputs/` exists at the repository root
> containing 7 files: `FINAL_PROJECT_LOG.docx`, `SESSION_07_level3_fusion.docx`,
> `SESSION_07_level3_fusion.md`, `SESSION_08_report_generator.docx`,
> `SESSION_09_audit_log_and_dashboard.docx`, `SESSION_10_evaluation.docx`,
> `comparison.png`. These duplicate files that also exist under `docs/` and
> `eval/results/`. It is listed in `.gitignore`.

---

# Consolidated gap list

| # | Sprint | Gap |
|---|---|---|
| 2-A | 2 | `direct_prompt_injection` attack family has only one instance; it is the only family Sprint 8 reports as blocked at 100%, on n=1 |
| 4-A | 4 | All three detectors ran on fallback backends (`is_model=False`); harness prints "RUN IS NOT CONCLUSIVE" |
| 4-B | 4 | Under fallbacks, injection returns constant 0.000 and entailment constant 1.000 across sampled documents — both distributions degenerate |
| 5-A | 5 | Reported precision, recall, F1 and F₃ are all 0.000 on the held-out set |
| 5-B | 5 | `eval/fusion_metrics.json` records a **negative** ASR reduction (−0.706) at the operating point |
| 6-A | 6 | `trust_percent` / `trust_interval` are null in reports generated on this machine, because the fitted model cannot load |
| 7-A | 7 | `streamlit` not installed here; dashboard cannot be launched, and rendered appearance is unverified |
| 8-A | 8 | Configuration (a) vanilla LLM produced **no measured values** — all metrics `STRUCTURAL`; no language model was queried |
| 8-B | 8 | `vanilla_rag` FPR 0.0 and FNR 1.0 are also `STRUCTURAL`, not measured |
| 8-C | 8 | Attack success measured as containment proxy, not at answer level; no generation backend |
| 9-A | 9 | `docs/PROJECT_REPORT.md` (and `.docx`) states `design-v1.1` and that fusion, reports, dashboard and audit log are "not implemented" — contradicted by the build. README links it as the primary entry point |
| X-A | cross | No file named `SPRINT_LOG.md`; convention is `SESSION_NN_*.md` (all 10 pairs complete) |
| X-B | 9 | Sprint 9 has no session log of its own |
| X-C | 3 | README and `SESSION_05` state 45 pipeline checks; measured 55 |
| X-D | 5 | README states 115 fusion checks; 112 run here (3 model-gated checks skipped without `sklearn`) |
| X-E | 7 | README states 61 dashboard checks; 55 run here; cause not established |
| X-F | env | `sklearn`, `joblib`, `streamlit` not installed on this machine |
| X-G | 5, 8 | Two attack-success figures in `eval/` with opposite directions and no cross-reference |
| X-H | all | `corpus/`, `fusion/`, `reports/`, `logs/`, `dashboard/`, four session logs and `FINAL_PROJECT_LOG.md` are untracked in git |
| X-I | cross | Stray `Claude outputs/` directory duplicating seven files |
| X-J | 7 | `dashboard.test_dashboard` writes an empty `logs/audit.db` to the default path as a side effect instead of staying in its temporary directory |

---

# What verified clean

Recorded because a gap list on its own is not a fair picture of the tree.

- **The design and the implementation agree exactly.** 11 cases in both; all names,
  priorities and actions match; precedence order identical.
- **The Tier-3 fail-safe holds.** 90 function-level input combinations, 33 case × tier
  combinations and 36 end-to-end retrieval sets across three threshold regimes: GREEN
  is reachable only from `ACCEPT` at Tier 1. No Tier-3 or Tier-2 path to GREEN exists,
  and no degenerate input raises.
- **Both corpora validate with zero errors and zero warnings**, and no answer-key field
  appears inside any document in either partition.
- **`retrieve_top_k()` returns structured records** with similarity and full provenance,
  not strings.
- **Perplexity is absent and documented as a deliberate exclusion** in the Sprint 3 log.
- **The grounding tests are real** — they include negative controls that prove the check
  can fail, and both pass.
- **The audit log's never-auto-populated invariant is enforced** at schema, code-path
  and provenance level, and the hash chain detects tampering.
- **All six test suites pass** on this machine.
- **The Mermaid diagram matches the build**, including explicit "NOT BUILT" markers on
  the two components that do not exist.
- **README contains no narrative use of the word "sprint"**, and the evaluation figures
  in `FINAL_PROJECT_LOG.md` match `eval/results/evaluation.json` exactly.

---

## Audit side effects

Executing `python -m dashboard.test_dashboard` as part of this audit **created
`logs/audit.db`**, an empty SQLite file (0 rows in both tables). The cause is in
`dashboard/app.py`: `main()` calls `get_audit_log()` with no argument, so it resolves
to `DEFAULT_DB` rather than to the temporary path the test sets up for
`get_audit_log(db)` — the two calls are different `lru_cache` keys.

The file was absent before the audit, is matched by `.gitignore:52` (`logs/*.db`), and
was **deleted after the check** to restore the pre-audit state. `logs/` now contains
`audit.py`, `retrieval_log.jsonl` and `test_audit.py`, as it did beforehand.

> **Gap X-J (Sprint 7).** Running the dashboard test suite writes an empty database to
> the default audit path as a side effect, rather than confining itself to the
> temporary directory it creates. Recorded as an observation about test isolation.

---

*Audit performed by reading files under `C:\Projects\Capstone` and executing existing
test and scoring code against them. Aside from `logs/audit.db` — created by a test run
and then removed, as described above — no project file was created, modified or
deleted; this report is the only artefact produced.*
