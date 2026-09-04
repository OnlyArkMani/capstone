# Project Runbook

**Trust & Risk Layer for Healthcare Threat-Intelligence RAG** — Team Zetabyte

Installation, verification and live demonstration procedure.

---

## 0. Read this first

Three things will affect the demonstration, and all three are known in advance.

| # | Issue | Effect if unaddressed |
|---|---|---|
| 1 | `streamlit`, `joblib` and `matplotlib` were **missing from `requirements.txt`** until now | The console will not start; the trust score shows "not computed"; the evaluation chart is not produced |
| 2 | Detector models (~750 MB) are **downloaded, not bundled** | Everything runs, but on fallback backends: almost every query returns ORANGE and no detector signal fires |
| 3 | The Docker image has **never been built** in any environment available to this project | Build time is unknown; allow an hour the first time |

If you installed dependencies before today, **reinstall**: `pip install -r requirements.txt`.

**Allow one hour** for first-time setup on a machine that has never run this. Steps 1–3
are the long ones; everything after is seconds.

---

## 1. Path A — Docker (recommended)

Requires Docker Desktop running.

### 1.1 Build

```bash
cd C:\Projects\Capstone
docker compose build
```

*Expect 10–25 minutes.* Downloads a CPU-only PyTorch (~200 MB) plus the rest of the
dependency tree. Rebuilds after this are seconds unless `requirements.txt` changes.

### 1.2 Download the detector models — optional but strongly recommended

```bash
docker compose run --rm fetch-models
```

*Expect 5–15 minutes and ~750 MB.* Needs internet. Cached in a named Docker volume, so
this is a once-per-machine cost that survives `docker compose down`.

**Skipping this is supported and the system will run**, but every detector falls back to
a stand-in, and the demonstration will show nine ORANGE results out of ten with no
signals firing. If you have internet before the demo, run it.

### 1.3 Verify

```bash
docker compose run --rm verify
```

Runs nine stages in order: backend report, corpus validation, index build, five test
suites, and model fitting. **The backend report comes first deliberately** — a missing
model is then visible at the top of the log rather than inferred from odd numbers at the
bottom.

Must end with `ALL SUITES COMPLETE`. Expected counts in §4.

### 1.4 Start the console

```bash
docker compose up dashboard
```

Open **http://localhost:8501**. Leave this running for the demonstration.

### 1.5 Other services

```bash
docker compose run --rm evaluate    # three-configuration comparison -> eval/results/
docker compose run --rm report      # one sample analyst report, printed
docker compose run --rm shell       # interactive shell inside the image
docker compose down                 # stop everything (volumes survive)
```

---

## 2. Path B — Local Python

Use if Docker is unavailable. Python 3.11 or later.

```bash
cd C:\Projects\Capstone

python -m venv .venv
.venv\Scripts\activate                 # Windows
# source .venv/bin/activate            # macOS / Linux

pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
```

Installing `torch` from the CPU index **first** matters: without it, pip resolves the
CUDA build as a transitive dependency of `sentence-transformers` and pulls roughly 2 GB
of libraries this project never uses.

```bash
python -m pipeline.check_backends       # what is real and what is a fallback
python -m pipeline.build_index          # build the FAISS index over 84 documents
python -m fusion.train                  # fit the model, write fusion/artifacts/
```

Optional, to set `GROQ_API_KEY` for generation (free tier at console.groq.com):

```bash
set GROQ_API_KEY=gsk_...                # Windows
export GROQ_API_KEY=gsk_...             # macOS / Linux
```

Generation is **not** required for the demonstration. Without it the pipeline uses an
extractive stub and says so.

---

## 3. Verification gate

Every one of these must pass before the demonstration. Roughly two minutes total.

```bash
python corpus/validate_corpus.py --corpus clean    --strict
python corpus/validate_corpus.py --corpus poisoned --strict

python -m pipeline.test_pipeline
python -m detectors.test_detectors
python -m fusion.test_fusion
python -m reports.test_reports
python -m logs.test_audit
python -m dashboard.test_dashboard
```

### Expected results

| Command | Expected | Ends with |
|---|---|---|
| `validate_corpus --corpus clean` | 72 documents | `PASSED: 0 error(s), 0 warning(s)` |
| `validate_corpus --corpus poisoned` | 12 documents, 6 families | `PASSED: 0 error(s), 0 warning(s)` |
| `pipeline.test_pipeline` | 55 checks | `ALL CHECKS PASSED` |
| `detectors.test_detectors` | 20 checks | `All structural checks passed.` |
| `fusion.test_fusion` | **115** checks | `All contract checks passed.` |
| `reports.test_reports` | 100 checks | `All report checks passed.` |
| `logs.test_audit` | 62 checks | `All audit log checks passed.` |
| `dashboard.test_dashboard` | 55 checks | `All dashboard checks passed.` |

**If `fusion.test_fusion` reports 112 rather than 115**, `scikit-learn` or `joblib` is
missing. Three checks are gated on the fitted model loading. The suite still passes, but
the trust score will be absent from the console. Fix with
`pip install scikit-learn joblib`.

`detectors.test_detectors` printing **`RUN IS NOT CONCLUSIVE`** means the detector models
are not installed. This is expected without §1.2 and is not a failure.

---

## 4. Pre-demonstration checklist

### T-minus 1 day

- [ ] `docker compose build` completes, **or** local install completes
- [ ] `docker compose run --rm fetch-models` completes (needs internet)
- [ ] `docker compose run --rm verify` ends with `ALL SUITES COMPLETE`
- [ ] `docker compose up dashboard` — console loads at http://localhost:8501
- [ ] Run all four demonstration queries in §5 and confirm the colours match
- [ ] `docker compose run --rm evaluate` — confirm `eval/results/comparison.png` exists

### T-minus 1 hour

- [ ] `docker compose up dashboard` running, browser open at http://localhost:8501
- [ ] Browser zoom at 100%; window maximised so the banner fills the width
- [ ] `eval/results/comparison.png` open in a second tab as a fallback
- [ ] `docs/FINAL_PROJECT_LOG.md` open — the evaluation numbers are in §1
- [ ] Terminal open in `C:\Projects\Capstone` for the command-line fallback
- [ ] Run one query end to end and press **Accept**, so the audit log is not empty

### T-minus 5 minutes

- [ ] Press **Clear** on the console so it opens on a blank query box
- [ ] Confirm the audit log page loads and shows at least one row

---

## 5. The demonstration

Four queries, chosen to show all four headline states. **Verified to produce these
results** on fallback backends; with the real models installed the colours may differ,
so re-run §5 after §1.2 and note any change.

### Query 1 — GREEN

```
Risk Guidance for End-of-Support Operating Systems in Clinical Environments
```

**Expect:** GREEN · *Good to Go* · C1 Authoritative Confirmation · ACCEPT · trust ≈ 93.5%

Verified authoritative source, no detector signal above threshold. Normal operation.

> *Talking point:* GREEN requires two conditions at once — an explicit accept **and** a
> Tier-1 verified source. Tier 2 and Tier 3 can never reach GREEN regardless of how
> clean the content looks, because the absence of evidence against a document is not
> evidence for it.

### Query 2 — ORANGE

```
Is the Contec CMS8000 patient monitor safe to keep connected to our clinical network?
```

**Expect:** ORANGE · *Mid-Suspicious, Review Recommended* · REVIEW · trust ≈ 84.4%

The answer is returned marked unverified and queued for an analyst.

> *Talking point:* ORANGE is the default for anything the system will not positively
> vouch for. Note the trust score is high — the system still declines to auto-accept.

### Query 3 — RED, Attack Detected

```
Do we need to isolate infusion pumps affected by CVE-2020-27252?
```

**Expect:** RED · *Attack Detected* · C8 Unverified Irregularity · REJECT · trust ≈ 18.3%

Expand a document panel to show the per-detector scores and which threshold was crossed.

> *Talking point:* The document is the unit of concern here. Quarantining it largely
> closes the matter.

### Query 4 — RED, Trusted Source Compromise *(the important one)*

```
Lateral Movement into Biomedical Device Segments Following Workstation Compromise
```

**Expect:** RED · *Trusted Source Compromise Suspected* · C4 Trusted-Source Anomaly ·
ESCALATE · **trust ≈ 93.5%**

> *Talking point — this is the strongest moment in the demonstration.* The composite
> trust score is **93.5%**, and the system escalated anyway. A dashboard that led with
> the score would have shown a reassuring number sitting on top of a suspected source
> compromise. The banner is derived from the decision actually taken, not from the
> score, so it cannot do that.
>
> This is also why RED is split in two: an ordinary attack from an unverified source is
> closed by quarantining a document, whereas a verified source behaving anomalously is a
> finding about our own trust infrastructure that outlives the query.

### Then demonstrate the decision capture

1. On any result, scroll to **Analyst decision**
2. Press **Accept**, **Reject** or **Override** (Override requires an action and a reason
   code from the eleven-code controlled vocabulary)
3. Open **Audit log viewer** in the sidebar
4. Filter by class, by case, or by analyst decision
5. Open the **Integrity** panel at the bottom — the decision hash chain verifies

> *Talking point:* Until somebody presses one of those buttons, the query has **no
> decision row at all** — not a blank one, and not one marked "pending". A pending value
> in the same column as real verdicts means every future query has to remember to
> exclude it, and the first one that forgets is silently wrong.

---

## 6. Questions to expect, and honest answers

**"What is the headline result?"**
Against a plain RAG baseline, the system never returned adversarial content inside an
answer it vouched for — 100% → 0%. But adversarial content still reached the reader in 9
of 10 attack cases, flagged as unverified. And it achieves that by auto-accepting 5% of
queries and routing 93% of clean traffic to human review, which is not a deployable
operating point.

**"Do the detectors actually work?"**
Unknown. No development environment could reach the model repository, so all three ran on
fallback backends. Lexical overlap, standing in for the entailment model, cannot detect
contradiction at all — which is exactly what a severity-downgrade attack is. Three of six
attack families were blocked zero times. The evaluation demonstrates the architecture
functions end to end; it does not establish detection performance.

**"Why is the false-positive rate 18%?"**
Because the operating thresholds are calibrated very conservatively on a small corpus.
That is a tuning problem, addressable once the detector scores are real.

**"Is the reasoning text generated by an LLM?"**
No. It is template substitution. Every number is supplied with a JSON pointer into the
report, and a test extracts every numeric token from the rendered text and requires each
to resolve to a real value. Two negative controls confirm the check can fail.

**"How big is the corpus?"**
72 genuine and 12 adversarial documents across three source trust tiers. The adversarial
set spans six attack families. Small — the statistical model runs at its underpowered
setting and reports itself as such.

**"What is left to do?"**
Install the detector models and re-run the evaluation. That is the single
highest-value remaining action and every accuracy figure is provisional until then.

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: streamlit` | Installed before `requirements.txt` was corrected | `pip install -r requirements.txt` |
| Trust score shows "not computed" | `joblib` or `scikit-learn` missing, so `fusion/artifacts/trust_model.joblib` cannot load | `pip install scikit-learn joblib` then re-run `python -m fusion.train` |
| Evaluation produces no chart | `matplotlib` missing | `pip install matplotlib` |
| `retrieval failed … Has the index been built?` | No FAISS index | `python -m pipeline.build_index` |
| `[fusion] NOTE: no trained model found` | `fusion.train` never run | `python -m fusion.train` |
| Every query returns ORANGE, no signals fire | Detector models absent — running on fallbacks | `docker compose run --rm fetch-models`, or `pip install transformers sentencepiece` with internet |
| `fusion.test_fusion` reports 112 not 115 | Three model-gated checks skipped | Install `scikit-learn` and `joblib` |
| `RUN IS NOT CONCLUSIVE` from detectors | Expected without the models | Not a failure |
| Generation says "extractive stub" | No `GROQ_API_KEY` and no Ollama | Optional; not needed for the demonstration |
| Docker: permission denied writing `eval/results` | Host directory owner differs from container UID 1000 | `docker compose run --rm --user root evaluate`, or `chmod 777 eval/results` |
| Port 8501 in use | Another Streamlit instance | `docker compose down`, or edit the port mapping in `docker-compose.yml` |
| Console shows a stale result | Session state retained | Press **Clear** |

---

## 8. Fallback plan

If the console will not start during the demonstration, everything can be shown from the
command line:

```bash
python -m reports.test_reports --sample      # a full analyst report, headline first
python -m eval.run_evaluation                # the comparison table and weakness breakdown
type eval\results\comparison_table.txt       # the saved table
```

`eval/results/comparison.png` is a static image and needs nothing running. Keep it open
in a browser tab.

---

## 9. Command reference

| Purpose | Command |
|---|---|
| Report backend status | `python -m pipeline.check_backends` |
| Validate the corpus | `python corpus/validate_corpus.py --corpus clean --strict` |
| Rebuild the genuine corpus | `python corpus/build_clean_corpus.py --ingestion-date 2026-09-02 --clean` |
| Rebuild the adversarial corpus | `python corpus/build_poisoned_corpus.py --ingestion-date 2026-09-03 --clean` |
| Build the retrieval index | `python -m pipeline.build_index` |
| Run a single query | `python -m pipeline.run_query "your question"` |
| Fit the trust model | `python -m fusion.train` |
| Sample analyst report | `python -m reports.test_reports --sample` |
| Full evaluation | `python -m eval.run_evaluation --verbose` |
| Start the console | `streamlit run dashboard/app.py` |
| All test suites | See §3 |

---

*Design specification: `docs/design/TRUST_RISK_DESIGN.md`.
Results and limitations: `docs/FINAL_PROJECT_LOG.md`.
Deliverable verification: `docs/AUDIT_REPORT.md`.*
