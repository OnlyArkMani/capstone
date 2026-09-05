#!/usr/bin/env python3
"""
Sanity check for Level 3: do the fusion mechanics behave as the design says?

    python -m fusion.test_fusion
    python -m fusion.test_fusion --verbose

What this is
------------
A contract test, not a performance evaluation. Sprint 5's accuracy numbers come
from `python -m fusion.train`, which fits on the corpus and reports precision,
recall and attack-success-rate reduction. This file asks a narrower and more
important question first: **is the machinery wired the way the design specifies?**

The distinction matters because a fusion layer that is wired backwards still
produces confident, plausible, well-formatted numbers. Every check below is one
the design would fail loudly on if the implementation drifted:

  Part A   the C4 > C9 inversion survives, precedence is deterministic,
           escalation dominance is monotone, degenerate signals are excluded
  Part B   feature encoding is dummy-coded not ordinal, the ladder respects
           events-per-variable, calibration is monotone, save/load round-trips
  Part C   confidence is conjunctive, the caps bind, the review floor fires
  Wiring   score_query() returns the full contract and can only ever be made
           MORE conservative by the statistical track, never less

Ground truth
------------
This script does not read corpus/ground_truth/ at all. It builds its own
synthetic retrieval records, because the questions here are about logic rather
than about corpus content. A check below asserts that no *inference-time* module
in the fusion package reads the answer key.
"""

from __future__ import annotations

import argparse
import ast
import math
import sys
import tempfile
from pathlib import Path
from typing import Any

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pipeline.records import Provenance, RetrievedRecord  # noqa: E402

from fusion.bands import (  # noqa: E402
    FIXED_THRESHOLD_SIGNALS,
    CLEAN, SUSPICIOUS, MALICIOUS, BandThresholds, SignalSet, assign_band,
)
from fusion.cases import (  # noqa: E402
    ACCEPT, REVIEW, REJECT, ESCALATE, ACTION_SEVERITY, CASES, CASES_BY_ID,
    GREEN, ORANGE, RED, HEADLINE_BANDS, ATTACK_DETECTED, TRUSTED_SOURCE_COMPROMISE,
    classify_document, classify_response, escalation_dominance, headline_band,
)
from fusion.confidence import (  # noqa: E402
    N_EFF_ONE_CAP, REVIEW_FLOOR, SINGLETON_CAP, compute_confidence,
    effective_sample_size, forces_review,
)
from fusion.features import choose_feature_spec, encode, logit  # noqa: E402
from fusion.model import TrustModel  # noqa: E402
from fusion.evaluate import (  # noqa: E402
    compute_metrics, derive_thresholds, precision_at_prevalence,
)
from fusion.scorer import FusionScorer  # noqa: E402

FAILURES: list[str] = []
WARNINGS: list[str] = []
VERBOSE = False


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        FAILURES.append(name)


def note(msg: str) -> None:
    if VERBOSE:
        print(f"        {msg}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Hand-built thresholds so the band tests do not depend on a fitted artefact.
FIXED = BandThresholds(
    suspicious={"unsupport": 0.60, "anomaly": 0.60, "injection": 0.60, "conflict": 0.60},
    malicious={"unsupport": 0.85, "anomaly": 0.85, "injection": 0.85, "conflict": 0.85},
    n_clean_calibration=100, fitted=True, note="fixture",
)

TIER_LABEL = {1: "verified-authoritative", 2: "trusted-open", 3: "unverified"}


def rec(doc_id: str, tier: int, similarity: float = 0.80,
        source_id: str | None = None, content: str = "") -> RetrievedRecord:
    """A minimal retrieval record. Only the fields fusion actually reads matter."""
    sid = source_id or f"src-t{tier}"
    return RetrievedRecord(
        rank=0, doc_id=doc_id, similarity=similarity, raw_score=similarity,
        title=f"Advisory {doc_id}", summary="fixture summary",
        content=content or (
            f"Ransomware activity affecting hospital imaging systems, advisory {doc_id}. "
            f"Affected product versions should be patched. Network segmentation is advised."),
        provenance=Provenance(
            source_id=sid, source_name=f"Source {sid}", source_tier=tier,
            source_tier_label=TIER_LABEL[tier], source_type="advisory"),
    )


def sig(unsupport=0.10, anomaly=0.10, injection=0.10, conflict=None) -> SignalSet:
    return SignalSet(unsupport=unsupport, anomaly=anomaly,
                     injection=injection, conflict=conflict)


CLEAN_SIG = sig()
SUS_SIG = sig(unsupport=0.70)
MAL_SIG = sig(injection=0.95)


# ---------------------------------------------------------------------------
# Isolation: no inference-time module reads the answer key
# ---------------------------------------------------------------------------

INFERENCE_MODULES = ("bands.py", "cases.py", "confidence.py", "features.py",
                     "model.py", "scorer.py", "__init__.py")
GT_PATTERNS = ("ground_truth/", "ground_truth\\", "ground_truth.json",
               "clean.json", "poisoned.json")
FORBIDDEN_NAMES = {"GROUND_TRUTH_DIRNAME", "GROUND_TRUTH_FILENAME"}


def test_isolation() -> None:
    """The scoring path must never be able to see the labels.

    Checked on the parsed AST rather than by searching the source text, so that a
    module which *documents* not reading ground truth is not flagged for saying
    so. `dataset.py`, `train.py` and this file are exempt by design: training and
    evaluation code is exactly where the answer key belongs.
    """
    print("\nGround-truth isolation (inference path)")
    here = Path(__file__).resolve().parent
    offenders: list[str] = []
    for mod in INFERENCE_MODULES:
        path = here / mod
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                # A docstring is prose, not a path. Only flag short string
                # literals that look like an actual filesystem reference.
                if len(s) < 120 and any(p in s for p in GT_PATTERNS):
                    offenders.append(f"{mod}: string {s!r}")
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
                offenders.append(f"{mod}: name {node.id}")
    check("no inference module references the ground-truth manifests",
          not offenders, "; ".join(offenders))


# ---------------------------------------------------------------------------
# Part A -- bands
# ---------------------------------------------------------------------------

def test_bands() -> None:
    print("\nPart A -- signal bands")

    check("clean signals -> CLEAN", assign_band(CLEAN_SIG, FIXED)[0] == CLEAN)
    check("one signal over suspicious -> SUSPICIOUS",
          assign_band(SUS_SIG, FIXED)[0] == SUSPICIOUS)

    band, detail = assign_band(sig(injection=0.95), FIXED)
    check("injection alone is sufficient for MALICIOUS",
          band == MALICIOUS and detail["rule"] == "injection_alone", str(detail))

    band, detail = assign_band(sig(unsupport=0.95), FIXED)
    check("unsupport alone is NOT sufficient for MALICIOUS",
          band == SUSPICIOUS, f"got {band} via {detail['rule']}")

    band, detail = assign_band(sig(unsupport=0.95, anomaly=0.95), FIXED)
    check("two malicious signals -> MALICIOUS",
          band == MALICIOUS and detail["rule"] == "two_signals_malicious", str(detail))

    # Missing signal is excluded, not zeroed. A zero would be an assertion of
    # "no conflict", which is a claim we have no evidence for.
    s = SignalSet(unsupport=0.70, anomaly=None, injection=None, conflict=None)
    band, detail = assign_band(s, FIXED)
    check("missing signals are excluded, not treated as zero",
          band == SUSPICIOUS and set(detail["missing_signals"]) == {"anomaly", "injection", "conflict"},
          str(detail))

    # Degeneracy guard: a detector returning a constant must not become an
    # always-fire or never-fire threshold.
    #
    # This used to be exercised through `injection`, which no longer works as the
    # vehicle: design §9A.2 declares that signal's cut points instead of fitting
    # them, so it is exempt from the guard by construction. The guard itself is
    # unchanged and still governs every fitted signal, so the test now drives it
    # with `anomaly` — and a second check below pins the exemption, so neither
    # behaviour can regress silently into the other.
    const_zero = [SignalSet(unsupport=0.4, anomaly=0.0, injection=0.0) for _ in range(50)]
    fitted = BandThresholds.fit(const_zero)
    check("constant-zero clean distribution marks the signal unusable",
          "anomaly" in fitted.unusable, f"unusable={fitted.unusable}")
    note(f"unusable reason: {fitted.unusable.get('anomaly', '')}")

    band, detail = assign_band(sig(anomaly=0.99, unsupport=0.4, injection=0.0), fitted)
    check("an unusable signal cannot drive a band on its own",
          band == CLEAN and "anomaly" in detail["unusable_signals"],
          f"got {band} via {detail['rule']}")

    # The exemption, pinned. `injection` is a noisy-OR over hand-specified
    # patterns: its clean distribution is a column of zeros because no pattern
    # fires on a clean document, which is the detector WORKING, not a calibration
    # sample. Fitting quantiles on it would put Q0.95 at 0.0, the guard would
    # (correctly, for a fitted signal) mark it unusable, and `assign_band`
    # excludes unusable signals -- so the `injection_alone` rule of §2.1, the one
    # rule permitted to act on a single signal, would become unreachable code
    # while every suite still reported green. That is the failure this check
    # exists to prevent recurring.
    check("injection is exempt from the guard: declared, not fitted",
          "injection" not in fitted.unusable
          and fitted.suspicious.get("injection") == FIXED_THRESHOLD_SIGNALS["injection"][0]
          and fitted.malicious.get("injection") == FIXED_THRESHOLD_SIGNALS["injection"][1],
          f"sus={fitted.suspicious.get('injection')} mal={fitted.malicious.get('injection')} "
          f"unusable={fitted.unusable}")

    band, detail = assign_band(sig(injection=0.99, unsupport=0.4, anomaly=0.3), fitted)
    check("and injection alone still reaches MALICIOUS through the declared threshold",
          band == MALICIOUS and detail["rule"] == "injection_alone",
          f"got {band} via {detail['rule']}")

    # Thresholds must be quantiles of the clean distribution, not hand-picked.
    rng = np.random.default_rng(7)
    spread = [SignalSet(unsupport=float(v), anomaly=0.2 + 0.6 * float(v), injection=float(v) / 2)
              for v in rng.uniform(0.05, 0.75, size=200)]
    q = BandThresholds.fit(spread)
    ok = (q.fitted and q.suspicious["unsupport"] < q.malicious["unsupport"]
          and 0.6 < q.suspicious["unsupport"] < 0.76)
    check("fitted thresholds are Q95/Q99 of the clean distribution", ok,
          f"sus={q.suspicious.get('unsupport')} mal={q.malicious.get('unsupport')}")

    thin = BandThresholds.fit(spread[:10])
    check("fewer than 20 calibration points falls back rather than fitting noise",
          thin.suspicious.get("unsupport") == 0.60)


# ---------------------------------------------------------------------------
# Part A -- cases
# ---------------------------------------------------------------------------

def test_case_grid() -> None:
    print("\nPart A -- case grid (tier x band)")

    expected = {
        (1, "clean"): ("C1", ACCEPT), (1, "sus"): ("C4", ESCALATE), (1, "mal"): ("C5", ESCALATE),
        (2, "clean"): ("C2", ACCEPT), (2, "sus"): ("C6", REVIEW), (2, "mal"): ("C7", REJECT),
        (3, "clean"): ("C3", REVIEW), (3, "sus"): ("C8", REJECT), (3, "mal"): ("C9", REJECT),
    }
    signals = {"clean": CLEAN_SIG, "sus": SUS_SIG, "mal": MAL_SIG}
    wrong: list[str] = []
    for (tier, kind), (case_id, action) in expected.items():
        a = classify_document(tier, signals[kind], FIXED)
        if a.case_id != case_id or a.action != action:
            wrong.append(f"tier{tier}/{kind} -> {a.case_id}/{a.action}, expected {case_id}/{action}")
        else:
            note(f"tier{tier} {kind:5s} -> {a.case_id} {a.priority} {a.action}")
    check("all nine grid cells map to the specified case and action", not wrong, "; ".join(wrong))

    check("the grid covers nine cells plus two cross-cutting cases", len(CASES) == 11,
          f"{len(CASES)} cases defined")
    check("case ids are unique", len({c.case_id for c in CASES}) == 11)
    check("every case action is a defined action",
          all(c.action in ACTION_SEVERITY for c in CASES))

    with_bad_tier = False
    try:
        classify_document(4, CLEAN_SIG, FIXED)
    except ValueError:
        with_bad_tier = True
    check("an unknown source tier raises rather than defaulting", with_bad_tier)


def test_tier1_inversion() -> None:
    """The single most consequential assertion in the taxonomy."""
    print("\nPart A -- the C4 > C9 inversion")

    c4 = CASES_BY_ID["C4"]
    c9 = CASES_BY_ID["C9"]
    check("C4 (Tier-1 suspicious) outranks C9 (Tier-3 malicious) in priority",
          c4.priority < c9.priority, f"C4={c4.priority} C9={c9.priority}")
    check("C4 escalates while C9 rejects",
          c4.action == ESCALATE and c9.action == REJECT,
          f"C4={c4.action} C9={c9.action}")

    order = [c.case_id for c in CASES]
    check("C4 precedes C9 in the precedence order",
          order.index("C4") < order.index("C9"), str(order))
    check("C5 has the highest precedence of all", order[0] == "C5", str(order))

    # And the same thing end to end, through the classifier rather than the table.
    a1 = classify_document(1, SUS_SIG, FIXED)
    a3 = classify_document(3, MAL_SIG, FIXED)
    check("a merely suspicious Tier-1 doc escalates; an outright malicious Tier-3 doc does not",
          a1.action == ESCALATE and a3.action == REJECT,
          f"tier1-sus={a1.action} tier3-mal={a3.action}")

    # An ordinal tier encoding would make this structurally unlearnable; the
    # feature encoder must therefore never emit a single ordered tier column.
    spec = choose_feature_spec(["unsupport", "anomaly", "injection"], n_pos=200)
    check("tier is dummy-coded, not ordinal",
          "is_tier1" in spec.names and "is_tier3" in spec.names
          and not any(n in spec.names for n in ("tier", "source_tier", "tier_ordinal")),
          str(spec.names))


def test_cross_cutting_cases() -> None:
    print("\nPart A -- cross-cutting cases (C10, C11)")

    # C10: two Tier-1 documents contradicting each other, attack indicators quiet.
    docs = {"d1": sig(unsupport=0.2), "d2": sig(unsupport=0.2)}
    tiers = {"d1": 1, "d2": 1}
    a = classify_response(1, docs, tiers, FIXED, tier1_conflict=0.95,
                          similarities={"d1": 0.8, "d2": 0.78}, n_eff=2.0)
    check("Tier-1 vs Tier-1 contradiction with quiet indicators -> C10",
          a.case_id == "C10" and a.action == REVIEW, f"{a.case_id}/{a.action}")
    check("C10 reviews rather than adjudicating between two authorities",
          a.action == REVIEW and CASES_BY_ID["C10"].action == REVIEW)

    # The quiet clause: the same contradiction with a loud injection signal must
    # be caught as a possible compromise instead, not filed as a disagreement.
    docs_loud = {"d1": sig(unsupport=0.2, injection=0.95), "d2": sig(unsupport=0.2)}
    a = classify_response(1, docs_loud, tiers, FIXED, tier1_conflict=0.95,
                          similarities={"d1": 0.8, "d2": 0.78}, n_eff=2.0)
    check("the same contradiction with a loud injection signal is C5, not C10",
          a.case_id == "C5" and a.action == ESCALATE, f"{a.case_id}/{a.action}")

    # C11: one embedding outlier, no corroboration, almost no independent evidence.
    docs = {"d1": sig(anomaly=0.95), "d2": sig()}
    tiers = {"d1": 3, "d2": 3}
    a = classify_response(3, docs, tiers, FIXED, similarities={"d1": 0.9, "d2": 0.3},
                          n_eff=1.2, corroborated=False)
    check("isolated high-similarity outlier with no corroboration -> C11",
          a.case_id == "C11" and a.action == ESCALATE, f"{a.case_id}/{a.action}")

    # Corroborated, the same outlier is an ordinary grid case.
    a = classify_response(3, docs, tiers, FIXED, similarities={"d1": 0.9, "d2": 0.3},
                          n_eff=3.0, corroborated=True)
    check("the same outlier with corroboration is not C11",
          a.case_id != "C11", f"{a.case_id}")

    # Set-level signals must take the MAX, never the mean: one crafted document
    # among four clean ones is the entire attack.
    docs = {f"d{i}": sig() for i in range(4)}
    docs["d4"] = sig(injection=0.95)
    tiers = {k: 2 for k in docs}
    a = classify_response(2, docs, tiers, FIXED, n_eff=4.0)
    check("one malicious doc among four clean ones still drives the response band",
          a.band == MALICIOUS and a.case_id == "C7", f"{a.case_id}/{a.band}")

    empty_raises = False
    try:
        classify_response(1, {}, {}, FIXED)
    except ValueError:
        empty_raises = True
    check("classifying an empty retrieval set raises rather than returning ACCEPT", empty_raises)


def test_escalation_dominance() -> None:
    print("\nPart A -- escalation dominance")

    check("severity is ordered ACCEPT < REVIEW < REJECT < ESCALATE",
          ACTION_SEVERITY[ACCEPT] < ACTION_SEVERITY[REVIEW]
          < ACTION_SEVERITY[REJECT] < ACTION_SEVERITY[ESCALATE])

    pairs = [((ACCEPT, REVIEW), REVIEW), ((REJECT, REVIEW), REJECT),
             ((ESCALATE, ACCEPT), ESCALATE), ((ACCEPT, ACCEPT), ACCEPT),
             ((REJECT, ESCALATE), ESCALATE)]
    wrong = [f"{a}->{escalation_dominance(*a)} != {e}" for a, e in pairs
             if escalation_dominance(*a) != e]
    check("the more conservative action always wins", not wrong, "; ".join(wrong))

    # The property that matters: combining can never DE-escalate. If it could,
    # adding the statistical track could make the system less safe than the
    # rules alone -- the one thing the two-track design exists to prevent.
    actions = (ACCEPT, REVIEW, REJECT, ESCALATE)
    violations = [f"{a}+{b}" for a in actions for b in actions
                  if ACTION_SEVERITY[escalation_dominance(a, b)]
                  < max(ACTION_SEVERITY[a], ACTION_SEVERITY[b])]
    check("no combination of actions can de-escalate either input",
          not violations, "; ".join(violations))

    invalid_raises = False
    try:
        escalation_dominance("MAYBE", "PROBABLY")
    except ValueError:
        invalid_raises = True
    check("an unrecognised action raises rather than being silently ignored", invalid_raises)


# ---------------------------------------------------------------------------
# Part A -- headline classification (design 2.9)
# ---------------------------------------------------------------------------

ALL_ACTIONS = (ACCEPT, REVIEW, REJECT, ESCALATE)
ALL_TIERS = (1, 2, 3)


def test_headline_rule() -> None:
    print("\nPart A -- headline band (GREEN / ORANGE / RED)")

    check("only three bands exist", set(HEADLINE_BANDS) == {GREEN, ORANGE, RED})

    expected = {
        (ACCEPT, 1): (GREEN, None), (ACCEPT, 2): (ORANGE, None), (ACCEPT, 3): (ORANGE, None),
        (REVIEW, 1): (ORANGE, None), (REVIEW, 2): (ORANGE, None), (REVIEW, 3): (ORANGE, None),
        (REJECT, 1): (RED, TRUSTED_SOURCE_COMPROMISE),
        (REJECT, 2): (RED, ATTACK_DETECTED), (REJECT, 3): (RED, ATTACK_DETECTED),
        (ESCALATE, 1): (RED, TRUSTED_SOURCE_COMPROMISE),
        (ESCALATE, 2): (RED, ATTACK_DETECTED), (ESCALATE, 3): (RED, ATTACK_DETECTED),
    }
    wrong = []
    for (action, tier), (band, sub) in expected.items():
        h = headline_band(action, tier)
        if (h.band, h.subtype) != (band, sub):
            wrong.append(f"{action}/tier{tier} -> {h.band}/{h.subtype}, expected {band}/{sub}")
        else:
            note(f"{action:9} tier {tier} -> {h.band:7} {h.subtype or '-'}")
    check("the full action x tier truth table matches the design", not wrong, "; ".join(wrong))

    check("only RED carries a sub-type",
          all(headline_band(a, t).subtype is None
              for a in (ACCEPT, REVIEW) for t in ALL_TIERS)
          and all(headline_band(a, t).subtype is not None
                  for a in (REJECT, ESCALATE) for t in ALL_TIERS))

    check("every headline carries a human-readable label and a rule",
          all(headline_band(a, t).label and headline_band(a, t).rule
              and headline_band(a, t).meaning
              for a in ALL_ACTIONS for t in ALL_TIERS))


def test_headline_failsafe() -> None:
    """The property the whole band exists to guarantee."""
    print("\nPart A -- headline fail-safe: nothing ambiguous may reach GREEN")

    # 1. GREEN requires an affirmative conjunction. Exactly one input pair produces it.
    greens = [(a, t) for a in ALL_ACTIONS for t in ALL_TIERS
              if headline_band(a, t).band == GREEN]
    check("GREEN is reachable only from ACCEPT at Tier 1",
          greens == [(ACCEPT, 1)], str(greens))

    # 2. Unverified provenance can never be GREEN, whatever the action says.
    t3 = [a for a in ALL_ACTIONS if headline_band(a, 3).band == GREEN]
    check("no action at Tier 3 can produce GREEN", not t3, str(t3))
    t2 = [a for a in ALL_ACTIONS if headline_band(a, 2).band == GREEN]
    check("no action at Tier 2 can produce GREEN", not t2, str(t2))

    # 3. Degenerate inputs fall to ORANGE, never GREEN and never a crash. An
    # implementation that returns GREEN when it does not know what else to return
    # has inverted the guarantee.
    degenerate = [("NONSENSE", 1), ("", 2), (None, 3), (ACCEPT, None), (ACCEPT, 0),
                  (ACCEPT, 99), (REVIEW, None), (None, None), ("accept", 1)]
    bad, crashed = [], []
    for action, tier in degenerate:
        try:
            h = headline_band(action, tier)
        except Exception as exc:
            crashed.append(f"{action!r}/{tier!r}: {type(exc).__name__}")
            continue
        if h.band == GREEN:
            bad.append(f"{action!r}/{tier!r} -> GREEN")
    check("degenerate or unknown inputs never produce GREEN", not bad, "; ".join(bad))
    check("degenerate inputs return a band rather than raising", not crashed, "; ".join(crashed))
    note("lowercase 'accept' is deliberately NOT accepted — it falls to ORANGE")

    # 4. Every case in the taxonomy resolves to a band, and the Tier-3 invariant is
    # checked against the case TABLE rather than a hard-coded list, so adding a case
    # cannot quietly break it.
    unbanded, t3_green = [], []
    for c in CASES:
        tiers = ALL_TIERS if c.tier in ("any", "—", "1 vs 1") else (int(c.tier),)
        for tier in tiers:
            h = headline_band(c.action, tier)
            if h.band not in HEADLINE_BANDS:
                unbanded.append(c.case_id)
            if tier == 3 and h.band == GREEN:
                t3_green.append(f"{c.case_id} at tier 3")
    check("every case in the taxonomy resolves to a valid band", not unbanded, str(unbanded))
    check("no case can reach GREEN at Tier 3 (invariant, checked against the case table)",
          not t3_green, "; ".join(t3_green))

    # 5. The current coverage claim, stated explicitly so it fails loudly if it changes.
    tier3_cases = sorted(c.case_id for c in CASES if c.tier == "3")
    check("the Tier-3 governing cases are C3, C8 and C9",
          tier3_cases == ["C3", "C8", "C9"], str(tier3_cases))
    accept_cases = sorted(c.case_id for c in CASES if c.action == ACCEPT)
    check("only C1 and C2 route to ACCEPT, and only C1 survives to GREEN",
          accept_cases == ["C1", "C2"]
          and headline_band(ACCEPT, 1).band == GREEN
          and headline_band(ACCEPT, 2).band == ORANGE, str(accept_cases))

    # 6. Monotonicity: the band may never soften as the action hardens.
    order = {GREEN: 0, ORANGE: 1, RED: 2}
    violations = []
    for tier in ALL_TIERS:
        seq = [order[headline_band(a, tier).band] for a in ALL_ACTIONS]
        if any(b < a for a, b in zip(seq, seq[1:])):
            violations.append(f"tier {tier}: {seq}")
    check("the band never softens as the action becomes more conservative",
          not violations, "; ".join(violations))


# ---------------------------------------------------------------------------
# Part B -- features and model
# ---------------------------------------------------------------------------

def test_features() -> None:
    print("\nPart B -- feature encoding")

    check("logit is monotone increasing", logit(0.2) < logit(0.5) < logit(0.8))
    check("logit is clipped at both ends rather than returning infinity",
          math.isfinite(logit(0.0)) and math.isfinite(logit(1.0)),
          f"logit(0)={logit(0.0)} logit(1)={logit(1.0)}")
    check("logit(0.5) is zero", abs(logit(0.5)) < 1e-9)

    sigs = ["unsupport", "anomaly", "injection"]
    ladder = {200: "full", 100: "reduced", 30: "base_only"}
    wrong = [f"n_pos={n} -> {choose_feature_spec(sigs, n).rung}, expected {r}"
             for n, r in ladder.items() if choose_feature_spec(sigs, n).rung != r]
    check("the feature ladder follows events-per-variable", not wrong, "; ".join(wrong))

    base = choose_feature_spec(sigs, 30)
    check("the underpowered rung is flagged as such, not silently used",
          base.underpowered and "UNDERPOWERED" in base.note)

    reduced = choose_feature_spec(sigs, 100)
    check("the reduced rung keeps the two interactions carrying the Tier-1 inversion",
          set(reduced.interactions) == {("is_tier1", "anomaly"), ("is_tier1", "conflict")}
          or set(reduced.interactions) == {("is_tier1", "anomaly")},
          str(reduced.interactions))

    full = choose_feature_spec(sigs, 200)
    check("feature names are unique and match the vector length",
          len(set(full.names)) == len(full.names)
          and len(encode(CLEAN_SIG, 2, full, anomaly_z=0.0)) == len(full.names))

    # Dummy coding: Tier 2 is the reference level, so both dummies are zero.
    x2 = encode(CLEAN_SIG, 2, full, anomaly_z=0.0)
    i1, i3 = full.names.index("is_tier1"), full.names.index("is_tier3")
    check("Tier 2 is the reference level (both dummies zero)",
          x2[i1] == 0.0 and x2[i3] == 0.0, f"{x2[i1]}, {x2[i3]}")
    x1 = encode(CLEAN_SIG, 1, full, anomaly_z=0.0)
    x3 = encode(CLEAN_SIG, 3, full, anomaly_z=0.0)
    check("Tier 1 and Tier 3 each set exactly one dummy",
          (x1[i1], x1[i3]) == (1.0, 0.0) and (x3[i1], x3[i3]) == (0.0, 1.0))

    # No ordering is implied between the dummies -- the whole point.
    check("no encoded feature orders the tiers 1 < 2 < 3",
          not any(np.allclose(x1[j], 1.0) and np.allclose(x3[j], 3.0)
                  for j in range(len(full.names))))

    # A missing signal encodes to the neutral value, and the interaction that
    # would have used it is zero for non-Tier-1 documents either way.
    x = encode(SignalSet(unsupport=0.5, anomaly=None, injection=None), 2, full, anomaly_z=None)
    check("a missing signal does not produce NaN in the feature vector",
          np.all(np.isfinite(x)), str(x))

    # The anomaly z-score is passed through, not re-squashed.
    xz = encode(sig(anomaly=0.5), 2, full, anomaly_z=3.7)
    check("the anomaly robust-z is used as-is when supplied",
          abs(xz[full.names.index("x_anomaly")] - 3.7) < 1e-9,
          str(xz[full.names.index("x_anomaly")]))


def _toy_dataset(n: int = 400, seed: int = 3) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """A separable-but-noisy toy problem, for testing mechanics not accuracy."""
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.25).astype(int)
    x1 = rng.normal(loc=y * 1.6, scale=1.0, size=n)
    x2 = rng.normal(loc=y * 0.8, scale=1.0, size=n)
    tier1 = (rng.random(n) < 0.30).astype(float)
    tier3 = ((rng.random(n) < 0.40) & (tier1 == 0)).astype(float)
    X = np.column_stack([x1, x2, tier1, tier3])
    groups = rng.integers(0, 40, size=n)
    return X, y, groups


def test_model() -> None:
    print("\nPart B -- composite score")

    spec = choose_feature_spec(["unsupport", "anomaly"], n_pos=200)
    X, y, groups = _toy_dataset()
    # Trim the spec to the toy vector width so the model's own width check holds.
    spec.names = ["x_unsupport", "x_anomaly", "is_tier1", "is_tier3"]
    spec.interactions = []

    model = TrustModel(spec)
    report = model.fit(X, y, groups=groups)
    check("the model fits and reports a backend", model.fitted and bool(report.backend),
          str(report.backend if report else ""))
    note(f"backend={report.backend} C={report.chosen_C} calibrated={report.calibrated}")
    if "sklearn" not in str(report.backend):
        WARNINGS.append(f"model fitted on the {report.backend} fallback, not sklearn")

    p = model.predict_risk(X)
    check("risk is a probability in [0, 1] for every row",
          bool(np.all((p >= 0.0) & (p <= 1.0)) and np.all(np.isfinite(p))),
          f"range {p.min():.4f}-{p.max():.4f}")

    check("mean predicted risk is higher for the positive class than the negative",
          p[y == 1].mean() > p[y == 0].mean(),
          f"pos {p[y == 1].mean():.4f} vs neg {p[y == 0].mean():.4f}")

    trust = model.predict_trust_percent(X)
    check("trustworthiness is the complement of risk, on a 0-100 scale",
          bool(np.allclose(trust, 100.0 * (1.0 - p), atol=1e-6))
          and bool(np.all((trust >= 0.0) & (trust <= 100.0))))

    # A monotone requirement: pushing the risk-bearing feature up may not lower
    # the risk. If it does, a coefficient is signed backwards.
    row = X[0].copy()
    ladder = []
    for v in (-2.0, -1.0, 0.0, 1.0, 2.0, 3.0):
        r = row.copy()
        r[0] = v
        ladder.append(float(model.predict_risk(r.reshape(1, -1))[0]))
    check("risk is monotone in the risk-bearing feature",
          all(b >= a - 1e-9 for a, b in zip(ladder, ladder[1:])),
          " -> ".join(f"{v:.4f}" for v in ladder))

    lo, pt, hi = model.risk_interval(X[0])
    check("the risk interval brackets the point estimate",
          lo <= pt <= hi and 0.0 <= lo and hi <= 1.0, f"({lo:.4f}, {pt:.4f}, {hi:.4f})")
    check("the interval has non-zero width (the bootstrap actually ran)",
          hi - lo > 1e-6, f"width {hi - lo:.6f}")

    # Persistence round-trip: the deployed scorer loads from disk, so a model
    # that predicts differently after a save/load is a silent production bug.
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "trust_model.joblib"
        model.save(path)
        reloaded = TrustModel.load(path)
        p2 = reloaded.predict_risk(X[:50])
        check("save/load round-trips to identical predictions",
              bool(np.allclose(p, p2[:0]) if False else np.allclose(p[:50], p2, atol=1e-9)),
              f"max diff {np.max(np.abs(p[:50] - p2)):.3e}")
        check("the reloaded model carries its feature spec",
              reloaded.spec.names == model.spec.names, str(reloaded.spec.names))

    # Feature-width mismatch must raise, not broadcast into a wrong answer.
    width_raises = False
    try:
        model.predict_risk(np.zeros((1, 2)))
    except Exception:
        width_raises = True
    check("a feature vector of the wrong width raises rather than silently scoring",
          width_raises)


def test_evaluation() -> None:
    print("\nPart B -- evaluation metrics")

    y = [0] * 90 + [1] * 10
    perfect = [0.1] * 90 + [0.9] * 10
    m = compute_metrics(y, perfect, threshold=0.5)
    check("a perfect separator scores precision and recall 1.0",
          abs(m.precision - 1.0) < 1e-9 and abs(m.recall - 1.0) < 1e-9,
          f"P={m.precision} R={m.recall}")
    check("PR-AUC is reported alongside ROC-AUC",
          m.pr_auc is not None and m.roc_auc is not None)

    # F-beta with beta=3 must weight recall far above precision, because the
    # cost ratio assumption is C_FN/C_FP = 10.
    y2 = [0] * 90 + [1] * 10
    high_recall = [0.6] * 30 + [0.1] * 60 + [0.9] * 10       # catches all, many false alarms
    high_prec = [0.1] * 90 + [0.9] * 3 + [0.1] * 7           # few alarms, misses most
    m_r = compute_metrics(y2, high_recall, 0.5)
    m_p = compute_metrics(y2, high_prec, 0.5)
    check("F3 prefers the high-recall operating point over the high-precision one",
          m_r.f_beta > m_p.f_beta,
          f"recall-heavy F3={m_r.f_beta:.4f} vs precision-heavy F3={m_p.f_beta:.4f}")

    # Prevalence correction: our corpus prevalence is not deployment prevalence,
    # so raw precision on a benchmark overstates what an analyst would see.
    p_bench = precision_at_prevalence(tpr=0.9, fpr=0.05, prevalence=0.20)
    p_real = precision_at_prevalence(tpr=0.9, fpr=0.05, prevalence=0.01)
    check("precision falls when corrected to a realistic prevalence",
          p_real < p_bench, f"{p_bench:.4f} at 20% vs {p_real:.4f} at 1%")

    th = derive_thresholds(y, perfect)
    check("derived thresholds are ordered and report reachability",
          th["tau_review"] <= th["tau_reject"] and "reject_reachable" in th, str(th))

    # A threshold pinned at 1.0 can never fire, and must be reported as such
    # rather than presented as a working three-band regime.
    y3 = [0] * 95 + [1] * 5
    inverted = [0.9] * 95 + [0.1] * 5
    th3 = derive_thresholds(y3, inverted)
    check("an unreachable reject threshold is flagged, not reported as a live band",
          (th3["tau_reject"] >= 1.0) <= (not th3["reject_reachable"]), str(th3))


# ---------------------------------------------------------------------------
# Part C -- confidence
# ---------------------------------------------------------------------------

def test_confidence() -> None:
    print("\nPart C -- confidence")

    check("n_eff of five equal weights is five",
          abs(effective_sample_size([1, 1, 1, 1, 1]) - 5.0) < 1e-9)
    n_eff = effective_sample_size([0.9, 0.025, 0.025, 0.025, 0.025])
    check("one document carrying almost all the weight gives n_eff near one",
          n_eff < 1.5, f"n_eff={n_eff:.4f}")
    check("n_eff is capped by the number of distinct sources",
          abs(effective_sample_size([1, 1, 1, 1, 1], n_distinct_sources=2) - 2.0) < 1e-9)
    check("an empty weight vector gives n_eff zero rather than raising",
          effective_sample_size([]) == 0.0)

    strong = compute_confidence(n_eff=4.5, d_conflict_max=0.05, n_distinct_sources=4,
                                n_distinct_tiers=3, signal_votes=[0.1, 0.12, 0.09],
                                risk_interval_width=0.10)
    weak = compute_confidence(n_eff=1.0, d_conflict_max=0.80, n_distinct_sources=1,
                              n_distinct_tiers=1, signal_votes=[0.05, 0.95, 0.5],
                              risk_interval_width=0.70)
    check("strong evidence yields higher confidence than weak",
          strong.confidence > weak.confidence,
          f"{strong.confidence:.4f} vs {weak.confidence:.4f}")
    note(f"strong components: {strong.components}")
    note(f"weak components:   {weak.components}")

    check("confidence stays within [0, 1]",
          0.0 <= strong.confidence <= 1.0 and 0.0 <= weak.confidence <= 1.0)
    check("all five components are reported, not just the composite",
          set(strong.components) == {"volume", "agreement", "independence",
                                     "coherence", "model_stability"},
          str(sorted(strong.components)))

    # Conjunctive combination: one fatal component must drag the composite down,
    # which an arithmetic mean would not do.
    zeroed = compute_confidence(n_eff=5.0, d_conflict_max=1.0, n_distinct_sources=5,
                                n_distinct_tiers=3, signal_votes=[0.1, 0.1, 0.1],
                                risk_interval_width=0.05)
    check("total disagreement drives confidence to zero however strong the rest is",
          zeroed.confidence == 0.0, f"{zeroed.confidence}")

    arithmetic = sum(strong.components.values()) / 5.0
    lopsided = compute_confidence(n_eff=5.0, d_conflict_max=0.75, n_distinct_sources=5,
                                  n_distinct_tiers=3, signal_votes=[0.1, 0.1, 0.1],
                                  risk_interval_width=0.02)
    lop_arith = sum(lopsided.components.values()) / 5.0
    check("the geometric mean penalises a weak component below the arithmetic mean",
          lopsided.confidence < lop_arith - 1e-6,
          f"geometric {lopsided.confidence:.4f} vs arithmetic {lop_arith:.4f}")
    note(f"a strong case: geometric {strong.confidence:.4f} vs arithmetic {arithmetic:.4f}")

    # The caps bind regardless of how clean everything else looks.
    single = compute_confidence(n_eff=1.0, d_conflict_max=0.0, n_distinct_sources=1,
                                n_distinct_tiers=1, signal_votes=[0.05, 0.05, 0.05],
                                risk_interval_width=0.01, is_singleton=True)
    check("a single-document answer can never be high confidence",
          single.confidence <= SINGLETON_CAP + 1e-9 and single.caps_applied,
          f"{single.confidence:.4f}, caps={single.caps_applied}")

    n1 = compute_confidence(n_eff=1.0, d_conflict_max=0.0, n_distinct_sources=3,
                            n_distinct_tiers=2, signal_votes=[0.05, 0.05, 0.05],
                            risk_interval_width=0.01, is_singleton=False)
    check("n_eff <= 1 caps confidence even with several nominal sources",
          n1.confidence <= N_EFF_ONE_CAP + 1e-9, f"{n1.confidence:.4f}")

    check("the review floor fires below the threshold and not above",
          forces_review(REVIEW_FLOOR - 0.01) and not forces_review(REVIEW_FLOOR + 0.01))
    check("a single-document answer always trips the review floor",
          forces_review(single.confidence), f"{single.confidence:.4f}")


# ---------------------------------------------------------------------------
# Wiring -- score_query end to end
# ---------------------------------------------------------------------------

def test_score_query() -> None:
    print("\nWiring -- score_query() end to end")

    scorer = FusionScorer.load(verbose=False)
    scorer.bands = FIXED     # deterministic bands, so this test does not depend on training
    if scorer.model is None:
        WARNINGS.append("no trained model on disk; the statistical track was skipped "
                        "(run `python -m fusion.train` first for a complete check)")

    docs = [rec("d1", 2, 0.84, "src-a"), rec("d2", 2, 0.71, "src-b"),
            rec("d3", 3, 0.66, "src-c")]
    result = scorer.score_query("ransomware targeting hospital imaging systems", docs)

    required = ("query", "headline", "headline_label", "headline_subtype",
                "headline_subtype_label", "headline_meaning",
                "trust_percent", "confidence", "confidence_interval", "risk",
                "risk_interval", "case_id", "case_name", "priority", "action",
                "action_meaning", "band", "tier_governing", "n_retrieved", "n_eff",
                "documents", "detail")
    missing = [f for f in required if not hasattr(result, f)]
    check("the result carries the full contract", not missing, str(missing))

    check("the headline is one of the three bands",
          result.headline in HEADLINE_BANDS, str(result.headline))
    check("the headline agrees with the action it was derived from",
          result.headline == headline_band(result.action, result.tier_governing).band,
          f"{result.headline} vs action {result.action} at tier {result.tier_governing}")
    check("a sub-type is present exactly when the headline is RED",
          (result.headline_subtype is not None) == (result.headline == RED),
          f"{result.headline}/{result.headline_subtype}")
    check("the derivation rule is recorded for the audit log",
          bool(result.detail.get("headline_rule")), str(result.detail.get("headline_rule")))
    check("every document also carries a headline",
          all(d.headline in HEADLINE_BANDS for d in result.documents))

    check("a case, an action and a meaning are all populated",
          result.case_id in CASES_BY_ID and result.action in ACTION_SEVERITY
          and bool(result.action_meaning), f"{result.case_id}/{result.action}")
    check("confidence is in [0, 1]", 0.0 <= result.confidence <= 1.0, str(result.confidence))
    check("one score per retrieved document",
          len(result.documents) == len(docs) == result.n_retrieved,
          f"{len(result.documents)} scores for {len(docs)} documents")
    check("n_eff never exceeds the number retrieved",
          result.n_eff <= len(docs) + 1e-9, str(result.n_eff))
    note(f"  {result.summary()}")

    if result.risk is not None and not math.isnan(result.risk):
        lo, hi = result.risk_interval
        check("the risk interval brackets the reported risk",
              lo <= result.risk <= hi, f"{lo} <= {result.risk} <= {hi}")
        tlo, thi = result.confidence_interval
        check("the trust interval is the risk interval mirrored onto 0-100",
              abs(tlo - 100.0 * (1.0 - hi)) < 0.02 and abs(thi - 100.0 * (1.0 - lo)) < 0.02,
              f"trust ({tlo}, {thi}) vs risk ({lo}, {hi})")
        check("trust percent is the complement of risk",
              abs(result.trust_percent - 100.0 * (1.0 - result.risk)) < 0.02)

    # Provenance of the decision must be auditable: which track produced what.
    d = result.detail
    check("the detail records both tracks and how they were reconciled",
          {"taxonomy_action", "score_action", "reconciliation"} <= set(d), str(sorted(d)))
    check("the final action is at least as conservative as the rule track",
          ACTION_SEVERITY[result.action] >= ACTION_SEVERITY[d["taxonomy_action"]],
          f"final={result.action} taxonomy={d['taxonomy_action']}")
    check("the final action is at least as conservative as the statistical track",
          ACTION_SEVERITY[result.action] >= ACTION_SEVERITY[d["score_action"]],
          f"final={result.action} score={d['score_action']}")
    check("whether a fitted model and fitted bands were used is reported, not assumed",
          "model_fitted" in d and "bands_fitted" in d)
    check("detector backends are recorded so a fallback figure cannot pass as a measurement",
          "detector_backends" in d, str(sorted(d)))

    # A Tier-1 document behaving strangely must escalate, through the whole stack.
    scorer_t1 = FusionScorer(model=scorer.model, band_thresholds=BandThresholds(
        suspicious={"unsupport": 0.01, "anomaly": 0.01, "injection": 0.60, "conflict": 0.60},
        malicious={"unsupport": 0.99, "anomaly": 0.99, "injection": 0.85, "conflict": 0.85},
        n_clean_calibration=100, fitted=True, note="fixture: everything looks suspicious"),
        operating=scorer.operating)
    r1 = scorer_t1.score_query("q", [rec("t1a", 1, 0.9, "cisa"), rec("t1b", 1, 0.7, "hhs")])
    check("a suspicious Tier-1 retrieval set escalates end to end",
          r1.action == ESCALATE and r1.case_id in ("C4", "C5"),
          f"{r1.case_id}/{r1.action}")
    check("and surfaces as RED / Trusted Source Compromise Suspected, not a generic RED",
          r1.headline == RED and r1.headline_subtype == TRUSTED_SOURCE_COMPROMISE,
          f"{r1.headline}/{r1.headline_subtype}")

    # The same band severity from an untrusted source must read as an ordinary attack --
    # the distinction the sub-type exists to carry.
    r3 = scorer_t1.score_query("q", [rec("t3a", 3, 0.9, "blog"), rec("t3b", 3, 0.7, "forum")])
    check("the same signals from Tier 3 read as RED / Attack Detected instead",
          r3.headline == RED and r3.headline_subtype == ATTACK_DETECTED,
          f"{r3.headline}/{r3.headline_subtype}")

    # An unverified source with quiet signals must never come back GREEN, end to end.
    r_t3clean = scorer.score_query("q", [rec("u1", 3, 0.8, "blog-a"),
                                         rec("u2", 3, 0.7, "blog-b"),
                                         rec("u3", 3, 0.6, "blog-c")])
    check("a clean-looking Tier-3 retrieval set is never GREEN end to end",
          r_t3clean.headline != GREEN,
          f"{r_t3clean.headline} via {r_t3clean.case_id}/{r_t3clean.action}")

    # And a clean Tier-2 set, which the taxonomy would Accept, is demoted to ORANGE.
    r_t2 = scorer.score_query("q", [rec("c1", 2, 0.8, "isac-a"), rec("c2", 2, 0.7, "isac-b"),
                                    rec("c3", 2, 0.6, "isac-c")])
    check("a clean Tier-2 set is ORANGE even where the taxonomy says Accept",
          r_t2.headline in (ORANGE, RED),
          f"{r_t2.headline} via {r_t2.case_id}/{r_t2.action}")

    # Low confidence may only ever tighten the outcome.
    r_single = scorer.score_query("q", [rec("only", 2, 0.9, "src-a")])
    check("a single-document answer is at least REVIEW",
          ACTION_SEVERITY[r_single.action] >= ACTION_SEVERITY[REVIEW],
          f"{r_single.action} at confidence {r_single.confidence:.4f}")
    check("the forced review is recorded in the detail, not applied silently",
          r_single.detail.get("confidence_forced_review") is not None)

    empty_raises = False
    try:
        scorer.score_query("q", [])
    except ValueError:
        empty_raises = True
    check("scoring an empty retrieval set raises rather than returning a trust figure",
          empty_raises)

    # Serialisation, because the audit log stores this.
    import json  # noqa: PLC0415
    ok = True
    try:
        json.dumps(result.to_dict(), default=str)
    except Exception as exc:
        ok, detail = False, str(exc)
    check("the result serialises to JSON for the audit log", ok,
          detail if not ok else "")


# ---------------------------------------------------------------------------

def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(description="Sanity checks for the Level 3 fusion layer.")
    ap.add_argument("--verbose", action="store_true", help="print intermediate values")
    args = ap.parse_args()
    VERBOSE = args.verbose

    print("=" * 78)
    print("Level 3 fusion -- contract tests")
    print("=" * 78)
    print("These check that the machinery matches the design. Accuracy figures come")
    print("from `python -m fusion.train`, not from here.")

    test_isolation()
    test_bands()
    test_case_grid()
    test_tier1_inversion()
    test_cross_cutting_cases()
    test_escalation_dominance()
    test_headline_rule()
    test_headline_failsafe()
    test_features()
    test_model()
    test_evaluation()
    test_confidence()
    test_score_query()

    print("\n" + "=" * 78)
    if WARNINGS:
        print("NOTES — this run was not fully exercised:")
        for w in WARNINGS:
            print(f"  - {w}")
        print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): {FAILURES}")
        return 1
    print("All contract checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
