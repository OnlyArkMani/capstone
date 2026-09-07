# Session Log — The Console Could Not Answer a Single Question

**Date:** 7 September 2026
**Team:** Zetabyte
**Session type:** Bug fix, then a visual rebuild of the analyst console
**Main output:** `dashboard/service.py` fix, `dashboard/charts.py`, rebuilt
`style.py` / `components.py` / `app.py` / audit page, `dashboard/demo_queries.py`,
`dashboard/make_preview.py`, Dockerfile fix

> Short version: the dashboard was broken — every query came back "retrieval
> failed", and the error message blamed the index, which was fine. One line of
> code was building the pipeline object wrongly. We fixed it, then rebuilt the way
> the console looks, because it looked like a template rather than a security
> tool, and added six charts so the detector results can be read at a glance
> instead of by opening five panels one at a time.

---

## The bug

Type a question, press Run, and the console said:

> Could not score this query: retrieval failed (TypeError: BaselineRAG.__init__()
> missing 1 required positional argument: 'retriever'). Has the index been built?
> Run `python -m pipeline.build_index`.

Two things were wrong with that, and the second is worse than the first.

**What actually broke.** `dashboard/service.py` created the retrieval pipeline by
calling `BaselineRAG()` with no arguments. That object has never had a
no-argument form — it needs a retriever handed to it, or it should be built
through one of the two named constructors that make one for it
(`BaselineRAG.from_disk()` loads a saved index, `BaselineRAG.build()` makes a
fresh one). So the very first query of every session died before retrieval even
started. Nothing downstream of it had ever run from the console.

**Why the message was misleading.** The code that catches this failure was
written to catch a missing index, so it says "has the index been built?" no
matter what actually went wrong. The index had been built. Anyone following that
message would have rebuilt the index, watched it succeed, tried again, and got
the same error — which is a bad half-hour to hand to somebody five minutes before
a demonstration.

**The fix.** Build through `from_disk()`, and fall back to `build()` if there is
no saved index to load. The fallback is not defensiveness for its own sake: in
Docker the index directory is an empty volume on a fresh machine, so the first
run genuinely has nothing to load, and failing there would make a first-time demo
look broken when it is only cold.

We confirmed the whole chain end to end afterwards — retrieval, generation,
detectors, scoring, report, audit write — on a real question. The poisoned
document ranked first, exactly where the corpus manifest predicted it would.

---

## Why the console looked wrong

The honest summary is that it looked auto-generated. Specific things, each of
which we changed:

- **Emoji.** A shield on the tab, a clipboard on the audit link, warning
  triangles on every caveat. Emoji render differently on every machine, carry a
  colour our palette did not choose, and read as decoration in a tool whose whole
  job is to be believed. There are none anywhere now.
- **"GOOD TO GO."** That is how the green banner described a cleared answer. It
  tells an analyst how to feel rather than what the system authorised. It now
  reads **CLEARED FOR ANALYST USE**, and the red one reads **REJECTED — DO NOT
  ACT ON THIS ANSWER**. Those are sentences somebody could defend afterwards.
- **The banner was a poster.** A huge coloured block with a tick in it and
  nothing else. It is now a verdict bar: the band still at full size on the left,
  because it has to be readable across a room, and the action, case and priority
  set beside it on the right. A photograph of the banner now carries the whole
  decision instead of half of it.
- **Bright colours everywhere.** The palette was a candy green, a yellow and a
  strong blue. It is now a graphite console with muted status colours, and state
  colour is used only for verdicts. Trust tiers are drawn in neutral greys of
  different weight, because a tier is a fact about where a document came from,
  not an alarm, and colouring it puts two unrelated meanings in one channel.
- **Numbers that jump.** Every figure is now monospaced and tabular, so a column
  of detector scores lines up on the decimal point and a number that changes
  between two runs does not shift the ones next to it.
- **The Deploy button.** That is a development control, and on a projector it
  reads as part of the product. It is switched off.

---

## The charts

There were none before. Reading a result meant opening five panels and comparing
numbers by eye. There are now six, and every one of them plots values straight
off the report — none of them computes anything, which is the same rule the rest
of the dashboard already follows.

1. **Detector grid.** Four detectors against five documents in one picture. This
   is the one that matters: the question an analyst asks is not "what was the
   average injection score" but "which document tripped which detector", and that
   is a question about one square of a grid.
2. **Retrieval profile.** How similar each document was to the question, with its
   trust tier on the bar. Retrieval knows nothing about provenance — it ranks by
   similarity alone — so when the top bar is a Tier 3 source, the picture makes
   the argument the project exists to make, without a word of explanation.
3. **Distance to threshold.** Detector scores are not comparable to each other:
   0.4 is unremarkable for one and over the line for another. This plots how far
   each reading sat from its own threshold, so one axis is meaningful for all
   four at once and a reading that only just cleared its line looks like one.
4. **Trust score and interval**, on a fixed 0–100 axis so that a wide interval
   and a narrow one cannot be made to look the same.
5. **What confidence rests on** — its five components side by side, so a run held
   back by "not enough documents" is distinguishable from one held back by
   "the documents disagree".
6. **Where the time went**, by stage. The cost of the security layer is a fair
   question and a number answers it better than a claim.

On the audit page there are three more: the split across verdict bands, which of
the eleven cases have actually been seen, and what analysts decided.

Two rules we wrote into the chart code so that nobody has to remember them later.
A detector that did not run is never drawn as a bar at zero — a zero bar says "we
measured this and it was clean", which is the opposite of what it means. And the
grid is coloured by status rather than by raw value, because the four detectors
have different thresholds and equal colours would otherwise imply equal severity.

---

## Two smaller things that were also wrong

**The theme never reached the container.** `.streamlit/config.toml` sets the
colours Streamlit paints its own dropdowns, tables and toolbar with. The
Dockerfile never copied it. The page still looked broadly dark because our own
stylesheet paints the background, so the fault was quiet rather than obvious —
but Streamlit's own widgets were falling back to their light default inside a
dark page, and the Deploy button we thought we had switched off was still there.
Now copied.

**Demonstration questions are now in the console.** There is a picker beside the
query box with ten benchmark questions covering all six attack families in our
corpus, so a demonstration is a click rather than a paste. The list holds the
question text and a label and nothing else — no expected answer, no poisoned
document id, no case. Those live in the ground-truth manifest, which opens with a
warning that the scoring path must never read it, and the cheapest way to keep
that true is to not have the file anywhere near the running application. The
labels are shown to the room; only the question text is passed to the system.

---

## How we checked it

The existing dashboard test suite passes — 55 checks, including the one that
matters most, which is that the verdict banner is the first thing rendered with
nothing above it. That suite deliberately checks structure and call order, and
it says in its own closing note that it cannot check appearance.

So we built something that can. `dashboard/make_preview.py` walks the same render
functions the real page calls and writes one self-contained HTML file, using the
real stylesheet and the real chart specifications. It renders a real scored
query, not a made-up one, so it carries the same caveats the console would. We
used it to look at the rebuilt console and fixed two layout faults we would
otherwise have shipped. It is checked in, so anyone can look at the console
without starting the stack — including the mentor.

One caution worth writing down: on the machine this session could reach, the
detector models are not installed, so the scores in that preview come from
fallback backends. The console says so on every screen, in three separate
warnings. That is the system behaving correctly, not a defect.

---

## What is open

- **Run it in Docker and look at it.** Everything above was verified against the
  real code, but the machine this session could reach cannot run the container.
  `docker compose build` then `docker compose up dashboard`.
- **The misleading error message.** We fixed the bug behind it; we did not fix
  the handler that reports every retrieval failure as a missing index. It should
  say what actually failed.
- **Charts are unread by the test suite.** The specifications are checked for
  being well-formed, and looked at in the preview, but nothing asserts that a
  fired detector actually shows as fired. Worth a small test.
- **The trust dial is often empty**, because a query with no fitted model reports
  no composite score. That is honest, but the empty half-width panel looks like a
  fault. Either fill it or drop it when there is no score.
