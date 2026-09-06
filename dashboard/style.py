"""
The dashboard's visual language: design tokens, one CSS injection, and the small
HTML builders that the render functions in `components.py` compose.

Why this is a separate module
-----------------------------
Two reasons.

Nothing here reads the report or decides anything. Every function takes plain
numbers and strings and returns a string of HTML. That keeps the rule that
`components.py` already follows — the dashboard displays figures, it never
derives them — true one level further down, and it means the visual layer can be
changed without reopening any file that touches the scoring path.

And the CSS is injected exactly once, from `app.py`, *after* `set_page_config`
and *before* anything else renders. It is deliberately not injected from
`render_banner`: the banner has to be the first thing rendered on the results
view (design §2.9) and `test_dashboard.py` asserts that by checking the very
first recorded Streamlit call. A stylesheet emitted from inside the banner would
be call number one and the requirement would quietly stop being tested.

Palette
-------
Dark console, in the manner of the security-operations tools this system would
sit beside. Surfaces and ink are our own; the four state colours are taken from a
validated status palette and checked against the panel surface `#191B21`:

    good  #0CA30C   warning #FAB219   critical #E15554   accent #5B8DEF

All four clear 3:1 against the panel. Worst adjacent separation under simulated
colour-vision deficiency is dE 11.3, and dE 23.5 for normal vision — comfortably
above the dE 8 / dE 15 floors. That margin is not a licence to lean on hue: every
state in this interface carries an icon and a word as well as a colour, because a
projector, a colourblind reviewer, or a greyscale printout each remove the colour
channel entirely and the verdict still has to survive.

State colour is reserved. GREEN / ORANGE / RED mean a verdict and nothing else,
which is why source trust tiers are drawn as neutral badges of differing weight
rather than as a third colour ramp — a tier is an ordinal fact about provenance,
not an alarm, and colouring it would put two unrelated meanings in the same
channel.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

BG = "#101116"          # page plane
PANEL = "#191B21"       # card / panel surface
PANEL_2 = "#1F222A"     # nested surface: table headers, inset blocks
LINE = "#2C303A"        # hairline border
LINE_SOFT = "#23262E"   # separator inside a panel

INK = "#E1E6EF"         # primary text
INK_2 = "#A2AAB8"       # secondary text
INK_3 = "#737C8B"       # muted: labels, axis, captions

ACCENT = "#5B8DEF"      # links, focus, "measured and below threshold"
GOOD = "#0CA30C"
WARN = "#FAB219"
CRIT = "#E15554"
NEUTRAL = "#6F7784"     # not measured — deliberately colourless

MONO = ('ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, '
        '"Liberation Mono", monospace')

#: Verdict bands. ``bg`` is the banner fill (white text sits on it at display
#: size); ``accent`` is the same state at a step bright enough to read as a rule,
#: a dot or a bar against the dark panel. Two roles, because one colour cannot do
#: both — a fill dark enough for white text is too dark to see as a 3px line.
BAND: dict[str, dict[str, str]] = {
    "GREEN":  {"bg": "#1B7F4C", "accent": GOOD,  "icon": "✓", "dot": "\U0001F7E2"},
    "ORANGE": {"bg": "#A85A0B", "accent": WARN,  "icon": "!",      "dot": "\U0001F7E0"},
    "RED":    {"bg": "#B3261E", "accent": CRIT,  "icon": "✕", "dot": "\U0001F534"},
}

STATUS_COLOUR = {
    "over_malicious": CRIT,
    "over_suspicious": WARN,
    "below": ACCENT,
    "unusable": NEUTRAL,
    "missing": NEUTRAL,
}


def band_accent(band: str) -> str:
    return BAND.get(band, BAND["ORANGE"])["accent"]


def band_dot(band: str) -> str:
    return BAND.get(band, BAND["ORANGE"])["dot"]


# ---------------------------------------------------------------------------
# The stylesheet
# ---------------------------------------------------------------------------

_CSS = f"""
<style>
:root {{
  --tz-bg: {BG};        --tz-panel: {PANEL};   --tz-panel2: {PANEL_2};
  --tz-line: {LINE};    --tz-line-soft: {LINE_SOFT};
  --tz-ink: {INK};      --tz-ink2: {INK_2};    --tz-ink3: {INK_3};
  --tz-accent: {ACCENT};
  --tz-good: {GOOD};    --tz-warn: {WARN};     --tz-crit: {CRIT};
  --tz-mono: {MONO};
}}

/* ---- page plane -------------------------------------------------------- */
.stApp {{ background: var(--tz-bg); }}
[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 2.2rem; padding-bottom: 4rem; max-width: 1400px; }}

/* Streamlit stacks a lot of air between blocks. Tighten it so panels group. */
[data-testid="stVerticalBlock"] > [data-testid="stVerticalBlockBorderWrapper"],
[data-testid="stVerticalBlock"] {{ gap: 0.55rem; }}

/* Horizontal rules become hairlines rather than the default heavy divider. */
hr {{ border: none; border-top: 1px solid var(--tz-line); margin: 1.1rem 0; }}

/* ---- typography -------------------------------------------------------- */
html, body, .stApp {{ color: var(--tz-ink); }}
p, li, span, label {{ color: var(--tz-ink); }}

/* Every st.subheader in this app is a section header. Small caps, letterspaced,
   with a hairline beneath — the pattern the reference console uses to separate
   panels without drawing boxes around everything. */
.stApp h3, [data-testid="stHeading"] h3, .stMarkdown h3 {{
  font-size: 0.70rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.11em;
  text-transform: uppercase;
  color: var(--tz-ink3) !important;
  border-bottom: 1px solid var(--tz-line);
  padding: 0 0 0.42rem 0 !important;
  margin: 1.5rem 0 0.85rem 0 !important;
}}

[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {{
  color: var(--tz-ink3) !important;
  font-size: 0.78rem;
  line-height: 1.5;
}}

code, kbd {{
  font-family: var(--tz-mono) !important;
  background: var(--tz-panel2) !important;
  color: {ACCENT} !important;
  border: 1px solid var(--tz-line);
  border-radius: 3px;
  padding: 0.05rem 0.32rem !important;
  font-size: 0.82em !important;
}}

/* ---- sidebar ----------------------------------------------------------- */
[data-testid="stSidebar"] {{
  background: {PANEL};
  border-right: 1px solid var(--tz-line);
}}
[data-testid="stSidebar"] .block-container {{ padding-top: 1.6rem; }}
[data-testid="stSidebar"] h1 {{
  font-size: 1.02rem !important; font-weight: 650 !important;
  letter-spacing: 0.01em; color: var(--tz-ink) !important;
  margin-bottom: 0.15rem !important;
}}
[data-testid="stSidebarNavLink"], [data-testid="stPageLink"] a {{
  border: 1px solid var(--tz-line); border-radius: 5px;
  background: var(--tz-panel2);
}}

/* ---- metric tiles ------------------------------------------------------ */
/* The reference draws a stat as a bordered panel with a coloured rule down its
   left edge. Streamlit's own metric is close enough in structure to restyle. */
[data-testid="stMetric"] {{
  background: var(--tz-panel);
  border: 1px solid var(--tz-line);
  border-left: 3px solid var(--tz-accent);
  border-radius: 5px;
  padding: 0.75rem 0.95rem 0.8rem 0.95rem;
}}
[data-testid="stMetricLabel"] p {{
  font-size: 0.66rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--tz-ink3) !important;
}}
[data-testid="stMetricValue"] {{
  font-size: 1.95rem !important;
  font-weight: 350 !important;
  line-height: 1.15 !important;
  color: var(--tz-ink) !important;
  letter-spacing: -0.01em;
}}

/* ---- expanders --------------------------------------------------------- */
[data-testid="stExpander"] {{
  background: var(--tz-panel);
  border: 1px solid var(--tz-line) !important;
  border-radius: 5px;
  margin-bottom: 0.45rem;
}}
[data-testid="stExpander"] summary {{
  font-size: 0.86rem;
  padding: 0.62rem 0.9rem !important;
}}
[data-testid="stExpander"] summary:hover {{ background: var(--tz-panel2); }}
[data-testid="stExpander"] summary p {{
  font-family: var(--tz-mono);
  font-size: 0.83rem !important;
  color: var(--tz-ink) !important;
}}
[data-testid="stExpanderDetails"] {{ padding: 0.2rem 0.95rem 0.9rem 0.95rem; }}

/* ---- tables ------------------------------------------------------------ */
[data-testid="stTable"] table {{
  background: transparent;
  border: 1px solid var(--tz-line);
  border-radius: 5px;
  border-collapse: separate;
  border-spacing: 0;
  font-size: 0.79rem;
  font-variant-numeric: tabular-nums;
}}
[data-testid="stTable"] thead th {{
  background: var(--tz-panel2) !important;
  color: var(--tz-ink3) !important;
  font-size: 0.63rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  border: none !important;
  border-bottom: 1px solid var(--tz-line) !important;
  text-align: left !important;
  padding: 0.5rem 0.7rem !important;
}}
[data-testid="stTable"] tbody th {{ display: none; }}
[data-testid="stTable"] tbody td {{
  background: transparent !important;
  color: var(--tz-ink2) !important;
  border: none !important;
  border-bottom: 1px solid var(--tz-line-soft) !important;
  padding: 0.45rem 0.7rem !important;
  font-family: var(--tz-mono);
}}
[data-testid="stTable"] tbody tr:last-child td {{ border-bottom: none !important; }}
[data-testid="stDataFrame"] {{
  border: 1px solid var(--tz-line);
  border-radius: 5px;
}}

/* ---- controls ---------------------------------------------------------- */
.stButton button, .stDownloadButton button {{
  border-radius: 5px;
  border: 1px solid var(--tz-line);
  background: var(--tz-panel2);
  color: var(--tz-ink);
  font-size: 0.82rem;
  font-weight: 550;
  letter-spacing: 0.01em;
  transition: border-color 120ms ease, background 120ms ease;
}}
.stButton button:hover {{ border-color: var(--tz-accent); background: #242833; }}
.stButton button[kind="primary"] {{
  background: var(--tz-accent); border-color: var(--tz-accent); color: #0B1220;
  font-weight: 650;
}}
.stButton button[kind="primary"]:hover {{ background: #7AA4F3; border-color: #7AA4F3; }}

[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"] {{
  background: var(--tz-panel) !important;
  border-color: var(--tz-line) !important;
  border-radius: 5px !important;
}}
[data-testid="stWidgetLabel"] p {{
  font-size: 0.68rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  color: var(--tz-ink3) !important;
}}

/* ---- alerts ------------------------------------------------------------ */
[data-testid="stAlert"] {{
  border-radius: 5px;
  border: 1px solid var(--tz-line);
  background: var(--tz-panel);
  font-size: 0.83rem;
}}

/* ======================================================================== */
/*  Project components                                                       */
/* ======================================================================== */

.tz-eyebrow {{
  font-size: 0.63rem; font-weight: 700; letter-spacing: 0.14em;
  text-transform: uppercase; color: var(--tz-ink3);
}}

/* Page masthead ---------------------------------------------------------- */
.tz-masthead {{
  display: flex; align-items: baseline; gap: 0.85rem;
  border-bottom: 1px solid var(--tz-line);
  padding-bottom: 0.7rem; margin-bottom: 1.3rem;
}}
.tz-masthead .tz-title {{
  font-size: 1.12rem; font-weight: 650; color: var(--tz-ink);
  letter-spacing: -0.01em;
}}
.tz-masthead .tz-sub {{ font-size: 0.78rem; color: var(--tz-ink3); }}

/* Verdict banner --------------------------------------------------------- */
.tz-banner {{
  border-radius: 6px;
  padding: 1.9rem 2.2rem 2rem 2.2rem;
  margin: 0 0 0.9rem 0;
  text-align: center;
  position: relative;
  overflow: hidden;
}}
.tz-banner::before {{
  content: ""; position: absolute; inset: 0 0 auto 0; height: 3px;
  background: rgba(255,255,255,0.32);
}}
.tz-banner .tz-banner-eyebrow {{
  font-size: 0.64rem; font-weight: 700; letter-spacing: 0.2em;
  text-transform: uppercase; opacity: 0.78; margin-bottom: 0.5rem;
}}
.tz-banner .tz-banner-sub {{
  font-size: 1.5rem; font-weight: 600; margin-top: 0.28rem; letter-spacing: 0.02em;
}}
.tz-banner .tz-banner-subtype {{
  font-size: 1.5rem; font-weight: 600; margin-top: 0.45rem;
  padding-top: 0.45rem; letter-spacing: 0.01em;
  border-top: 1px solid rgba(255,255,255,0.25);
  display: inline-block; padding-left: 1.4rem; padding-right: 1.4rem;
}}

/* Panels ----------------------------------------------------------------- */
.tz-panel {{
  background: var(--tz-panel);
  border: 1px solid var(--tz-line);
  border-radius: 5px;
  padding: 0.85rem 1rem;
}}
.tz-panel-accent {{ border-left-width: 3px; border-left-style: solid; }}

/* Key/value grid --------------------------------------------------------- */
.tz-kv {{ display: grid; grid-template-columns: auto 1fr; gap: 0.4rem 1.1rem; }}
.tz-kv dt {{
  font-size: 0.63rem; font-weight: 700; letter-spacing: 0.09em;
  text-transform: uppercase; color: var(--tz-ink3); white-space: nowrap;
  padding-top: 0.12rem;
}}
.tz-kv dd {{
  margin: 0; font-size: 0.86rem; color: var(--tz-ink);
  font-family: var(--tz-mono);
}}

/* State chip ------------------------------------------------------------- */
.tz-chip {{
  display: inline-flex; align-items: center; gap: 0.42rem;
  border-radius: 3px; padding: 0.16rem 0.55rem;
  font-size: 0.68rem; font-weight: 700; letter-spacing: 0.07em;
  text-transform: uppercase; white-space: nowrap;
  border: 1px solid; background: rgba(255,255,255,0.03);
}}
.tz-chip .tz-chip-dot {{
  width: 7px; height: 7px; border-radius: 50%; flex: 0 0 7px;
}}

/* Tier badge — neutral by design; see the module docstring. */
.tz-tier {{
  display: inline-block; border-radius: 3px; padding: 0.12rem 0.48rem;
  font-size: 0.66rem; font-weight: 650; letter-spacing: 0.06em;
  font-family: var(--tz-mono); white-space: nowrap;
}}
.tz-tier-1 {{ color: var(--tz-ink);  border: 1px solid var(--tz-ink3); }}
.tz-tier-2 {{ color: var(--tz-ink2); border: 1px solid var(--tz-line); }}
.tz-tier-3 {{ color: var(--tz-ink3); border: 1px dashed var(--tz-line); }}

/* Threshold meter -------------------------------------------------------- */
.tz-meter {{ margin: 0 0 0.72rem 0; }}
.tz-meter-head {{
  display: flex; justify-content: space-between; align-items: baseline;
  margin-bottom: 0.28rem; gap: 1rem;
}}
.tz-meter-name {{
  font-family: var(--tz-mono); font-size: 0.75rem; color: var(--tz-ink2);
}}
.tz-meter-val {{
  font-family: var(--tz-mono); font-size: 0.8rem; font-weight: 650;
  font-variant-numeric: tabular-nums;
}}
.tz-track {{
  position: relative; height: 8px; border-radius: 2px;
  background: rgba(255,255,255,0.055); overflow: visible;
}}
.tz-fill {{
  position: absolute; left: 0; top: 0; bottom: 0;
  border-radius: 2px 4px 4px 2px; min-width: 2px;
}}
.tz-tick {{
  position: absolute; top: -4px; bottom: -4px; width: 2px;
  background: rgba(255,255,255,0.45);
}}
/* The malicious tick is taller as well as brighter. Two ticks separated only
   by brightness is a distinction that dies on a projector. */
.tz-tick-crit {{
  top: -7px; bottom: -7px;
  background: rgba(255,255,255,0.88);
  box-shadow: 0 0 0 1px rgba(0,0,0,0.35);
}}
.tz-meter-foot {{
  display: flex; gap: 1.1rem; margin-top: 0.26rem;
  font-size: 0.66rem; color: var(--tz-ink3);
  font-family: var(--tz-mono); font-variant-numeric: tabular-nums;
}}
.tz-meter-none {{
  font-size: 0.7rem; color: var(--tz-ink3); font-style: italic;
}}

/* Interval bar ----------------------------------------------------------- */
.tz-int {{ margin: 0.5rem 0 0.2rem 0; }}
.tz-int-track {{
  position: relative; height: 6px; border-radius: 2px;
  background: rgba(255,255,255,0.055);
}}
.tz-int-range {{
  position: absolute; top: 0; bottom: 0; border-radius: 2px;
  background: rgba(91,141,239,0.42);
}}
.tz-int-point {{
  position: absolute; top: 50%; width: 10px; height: 10px; border-radius: 50%;
  transform: translate(-50%, -50%);
  background: var(--tz-accent);
  box-shadow: 0 0 0 2px var(--tz-panel);
}}
.tz-int-foot {{
  display: flex; justify-content: space-between; margin-top: 0.3rem;
  font-size: 0.66rem; color: var(--tz-ink3);
  font-family: var(--tz-mono); font-variant-numeric: tabular-nums;
}}

/* Sidebar stat strip ----------------------------------------------------- */
.tz-side-stat {{
  display: flex; justify-content: space-between; align-items: baseline;
  padding: 0.3rem 0; border-bottom: 1px solid var(--tz-line-soft);
  font-size: 0.74rem;
}}
.tz-side-stat span:first-child {{ color: var(--tz-ink3); }}
.tz-side-stat span:last-child {{
  color: var(--tz-ink); font-family: var(--tz-mono); font-weight: 650;
}}
</style>
"""


def inject(st: Any) -> None:
    """Emit the stylesheet. Call once, from the page file, after set_page_config.

    Never call this from a render function — see the module docstring.
    """
    st.markdown(_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# HTML builders
# ---------------------------------------------------------------------------

def masthead(title: str, subtitle: str = "") -> str:
    sub = f'<div class="tz-sub">{subtitle}</div>' if subtitle else ""
    return (f'<div class="tz-masthead"><div class="tz-title">{title}</div>'
            f'{sub}</div>')


def chip(label: str, colour: str, icon: str = "") -> str:
    """A state chip. Always colour *plus* a word, never colour alone."""
    glyph = f"<span>{icon}</span>" if icon else ""
    return (f'<span class="tz-chip" style="color:{colour};border-color:{colour}66;">'
            f'<span class="tz-chip-dot" style="background:{colour}"></span>'
            f'{glyph}{label}</span>')


def band_chip(band: str, label: str = "") -> str:
    spec = BAND.get(band, BAND["ORANGE"])
    return chip(label or band, spec["accent"], spec["icon"])


def tier_badge(tier: Any, label: str = "") -> str:
    try:
        n = int(tier)
    except (TypeError, ValueError):
        n = 3
    text = f"T{n}" + (f" · {label}" if label else "")
    return f'<span class="tz-tier tz-tier-{max(1, min(3, n))}">{text}</span>'


def kv(pairs: list[tuple[str, str]]) -> str:
    body = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in pairs)
    return f'<div class="tz-panel"><dl class="tz-kv">{body}</dl></div>'


def _pct(value: float, scale: float) -> float:
    if scale <= 0:
        return 0.0
    return max(0.0, min(100.0, (value / scale) * 100.0))


def meter(name: str, value: Any, suspicious: Any, malicious: Any,
          status: str) -> str:
    """One detector reading as a bar with both thresholds marked on the track.

    The bar answers "how close is this to firing" at a glance, which the three
    numeric columns of the table below it cannot. The fill colour carries the
    severity the reading has actually reached; the two hairline ticks are where
    the thresholds sit, so a reading just under the line looks like one.

    A reading that never ran, or could not be calibrated, gets no bar at all.
    Drawing an empty track for it would read as a measurement of zero, and "we
    did not measure this" is a different statement from "this measured low".
    """
    colour = STATUS_COLOUR.get(status, NEUTRAL)

    if value is None or status in ("unusable", "missing"):
        word = "not calibrated" if status == "unusable" else "did not run"
        return (f'<div class="tz-meter"><div class="tz-meter-head">'
                f'<span class="tz-meter-name">{name}</span>'
                f'<span class="tz-meter-val" style="color:{NEUTRAL}">n/a</span></div>'
                f'<div class="tz-meter-none">{word} — this is not a clean '
                f'result, it means the system does not know</div></div>')

    scale = max(1.0, float(value),
                float(malicious or 0), float(suspicious or 0))
    ticks = ""
    if suspicious is not None:
        ticks += (f'<div class="tz-tick" style="left:'
                  f'{_pct(float(suspicious), scale):.2f}%"></div>')
    if malicious is not None:
        ticks += (f'<div class="tz-tick tz-tick-crit" style="left:'
                  f'{_pct(float(malicious), scale):.2f}%"></div>')

    foot = ""
    if suspicious is not None:
        foot += f"<span>suspicious {float(suspicious):.3f}</span>"
    if malicious is not None:
        foot += f"<span>malicious {float(malicious):.3f}</span>"

    fired = status in ("over_malicious", "over_suspicious")
    flag = (f'<span class="tz-chip" style="color:{colour};border-color:{colour}66;'
            f'margin-left:0.5rem;"><span class="tz-chip-dot" '
            f'style="background:{colour}"></span>fired</span>') if fired else ""

    return (
        f'<div class="tz-meter">'
        f'<div class="tz-meter-head">'
        f'<span class="tz-meter-name">{name}{flag}</span>'
        f'<span class="tz-meter-val" style="color:{colour}">'
        f'{float(value):.3f}</span></div>'
        f'<div class="tz-track">'
        f'<div class="tz-fill" style="width:{_pct(float(value), scale):.2f}%;'
        f'background:{colour}"></div>{ticks}</div>'
        f'<div class="tz-meter-foot">{foot}</div></div>')


def interval(point: Any, lo: Any, hi: Any, unit: str = "%") -> str:
    """A point estimate with its 95% interval drawn to scale on a 0-100 track.

    The interval is the more informative half of this figure and it was
    previously a line of caption text under the number. Drawn, a wide one is
    obviously wide.
    """
    if point is None:
        return ""
    if lo is None or hi is None:
        return ""
    lo_f, hi_f, p_f = float(lo), float(hi), float(point)
    return (
        f'<div class="tz-int"><div class="tz-int-track">'
        f'<div class="tz-int-range" style="left:{max(0.0, lo_f):.2f}%;'
        f'width:{max(0.5, min(100.0, hi_f) - max(0.0, lo_f)):.2f}%"></div>'
        f'<div class="tz-int-point" style="left:{max(0.0, min(100.0, p_f)):.2f}%">'
        f'</div></div>'
        f'<div class="tz-int-foot"><span>{lo_f:.1f}{unit}</span>'
        f'<span>95% interval</span><span>{hi_f:.1f}{unit}</span></div></div>')


def side_stat(label: str, value: Any) -> str:
    return (f'<div class="tz-side-stat"><span>{label}</span>'
            f'<span>{value}</span></div>')


__all__ = [
    "BAND", "STATUS_COLOUR", "ACCENT", "GOOD", "WARN", "CRIT", "NEUTRAL",
    "INK", "INK_2", "INK_3", "PANEL", "LINE",
    "inject", "masthead", "chip", "band_chip", "tier_badge", "kv", "meter",
    "interval", "side_stat", "band_accent", "band_dot",
]
