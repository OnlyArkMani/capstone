"""
The dashboard's visual language: design tokens, one CSS injection, and the small
HTML builders that the render functions in `components.py` compose.

Why this is a separate module
-----------------------------
Nothing here reads the report or decides anything. Every function takes plain
numbers and strings and returns a string of HTML. That keeps the rule
`components.py` already follows -- the dashboard displays figures, it never
derives them -- true one level further down, and it means the visual layer can be
changed without reopening any file that touches the scoring path.

The CSS is injected exactly once, from the page file, *after* `set_page_config`
and *before* anything else renders. It is deliberately not injected from
`render_banner`: the banner has to be the first thing rendered on the results
view (design 2.9) and `test_dashboard.py` asserts that by checking the very first
recorded Streamlit call. A stylesheet emitted from inside the banner would be
call number one and the requirement would quietly stop being tested.

Palette
-------
A graphite console, in the manner of the security-operations tools this system
would sit beside. The surfaces are deliberately dark and low-chroma so that the
only saturated colour on the page is a verdict; state colour is scarce because
scarcity is what makes it mean something.

    good  #2FA36B   warning #D2971F   critical #C8453D   accent #4E8FD4

All four clear 3:1 against the panel surface `#12151B`. That margin is not a
licence to lean on hue: every state in this interface carries a mark and a word
as well as a colour, because a projector, a colourblind reviewer, or a greyscale
printout each remove the colour channel entirely and the verdict still has to
survive.

State colour is reserved. GREEN / ORANGE / RED mean a verdict and nothing else,
which is why source trust tiers are drawn as neutral badges of differing weight
rather than as a third colour ramp -- a tier is an ordinal fact about provenance,
not an alarm, and colouring it would put two unrelated meanings in one channel.

No emoji, anywhere. Numerals are monospaced and tabular so that a column of
scores aligns on the decimal point and a figure that changes between two runs
does not move the ones beside it.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

BG = "#0B0D11"          # page plane
PANEL = "#12151B"       # card / panel surface
PANEL_2 = "#181C24"     # nested surface: table headers, inset blocks
LINE = "#242932"        # hairline border
LINE_SOFT = "#1C2029"   # separator inside a panel

INK = "#DCE2EA"         # primary text
INK_2 = "#97A1AF"       # secondary text
INK_3 = "#68727F"       # muted: labels, axis, captions

ACCENT = "#4E8FD4"      # links, focus, "measured and below threshold"
GOOD = "#2FA36B"
WARN = "#D2971F"
CRIT = "#C8453D"
NEUTRAL = "#5C6673"     # not measured -- deliberately colourless

MONO = ('ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, '
        '"Liberation Mono", monospace')

#: Verdict bands. ``bg`` is the banner fill (white text sits on it at display
#: size); ``accent`` is the same state at a step bright enough to read as a rule,
#: a dot or a bar against the dark panel. Two roles, because one colour cannot do
#: both -- a fill dark enough for white text is too dark to see as a 3px line.
#: ``dot`` is a plain geometric mark and ``code`` a three-letter severity word.
#: Neither is an emoji and neither is Streamlit colour-markdown: a widget label
#: that fails to parse markdown shows the source text, and ":red[*]" printed
#: literally in a demo looks broken in a way a plain mark never can. The code is
#: what the expander rows carry, because a collapsed row is exactly where the
#: colour channel is least reliable and a word still reads in greyscale.
BAND: dict[str, dict[str, str]] = {
    "GREEN":  {"bg": "#145A3C", "accent": GOOD, "icon": "✓",
               "dot": "●", "code": "OK"},
    "ORANGE": {"bg": "#8A5411", "accent": WARN, "icon": "!",
               "dot": "●", "code": "SUS"},
    "RED":    {"bg": "#8E2F29", "accent": CRIT, "icon": "✕",
               "dot": "●", "code": "MAL"},
}

STATUS_COLOUR = {
    "over_malicious": CRIT,
    "over_suspicious": WARN,
    "below": ACCENT,
    "unusable": NEUTRAL,
    "missing": NEUTRAL,
}

#: What each detector status is called in front of an analyst. `below` is not
#: "clean" -- it is a measurement that came in under the line, which is a
#: narrower claim and the one the number actually supports.
STATUS_LABEL = {
    "over_malicious": "over malicious",
    "over_suspicious": "over suspicious",
    "below": "below threshold",
    "unusable": "not calibrated",
    "missing": "did not run",
}


def band_accent(band: str) -> str:
    return BAND.get(band, BAND["ORANGE"])["accent"]


def band_dot(band: str) -> str:
    return BAND.get(band, BAND["ORANGE"])["dot"]


def band_code(band: str) -> str:
    return BAND.get(band, BAND["ORANGE"])["code"]


# ---------------------------------------------------------------------------
# The stylesheet
# ---------------------------------------------------------------------------

_CSS = f"""
<style>
:root {{
  --bg: {BG};
  --panel: {PANEL};
  --panel-2: {PANEL_2};
  --line: {LINE};
  --line-soft: {LINE_SOFT};
  --ink: {INK};
  --ink-2: {INK_2};
  --ink-3: {INK_3};
  --accent: {ACCENT};
  --good: {GOOD};
  --warn: {WARN};
  --crit: {CRIT};
  --mono: {MONO};
}}

/* ---- page plane ---------------------------------------------------- */

.stApp {{ background: var(--bg); }}

[data-testid="stAppViewContainer"] > .main .block-container {{
  padding-top: 1.6rem;
  padding-bottom: 4rem;
  max-width: 1500px;
}}

/* The deploy button and the coloured run-decoration are development chrome.
   On a projector they read as part of the product, which they are not. */
[data-testid="stDecoration"], [data-testid="stToolbar"] {{ display: none; }}
header[data-testid="stHeader"] {{ background: transparent; height: 0; }}

html, body, [class*="css"] {{
  font-feature-settings: "tnum" 1, "cv05" 1;
}}

/* Every numeral in the interface is tabular and monospaced. A column of
   detector scores has to align on the decimal point to be scannable, and a
   figure that changes between runs must not shift the ones beside it. */
code, kbd, samp, pre, .tz-num {{
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
}}
code {{
  background: var(--panel-2);
  border: 1px solid var(--line);
  border-radius: 2px;
  padding: 0.06rem 0.3rem;
  font-size: 0.82em;
  color: var(--ink-2);
}}

/* ---- masthead ------------------------------------------------------ */

.tz-masthead {{
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 1.5rem;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--line);
  padding-bottom: 0.75rem;
  margin-bottom: 1.35rem;
}}
.tz-masthead-l {{ display: flex; align-items: baseline; gap: 0.85rem;
                  flex-wrap: wrap; }}
.tz-title {{
  font-size: 1.12rem;
  font-weight: 600;
  letter-spacing: -0.005em;
  color: var(--ink);
  margin: 0;
}}
.tz-sub {{ font-size: 0.82rem; color: var(--ink-3); font-weight: 400; }}
.tz-mark {{
  font-family: var(--mono);
  font-size: 0.66rem;
  letter-spacing: 0.12em;
  color: var(--ink-3);
  border: 1px solid var(--line);
  border-radius: 2px;
  padding: 0.16rem 0.42rem;
  white-space: nowrap;
}}

/* ---- eyebrow: the small capitalised label above a block ------------ */

.tz-eyebrow {{
  font-size: 0.65rem;
  font-weight: 600;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  color: var(--ink-3);
}}

/* ---- panels -------------------------------------------------------- */

.tz-panel {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 0.85rem 1rem;
}}
.tz-panel-accent {{ border-left: 2px solid var(--accent); }}

/* ---- the verdict banner -------------------------------------------- */
/* Geometry stays inline in components.py: the test reads that string and
   asserts the display size and the fill are present, and a banner whose
   loudness could be removed by a stylesheet that failed to load is exactly
   the failure the requirement exists to prevent. What lives here is only
   what is safe to lose. */

.tz-banner {{
  display: grid;
  grid-template-columns: minmax(0, auto) minmax(0, 1fr);
  align-items: center;
  gap: 1.6rem;
  padding: 1.05rem 1.5rem;
  margin-bottom: 0.9rem;
}}
.tz-banner-eyebrow {{
  font-size: 0.62rem;
  font-weight: 600;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  opacity: 0.75;
  margin-bottom: 0.1rem;
}}
.tz-banner-sub {{
  font-size: 0.95rem;
  font-weight: 600;
  letter-spacing: 0.02em;
  opacity: 0.95;
}}
.tz-banner-subtype {{
  margin-top: 0.3rem;
  padding-top: 0.3rem;
  border-top: 1px solid rgba(255,255,255,0.22);
  opacity: 0.97;
}}
.tz-banner-side {{
  display: flex;
  gap: 1.9rem;
  flex-wrap: wrap;
  justify-content: flex-end;
}}
.tz-banner-fig {{ text-align: right; }}
.tz-banner-fig .k {{
  display: block;
  font-size: 0.6rem;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  opacity: 0.72;
}}
.tz-banner-fig .v {{
  display: block;
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  font-size: 1.28rem;
  font-weight: 600;
  line-height: 1.35;
}}

/* ---- chips and badges ---------------------------------------------- */

.tz-chip {{
  display: inline-flex;
  align-items: center;
  gap: 0.34rem;
  font-size: 0.7rem;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  border: 1px solid;
  border-radius: 2px;
  padding: 0.12rem 0.42rem;
  white-space: nowrap;
}}
.tz-chip-dot {{
  width: 5px; height: 5px; border-radius: 50%;
  display: inline-block; flex: none;
}}

/* A tier is an ordinal fact about provenance, not an alarm. Weight, not hue. */
.tz-tier {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 0.68rem;
  letter-spacing: 0.04em;
  border-radius: 2px;
  padding: 0.12rem 0.42rem;
  white-space: nowrap;
}}
.tz-tier-1 {{ background: #2B313C; color: #D3DAE4; border: 1px solid #3A4250; }}
.tz-tier-2 {{ background: #1E232B; color: #A6AFBC; border: 1px solid #2C323C; }}
.tz-tier-3 {{ background: #171A21; color: #7C8593; border: 1px solid #232830; }}

/* ---- key/value block ----------------------------------------------- */

.tz-kv {{ margin: 0; display: grid; grid-template-columns: 8.5rem 1fr;
          gap: 0.3rem 0.9rem; }}
.tz-kv dt {{
  font-size: 0.68rem;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  color: var(--ink-3);
  padding-top: 0.06rem;
}}
.tz-kv dd {{ margin: 0; font-size: 0.83rem; color: var(--ink); word-break: break-word; }}

/* ---- detector meter ------------------------------------------------ */

.tz-meter {{ margin-bottom: 0.85rem; }}
.tz-meter-head {{
  display: flex; align-items: center; justify-content: space-between;
  gap: 0.7rem; margin-bottom: 0.3rem;
}}
.tz-meter-name {{
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--ink-2);
  letter-spacing: 0.01em;
}}
.tz-meter-val {{
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  font-size: 0.86rem;
  font-weight: 600;
}}
.tz-track {{
  position: relative; height: 5px; border-radius: 1px;
  background: var(--panel-2); border: 1px solid var(--line-soft); overflow: hidden;
}}
.tz-fill {{ position: absolute; top: 0; bottom: 0; left: 0; border-radius: 1px; }}
.tz-tick {{
  position: absolute; top: -2px; bottom: -2px; width: 1px;
  background: {WARN}; opacity: 0.85;
}}
.tz-tick-crit {{ background: {CRIT}; }}
.tz-meter-foot {{
  display: flex; gap: 1.05rem; margin-top: 0.22rem;
  font-family: var(--mono); font-size: 0.65rem; color: var(--ink-3);
}}
.tz-meter-none {{
  font-size: 0.72rem; color: var(--ink-3); font-style: italic;
  border-left: 2px solid var(--line); padding-left: 0.5rem;
}}

/* ---- interval bar --------------------------------------------------- */

.tz-int {{ margin-top: 0.3rem; }}
.tz-int-track {{
  position: relative; height: 4px; border-radius: 1px;
  background: var(--panel-2); border: 1px solid var(--line-soft);
}}
.tz-int-range {{
  position: absolute; top: 0; bottom: 0;
  background: var(--accent); opacity: 0.4; border-radius: 1px;
}}
.tz-int-point {{
  position: absolute; top: -3px; width: 2px; height: 10px;
  background: var(--ink); border-radius: 1px;
}}
.tz-int-foot {{
  display: flex; justify-content: space-between; margin-top: 0.24rem;
  font-family: var(--mono); font-size: 0.63rem; color: var(--ink-3);
}}

/* ---- sidebar -------------------------------------------------------- */

[data-testid="stSidebar"] {{
  background: var(--panel);
  border-right: 1px solid var(--line);
}}
[data-testid="stSidebar"] .block-container {{ padding-top: 1.4rem; }}
.tz-side-stat {{
  display: flex; justify-content: space-between; align-items: baseline;
  padding: 0.34rem 0; border-bottom: 1px solid var(--line-soft);
  font-size: 0.78rem; color: var(--ink-2);
}}
.tz-side-stat span:last-child {{
  font-family: var(--mono); font-variant-numeric: tabular-nums;
  color: var(--ink); font-weight: 600;
}}
.tz-side-brand {{
  font-size: 0.78rem; font-weight: 600; color: var(--ink);
  letter-spacing: 0.01em;
}}
.tz-side-brand-sub {{
  font-size: 0.68rem; color: var(--ink-3); margin-top: 0.1rem;
  line-height: 1.45;
}}

/* ---- Streamlit widget overrides ------------------------------------- */

.stButton > button {{
  border-radius: 2px;
  border: 1px solid var(--line);
  background: var(--panel-2);
  color: var(--ink);
  font-size: 0.78rem;
  font-weight: 600;
  letter-spacing: 0.03em;
  padding: 0.38rem 0.9rem;
  transition: border-color 120ms ease, background 120ms ease;
}}
.stButton > button:hover {{ border-color: var(--accent); color: var(--ink); }}
.stButton > button[kind="primary"] {{
  background: var(--accent); border-color: var(--accent); color: #06090D;
}}
.stButton > button[kind="primary"]:hover {{ filter: brightness(1.08); }}

[data-testid="stTextInput"] input, [data-testid="stTextArea"] textarea {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 2px;
  color: var(--ink);
  font-size: 0.86rem;
}}
[data-testid="stTextInput"] input:focus {{ border-color: var(--accent); }}

[data-testid="stMetric"] {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 3px;
  padding: 0.7rem 0.9rem 0.75rem 0.9rem;
}}
[data-testid="stMetricLabel"] p {{
  font-size: 0.65rem !important;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--ink-3) !important;
}}
[data-testid="stMetricValue"] {{
  font-family: var(--mono);
  font-variant-numeric: tabular-nums;
  font-size: 1.62rem !important;
  font-weight: 500;
  color: var(--ink);
  letter-spacing: -0.01em;
}}

[data-testid="stExpander"] {{
  border: 1px solid var(--line);
  border-radius: 3px;
  background: var(--panel);
}}
[data-testid="stExpander"] summary {{ font-size: 0.82rem; }}
[data-testid="stExpander"] summary p {{
  font-family: var(--mono);
  font-size: 0.78rem;
  letter-spacing: 0.01em;
}}

.stTabs [data-baseweb="tab-list"] {{
  gap: 0.2rem;
  border-bottom: 1px solid var(--line);
}}
.stTabs [data-baseweb="tab"] {{
  font-size: 0.76rem;
  font-weight: 600;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--ink-3);
  padding: 0.5rem 0.85rem;
}}
.stTabs [aria-selected="true"] {{ color: var(--ink); }}

[data-testid="stDataFrame"] {{ border: 1px solid var(--line); border-radius: 3px; }}

hr {{ border-color: var(--line); }}

h1, h2, h3, h4 {{ color: var(--ink); letter-spacing: -0.008em; }}
h2 {{ font-size: 1.02rem !important; font-weight: 600 !important;
      margin-top: 1.6rem !important; }}
h3 {{ font-size: 0.9rem !important; font-weight: 600 !important; }}

[data-testid="stCaptionContainer"] p {{
  font-size: 0.74rem; color: var(--ink-3); line-height: 1.55;
}}

/* Streamlit's alerts default to saturated pastel fills that read as a fifth
   and sixth state colour. Flattened to a rule and a surface so the only loud
   colour on the page stays the verdict. */
[data-testid="stAlert"] {{
  border-radius: 3px;
  border: 1px solid var(--line);
  border-left-width: 2px;
  background: var(--panel);
  font-size: 0.8rem;
}}
</style>
"""


def inject(st: Any) -> None:
    """Emit the stylesheet. Call once, from the page file, after set_page_config.

    Never call this from a render function -- see the module docstring.
    """
    st.markdown(_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# HTML builders
# ---------------------------------------------------------------------------

def masthead(title: str, subtitle: str = "", mark: str = "") -> str:
    """Page header. `mark` is the right-hand system stamp -- build, corpus, mode.

    It sits in the masthead rather than the sidebar because it qualifies
    everything on the page: a reader who has scrolled past it has still seen it,
    and a screenshot of the page carries the conditions it was taken under.
    """
    sub = f'<div class="tz-sub">{subtitle}</div>' if subtitle else ""
    right = f'<div class="tz-mark">{mark}</div>' if mark else ""
    return (f'<div class="tz-masthead"><div class="tz-masthead-l">'
            f'<div class="tz-title">{title}</div>{sub}</div>{right}</div>')


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
    text = f"T{n}" + (f" {label}" if label else "")
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
                f'<div class="tz-meter-none">{word} &mdash; this is not a clean '
                f'result, it means the system does not know</div></div>')

    scale = max(1.0, float(value), float(malicious or 0), float(suspicious or 0))
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
    if point is None or lo is None or hi is None:
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


def stat_cards(items: list[tuple[str, Any, str]]) -> str:
    """A row of figures, each with its own accent rule. `items` is (label, value,
    colour). Used where `st.metric` would be too tall to repeat five times."""
    cells = "".join(
        f'<div class="tz-panel tz-panel-accent" style="border-left-color:{c};">'
        f'<div class="tz-eyebrow">{label}</div>'
        f'<div class="tz-num" style="font-size:1.5rem;font-weight:500;'
        f'line-height:1.25;margin-top:0.2rem;color:{INK};">{value}</div></div>'
        for label, value, c in items)
    return (f'<div style="display:grid;grid-template-columns:'
            f'repeat({len(items)},minmax(0,1fr));gap:0.55rem;">{cells}</div>')


__all__ = [
    "BAND", "STATUS_COLOUR", "STATUS_LABEL", "ACCENT", "GOOD", "WARN", "CRIT",
    "NEUTRAL", "INK", "INK_2", "INK_3", "PANEL", "PANEL_2", "LINE", "MONO", "BG",
    "inject", "masthead", "chip", "band_chip", "tier_badge", "kv", "meter",
    "interval", "side_stat", "stat_cards", "band_accent", "band_dot", "band_code",
]
