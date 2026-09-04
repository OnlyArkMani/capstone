"""
Indicator extraction — IPs, domains, file hashes and CVE IDs.

**Regex and rule-based only. No language model touches this.** That is a
requirement, not a convenience, and the reason is worth stating: an analyst pivots
on these values. They paste the IP into a SIEM query, they look the hash up in
VirusTotal, they check the CVE against their asset inventory. An extractor that
occasionally invents a plausible-looking indicator sends an analyst chasing
something that was never in the document, and — worse — an LLM reading a poisoned
document is exactly the component an attacker is trying to influence. A regex
cannot be prompt-injected.

The cost of that choice is recall: this misses indicators written in prose ("the
attacker used the same subnet as last quarter"). That trade is correct here.
Precision is what makes an indicator list usable; recall failures are visible to
the analyst reading the document, invented indicators are not.

Defanging
---------
Threat intelligence routinely neutralises indicators so they are not accidentally
clicked or resolved: `1.2.3[.]4`, `evil[.]com`, `hxxps://`. These are re-fanged
before matching, because a defanged indicator is the same indicator, and the
report records both the original and the normalised form.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Defanging
# ---------------------------------------------------------------------------

_DEFANG_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\[\s*\.\s*\]", "."),      # 1.2.3[.]4   evil[.]com
    (r"\(\s*\.\s*\)", "."),      # evil(.)com
    (r"\{\s*\.\s*\}", "."),      # evil{.}com
    (r"\[\s*:\s*\]", ":"),       # http[:]//
    (r"\bhxxp(s?)\b", r"http\1"),
    (r"\bmeow(s?)\b(?=://)", r"http\1"),
    (r"\[\s*at\s*\]", "@"),
    (r"\[\s*dot\s*\]", "."),
)


def refang(text: str) -> str:
    """Restore defanged indicators so they can be matched.

    Applied to a COPY for matching only. The original document text is never
    modified — an analyst needs to see what the document actually said.
    """
    out = text
    for pattern, repl in _DEFANG_PATTERNS:
        out = re.sub(pattern, repl, out, flags=re.IGNORECASE)
    return out


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Dotted quad. Deliberately permissive here and validated properly below --
# a regex that tries to express "0-255" four times is unreadable and still wrong.
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

# Conservative IPv6: at least two groups and one "::" or five colons. A stricter
# full-form pattern is long and still needs validation, so validation does the work.
_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")

_CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)

# Hashes are fixed-length hex. Order matters: check longest first so a SHA-256 is
# not reported as an MD5 prefix.
_HASH_SPECS: tuple[tuple[str, int], ...] = (("sha512", 128), ("sha256", 64),
                                            ("sha1", 40), ("md5", 32))
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{32,128}\b")

_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

_URL = re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.IGNORECASE)

# Suffixes that look like domains but are filenames. Extracting `report.pdf` as a
# domain and handing it to an analyst to look up is worse than missing it.
_FILE_SUFFIXES = frozenset("""
exe dll sys bin dat log txt md pdf doc docx xls xlsx ppt pptx csv json xml yaml yml
zip tar gz bz2 7z rar iso img png jpg jpeg gif svg webp mp4 avi
py js ts jsx tsx java c cpp h hpp go rs rb php sh ps1 bat cmd
conf cfg ini toml env lock sql db sqlite html htm css scss
""".split())

# Domains that appear in every threat-intel document as citations rather than as
# indicators. Listing them as IOCs is noise that trains an analyst to skim the list.
_CITATION_DOMAINS = frozenset("""
cisa.gov nvd.nist.gov nist.gov mitre.org attack.mitre.org cve.mitre.org
hhs.gov fda.gov cert.org us-cert.gov first.org
github.com microsoft.com google.com apache.org kb.cert.org
""".split())

_TLD_ALLOWLIST_MIN_LEN = 2


@dataclass(frozen=True)
class Entity:
    """One extracted indicator.

    `raw` is what the document actually contained (possibly defanged); `value` is
    the normalised form an analyst would pivot on. Keeping both means the report
    can show the document's own wording while still offering a usable value.
    """

    kind: str            # ipv4 | ipv6 | domain | url | cve | md5 | sha1 | sha256 | sha512
    value: str
    raw: str
    doc_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["doc_ids"] = list(self.doc_ids)
        return d


# ---------------------------------------------------------------------------
# Validation — the part that does the real work
# ---------------------------------------------------------------------------

def _valid_ipv4(candidate: str) -> str | None:
    """Reject the things that look like dotted quads and are not.

    Version strings are the main offender: `10.1.2.3` is a plausible IP and also a
    plausible software version, and threat-intel documents are full of the latter.
    `ipaddress` settles the octet-range question; it cannot settle the semantic one,
    so callers get context-based suppression via `_looks_like_version`.
    """
    text = candidate.split("/")[0]
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return None
    return candidate


def _valid_ipv6(candidate: str) -> str | None:
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return None
    # A bare "::" or a two-group fragment is almost always punctuation or a time
    # range, not an address.
    if candidate.count(":") < 2 or candidate.strip(":") == "":
        return None
    return candidate


_VERSION_CONTEXT = re.compile(
    r"(?:version|ver\.?|v|release|firmware|build|patch|update|prior to|before|"
    r"through|upgrade to|fixed in)\s*$", re.IGNORECASE)


def _looks_like_version(text: str, start: int) -> bool:
    """True when the 30 characters before a dotted quad mark it as a version."""
    return bool(_VERSION_CONTEXT.search(text[max(0, start - 30):start]))


def _classify_hash(value: str) -> str | None:
    length = len(value)
    for name, expected in _HASH_SPECS:
        if length == expected:
            return name
    return None


def _plausible_domain(value: str) -> bool:
    label = value.rsplit(".", 1)
    if len(label) != 2:
        return False
    tld = label[1].lower()
    if len(tld) < _TLD_ALLOWLIST_MIN_LEN or tld.isdigit():
        return False
    if tld in _FILE_SUFFIXES:
        return False
    if value.lower() in _CITATION_DOMAINS:
        return False
    # A "domain" whose last label is all digits was an IP we already handled.
    return not value.replace(".", "").isdigit()


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_entities(text: str, doc_id: str | None = None) -> list[Entity]:
    """Extract indicators from one document's text.

    Order matters. URLs are taken first and their hosts removed from domain
    consideration, so a URL is not also reported as a bare domain; hashes are
    classified longest-first; IPs are validated and version-suppressed.
    """
    if not text:
        return []

    fanged = refang(text)
    found: dict[tuple[str, str], Entity] = {}
    ids = (doc_id,) if doc_id else ()

    def add(kind: str, value: str, raw: str) -> None:
        key = (kind, value.lower())
        if key in found:
            existing = found[key]
            if doc_id and doc_id not in existing.doc_ids:
                found[key] = Entity(kind, existing.value, existing.raw,
                                    existing.doc_ids + (doc_id,))
            return
        found[key] = Entity(kind, value, raw, ids)

    # --- CVEs. Normalised to upper case; the year/number split is validated. ---
    for m in _CVE.finditer(fanged):
        year = int(m.group(1))
        if 1999 <= year <= 2100:
            add("cve", f"CVE-{m.group(1)}-{m.group(2)}", m.group(0))

    # --- URLs, and the hosts inside them. ---
    url_hosts: set[str] = set()
    for m in _URL.finditer(fanged):
        url = m.group(0).rstrip(".,;:")
        add("url", url, url)
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
        url_hosts.add(host.split(":")[0].lower())

    # --- Hashes, longest first. ---
    for m in _HEX_RUN.finditer(fanged):
        kind = _classify_hash(m.group(0))
        if kind:
            add(kind, m.group(0).lower(), m.group(0))

    # --- IPv4, validated and version-suppressed. ---
    for m in _IPV4.finditer(fanged):
        value = _valid_ipv4(m.group(0))
        if value and not _looks_like_version(fanged, m.start()):
            add("ipv4", value, m.group(0))

    # --- IPv6. ---
    for m in _IPV6.finditer(fanged):
        value = _valid_ipv6(m.group(0))
        if value:
            add("ipv6", value, m.group(0))

    # --- Domains, minus URL hosts and minus filenames. ---
    for m in _DOMAIN.finditer(fanged):
        value = m.group(0).rstrip(".")
        if value.lower() in url_hosts:
            continue
        if _plausible_domain(value):
            add("domain", value.lower(), m.group(0))

    return sorted(found.values(), key=lambda e: (e.kind, e.value))


def extract_from_documents(docs: Iterable[Any]) -> list[Entity]:
    """Extract across a retrieval set, merging duplicates and recording every
    document each indicator appeared in.

    Which documents an indicator came from is decision-relevant: an IP that
    appears only in the one document the detectors flagged is a different thing
    from an IP corroborated across four sources.
    """
    merged: dict[tuple[str, str], Entity] = {}
    for doc in docs:
        doc_id = getattr(doc, "doc_id", None) or (
            doc.get("doc_id") if isinstance(doc, dict) else None)
        text = " ".join(str(x) for x in (
            getattr(doc, "title", "") or "",
            getattr(doc, "summary", "") or "",
            getattr(doc, "content", "") or "",
        ) if x)
        if not text and isinstance(doc, dict):
            text = " ".join(str(doc.get(f, "")) for f in ("title", "summary", "content"))
        for ent in extract_entities(text, doc_id):
            key = (ent.kind, ent.value.lower())
            if key in merged:
                prev = merged[key]
                ids = tuple(dict.fromkeys(prev.doc_ids + ent.doc_ids))
                merged[key] = Entity(prev.kind, prev.value, prev.raw, ids)
            else:
                merged[key] = ent
    return sorted(merged.values(), key=lambda e: (e.kind, e.value))


def group_by_kind(entities: Iterable[Entity]) -> dict[str, list[Entity]]:
    out: dict[str, list[Entity]] = {}
    for ent in entities:
        out.setdefault(ent.kind, []).append(ent)
    return out
