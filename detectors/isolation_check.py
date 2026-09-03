"""
Assert that a package never reads the ground-truth answer key.

Shared by the pipeline and detector test suites.

A plain string search is not good enough here: both packages *document* the fact
that they do not read ground truth, so the phrase appears legitimately in
docstrings and comments. Searching for it flags exactly the modules that are
being most careful, which is the wrong way round.

This walks the AST instead and inspects only executable code -- string literals
that are not docstrings, identifiers, and attribute names. Prose is ignored,
paths are not.
"""

from __future__ import annotations

import ast
from pathlib import Path

# What counts as an offence is *reading the manifest*, not naming the concept.
# `pipeline/corpus_loader.py` legitimately contains the literal "ground_truth" --
# as the name of a field it BANS from documents, which is the guard, not a leak.
# So the patterns below match path construction and the schema constants that
# point at the manifest, and nothing else.
import re as _re

_PATH_PATTERNS = (
    _re.compile(r"ground_truth[\\/]"),        # a path segment
    _re.compile(r"ground_truth.*\.json"),      # a manifest filename
    _re.compile(r"^(clean|poisoned)\.json$"),  # the manifest filenames themselves
)

# Importing either of these from corpus/schema.py means resolving the manifest path.
FORBIDDEN_NAMES = {"GROUND_TRUTH_DIRNAME", "GROUND_TRUTH_FILENAME"}


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """id() of every string Constant that is a docstring."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                out.add(id(body[0].value))
    return out


def module_reads_ground_truth(path: Path) -> list[str]:
    """Return the offending code fragments, or [] if the module is clean."""
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:  # pragma: no cover
        return [f"could not parse: {exc}"]

    docstrings = _docstring_nodes(tree)
    hits: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            low = node.value.lower()
            if any(pat.search(low) for pat in _PATH_PATTERNS):
                hits.append(f"line {node.lineno}: manifest path {node.value[:60]!r}")
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            hits.append(f"line {node.lineno}: imports manifest constant {node.id}")
        elif isinstance(node, ast.alias) and node.name in FORBIDDEN_NAMES:
            hits.append(f"imports manifest constant {node.name}")
    return hits


def check_package(package_dir: Path, skip: tuple[str, ...] = ()) -> dict[str, list[str]]:
    """Map module name -> offending fragments, for every module that offends."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(package_dir.glob("*.py")):
        if path.name in skip:
            continue
        hits = module_reads_ground_truth(path)
        if hits:
            offenders[path.name] = hits
    return offenders
