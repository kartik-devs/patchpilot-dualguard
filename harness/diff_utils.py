"""Small diff / normalization helpers shared by data prep and the UI.

Pure-stdlib, dependency-free utilities for producing unified diffs between the
original and patched Java files and for lightweight text normalization used when
de-duplicating training pairs.
"""

from __future__ import annotations

import difflib
import re
from typing import List

_WS_RE = re.compile(r"\s+")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def unified_diff(
    original: str,
    patched: str,
    fromfile: str = "original",
    tofile: str = "patched",
    context: int = 3,
) -> str:
    """Return a unified diff string between two file contents."""
    a = (original or "").splitlines(keepends=True)
    b = (patched or "").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(a, b, fromfile=fromfile, tofile=tofile, n=context)
    )


def strip_comments(code: str) -> str:
    """Remove // line and /* block */ comments from Java-ish source."""
    code = _BLOCK_COMMENT_RE.sub(" ", code or "")
    code = _LINE_COMMENT_RE.sub(" ", code)
    return code


def normalize_code(code: str) -> str:
    """Normalize code for dedup: drop comments and collapse whitespace."""
    return _WS_RE.sub(" ", strip_comments(code or "")).strip()


def normalized_jaccard(a: str, b: str) -> float:
    """Token-set Jaccard similarity of two code strings after normalization."""
    ta = set(normalize_code(a).split())
    tb = set(normalize_code(b).split())
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def changed_line_count(original: str, patched: str) -> int:
    """Number of added/removed lines between original and patched."""
    a = (original or "").splitlines()
    b = (patched or "").splitlines()
    n = 0
    for line in difflib.ndiff(a, b):
        if line.startswith("+ ") or line.startswith("- "):
            n += 1
    return n


__all__ = [
    "unified_diff",
    "strip_comments",
    "normalize_code",
    "normalized_jaccard",
    "changed_line_count",
]
