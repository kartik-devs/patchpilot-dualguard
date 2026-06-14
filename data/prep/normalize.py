"""MG6 text-normalization helpers: dedup keys and leakage stripping.

Two responsibilities, kept separate on purpose:

  * `normalize_code` produces a *structural* dedup key. It deliberately throws
    away comments and whitespace so two cosmetically-different copies of the same
    fix collapse to the same key. It is NEVER used as training text.

  * `strip_leaky_tokens` sanitizes the instruction/input that the model SEES so
    it cannot pattern-match on the answer (CWE/CVE ids, file paths, commit
    hashes, '// FIX' markers, bug ids). It preserves code structure.

Both are pure functions with no third-party dependencies.
"""

from __future__ import annotations

import re


# --- dedup-key normalization -------------------------------------------------

# Block and line comments. Applied before whitespace collapsing.
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
# Collapse any run of whitespace (incl. newlines) to a single space.
_WS_RE = re.compile(r"\s+")


def normalize_code(text: str) -> str:
    """Structural normalization used ONLY as a dedup key.

    Steps:
      1. Strip ``/* ... */`` block comments and ``// ...`` line comments.
      2. Lowercase (so case-only differences collapse; this is a dedup key, not
         training text, so semantic case loss is acceptable here).
      3. Collapse all whitespace (including newlines) to single spaces and trim.

    Returns:
        A single-line normalized string. Empty input -> "".
    """
    if not text:
        return ""
    t = _BLOCK_COMMENT_RE.sub(" ", text)
    t = _LINE_COMMENT_RE.sub(" ", t)
    t = t.lower()
    t = _WS_RE.sub(" ", t)
    return t.strip()


def tokenize(text: str) -> list[str]:
    """Cheap word/identifier tokenization for Jaccard near-dup detection.

    Splits on non-alphanumeric/underscore boundaries over the normalized text so
    the token set is comment/whitespace-insensitive.
    """
    norm = normalize_code(text)
    if not norm:
        return []
    return re.findall(r"[a-z0-9_]+", norm)


def token_jaccard(a: str, b: str) -> float:
    """Jaccard similarity over token *sets* of two code strings.

    Returns:
        |A ∩ B| / |A ∪ B| in [0, 1]. Two empty inputs -> 1.0 (identical);
        one empty -> 0.0.
    """
    sa, sb = set(tokenize(a)), set(tokenize(b))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union if union else 0.0


# --- leakage stripping -------------------------------------------------------

# Order matters: more specific patterns first so they win before generic ones.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE[-_]?\d+\b", re.IGNORECASE)
# Vul4J / VJBench bug ids, e.g. VUL4J-10, VJBench-7, VJBENCH_3.
_BUGID_RE = re.compile(r"\b(?:VUL4J|VJBENCH|VJBench)[-_]?\d+\b", re.IGNORECASE)
# 7-40 char hex blobs that look like git commit hashes (word-bounded).
_COMMIT_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.IGNORECASE)
# Inline fix/vuln markers in comments, e.g. "// FIX", "/* VULN: ... */", "# FIXME".
_MARKER_RE = re.compile(
    r"(?://|/\*|#)\s*(?:FIX(?:ME|ED)?|VULN(?:ERABILITY|ERABLE)?|PATCH(?:ED)?|"
    r"SECURITY|EXPLOIT|SINK)\b[^\n*]*",
    re.IGNORECASE,
)
# Unix-style absolute/relative source paths (heuristic: contains a slash and a
# java/source-ish segment). Conservative to avoid mangling code like a/b division.
_PATH_RE = re.compile(
    r"\b(?:[A-Za-z0-9_.\-]+/){1,}[A-Za-z0-9_.\-]+\.(?:java|kt|xml|properties|json)\b"
)
# Windows-style paths.
_WIN_PATH_RE = re.compile(
    r"\b[A-Za-z]:\\(?:[^\s\\]+\\)*[^\s\\]+\.(?:java|kt|xml|properties|json)\b"
)


def strip_leaky_tokens(text: str) -> str:
    """Remove leakage tokens that would let the model shortcut the fix.

    Redacts, replacing each match with a neutral placeholder so token offsets
    don't collapse unexpectedly:
        * CVE ids            -> <CVE>
        * CWE ids            -> <CWE>
        * bug ids (VUL4J/VJBench) -> <BUGID>
        * commit-hash-like hex blobs -> <HASH>
        * file paths (unix/windows) -> <PATH>
        * // FIX / // VULN style markers -> removed (empty)

    Structure-preserving: only the redacted spans change; surrounding code is
    untouched. Returns "" for falsy input.
    """
    if not text:
        return ""
    t = text
    # Markers first (they may themselves contain CWE/CVE words we just drop).
    t = _MARKER_RE.sub("", t)
    t = _CVE_RE.sub("<CVE>", t)
    t = _CWE_RE.sub("<CWE>", t)
    t = _BUGID_RE.sub("<BUGID>", t)
    t = _WIN_PATH_RE.sub("<PATH>", t)
    t = _PATH_RE.sub("<PATH>", t)
    # Commit hashes LAST so we don't accidentally eat hex inside an already-
    # replaced <PATH>/<CVE> token (placeholders contain no long hex runs).
    t = _COMMIT_RE.sub("<HASH>", t)
    return t
