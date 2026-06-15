"""WebGate — the accessibility arm of PatchPilot's verified-remediation engine.

Mirrors :mod:`harness.gate` for UI/accessibility. A patch is "cleared" only if the
SAME proof pattern holds as for security:

  1. baseline (precondition): the original page HAS axe-core violations (RED) — else
     there is nothing to prove.
  2. a11y_flipped: the patched page's target violations are GONE (GREEN) — fail->pass.
  3. not_deleted: the patch did not just DELETE the offending elements (the UI
     equivalent of "delete-the-sink"); the patched DOM retains >= a ratio of the
     original element count. This keeps the metric ungameable.

axe-core (run via webgate/axe_scan.mjs in Node) is the objective oracle, exactly as
Semgrep/CodeQL are for the security gate. Fail-soft: a missing Node/axe install
degrades to a clear remediation message, never a crash.

CLI:
    python -m harness.webgate --original broken.html --patched fixed.html
    Exit 0 iff the verdict is cleared.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------- #
# Contracts (parallel to harness.verdict)
# --------------------------------------------------------------------------- #
@dataclass
class A11yScan:
    """Result of one axe-core scan."""

    source: str
    violation_count: int
    rule_count: int
    by_rule: Dict[str, int]
    violations: List[dict] = field(default_factory=list)


@dataclass
class A11yLayer:
    name: str
    passed: bool
    detail: str


@dataclass
class A11yVerdict:
    """Aggregated a11y gate result (parallel to GateVerdict)."""

    page_id: str
    had_baseline_violations: bool
    violations_after: int
    a11y_flipped: bool
    not_deleted: bool
    layers: List[A11yLayer] = field(default_factory=list)
    baseline_by_rule: Dict[str, int] = field(default_factory=dict)
    after_by_rule: Dict[str, int] = field(default_factory=dict)

    @property
    def cleared(self) -> bool:
        return self.had_baseline_violations and self.a11y_flipped and self.not_deleted

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cleared"] = self.cleared
        return d


# --------------------------------------------------------------------------- #
# axe-core oracle (via Node)
# --------------------------------------------------------------------------- #
def _webgate_dir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webgate")


def _node_bin() -> str:
    return os.environ.get("NODE_BIN", "node")


def run_axe(html_path: str, only: Optional[List[str]] = None, timeout: int = 120) -> A11yScan:
    """Run webgate/axe_scan.mjs on an HTML file and parse the JSON result.

    Raises FileNotFoundError if Node/axe is unavailable (callers fail-soft).
    """
    scanner = os.path.join(_webgate_dir(), "axe_scan.mjs")
    if not os.path.isfile(scanner):
        raise FileNotFoundError(f"axe scanner not found at {scanner}")
    cmd = [_node_bin(), scanner, html_path, "--quiet"]
    if only:
        cmd += ["--only", ",".join(only)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=_webgate_dir())
    if proc.returncode not in (0,):
        raise RuntimeError(f"axe_scan failed (rc={proc.returncode}): {proc.stderr.strip()}")
    data = json.loads(proc.stdout)
    return A11yScan(
        source=str(data.get("source", html_path)),
        violation_count=int(data.get("violationCount", 0)),
        rule_count=int(data.get("ruleCount", 0)),
        by_rule=dict(data.get("byRule", {}) or {}),
        violations=list(data.get("violations", []) or []),
    )


def scan_html(html: str, only: Optional[List[str]] = None) -> A11yScan:
    """Scan an HTML string by writing it to a temp file first."""
    fd, path = tempfile.mkstemp(prefix="webgate_", suffix=".html")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(html)
        return run_axe(path, only=only)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# DOM non-deletion guard (UI equivalent of the AST non-deletion guard)
# --------------------------------------------------------------------------- #
class _TagCounter(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.count = 0

    def handle_starttag(self, tag, attrs):  # noqa: D401
        self.count += 1


def count_elements(html: str) -> int:
    """Count start tags in an HTML string (a cheap DOM-size proxy)."""
    p = _TagCounter()
    try:
        p.feed(html or "")
    except Exception:  # noqa: BLE001 - malformed HTML still gives a partial count
        pass
    return p.count


def dom_non_deletion_ok(original: str, patched: str, min_ratio: float = 0.6):
    """Reject patches that 'fix' a11y by deleting the offending elements."""
    o = count_elements(original)
    p = count_elements(patched)
    ratio = (p / o) if o > 0 else 1.0
    ok = ratio >= min_ratio
    detail = f"elements patched/original={p}/{o} ratio={ratio:.3f} (min={min_ratio})"
    return ok, ratio, detail


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #
def a11y_gate(
    original_html: str,
    patched_html: str,
    page_id: str = "page",
    target_rules: Optional[List[str]] = None,
    min_retained_ratio: float = 0.6,
) -> A11yVerdict:
    """Run the a11y verification gate on (original, patched) HTML.

    Args:
        original_html: the page BEFORE the fix (should have violations).
        patched_html: the page AFTER the fix.
        page_id: a label for the page.
        target_rules: if given, only require THESE axe rule ids to flip; else all
            baseline-violated rules must be cleared.
        min_retained_ratio: DOM non-deletion threshold.

    Returns:
        An :class:`A11yVerdict`. Fail-soft: missing Node/axe -> all-False with a
        remediation message in the layer detail.
    """
    layers: List[A11yLayer] = []
    baseline_by_rule: Dict[str, int] = {}
    after_by_rule: Dict[str, int] = {}
    had_baseline = False
    violations_after = 0
    a11y_flipped = False

    try:
        base = scan_html(original_html, only=target_rules)
        patched = scan_html(patched_html, only=target_rules)
        baseline_by_rule = base.by_rule
        after_by_rule = patched.by_rule
        had_baseline = base.violation_count > 0
        violations_after = patched.violation_count

        # Which rules to require cleared.
        rules_to_clear = set(target_rules) if target_rules else set(base.by_rule.keys())
        still_failing = {r for r in rules_to_clear if patched.by_rule.get(r, 0) > 0}
        a11y_flipped = had_baseline and len(still_failing) == 0

        layers.append(A11yLayer("baseline_violations", had_baseline,
                                f"baseline violations={base.violation_count} by_rule={base.by_rule}"))
        layers.append(A11yLayer("a11y_flip", a11y_flipped,
                                f"after violations={patched.violation_count}; still_failing={sorted(still_failing)}"))
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        msg = (f"axe oracle unavailable: {exc}. Install Node + run "
               f"`cd webgate && npm install`.")
        layers.append(A11yLayer("baseline_violations", False, msg))
        layers.append(A11yLayer("a11y_flip", False, msg))

    nd_ok, ratio, nd_detail = dom_non_deletion_ok(original_html, patched_html, min_retained_ratio)
    layers.append(A11yLayer("dom_non_deletion", nd_ok, nd_detail))

    return A11yVerdict(
        page_id=page_id,
        had_baseline_violations=had_baseline,
        violations_after=violations_after,
        a11y_flipped=a11y_flipped,
        not_deleted=nd_ok,
        layers=layers,
        baseline_by_rule=baseline_by_rule,
        after_by_rule=after_by_rule,
    )


# --------------------------------------------------------------------------- #
# LLM fixer (the autonomous loop: scan -> propose_fix -> gate)
# --------------------------------------------------------------------------- #
A11Y_FIX_SYSTEM = (
    "You are an accessibility remediation assistant. Given an HTML document and a "
    "list of axe-core accessibility violations, return the COMPLETE corrected HTML "
    "document. Fix ONLY the listed violations using minimal, semantically-correct "
    "changes (add alt text, labels, lang, titles, accessible names) — do NOT delete "
    "the offending elements and do NOT change unrelated content. Output only the "
    "fixed HTML inside a single ```html code block."
)


def _extract_html_block(text: str) -> str:
    """Pull the fenced ```html block from a model response (fallback: whole text)."""
    import re

    m = re.search(r"```(?:html)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else text.strip()


def propose_fix(
    broken_html: str,
    scan: A11yScan,
    base_url: str,
    model: str,
    temperature: float = 0.2,
    timeout: int = 120,
) -> str:
    """Ask an OpenAI-compatible vLLM endpoint to fix the a11y violations.

    Returns the full patched HTML. Lazily imports requests so the gate works
    without it.
    """
    import requests  # lazy

    rules = ", ".join(f"{k} (x{v})" for k, v in scan.by_rule.items()) or "none reported"
    user = (
        f"axe-core violations to fix: {rules}.\n\n"
        f"HTML document:\n```html\n{broken_html}\n```\n\n"
        "Return the complete corrected HTML."
    )
    resp = requests.post(
        f"{base_url.rstrip('/')}/chat/completions",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": A11Y_FIX_SYSTEM},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    return _extract_html_block(content)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m harness.webgate",
        description="WebGate a11y verification gate: prove an accessibility fix flipped fail->pass.",
    )
    p.add_argument("--original", required=True, help="Path to the original (broken) HTML.")
    p.add_argument("--patched", default=None,
                   help="Path to the patched HTML. Omit to auto-generate via --fixer-url.")
    p.add_argument("--fixer-url", default=None,
                   help="vLLM /v1 base URL; if set and --patched omitted, the model generates the fix.")
    p.add_argument("--fixer-model", default="fixer", help="Served model name for the auto fix.")
    p.add_argument("--temperature", type=float, default=0.2)
    p.add_argument("--page-id", default="page")
    p.add_argument("--only", default=None, help="Comma-separated axe rule ids to require flipped.")
    p.add_argument("--min-retained-ratio", type=float, default=0.6)
    p.add_argument("-o", "--output", default=None, help="Write the verdict JSON here too.")
    return p


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        original = _read(args.original)
    except OSError as exc:
        sys.stderr.write(f"[webgate] error: {exc}\n")
        return 3

    if args.patched:
        try:
            patched = _read(args.patched)
        except OSError as exc:
            sys.stderr.write(f"[webgate] error: {exc}\n")
            return 3
    elif args.fixer_url:
        try:
            base_scan = scan_html(original)
            patched = propose_fix(original, base_scan, args.fixer_url, args.fixer_model, args.temperature)
        except Exception as exc:  # noqa: BLE001 - fixer/transport/oracle failure
            sys.stderr.write(f"[webgate] auto-fix failed: {exc}\n")
            return 3
    else:
        sys.stderr.write("[webgate] error: provide --patched or --fixer-url.\n")
        return 2

    only = args.only.split(",") if args.only else None
    verdict = a11y_gate(original, patched, page_id=args.page_id,
                        target_rules=only, min_retained_ratio=args.min_retained_ratio)
    text = json.dumps(verdict.to_dict(), indent=2, sort_keys=True)
    print(text)
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0 if verdict.cleared else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "A11yScan", "A11yLayer", "A11yVerdict",
    "run_axe", "scan_html", "count_elements", "dom_non_deletion_ok", "a11y_gate", "main",
]
