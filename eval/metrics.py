"""MG5 · The DualGuard headline metric: Functionality-Preserved & Vuln-Cleared Rate.

A patch counts as a success iff its :class:`harness.verdict.GateVerdict` is
``cleared`` (compile + regression + PoV-flip + Semgrep AND CodeQL clean +
AST non-deletion). This module computes that rate with a Wilson 95% confidence
interval, stratified by source (vul4j / vjbench / vjbench-trans) and by whether
the bug's CWE is covered by the Semgrep ruleset.

Public surface (imported by eval.metric shim, eval.run_eval, tests):
    wilson_ci, fp_vc_rate, stratified_rates, compare_tags, main,
    RateStat, EvalRow,
    STRATUM_OVERALL, SOURCE_STRATA, COVERAGE_COVERED, COVERAGE_UNCOVERED
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from harness.verdict import BugRecord, GateVerdict

# --------------------------------------------------------------------------- #
# Stratum keys
# --------------------------------------------------------------------------- #
STRATUM_OVERALL = "overall"
SOURCE_STRATA = ("vul4j", "vjbench", "vjbench-trans")
COVERAGE_COVERED = "semgrep-covered"
COVERAGE_UNCOVERED = "semgrep-uncovered"

# CWEs the free Semgrep ruleset covers well (mirrors config/cwe_focus.yaml; kept
# as a built-in default so the metric works even if the YAML is absent).
_DEFAULT_COVERED_CWES = {
    "CWE-89",   # SQL injection
    "CWE-78",   # OS command injection
    "CWE-79",   # XSS
    "CWE-22",   # path traversal
    "CWE-327",  # broken/weak crypto
    "CWE-328",  # weak hash
    "CWE-611",  # XXE
    "CWE-502",  # unsafe deserialization
    "CWE-90",   # LDAP injection
    "CWE-91",   # XML injection
    "CWE-113",  # HTTP response splitting
    "CWE-326",  # inadequate encryption strength
    "CWE-295",  # improper cert validation
}


# --------------------------------------------------------------------------- #
# Data holders
# --------------------------------------------------------------------------- #
@dataclass
class RateStat:
    """A cleared-rate with its Wilson confidence interval."""

    n: int
    cleared: int
    rate: float
    ci_low: float
    ci_high: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvalRow:
    """One evaluated bug: its record, the gate verdict, the run tag, cleared flag."""

    bug: BugRecord
    verdict: GateVerdict
    tag: str
    cleared: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bug": asdict(self.bug),
            "verdict": self.verdict.to_dict(),
            "tag": self.tag,
            "cleared": bool(self.cleared),
        }


# --------------------------------------------------------------------------- #
# Core statistics
# --------------------------------------------------------------------------- #
def wilson_ci(cleared: int, n: int, z: float = 1.96) -> "tuple[float, float]":
    """Wilson score interval for a binomial proportion.

    Args:
        cleared: number of successes.
        n: number of trials.
        z: z-score (1.96 -> 95%).

    Returns:
        (low, high) clamped to [0, 1]. Returns (0.0, 0.0) when n == 0.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = cleared / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * math.sqrt((p * (1 - p) + z2 / (4 * n)) / n)) / denom
    low = max(0.0, center - half)
    high = min(1.0, center + half)
    return (low, high)


def fp_vc_rate(verdicts: Sequence[GateVerdict], z: float = 1.96) -> RateStat:
    """Functionality-Preserved & Vuln-Cleared rate over a list of verdicts."""
    n = len(verdicts)
    cleared = sum(1 for v in verdicts if getattr(v, "cleared", False))
    rate = (cleared / n) if n else 0.0
    lo, hi = wilson_ci(cleared, n, z=z)
    return RateStat(n=n, cleared=cleared, rate=rate, ci_low=lo, ci_high=hi)


# --------------------------------------------------------------------------- #
# Stratification
# --------------------------------------------------------------------------- #
def _source_stratum(bug: BugRecord) -> str:
    """Map a bug to one of SOURCE_STRATA."""
    bid = (getattr(bug, "id", "") or "").lower()
    src = (getattr(bug, "source", "") or "").lower()
    if "trans" in bid:
        return "vjbench-trans"
    if src == "vjbench" or bid.startswith("vjbench"):
        return "vjbench"
    return "vul4j"


def _is_covered(cwe: str, covered: Optional[set] = None) -> bool:
    """True iff the CWE is in the Semgrep-covered set."""
    if not cwe:
        return False
    cset = covered if covered is not None else _DEFAULT_COVERED_CWES
    return cwe.strip().upper() in {c.upper() for c in cset}


def stratified_rates(
    rows: Sequence[EvalRow], z: float = 1.96, covered: Optional[set] = None
) -> Dict[str, RateStat]:
    """Compute the cleared-rate per stratum.

    Always returns every canonical key (overall, each source stratum, covered,
    uncovered) even when a stratum is empty (n=0, rate=0).
    """
    buckets: Dict[str, List[GateVerdict]] = {
        STRATUM_OVERALL: [],
        COVERAGE_COVERED: [],
        COVERAGE_UNCOVERED: [],
    }
    for s in SOURCE_STRATA:
        buckets[s] = []

    for row in rows:
        v = row.verdict
        buckets[STRATUM_OVERALL].append(v)
        buckets[_source_stratum(row.bug)].append(v)
        cwe = getattr(row.bug, "cwe", "") or ""
        if _is_covered(cwe, covered):
            buckets[COVERAGE_COVERED].append(v)
        else:
            buckets[COVERAGE_UNCOVERED].append(v)

    return {key: fp_vc_rate(vs, z=z) for key, vs in buckets.items()}


def compare_tags(
    rows: Sequence[EvalRow], baseline_tag: str = "baseline", z: float = 1.96
) -> Dict[str, Any]:
    """Compare cleared-rates across run tags (e.g. finetuned vs baseline).

    Returns a dict with per-tag overall RateStat and the delta of every non-baseline
    tag against the baseline tag (if present).
    """
    by_tag: Dict[str, List[GateVerdict]] = {}
    for row in rows:
        by_tag.setdefault(row.tag, []).append(row.verdict)

    per_tag = {tag: fp_vc_rate(vs, z=z) for tag, vs in by_tag.items()}
    out: Dict[str, Any] = {"per_tag": {t: rs.to_dict() for t, rs in per_tag.items()}}

    base = per_tag.get(baseline_tag)
    deltas: Dict[str, float] = {}
    if base is not None:
        for tag, rs in per_tag.items():
            if tag == baseline_tag:
                continue
            deltas[tag] = round(rs.rate - base.rate, 4)
    out["baseline_tag"] = baseline_tag
    out["delta_vs_baseline"] = deltas
    return out


# --------------------------------------------------------------------------- #
# CLI: summarize a results JSON written by eval.run_eval
# --------------------------------------------------------------------------- #
def _row_from_dict(d: Dict[str, Any]) -> EvalRow:
    """Reconstruct an EvalRow from a serialized results-file row (best effort)."""
    bd = d.get("bug", {}) or {}
    bug = BugRecord(
        id=str(bd.get("id", "")),
        project=str(bd.get("project", "")),
        cwe=str(bd.get("cwe", "")),
        source=bd.get("source", "vul4j"),  # type: ignore[arg-type]
        checkout_dir=str(bd.get("checkout_dir", "")),
        pov_tests=list(bd.get("pov_tests", []) or []),
        vulnerable_file=str(bd.get("vulnerable_file", "")),
    )
    vd = d.get("verdict", {}) or {}
    verdict = GateVerdict(
        bug_id=str(vd.get("bug_id", bug.id)),
        compiles=bool(vd.get("compiles", False)),
        regression_pass=bool(vd.get("regression_pass", False)),
        pov_flipped=bool(vd.get("pov_flipped", False)),
        semgrep_clean=bool(vd.get("semgrep_clean", False)),
        codeql_clean=bool(vd.get("codeql_clean", False)),
        not_deleted=bool(vd.get("not_deleted", False)),
    )
    tag = str(d.get("tag", "finetuned"))
    cleared = bool(d.get("cleared", verdict.cleared))
    return EvalRow(bug=bug, verdict=verdict, tag=tag, cleared=cleared)


def _format_table(strata: Dict[str, RateStat]) -> str:
    lines = [f"{'stratum':<18} {'n':>4} {'cleared':>8} {'rate':>7}  95% CI"]
    for key, rs in strata.items():
        lines.append(
            f"{key:<18} {rs.n:>4} {rs.cleared:>8} {rs.rate*100:>6.1f}%  "
            f"[{rs.ci_low*100:.1f}%, {rs.ci_high*100:.1f}%]"
        )
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m eval.metrics",
        description="Summarize a DualGuard eval results JSON into stratified rates.",
    )
    p.add_argument("--results", required=True, help="Path to a run_eval results JSON.")
    p.add_argument("-z", type=float, default=1.96, help="Wilson z-score (default 1.96).")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        with open(args.results, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"[metrics] error: cannot read {args.results}: {exc}\n")
        return 2
    rows = [_row_from_dict(r) for r in data.get("rows", [])]
    if not rows:
        sys.stderr.write("[metrics] warning: no 'rows' found in results file.\n")
    strata = stratified_rates(rows, z=args.z)
    print(_format_table(strata))
    print()
    print(json.dumps(compare_tags(rows, z=args.z), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "wilson_ci",
    "fp_vc_rate",
    "stratified_rates",
    "compare_tags",
    "main",
    "build_arg_parser",
    "RateStat",
    "EvalRow",
    "STRATUM_OVERALL",
    "SOURCE_STRATA",
    "COVERAGE_COVERED",
    "COVERAGE_UNCOVERED",
]
