"""MG5: Wilson CI known values + FP&VC-Rate / strata correctness."""

from __future__ import annotations

import math

from eval.metrics import (
    COVERAGE_COVERED,
    COVERAGE_UNCOVERED,
    SOURCE_STRATA,
    STRATUM_OVERALL,
    EvalRow,
    fp_vc_rate,
    stratified_rates,
    wilson_ci,
)
from harness.verdict import BugRecord, GateVerdict


def _verdict(cleared: bool) -> GateVerdict:
    flag = bool(cleared)
    return GateVerdict(
        bug_id="B",
        compiles=flag,
        regression_pass=flag,
        pov_flipped=flag,
        semgrep_clean=flag,
        codeql_clean=flag,
        not_deleted=flag,
    )


def _bug(bid: str, source: str = "vul4j", cwe: str = "CWE-89") -> BugRecord:
    return BugRecord(
        id=bid, project="p", cwe=cwe, source=source,
        checkout_dir="", pov_tests=[], vulnerable_file="X.java",
    )


def test_wilson_zero_n():
    assert wilson_ci(0, 0) == (0.0, 0.0)


def test_wilson_bounds_clamped():
    lo, hi = wilson_ci(10, 10)
    assert 0.0 <= lo <= hi <= 1.0
    # All successes -> upper bound is 1.0; lower bound strictly below 1.
    assert math.isclose(hi, 1.0, abs_tol=1e-9)
    assert lo < 1.0


def test_wilson_known_value_half():
    # n=100, p=0.5, z=1.96 -> Wilson interval approx (0.404, 0.596).
    lo, hi = wilson_ci(50, 100, z=1.96)
    assert abs(lo - 0.4038) < 0.01
    assert abs(hi - 0.5962) < 0.01


def test_fp_vc_rate_counts_cleared():
    verdicts = [_verdict(True), _verdict(False), _verdict(True)]
    stat = fp_vc_rate(verdicts)
    assert stat.n == 3
    assert stat.cleared == 2
    assert abs(stat.rate - (2 / 3)) < 1e-9
    assert stat.ci_low <= stat.rate <= stat.ci_high


def test_stratified_always_has_all_keys():
    rows = [
        EvalRow(_bug("VUL4J-1"), _verdict(True), "finetuned", True),
        EvalRow(_bug("VJBench-2", "vjbench"), _verdict(False), "finetuned", False),
        EvalRow(_bug("VJBench-trans-3", "vjbench"), _verdict(True), "finetuned", True),
    ]
    strata = stratified_rates(rows)
    for key in (STRATUM_OVERALL, *SOURCE_STRATA, COVERAGE_COVERED, COVERAGE_UNCOVERED):
        assert key in strata
    assert strata[STRATUM_OVERALL].n == 3
    assert strata["vjbench-trans"].n == 1
    assert strata[COVERAGE_COVERED].cleared == 2
