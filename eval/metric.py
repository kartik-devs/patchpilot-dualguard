"""Spec alias for the eval metric module (``eval/metric.py``).

The architect file tree names this ``eval/metric.py``; the implementation shipped
as :mod:`eval.metrics`. This thin shim re-exports the full public surface so BOTH
import paths resolve to the SAME code (single source of truth — no duplication).
"""

from __future__ import annotations

from eval.metrics import (  # noqa: F401 - re-exported public surface
    COVERAGE_COVERED,
    COVERAGE_UNCOVERED,
    SOURCE_STRATA,
    STRATUM_OVERALL,
    EvalRow,
    RateStat,
    compare_tags,
    fp_vc_rate,
    main,
    stratified_rates,
    wilson_ci,
)

__all__ = [
    "wilson_ci",
    "fp_vc_rate",
    "stratified_rates",
    "compare_tags",
    "RateStat",
    "EvalRow",
    "STRATUM_OVERALL",
    "SOURCE_STRATA",
    "COVERAGE_COVERED",
    "COVERAGE_UNCOVERED",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - delegates to eval.metrics
    raise SystemExit(main())
