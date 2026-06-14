"""Back-compat shim: re-exports the Vul4J runner (compile / regression / PoV).

Canonical implementation: :mod:`harness.layers.vul4j_runner`. This flat module
keeps the ``harness.vul4j_runner`` import path working (single source of truth).
"""

from harness.layers.vul4j_runner import (  # noqa: F401
    BaselineResult,
    EvalOutcome,
    FailureRec,
    TestSummary,
    Vul4JError,
    Vul4JNotInstalled,
    baseline_pov,
    checkout,
    compile_project,
    did_tests_pass,
    evaluate_patch,
    main,
    parse_test_results,
    run_tests,
)

__all__ = [
    "BaselineResult",
    "EvalOutcome",
    "FailureRec",
    "TestSummary",
    "Vul4JError",
    "Vul4JNotInstalled",
    "baseline_pov",
    "checkout",
    "compile_project",
    "did_tests_pass",
    "evaluate_patch",
    "main",
    "parse_test_results",
    "run_tests",
]
