"""Back-compat shim: re-exports the dual-SAST AND-gate.

Canonical implementation: :mod:`harness.layers.sast`. This flat module keeps the
``harness.sast`` import path working (single source of truth, no duplication).
"""

from harness.layers.sast import (  # noqa: F401
    CodeQLNotInstalled,
    Finding,
    SastFindings,
    SastOutcome,
    SemgrepNotInstalled,
    filter_by_cwe,
    main,
    parse_codeql_sarif,
    parse_semgrep_json,
    run_codeql,
    run_semgrep,
    sast_and_gate,
)

__all__ = [
    "CodeQLNotInstalled",
    "Finding",
    "SastFindings",
    "SastOutcome",
    "SemgrepNotInstalled",
    "filter_by_cwe",
    "main",
    "parse_codeql_sarif",
    "parse_semgrep_json",
    "run_codeql",
    "run_semgrep",
    "sast_and_gate",
]
