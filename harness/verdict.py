"""Canonical shared data contracts for the DualGuard verification gate.

Every module in PatchPilot v2 imports its types from THIS file. Do not redefine
these dataclasses anywhere else. The `cleared` property in GateVerdict is the
single source of truth for what counts as a passing patch.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Literal, Dict, Any


SourceName = Literal["vul4j", "vjbench"]


@dataclass
class BugRecord:
    """A single reproducible vulnerability under evaluation.

    Attributes:
        id: Canonical id, e.g. "VUL4J-10" or "VJBench-7".
        project: Maven/Gradle project name (e.g. "jenkins", "jackson-databind").
        cwe: CWE identifier string, e.g. "CWE-89". May be "" if unknown.
        source: Which benchmark this bug comes from.
        checkout_dir: Absolute path where the vulnerable revision is checked out.
        pov_tests: Fully-qualified test ids that act as the Proof-of-Vulnerability
            (must FAIL on the vulnerable revision), e.g.
            ["com.example.FooTest#testInjection"].
        vulnerable_file: Repo-relative path of the file that must be patched.
    """

    id: str
    project: str
    cwe: str
    source: SourceName
    checkout_dir: str
    pov_tests: List[str]
    vulnerable_file: str


@dataclass
class Patch:
    """A candidate patch produced by the fixer model for one BugRecord.

    Attributes:
        bug_id: BugRecord.id this patch targets.
        patched_file_path: Repo-relative path of the file being replaced
            (normally equals BugRecord.vulnerable_file).
        patched_code: Full new contents of the patched file (entire file, not a diff).
        model: Identifier of the model/config that generated the patch.
        attempt: 0-based retry index (for few-shot+retry baselines and best-of-n).
    """

    bug_id: str
    patched_file_path: str
    patched_code: str
    model: str
    attempt: int


@dataclass
class LayerResult:
    """Outcome of a single gate layer.

    Attributes:
        name: Layer name, one of:
            "compile", "regression", "pov_flip", "sast", "ast_non_deletion".
        passed: Whether this layer's requirement is satisfied.
        detail: Human-readable explanation / parsed metrics / error text.
    """

    name: str
    passed: bool
    detail: str


@dataclass
class GateVerdict:
    """Aggregated result of running all 5 gate layers on one Patch.

    The six boolean criteria are stored explicitly so downstream code never has
    to re-parse layer details. `cleared` is the AND of all six.
    """

    bug_id: str
    compiles: bool
    regression_pass: bool
    pov_flipped: bool
    semgrep_clean: bool
    codeql_clean: bool
    not_deleted: bool
    layers: List[LayerResult] = field(default_factory=list)

    @property
    def cleared(self) -> bool:
        """True iff the patch satisfies every DualGuard criterion."""
        return (
            self.compiles
            and self.regression_pass
            and self.pov_flipped
            and self.semgrep_clean
            and self.codeql_clean
            and self.not_deleted
        )

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable view, including the derived `cleared` flag."""
        d: Dict[str, Any] = asdict(self)
        d["cleared"] = self.cleared
        return d
