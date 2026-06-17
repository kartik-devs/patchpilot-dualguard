"""MG2 · Vul4J CLI wrapper: checkout, compile, test, baseline PoV, evaluate patch.

This module shells out to the verified ``vul4j`` CLI for every apply/compile/test
operation (it NEVER re-implements them). It parses ``VUL4J/test_results.json``
into a :class:`TestSummary`, confirms the Proof-of-Vulnerability *fails* on the
vulnerable revision (:func:`baseline_pov`), and applies+compiles+tests a candidate
patch via ``vul4j evaluate`` (:func:`evaluate_patch`), classifying regression vs
PoV tests so the gate orchestrator can build a :class:`harness.verdict.GateVerdict`.

Shared contracts (BugRecord, Patch) are imported from :mod:`harness.verdict`;
they are defined ONCE there and never redefined here. The dataclasses defined in
this module (TestSummary, FailureRec, BaselineResult, EvalOutcome) are local
helper types consumed by :mod:`harness.gate`.

CLI::

    python -m harness.layers.vul4j_runner baseline --bug-json bug.json
    python -m harness.layers.vul4j_runner evaluate --bug-json bug.json --patch-json patch.json [-o out.json]
    python -m harness.layers.vul4j_runner checkout --id VUL4J-10 -d /tmp/vul4j-10
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Canonical shared contracts — imported, never redefined (INTEGRATION INVARIANT 1).
from harness.verdict import BugRecord, Patch


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class Vul4JNotInstalled(RuntimeError):
    """Raised when the ``vul4j`` CLI binary cannot be located on PATH."""


class Vul4JError(RuntimeError):
    """Raised when a ``vul4j`` invocation fails or produces no expected output."""


# --------------------------------------------------------------------------- #
# Local dataclasses (NOT shared contracts — defined here per spec §3·MG2)
# --------------------------------------------------------------------------- #
@dataclass
class FailureRec:
    """A single failing/erroring test parsed from Vul4J ``failures[]``."""

    test_class: str
    test_method: str
    failure_name: str
    detail: str

    @property
    def test_id(self) -> str:
        """Fully-qualified test id ``<class>#<method>`` (Vul4J/JUnit style)."""
        if self.test_method:
            return f"{self.test_class}#{self.test_method}"
        return self.test_class


@dataclass
class TestSummary:
    """Normalized view of Vul4J ``test_results.json`` overall_metrics + failures."""

    running: int
    passing: int
    error: int
    failing: int
    skipping: int
    failures: List[FailureRec] = field(default_factory=list)
    passing_tests: List[str] = field(default_factory=list)
    skipping_tests: List[str] = field(default_factory=list)

    @property
    def failing_test_ids(self) -> List[str]:
        """Ids (``class#method``) of all failing/erroring tests."""
        return [f.test_id for f in self.failures]


@dataclass
class BaselineResult:
    """Outcome of confirming the PoV fails on the unpatched (vulnerable) revision."""

    pov_failed: bool
    summary: Optional[TestSummary]
    detail: str


@dataclass
class EvalOutcome:
    """Outcome of applying+compiling+testing a candidate patch.

    Consumed by :func:`harness.gate.run_gate` to populate the six GateVerdict
    booleans and to feed ``original_code``/``patched_code`` to the AST guard.
    """

    compiled: bool
    regression_passed: bool
    pov_passed: bool
    summary: Optional[TestSummary]
    original_code: str
    patched_code: str
    detail: str


# --------------------------------------------------------------------------- #
# Internal: locate + invoke the vul4j CLI
# --------------------------------------------------------------------------- #
def _vul4j_bin() -> str:
    """Return the ``vul4j`` executable path, honoring the ``VUL4J_BIN`` override.

    Raises:
        Vul4JNotInstalled: if no ``vul4j`` binary is on PATH.
    """
    override = os.environ.get("VUL4J_BIN")
    if override:
        if os.path.isfile(override) or shutil.which(override):
            return override
        raise Vul4JNotInstalled(
            f"VUL4J_BIN={override!r} is set but not executable. "
            "Install Vul4J (Docker image 'tuhhsoftsec/vul4j') and expose the "
            "`vul4j` CLI, or unset VUL4J_BIN."
        )
    found = shutil.which("vul4j")
    if not found:
        raise Vul4JNotInstalled(
            "`vul4j` CLI not found on PATH. Install Vul4J (Docker image "
            "'tuhhsoftsec/vul4j') and ensure the `vul4j` command is available, "
            "or set VUL4J_BIN to its path."
        )
    return found


def _run_vul4j(
    args: List[str],
    cwd: Optional[str] = None,
    timeout: int = 1800,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Invoke the ``vul4j`` CLI with ``args``.

    Args:
        args: Arguments AFTER the ``vul4j`` binary (e.g. ``["checkout", ...]``).
        cwd: Working directory for the call.
        timeout: Hard wall-clock timeout in seconds.
        check: When True, raise :class:`Vul4JError` on a non-zero exit code.

    Returns:
        The completed process (stdout/stderr captured as text).

    Raises:
        Vul4JNotInstalled: if the binary is missing.
        Vul4JError: on non-zero exit (when ``check``) or on timeout.
    """
    binary = _vul4j_bin()
    cmd = [binary, *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise Vul4JError(
            f"vul4j {' '.join(args)} timed out after {timeout}s"
        ) from exc
    except OSError as exc:  # pragma: no cover - defensive
        raise Vul4JError(f"failed to execute vul4j: {exc}") from exc

    if check and proc.returncode != 0:
        raise Vul4JError(
            f"vul4j {' '.join(args)} exited {proc.returncode}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    return proc


def _combined_log(proc: subprocess.CompletedProcess) -> str:
    """Concatenate stdout + stderr of a completed process into one log string."""
    out = proc.stdout or ""
    err = proc.stderr or ""
    return f"{out}\n{err}".strip()


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def checkout(bug_id: str, dest_dir: str) -> str:
    """Check out the vulnerable revision of ``bug_id`` into ``dest_dir``.

    Runs ``vul4j checkout --id <bug_id> -d <dest_dir>``. Idempotent: if
    ``dest_dir/VUL4J`` metadata already exists the re-checkout is skipped.

    Args:
        bug_id: Canonical Vul4J id, e.g. ``"VUL4J-10"``.
        dest_dir: Absolute destination directory for the checkout.

    Returns:
        ``dest_dir``.

    Raises:
        Vul4JNotInstalled: if the CLI is missing.
        Vul4JError: on a failed checkout.
    """
    meta = os.path.join(dest_dir, "VUL4J")
    if os.path.isdir(meta) and os.listdir(meta):
        return dest_dir
    # `vul4j checkout` asserts the dest dir does NOT already exist and creates it
    # itself — so DON'T pre-create it. Clear any stale/partial dir and ensure only
    # the PARENT exists.
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir, ignore_errors=True)
    parent = os.path.dirname(os.path.abspath(dest_dir))
    os.makedirs(parent, exist_ok=True)
    _run_vul4j(["checkout", "--id", bug_id, "-d", dest_dir], timeout=1800)
    return dest_dir


def compile_project(checkout_dir: str, timeout: int = 1200) -> Tuple[bool, str]:
    """Compile a checked-out project via ``vul4j compile -d <dir>``.

    Args:
        checkout_dir: Directory previously produced by :func:`checkout`.
        timeout: Compile timeout in seconds.

    Returns:
        ``(ok, combined_log)`` where ``ok`` is True iff the CLI exited 0.

    Raises:
        Vul4JNotInstalled: if the CLI is missing.
    """
    proc = _run_vul4j(
        ["compile", "-d", checkout_dir], timeout=timeout, check=False
    )
    return proc.returncode == 0, _combined_log(proc)


def _read_test_results(checkout_dir: str) -> Dict[str, Any]:
    """Read and parse ``<checkout_dir>/VUL4J/test_results.json``.

    Raises:
        Vul4JError: if the file is absent or not valid JSON.
    """
    vdir = os.path.join(checkout_dir, "VUL4J")
    # Vul4J 2.x writes VUL4J/testing_results.json; older docs say test_results.json.
    path = os.path.join(vdir, "testing_results.json")
    if not os.path.isfile(path):
        legacy = os.path.join(vdir, "test_results.json")
        if os.path.isfile(legacy):
            path = legacy
        else:
            raise Vul4JError(
                f"expected test results not found at {path}. Did `vul4j test` run?"
            )
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise Vul4JError(f"could not parse {path}: {exc}") from exc


def run_tests(checkout_dir: str, timeout: int = 1800) -> dict:
    """Run the test suite via ``vul4j test -d <dir>`` and return the parsed JSON.

    Args:
        checkout_dir: Directory previously produced by :func:`checkout`.
        timeout: Test-suite timeout in seconds.

    Returns:
        The parsed ``VUL4J/test_results.json`` dict.

    Raises:
        Vul4JNotInstalled: if the CLI is missing.
        Vul4JError: on a failed run or if the results json is absent.
    """
    _run_vul4j(["test", "-d", checkout_dir], timeout=timeout, check=False)
    return _read_test_results(checkout_dir)


def parse_test_results(results: dict) -> TestSummary:
    """Map a Vul4J ``test_results.json`` dict to a :class:`TestSummary`.

    Tolerant of both the documented schema (``overall_metrics`` /
    ``failures`` / ``passing_tests`` / ``skipping_tests``) and minor key
    variations. Missing numeric metrics default to 0; missing lists to [].

    Args:
        results: The parsed test_results.json content.

    Returns:
        A normalized :class:`TestSummary`.
    """
    # Vul4J 2.x nests metrics/failures/passing under a top-level "tests" key;
    # older shapes are flat. Unwrap so both parse correctly.
    data = results.get("tests") if isinstance(results.get("tests"), dict) else results
    metrics = data.get("overall_metrics") or {}

    def _metric(*keys: str) -> int:
        for key in keys:
            if key in metrics and metrics[key] is not None:
                try:
                    return int(metrics[key])
                except (TypeError, ValueError):
                    return 0
        return 0

    failures_raw = data.get("failures") or []
    failures: List[FailureRec] = []
    for item in failures_raw:
        if not isinstance(item, dict):
            continue
        failures.append(
            FailureRec(
                test_class=str(item.get("test_class", "") or ""),
                test_method=str(item.get("test_method", "") or ""),
                failure_name=str(
                    item.get("failure_name", item.get("name", "")) or ""
                ),
                detail=str(item.get("detail", item.get("message", "")) or ""),
            )
        )

    passing_tests = [str(t) for t in (data.get("passing_tests") or [])]
    skipping_tests = [str(t) for t in (data.get("skipping_tests") or [])]

    return TestSummary(
        running=_metric("number_running", "running"),
        passing=_metric("number_passing", "passing"),
        error=_metric("number_error", "error"),
        failing=_metric("number_failing", "failing"),
        skipping=_metric("number_skipping", "skipping"),
        failures=failures,
        passing_tests=passing_tests,
        skipping_tests=skipping_tests,
    )


def _normalize_test_id(test_id: str) -> str:
    """Normalize a test id for matching: accept ``a.b.C#m``, ``a.b.C::m``, ``a.b.C.m``.

    Returns a canonical ``Class#method`` (or bare class) lower-effort form so
    PoV ids from the manifest match ids found in passing/failing lists.
    """
    tid = test_id.strip().replace("::", "#")
    return tid


def _test_id_matches(target: str, candidate: str) -> bool:
    """True if ``candidate`` (from Vul4J output) identifies the same test as ``target``.

    Matches on exact normalized equality, or when one is a class#method form and
    the other lacks/has the method, or differing ``#`` vs ``.`` separators.
    """
    t = _normalize_test_id(target)
    c = _normalize_test_id(candidate)
    if t == c:
        return True
    # Compare class and (optional) method components.
    t_cls, _, t_m = t.partition("#")
    c_cls, _, c_m = c.partition("#")
    # Some Vul4J entries store the method as part of a dotted class path.
    if not c_m and "." in c_cls and t_m:
        c_cls2, _, c_m2 = c_cls.rpartition(".")
        if c_cls2 == t_cls and c_m2 == t_m:
            return True
    # Vul4J sometimes emits an id as <class><method> with NO separator (seen in
    # its reproduce log and some test_results.json fields). Match that form too.
    if not c_m and t_m and c_cls == f"{t_cls}{t_m}":
        return True
    if not t_m and c_m and t_cls == f"{c_cls}{c_m}":
        return True
    if not t_m:
        return c_cls == t_cls
    return c_cls == t_cls and c_m == t_m


def did_tests_pass(
    summary: TestSummary, required: Optional[List[str]] = None
) -> bool:
    """True iff no failing/erroring tests and (optionally) all ``required`` pass.

    Args:
        summary: A parsed :class:`TestSummary`.
        required: Optional list of test ids that must each appear in
            ``summary.passing_tests``.

    Returns:
        ``number_failing == 0 and number_error == 0`` and, when ``required`` is
        given, every required id is present in ``passing_tests``.
    """
    if summary.failing != 0 or summary.error != 0:
        return False
    if required:
        for req in required:
            if not any(
                _test_id_matches(req, p) for p in summary.passing_tests
            ):
                return False
    return True


def _pov_ids_in_failures(
    pov_tests: List[str], summary: TestSummary
) -> Tuple[List[str], List[str]]:
    """Partition ``pov_tests`` into (found_in_failures, missing_from_failures)."""
    failing_ids = summary.failing_test_ids
    found: List[str] = []
    missing: List[str] = []
    for pov in pov_tests:
        if any(_test_id_matches(pov, fid) for fid in failing_ids):
            found.append(pov)
        else:
            missing.append(pov)
    return found, missing


def baseline_pov(bug: BugRecord) -> BaselineResult:
    """Confirm the PoV tests FAIL on the unpatched (vulnerable) revision.

    Ensures the checkout exists (checks out if necessary), compiles, runs the
    test suite, and verifies that every id in ``bug.pov_tests`` appears among the
    failing/erroring tests. Errors are caught and reported (never crash) so the
    gate can degrade gracefully.

    Args:
        bug: The vulnerability under evaluation.

    Returns:
        :class:`BaselineResult` ``(pov_failed, summary, detail)``.
    """
    try:
        checkout(bug.id, bug.checkout_dir)
    except Vul4JNotInstalled as exc:
        return BaselineResult(False, None, f"baseline skipped: {exc}")
    except Vul4JError as exc:
        return BaselineResult(False, None, f"baseline checkout failed: {exc}")

    try:
        ok, log = compile_project(bug.checkout_dir)
        if not ok:
            return BaselineResult(
                False,
                None,
                "baseline compile FAILED on the vulnerable revision; cannot "
                f"establish PoV. Last log:\n{log[-2000:]}",
            )
        raw = run_tests(bug.checkout_dir)
    except Vul4JNotInstalled as exc:
        return BaselineResult(False, None, f"baseline skipped: {exc}")
    except Vul4JError as exc:
        return BaselineResult(False, None, f"baseline test run failed: {exc}")

    summary = parse_test_results(raw)

    if not bug.pov_tests:
        # No explicit PoV ids: fall back to "the suite had at least one failure".
        pov_failed = summary.failing > 0 or summary.error > 0
        detail = (
            f"no explicit pov_tests on bug; baseline failing={summary.failing} "
            f"error={summary.error} -> pov_failed={pov_failed}"
        )
        return BaselineResult(pov_failed, summary, detail)

    found, missing = _pov_ids_in_failures(bug.pov_tests, summary)
    pov_failed = len(missing) == 0
    if pov_failed:
        detail = (
            f"baseline PoV reproduced: all {len(found)} PoV test(s) FAIL on the "
            "vulnerable revision."
        )
    else:
        detail = (
            "baseline PoV did NOT fail as expected; missing from failures: "
            f"{missing}. Bug may not be reproducible. "
            f"failing={summary.failing} error={summary.error}"
        )
    return BaselineResult(pov_failed, summary, detail)


def _ensure_parent(path: str) -> None:
    """Create the parent directory of ``path`` if it does not exist."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def _read_file_text(path: str) -> str:
    """Read text from ``path`` (utf-8, errors replaced). Returns "" if absent."""
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _classify_regression_and_pov(
    summary: TestSummary,
    pov_tests: List[str],
    baseline_failing_ids: Optional[List[str]] = None,
) -> Tuple[bool, bool, str]:
    """Split tests into PoV vs regression and decide both booleans.

    Regression set = every test in ``passing_tests ∪ failures`` that is NOT a
    PoV test. ``regression_passed`` ⇔ no regression-set test currently fails.
    ``pov_passed`` ⇔ every ``pov_tests`` id now appears in ``passing_tests``.

    Returns:
        ``(regression_passed, pov_passed, detail)``.
    """
    # PoV pass: each PoV id must be in passing_tests.
    if pov_tests:
        pov_passed = all(
            any(_test_id_matches(pov, p) for p in summary.passing_tests)
            for pov in pov_tests
        )
    else:
        # No explicit PoV: treat "no failures at all" as PoV-passing.
        pov_passed = summary.failing == 0 and summary.error == 0

    # Regression: a non-PoV test that FAILS on the patched tree AND did NOT already
    # fail on the vulnerable baseline (env-flaky tests failing on both don't count as
    # regressions — only NEW breakage introduced by the patch does).
    baseline_failing_ids = baseline_failing_ids or []
    regression_failures = [
        fid
        for fid in summary.failing_test_ids
        if not any(_test_id_matches(pov, fid) for pov in pov_tests)
        and not any(_test_id_matches(b, fid) for b in baseline_failing_ids)
    ]
    regression_passed = len(regression_failures) == 0

    detail = (
        f"pov_passed={pov_passed} (pov_tests={pov_tests}); "
        f"regression_passed={regression_passed} "
        f"(non-PoV failures={regression_failures}); "
        f"totals running={summary.running} passing={summary.passing} "
        f"failing={summary.failing} error={summary.error}"
    )
    return regression_passed, pov_passed, detail


def evaluate_patch(
    bug: BugRecord,
    patch: Patch,
    output_dir: Optional[str] = None,
    compile_timeout: int = 1200,
    test_timeout: int = 1800,
    baseline_failing_ids: Optional[List[str]] = None,
) -> EvalOutcome:
    """Apply + compile + test a candidate patch IN PLACE on the checked-out bug.

    Drives the proven Vul4J primitives directly: write the candidate's full-file
    content into the checkout, then ``vul4j compile -d <checkout>`` and
    ``vul4j test -d <checkout>``, then parse ``<checkout>/VUL4J/test_results.json``.

    This deliberately does NOT use ``vul4j evaluate``: upstream ``evaluate`` takes a
    list of ``{vul_id, candidates:[{diff: <unified git diff>}]}`` records (applied
    via ``git apply``), re-checks each bug out into ``/tmp`` (ignoring our
    checkout), and writes results under ``<output-dir>/<vul_id>/<candidate>/VUL4J/``
    — none of which matches the full-file content this gate produces or the
    location we read. The in-place path reuses the SAME functions
    :func:`baseline_pov` uses, so the baseline and post-patch runs are directly
    comparable, and it operates on the already-checked-out tree with a warm Maven
    cache. All failures are caught and surfaced in ``detail`` (never crash).

    Args:
        bug: The vulnerability under evaluation.
        patch: The candidate patch (full-file content).
        output_dir: Unused; retained for call-site compatibility.
        compile_timeout: ``vul4j compile`` timeout in seconds.
        test_timeout: ``vul4j test`` timeout in seconds.

    Returns:
        :class:`EvalOutcome` with compile/regression/PoV booleans, the test
        summary, original/patched code, and a human-readable detail string.
    """
    rel = patch.patched_file_path or bug.vulnerable_file
    abs_target = os.path.join(bug.checkout_dir, rel)
    original_code = _read_file_text(abs_target)
    patched_code = patch.patched_code

    # Ensure the checkout exists so paths resolve (cheap if already present).
    try:
        checkout(bug.id, bug.checkout_dir)
    except Vul4JNotInstalled as exc:
        return EvalOutcome(
            False, False, False, None, original_code, patched_code,
            f"evaluate skipped: {exc}",
        )
    except Vul4JError as exc:
        return EvalOutcome(
            False, False, False, None, original_code, patched_code,
            f"evaluate checkout failed: {exc}",
        )

    # Re-read original now that the checkout is guaranteed present.
    if not original_code:
        original_code = _read_file_text(abs_target)

    if not rel:
        return EvalOutcome(
            False, False, False, None, original_code, patched_code,
            "evaluate aborted: no target file (patch.patched_file_path and "
            "bug.vulnerable_file are both empty — check the eval manifest's "
            "vulnerable_file metadata).",
        )

    # Write the candidate patch (full-file content) into the checkout, in place.
    try:
        _ensure_parent(abs_target)
        with open(abs_target, "w", encoding="utf-8") as handle:
            handle.write(patched_code)
    except OSError as exc:
        return EvalOutcome(
            False, False, False, None, original_code, patched_code,
            f"could not write patched file {abs_target}: {exc}",
        )

    # Compile the patched tree (same primitive baseline_pov uses).
    try:
        compiled, compile_log = compile_project(
            bug.checkout_dir, timeout=compile_timeout
        )
    except Vul4JNotInstalled as exc:
        return EvalOutcome(
            False, False, False, None, original_code, patched_code,
            f"evaluate skipped: {exc}",
        )
    if not compiled:
        return EvalOutcome(
            compiled=False,
            regression_passed=False,
            pov_passed=False,
            summary=None,
            original_code=original_code,
            patched_code=patched_code,
            detail=f"patched tree FAILED to compile. Last log:\n{compile_log[-2000:]}",
        )

    # Run the suite on the patched tree; classify regression vs PoV.
    try:
        raw = run_tests(bug.checkout_dir, timeout=test_timeout)
    except Vul4JNotInstalled as exc:
        return EvalOutcome(
            True, False, False, None, original_code, patched_code,
            f"compiled but test run skipped: {exc}",
        )
    except Vul4JError as exc:
        return EvalOutcome(
            True, False, False, None, original_code, patched_code,
            f"compiled but test run failed: {exc}",
        )

    summary = parse_test_results(raw)
    regression_passed, pov_passed, split_detail = _classify_regression_and_pov(
        summary, bug.pov_tests, baseline_failing_ids
    )
    detail = f"compiled=True; {split_detail}"
    return EvalOutcome(
        compiled=True,
        regression_passed=regression_passed,
        pov_passed=pov_passed,
        summary=summary,
        original_code=original_code,
        patched_code=patched_code,
        detail=detail,
    )


def _extract_eval_entry(
    results_doc: Dict[str, Any], bug_id: str
) -> Optional[Dict[str, Any]]:
    """Pull the per-bug entry out of a Vul4J evaluate ``results.json`` document.

    Tolerant of several shapes: ``{bug_id: {...}}``, ``{"results": {bug_id: ...}}``,
    or a list of ``{"vul_id"/"id": bug_id, ...}`` records.
    """
    if not results_doc:
        return None
    if bug_id in results_doc and isinstance(results_doc[bug_id], dict):
        return results_doc[bug_id]
    nested = results_doc.get("results")
    if isinstance(nested, dict) and isinstance(nested.get(bug_id), dict):
        return nested[bug_id]
    if isinstance(nested, list):
        for rec in nested:
            if isinstance(rec, dict) and rec.get("id") == bug_id or (
                isinstance(rec, dict) and rec.get("vul_id") == bug_id
            ):
                return rec
    if isinstance(results_doc, dict):
        # Single-record document without the id keyed at top level.
        if results_doc.get("id") == bug_id or results_doc.get("vul_id") == bug_id:
            return results_doc
    return None


def _entry_compiled(entry: Optional[Dict[str, Any]]) -> bool:
    """Interpret an evaluate result entry's compile/apply flags as a bool."""
    if not entry:
        return False
    for key in ("compile_success", "compiled", "compile", "build_success"):
        if key in entry:
            return bool(entry[key])
    # Some schemas nest under "results" / "metrics".
    inner = entry.get("results") or entry.get("metrics") or {}
    if isinstance(inner, dict):
        for key in ("compile_success", "compiled", "compile"):
            if key in inner:
                return bool(inner[key])
    return False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_bug(path: str) -> BugRecord:
    """Load a :class:`BugRecord` from a JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return BugRecord(**data)


def _load_patch(path: str) -> Patch:
    """Load a :class:`Patch` from a JSON file."""
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return Patch(**data)


def _emit(obj: Any, out: Optional[str]) -> None:
    """Serialize a dataclass (or dict) to JSON, to file or stdout."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        payload = dataclasses.asdict(obj)
    else:
        payload = obj
    text = json.dumps(payload, indent=2, default=str)
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)


def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for the Vul4J runner.

    Subcommands:
        checkout  --id ID -d DIR
        baseline  --bug-json BUG [-o OUT]
        evaluate  --bug-json BUG --patch-json PATCH [-o OUT]
    """
    parser = argparse.ArgumentParser(
        prog="vul4j_runner",
        description="Wrapper around the verified Vul4J CLI for the DualGuard gate.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_co = sub.add_parser("checkout", help="Checkout a vulnerable revision.")
    p_co.add_argument("--id", required=True, help="Vul4J bug id, e.g. VUL4J-10.")
    p_co.add_argument("-d", "--dest", required=True, help="Destination directory.")

    p_base = sub.add_parser(
        "baseline", help="Confirm the PoV fails on the vulnerable revision."
    )
    p_base.add_argument("--bug-json", required=True, help="Path to BugRecord JSON.")
    p_base.add_argument("-o", "--out", help="Optional output JSON path.")

    p_eval = sub.add_parser(
        "evaluate", help="Apply+compile+test a candidate patch."
    )
    p_eval.add_argument("--bug-json", required=True, help="Path to BugRecord JSON.")
    p_eval.add_argument(
        "--patch-json", required=True, help="Path to Patch JSON."
    )
    p_eval.add_argument("--output-dir", help="Artifacts directory.")
    p_eval.add_argument("-o", "--out", help="Optional output JSON path.")

    args = parser.parse_args(argv)

    try:
        if args.command == "checkout":
            dest = checkout(args.id, args.dest)
            print(dest)
            return 0

        if args.command == "baseline":
            bug = _load_bug(args.bug_json)
            result = baseline_pov(bug)
            _emit(result, args.out)
            return 0 if result.pov_failed else 1

        if args.command == "evaluate":
            bug = _load_bug(args.bug_json)
            patch = _load_patch(args.patch_json)
            outcome = evaluate_patch(bug, patch, output_dir=args.output_dir)
            _emit(outcome, args.out)
            ok = (
                outcome.compiled
                and outcome.regression_passed
                and outcome.pov_passed
            )
            return 0 if ok else 1
    except Vul4JNotInstalled as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    except Vul4JError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 4
    except FileNotFoundError as exc:
        print(f"ERROR: input file not found: {exc}", file=sys.stderr)
        return 2

    parser.error("unknown command")
    return 2  # pragma: no cover - argparse exits first


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
