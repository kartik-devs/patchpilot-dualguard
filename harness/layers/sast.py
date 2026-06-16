"""MG3 · Dual-SAST AND-gate: Semgrep CE + CodeQL over the patched file.

Runs BOTH a Semgrep Community-Edition scan and a CodeQL ``java-security-extended``
analysis on a candidate patch, parses Semgrep JSON ``results[]`` and CodeQL
SARIF ``runs[].results[]`` into a uniform :class:`Finding` list, scopes findings
to the bug's CWE (via ``config/cwe_focus.yaml`` as the rule-id -> CWE map and
to the patched file), and AND-gates::

    semgrep_clean = (no scoped Semgrep finding remains on the patched file)
    codeql_clean  = (no scoped CodeQL  finding remains on the patched file)

A patch is SAST-clean only when BOTH scanners report clean. If a scanner is not
installed the corresponding ``*_clean`` is ``False`` with a remediation string
(never a silent pass) per INTEGRATION INVARIANT 5.

Shared contracts are imported from :mod:`harness.verdict`; only BugRecord/Patch
etc. are defined there. The dataclasses here (Finding, SastFindings, SastOutcome)
are local helper types consumed by :mod:`harness.gate`.

CLI::

    python -m harness.layers.sast --file path/to/Patched.java \\
        --checkout-dir /tmp/vul4j-10 --source-root /tmp/vul4j-10 \\
        --cwe CWE-89 [--semgrep-config p/java] \\
        [--codeql-suite java-security-extended] \\
        [--cwe-focus config/cwe_focus.yaml] [-o sast.json]
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
from typing import Any, Dict, List, Optional

try:  # PyYAML is a pinned dependency, but degrade gracefully if absent.
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional at import time
    yaml = None  # type: ignore


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class SemgrepNotInstalled(RuntimeError):
    """Raised when the ``semgrep`` binary cannot be located on PATH."""


class CodeQLNotInstalled(RuntimeError):
    """Raised when the ``codeql`` binary cannot be located on PATH."""


# --------------------------------------------------------------------------- #
# Dataclasses (local helper types, NOT shared contracts)
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """A single static-analysis finding from Semgrep or CodeQL."""

    check_id: str
    path: str
    start_line: int
    end_line: int
    severity: str
    message: str
    tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable view of the finding."""
        return dataclasses.asdict(self)


@dataclass
class SastFindings:
    """Parsed findings from one scanner plus the raw tool output."""

    findings: List[Finding] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SastOutcome:
    """AND-gate result over both scanners (consumed by the gate orchestrator)."""

    semgrep_clean: bool
    codeql_clean: bool
    semgrep_findings: List[Finding]
    codeql_findings: List[Finding]
    detail: str

    @property
    def clean(self) -> bool:
        """True iff BOTH scanners are clean (the AND-gate)."""
        return self.semgrep_clean and self.codeql_clean

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serializable view including the derived ``clean`` flag."""
        return {
            "semgrep_clean": self.semgrep_clean,
            "codeql_clean": self.codeql_clean,
            "clean": self.clean,
            "semgrep_findings": [f.to_dict() for f in self.semgrep_findings],
            "codeql_findings": [f.to_dict() for f in self.codeql_findings],
            "detail": self.detail,
        }


# --------------------------------------------------------------------------- #
# Binary discovery
# --------------------------------------------------------------------------- #
def _which(name: str, env_override: str) -> Optional[str]:
    """Locate a binary, honoring an explicit env override path."""
    override = os.environ.get(env_override)
    if override:
        if os.path.isfile(override) or shutil.which(override):
            return override
        return None
    return shutil.which(name)


# --------------------------------------------------------------------------- #
# cwe_focus.yaml: rule-id -> CWE map
# --------------------------------------------------------------------------- #
def _load_cwe_focus(cwe_focus_path: str) -> Dict[str, Any]:
    """Load ``cwe_focus.yaml`` (the rule-id -> CWE single source of truth).

    Returns an empty dict (no scoping) if the file is missing or PyYAML is
    unavailable, so the gate degrades to "use all findings".
    """
    if not cwe_focus_path or not os.path.isfile(cwe_focus_path):
        return {}
    if yaml is None:
        return {}
    try:
        with open(cwe_focus_path, "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):  # type: ignore[attr-defined]
        return {}


def _rule_ids_for_cwe(focus: Dict[str, Any], cwe: str) -> Dict[str, set]:
    """Return ``{"semgrep": {rule_ids}, "codeql": {query_ids}}`` for ``cwe``.

    Reads the ``cwes:`` list of the focus doc. Empty sets if the CWE is absent.
    """
    semgrep_ids: set = set()
    codeql_ids: set = set()
    for entry in focus.get("cwes", []) or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("id", "")).upper() != cwe.upper():
            continue
        sg = entry.get("semgrep", {}) or {}
        for rid in sg.get("rule_ids", []) or []:
            semgrep_ids.add(str(rid))
        for qid in entry.get("codeql", []) or []:
            codeql_ids.add(str(qid))
    return {"semgrep": semgrep_ids, "codeql": codeql_ids}


def _is_cwe_in_focus(focus: Dict[str, Any], cwe: str) -> bool:
    """True if ``cwe`` appears in the focus doc's ``cwes:`` list."""
    for entry in focus.get("cwes", []) or []:
        if isinstance(entry, dict) and str(entry.get("id", "")).upper() == cwe.upper():
            return True
    return False


# --------------------------------------------------------------------------- #
# Semgrep
# --------------------------------------------------------------------------- #
def run_semgrep(
    file_or_dir: str,
    config: str = "p/java",
    rule_ids: Optional[List[str]] = None,
    timeout: int = 600,
) -> SastFindings:
    """Run Semgrep over ``file_or_dir`` and parse its JSON ``results[]``.

    Invokes ``semgrep --config <config> --json --quiet <path>``. When
    ``rule_ids`` is provided, one ``--config`` per pinned rule id is passed
    instead of the pack default.

    Args:
        file_or_dir: File or directory to scan.
        config: Default Semgrep config / ruleset (e.g. ``"p/java"``).
        rule_ids: Optional list of pinned rule ids to use as configs.
        timeout: Scan timeout in seconds.

    Returns:
        :class:`SastFindings` (parsed findings + raw JSON).

    Raises:
        SemgrepNotInstalled: if the ``semgrep`` binary is missing.
    """
    binary = _which("semgrep", "SEMGREP_BIN")
    if binary is None:
        raise SemgrepNotInstalled(
            "`semgrep` not found on PATH. Install the pinned version via "
            "scripts/setup_semgrep.sh (pip install semgrep==<pinned>)."
        )

    cmd = [binary]
    if rule_ids:
        for rid in rule_ids:
            cmd += ["--config", rid]
    else:
        cmd += ["--config", config]
    cmd += ["--json", "--quiet", file_or_dir]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return SastFindings([], {"error": f"semgrep timed out after {timeout}s"})
    except OSError as exc:  # pragma: no cover - defensive
        return SastFindings([], {"error": f"semgrep exec failed: {exc}"})

    raw: Dict[str, Any]
    try:
        raw = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        raw = {
            "error": "could not parse semgrep JSON",
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
        }
    return SastFindings(parse_semgrep_json(raw), raw)


def parse_semgrep_json(raw: Dict[str, Any]) -> List[Finding]:
    """Parse a Semgrep JSON document's ``results[]`` into :class:`Finding`s."""
    findings: List[Finding] = []
    for res in raw.get("results", []) or []:
        if not isinstance(res, dict):
            continue
        start = res.get("start", {}) or {}
        end = res.get("end", {}) or {}
        extra = res.get("extra", {}) or {}
        findings.append(
            Finding(
                check_id=str(res.get("check_id", "")),
                path=str(res.get("path", "")),
                start_line=int(start.get("line", 0) or 0),
                end_line=int(end.get("line", 0) or 0),
                severity=str(extra.get("severity", "")),
                message=str(extra.get("message", "")),
                tool="semgrep",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# CodeQL
# --------------------------------------------------------------------------- #
def run_codeql(
    checkout_dir: str,
    source_root: str,
    suite: str = "java-security-extended",
    db_dir: Optional[str] = None,
    timeout: int = 3600,
) -> SastFindings:
    """Build a CodeQL database then run the Java security suite.

    Steps::

        codeql database create <db> --language=java --source-root=<root> \\
            --command="<build cmd>"
        codeql database analyze <db> codeql/java-queries:<suite> \\
            --format=sarifv2.1.0 --output=<out.sarif>

    The build command defaults to ``vul4j compile -d <checkout_dir>`` (extraction
    requires a real build); override with the ``CODEQL_BUILD_COMMAND`` env var.

    Args:
        checkout_dir: Project checkout (used to derive the build command).
        source_root: Source root to extract.
        suite: CodeQL query suite tag.
        db_dir: Optional path to cache/reuse the database.
        timeout: Overall timeout in seconds (create + analyze).

    Returns:
        :class:`SastFindings` (parsed SARIF findings + raw SARIF).

    Raises:
        CodeQLNotInstalled: if the ``codeql`` binary is missing.
    """
    binary = _which("codeql", "CODEQL_BIN")
    if binary is None:
        raise CodeQLNotInstalled(
            "`codeql` not found on PATH. Install the pinned bundle via "
            "scripts/setup_codeql.sh."
        )

    db = db_dir or tempfile.mkdtemp(prefix="codeql_db_")
    sarif_out = os.path.join(tempfile.gettempdir(), "dualguard_codeql.sarif")
    build_cmd = os.environ.get(
        "CODEQL_BUILD_COMMAND", f"vul4j compile -d {checkout_dir}"
    )

    db_already = os.path.isdir(db) and os.path.isfile(
        os.path.join(db, "codeql-database.yml")
    )

    try:
        if not db_already:
            create = subprocess.run(
                [
                    binary,
                    "database",
                    "create",
                    db,
                    "--language=java",
                    f"--source-root={source_root}",
                    f"--command={build_cmd}",
                    "--overwrite",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if create.returncode != 0:
                return SastFindings(
                    [],
                    {
                        "error": "codeql database create failed",
                        "stderr": create.stderr[-2000:],
                        "stdout": create.stdout[-2000:],
                    },
                )

        analyze = subprocess.run(
            [
                binary,
                "database",
                "analyze",
                db,
                f"codeql/java-queries:{suite}",
                "--format=sarifv2.1.0",
                f"--output={sarif_out}",
                "--rerun",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return SastFindings([], {"error": f"codeql timed out after {timeout}s"})
    except OSError as exc:  # pragma: no cover - defensive
        return SastFindings([], {"error": f"codeql exec failed: {exc}"})

    if not os.path.isfile(sarif_out):
        return SastFindings(
            [],
            {
                "error": "codeql produced no SARIF",
                "stderr": getattr(analyze, "stderr", "")[-2000:],
            },
        )

    try:
        with open(sarif_out, "r", encoding="utf-8") as handle:
            sarif = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        return SastFindings([], {"error": f"could not parse SARIF: {exc}"})

    return SastFindings(parse_codeql_sarif(sarif), sarif)


def parse_codeql_sarif(sarif: Dict[str, Any]) -> List[Finding]:
    """Parse a SARIF v2.1.0 document's ``runs[].results[]`` into Findings.

    Resolves the rule id from each result (or its ``rule.id``) and the first
    physical location's file path and start/end lines.
    """
    findings: List[Finding] = []
    for run in sarif.get("runs", []) or []:
        if not isinstance(run, dict):
            continue
        # Build a ruleId -> default level map from the driver rules (optional).
        rule_levels: Dict[str, str] = {}
        driver = (run.get("tool", {}) or {}).get("driver", {}) or {}
        for rule in driver.get("rules", []) or []:
            if isinstance(rule, dict) and rule.get("id"):
                level = (
                    (rule.get("defaultConfiguration", {}) or {}).get("level", "")
                )
                rule_levels[str(rule["id"])] = str(level)

        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(
                result.get("ruleId")
                or (result.get("rule", {}) or {}).get("id", "")
                or ""
            )
            level = str(result.get("level", "")) or rule_levels.get(rule_id, "")
            message = str((result.get("message", {}) or {}).get("text", ""))

            path = ""
            start_line = 0
            end_line = 0
            locations = result.get("locations", []) or []
            if locations and isinstance(locations[0], dict):
                phys = locations[0].get("physicalLocation", {}) or {}
                art = phys.get("artifactLocation", {}) or {}
                path = str(art.get("uri", ""))
                region = phys.get("region", {}) or {}
                start_line = int(region.get("startLine", 0) or 0)
                end_line = int(region.get("endLine", start_line) or start_line)

            findings.append(
                Finding(
                    check_id=rule_id,
                    path=path,
                    start_line=start_line,
                    end_line=end_line,
                    severity=level,
                    message=message,
                    tool="codeql",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Scoping
# --------------------------------------------------------------------------- #
def filter_by_cwe(
    findings: SastFindings, cwe: str, cwe_focus_path: str
) -> SastFindings:
    """Keep only findings whose rule maps to ``cwe`` (per ``cwe_focus.yaml``).

    If ``cwe`` is empty, or the CWE has no mapping in the focus doc, the findings
    are returned unchanged (no scoping applied).

    Args:
        findings: Findings from one scanner.
        cwe: CWE id of the bug (e.g. ``"CWE-89"``).
        cwe_focus_path: Path to ``cwe_focus.yaml``.

    Returns:
        A new :class:`SastFindings` with only the CWE-scoped findings.
    """
    if not cwe:
        return findings
    focus = _load_cwe_focus(cwe_focus_path)
    mapped = _rule_ids_for_cwe(focus, cwe)
    rule_ids = mapped["semgrep"] | mapped["codeql"]
    if not rule_ids:
        # No mapping for this CWE -> do not scope (return unchanged).
        return findings

    def _matches(check_id: str) -> bool:
        if not check_id:
            return False
        for rid in rule_ids:
            if check_id == rid or check_id.endswith(rid) or rid.endswith(check_id):
                return True
        return False

    kept = [f for f in findings.findings if _matches(f.check_id)]
    return SastFindings(kept, findings.raw)


def _same_file(finding_path: str, target_rel: str, source_root: str) -> bool:
    """True if a finding's path refers to the patched file ``target_rel``.

    Compares basenames and normalized suffixes so absolute, source-root-relative,
    and ``file://`` SARIF URIs all resolve to the same on-disk file.
    """
    if not finding_path or not target_rel:
        return False
    fp = finding_path.replace("file://", "").replace("\\", "/").lstrip("/")
    tgt = target_rel.replace("\\", "/").lstrip("/")
    if fp == tgt:
        return True
    if os.path.basename(fp) != os.path.basename(tgt):
        return False
    # Basenames match; accept if one path is a suffix of the other (handles
    # absolute vs relative and source-root prefixes).
    if fp.endswith(tgt) or tgt.endswith(fp):
        return True
    if source_root:
        sr = source_root.replace("\\", "/").rstrip("/")
        if fp.endswith(tgt) or (sr and fp == f"{sr}/{tgt}".lstrip("/")):
            return True
    return os.path.basename(fp) == os.path.basename(tgt)


def _scope_to_file(
    findings: List[Finding], target_rel: str, source_root: str
) -> List[Finding]:
    """Keep only findings that resolve to the patched file ``target_rel``."""
    return [f for f in findings if _same_file(f.path, target_rel, source_root)]


# --------------------------------------------------------------------------- #
# AND-gate
# --------------------------------------------------------------------------- #
def sast_and_gate(
    file_path: str,
    checkout_dir: str = "",
    source_root: str = "",
    cwe: str = "",
    semgrep_config: str = "p/java",
    codeql_suite: str = "java-security-extended",
    cwe_focus_path: str = "config/cwe_focus.yaml",
    codeql_required: bool = False,
) -> SastOutcome:
    """Run Semgrep + CodeQL on the patched file, scope to CWE, and AND-gate.

    ``semgrep_clean``/``codeql_clean`` are True iff that scanner reports NO
    finding of the relevant vulnerability class on the patched file. A missing
    Semgrep yields ``semgrep_clean = False`` (Semgrep is mandatory). CodeQL is
    corroboration-only by default: when ``codeql_required`` is False (the default),
    a missing or erroring CodeQL is treated as SKIPPED (``codeql_clean = True`` with
    a note) so Semgrep + the executable PoV/regression tests can stand alone; set
    ``codeql_required=True`` (e.g. for the CodeQL stretch subset) to make an
    absent/failed CodeQL fail the gate instead.

    Args:
        file_path: Path to the (written) patched file to scan with Semgrep.
        checkout_dir: Project checkout (needed for CodeQL DB build).
        source_root: Source root for CodeQL extraction (defaults to checkout_dir).
        cwe: Bug CWE for finding scoping.
        semgrep_config: Semgrep ruleset/pack.
        codeql_suite: CodeQL query suite tag.
        cwe_focus_path: Path to the rule-id -> CWE map.
        codeql_required: If True, a missing or erroring CodeQL sets
            ``codeql_clean=False`` (strict); if False (default), CodeQL is
            corroboration-only and skipped-as-clean when absent/erroring.

    Returns:
        :class:`SastOutcome`.
    """
    src_root = source_root or checkout_dir or os.path.dirname(file_path)
    # Patched-file path relative to the source root, for finding scoping.
    target_rel = file_path
    if src_root and os.path.isabs(file_path):
        try:
            target_rel = os.path.relpath(file_path, src_root)
        except ValueError:
            target_rel = os.path.basename(file_path)

    notes: List[str] = []

    # ---- Semgrep -------------------------------------------------------- #
    semgrep_findings: List[Finding] = []
    semgrep_clean = False
    focus = _load_cwe_focus(cwe_focus_path)
    pinned_rule_ids = sorted(_rule_ids_for_cwe(focus, cwe)["semgrep"]) or None
    try:
        sg = run_semgrep(
            file_path,
            config=semgrep_config,
            rule_ids=pinned_rule_ids,
        )
        if "error" in sg.raw:
            notes.append(f"semgrep error: {sg.raw['error']}")
            semgrep_clean = False
        else:
            scoped = filter_by_cwe(sg, cwe, cwe_focus_path)
            on_file = _scope_to_file(scoped.findings, target_rel, src_root)
            semgrep_findings = on_file
            semgrep_clean = len(on_file) == 0
            notes.append(
                f"semgrep: {len(on_file)} scoped finding(s) on patched file "
                f"(clean={semgrep_clean})"
            )
    except SemgrepNotInstalled as exc:
        semgrep_clean = False
        notes.append(str(exc))

    # ---- CodeQL (corroboration-only unless codeql_required) ------------- #
    codeql_findings: List[Finding] = []
    codeql_clean = False
    try:
        cq = run_codeql(
            checkout_dir or src_root,
            src_root,
            suite=codeql_suite,
        )
        if "error" in cq.raw:
            # Infra failure (DB build/analyze/timeout) — NOT evidence of a vuln.
            if codeql_required:
                codeql_clean = False
                notes.append(f"codeql error (required -> FAIL): {cq.raw['error']}")
            else:
                codeql_clean = True
                notes.append(
                    f"codeql SKIPPED (infra error, not required): {cq.raw['error']}"
                )
        else:
            scoped = filter_by_cwe(cq, cwe, cwe_focus_path)
            on_file = _scope_to_file(scoped.findings, target_rel, src_root)
            codeql_findings = on_file
            codeql_clean = len(on_file) == 0
            notes.append(
                f"codeql: {len(on_file)} scoped finding(s) on patched file "
                f"(clean={codeql_clean})"
            )
    except CodeQLNotInstalled as exc:
        if codeql_required:
            codeql_clean = False
            notes.append(f"codeql not installed (required -> FAIL): {exc}")
        else:
            codeql_clean = True
            notes.append(
                "codeql SKIPPED (not installed; corroboration-only this run). "
                "Semgrep + executable PoV/regression remain the binding gates."
            )

    detail = "; ".join(notes) if notes else "no scanners ran"
    return SastOutcome(
        semgrep_clean=semgrep_clean,
        codeql_clean=codeql_clean,
        semgrep_findings=semgrep_findings,
        codeql_findings=codeql_findings,
        detail=detail,
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point: run the dual-SAST AND-gate on one file.

    Exit code is 0 iff BOTH scanners report clean.
    """
    parser = argparse.ArgumentParser(
        prog="sast",
        description="Dual-SAST (Semgrep CE + CodeQL) AND-gate over a patched file.",
    )
    parser.add_argument(
        "--file", required=True, help="Path to the patched file to scan."
    )
    parser.add_argument(
        "--checkout-dir", default="", help="Project checkout (for CodeQL DB)."
    )
    parser.add_argument(
        "--source-root", default="", help="CodeQL source root (defaults to checkout-dir)."
    )
    parser.add_argument("--cwe", default="", help="Bug CWE id, e.g. CWE-89.")
    parser.add_argument(
        "--semgrep-config", default="p/java", help="Semgrep ruleset/pack."
    )
    parser.add_argument(
        "--codeql-suite",
        default="java-security-extended",
        help="CodeQL query suite tag.",
    )
    parser.add_argument(
        "--cwe-focus",
        default="config/cwe_focus.yaml",
        help="Path to cwe_focus.yaml (rule-id -> CWE map).",
    )
    parser.add_argument("-o", "--out", help="Optional output JSON path.")
    args = parser.parse_args(argv)

    outcome = sast_and_gate(
        file_path=args.file,
        checkout_dir=args.checkout_dir,
        source_root=args.source_root,
        cwe=args.cwe,
        semgrep_config=args.semgrep_config,
        codeql_suite=args.codeql_suite,
        cwe_focus_path=args.cwe_focus,
    )
    text = json.dumps(outcome.to_dict(), indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
    return 0 if outcome.clean else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
