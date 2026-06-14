"""DualGuard 5-layer verification gate orchestrator: run_gate(bug, patch) -> GateVerdict.

This module is the single entry point that runs every DualGuard layer on one
candidate patch and aggregates the result into the canonical
:class:`harness.verdict.GateVerdict`. It is *fail-soft*: every layer always runs
(so the UI can render all badges) and a missing external tool (Vul4J / Semgrep /
CodeQL / javalang) degrades to a ``False`` boolean with a clear remediation
string instead of a cryptic crash.

Layer order (canonical):
    1. baseline confirmation   -> vul4j_runner.baseline_pov(bug)   [precondition]
    2. apply+compile+regression+PoV -> vul4j_runner.evaluate_patch(bug, patch)
    3. SAST AND-gate           -> sast.sast_and_gate(...)
    4. AST non-deletion        -> ast_guard.non_deletion_ok(original, patched, ...)

CLI:
    python -m harness.gate --bug-json bug.json --patch-json patch.json \\
        [--config config/gate.yaml] [-o verdict.json]
Exit code is 0 iff the verdict is `cleared`, else 1 (3 on infra/arg error).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import traceback
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from harness.verdict import BugRecord, GateVerdict, LayerResult, Patch


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class GateConfig:
    """Tunable thresholds & tool settings for the gate (loaded from gate.yaml).

    Attributes:
        min_retained_ratio: AST guard threshold; patched reachable statements
            must be at least this fraction of the original.
        compile_timeout_s: Seconds allowed for the Vul4J compile step.
        test_timeout_s: Seconds allowed for the Vul4J test step.
        semgrep_config: Semgrep ruleset/config passed to the SAST layer.
        codeql_suite: CodeQL query suite passed to the SAST layer.
        cwe_focus_path: Path to cwe_focus.yaml (rule-id -> CWE map).
        require_baseline_pov_fail: If True, a bug whose PoV does NOT fail on the
            vulnerable revision is treated as unusable (not reproducible).
    """

    min_retained_ratio: float = 0.6
    compile_timeout_s: int = 1200
    test_timeout_s: int = 1800
    semgrep_config: str = "p/java"
    codeql_suite: str = "java-security-extended"
    cwe_focus_path: str = "config/cwe_focus.yaml"
    require_baseline_pov_fail: bool = True

    @classmethod
    def from_yaml(cls, path: str) -> "GateConfig":
        """Load a GateConfig from a YAML file.

        Unknown keys are ignored; missing keys fall back to the dataclass
        defaults. If PyYAML is not installed or the file is missing/empty, a
        default :class:`GateConfig` is returned (the gate must never crash on
        config alone).
        """
        if not path or not os.path.isfile(path):
            return cls()
        try:
            import yaml  # type: ignore
        except ImportError:
            sys.stderr.write(
                "[gate] warning: pyyaml not installed; using default GateConfig "
                "(install with `pip install pyyaml==6.0.2`).\n"
            )
            return cls()
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        except (OSError, ValueError) as exc:  # pragma: no cover - defensive
            sys.stderr.write(f"[gate] warning: could not read {path}: {exc}\n")
            return cls()
        if not isinstance(raw, dict):
            return cls()
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in raw.items() if k in known}
        return cls(**kwargs)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _write_patched_file(checkout_dir: str, rel_path: str, code: str) -> str:
    """Write `code` to `checkout_dir/rel_path`, returning the absolute path.

    Falls back to a temp file if the checkout dir is unavailable so the SAST
    layer always has a concrete file to scan. Best-effort; never raises.
    """
    try:
        if checkout_dir and os.path.isdir(checkout_dir):
            abs_path = os.path.join(checkout_dir, rel_path)
            os.makedirs(os.path.dirname(abs_path) or ".", exist_ok=True)
            with open(abs_path, "w", encoding="utf-8") as fh:
                fh.write(code)
            return abs_path
    except OSError:
        pass
    # Fallback: temp file preserving the original basename for path scoping.
    suffix = os.path.splitext(rel_path)[1] or ".java"
    fd, tmp = tempfile.mkstemp(prefix="dualguard_patch_", suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(code)
    except OSError:  # pragma: no cover - defensive
        pass
    return tmp


def _unusable_verdict(bug_id: str, reason: str) -> GateVerdict:
    """Build an all-False verdict carrying every canonical layer (fail-soft)."""
    layers = [
        LayerResult("compile", False, reason),
        LayerResult("regression", False, reason),
        LayerResult("pov_flip", False, reason),
        LayerResult("sast", False, reason),
        LayerResult("ast_non_deletion", False, reason),
    ]
    return GateVerdict(
        bug_id=bug_id,
        compiles=False,
        regression_pass=False,
        pov_flipped=False,
        semgrep_clean=False,
        codeql_clean=False,
        not_deleted=False,
        layers=layers,
    )


# --------------------------------------------------------------------------- #
# The orchestrator
# --------------------------------------------------------------------------- #
def run_gate(
    bug: BugRecord, patch: Patch, cfg: Optional[GateConfig] = None
) -> GateVerdict:
    """Run all 5 DualGuard layers on one patch and return the aggregated verdict.

    Order (fail-soft: every layer always runs so the UI shows all badges):
      1. baseline confirmation  -> vul4j_runner.baseline_pov(bug)   [precondition]
      2. apply+compile+regression+PoV -> vul4j_runner.evaluate_patch(bug, patch)
      3. SAST AND-gate          -> sast.sast_and_gate(...)
      4. AST non-deletion       -> ast_guard.non_deletion_ok(original, patched, ...)

    Args:
        bug: The reproducible vulnerability under test.
        patch: The candidate full-file patch produced by the fixer.
        cfg: Gate thresholds/tool settings; defaults to GateConfig() if None.

    Returns:
        A fully populated :class:`GateVerdict`. The six booleans and the per-layer
        ``layers`` list are always present. ``cleared`` is derived (AND of all six).
    """
    cfg = cfg or GateConfig()

    # Sibling layer modules are imported lazily so a missing dependency in one
    # layer (e.g. javalang) never prevents the others from running.
    layers: List[LayerResult] = []

    # ------------------------------------------------------------------ #
    # Layer 1 (precondition): baseline PoV must FAIL on the vulnerable rev.
    # ------------------------------------------------------------------ #
    base_failed = False
    base_detail = ""
    try:
        from harness.layers import vul4j_runner

        base = vul4j_runner.baseline_pov(bug)
        base_failed = bool(getattr(base, "pov_failed", False))
        base_detail = str(getattr(base, "detail", "") or "")
    except ImportError as exc:
        base_detail = (
            f"vul4j_runner unavailable: {exc}. Install Vul4J (Docker image "
            "tuhhsoftsec/vul4j) and ensure harness.layers.vul4j_runner is present."
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft per spec invariant 5
        base_failed = False
        base_detail = f"baseline_pov raised {type(exc).__name__}: {exc}"

    if cfg.require_baseline_pov_fail and not base_failed:
        reason = (
            "baseline PoV did not fail; bug not reproducible"
            if base_failed is False and not base_detail
            else f"baseline PoV did not fail; bug not reproducible ({base_detail})"
        )
        # Per spec: bug unusable -> all booleans False, pov_flip layer carries reason.
        verdict = _unusable_verdict(bug.id, reason)
        # Overwrite the pov_flip layer with the canonical message for clarity.
        for lr in verdict.layers:
            if lr.name == "pov_flip":
                lr.detail = (
                    "baseline PoV did not fail; bug not reproducible"
                    + (f" ({base_detail})" if base_detail else "")
                )
        return verdict

    # ------------------------------------------------------------------ #
    # Layer 2: apply + compile + regression + PoV via Vul4J evaluate.
    # ------------------------------------------------------------------ #
    compiles = False
    regression_pass = False
    pov_passed = False
    ev_detail = ""
    original_code = ""
    patched_code = patch.patched_code
    try:
        from harness.layers import vul4j_runner

        ev = vul4j_runner.evaluate_patch(bug, patch)
        compiles = bool(getattr(ev, "compiled", False))
        regression_pass = bool(getattr(ev, "regression_passed", False))
        pov_passed = bool(getattr(ev, "pov_passed", False))
        ev_detail = str(getattr(ev, "detail", "") or "")
        original_code = str(getattr(ev, "original_code", "") or "")
        # Prefer the runner's captured patched_code (post-apply) when available.
        patched_code = str(getattr(ev, "patched_code", "") or patch.patched_code)
    except ImportError as exc:
        ev_detail = (
            f"vul4j_runner unavailable: {exc}. Install Vul4J (Docker image "
            "tuhhsoftsec/vul4j)."
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft
        ev_detail = f"evaluate_patch raised {type(exc).__name__}: {exc}"

    # pov_flipped requires a confirmed fail-before AND pass-after (red -> green).
    pov_flipped = bool(base_failed) and bool(pov_passed)

    layers.append(LayerResult("compile", compiles, ev_detail or "compile result"))
    layers.append(
        LayerResult(
            "regression",
            regression_pass,
            ev_detail or "regression (non-PoV) suite result",
        )
    )
    layers.append(
        LayerResult(
            "pov_flip",
            pov_flipped,
            (
                f"baseline_failed={base_failed}; pov_passed={pov_passed}"
                + (f"; {ev_detail}" if ev_detail else "")
            ),
        )
    )

    # ------------------------------------------------------------------ #
    # Layer 3: dual-SAST AND-gate (Semgrep AND CodeQL), scoped to bug.cwe.
    # ------------------------------------------------------------------ #
    semgrep_clean = False
    codeql_clean = False
    sast_detail = ""
    patched_file_abs = _write_patched_file(
        bug.checkout_dir, patch.patched_file_path, patched_code
    )
    try:
        from harness.layers import sast

        sast_out = sast.sast_and_gate(
            file_path=patched_file_abs,
            checkout_dir=bug.checkout_dir,
            source_root=bug.checkout_dir,
            cwe=bug.cwe,
            semgrep_config=cfg.semgrep_config,
            codeql_suite=cfg.codeql_suite,
            cwe_focus_path=cfg.cwe_focus_path,
        )
        semgrep_clean = bool(getattr(sast_out, "semgrep_clean", False))
        codeql_clean = bool(getattr(sast_out, "codeql_clean", False))
        sast_detail = str(getattr(sast_out, "detail", "") or "")
    except ImportError as exc:
        sast_detail = (
            f"sast layer unavailable: {exc}. Install Semgrep "
            "(scripts/setup_semgrep.sh) and CodeQL (scripts/setup_codeql.sh)."
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft
        sast_detail = f"sast_and_gate raised {type(exc).__name__}: {exc}"

    layers.append(
        LayerResult(
            "sast",
            semgrep_clean and codeql_clean,
            (
                f"semgrep_clean={semgrep_clean}; codeql_clean={codeql_clean}"
                + (f"; {sast_detail}" if sast_detail else "")
            ),
        )
    )

    # ------------------------------------------------------------------ #
    # Layer 4: AST non-deletion guard (defeats delete-the-sink gaming).
    # ------------------------------------------------------------------ #
    not_deleted = False
    ast_detail = ""
    try:
        from harness.layers import ast_guard

        nd = ast_guard.non_deletion_ok(
            original_code,
            patched_code,
            min_retained_ratio=cfg.min_retained_ratio,
        )
        not_deleted = bool(getattr(nd, "ok", False))
        ratio = getattr(nd, "retained_ratio", None)
        returns_kept = getattr(nd, "returns_kept", None)
        nd_detail = str(getattr(nd, "detail", "") or "")
        ast_detail = (
            f"retained_ratio={ratio}; returns_kept={returns_kept}"
            + (f"; {nd_detail}" if nd_detail else "")
        )
    except ImportError as exc:
        ast_detail = (
            f"ast_guard unavailable: {exc}. Install javalang "
            "(`pip install javalang==0.13.0`)."
        )
    except Exception as exc:  # noqa: BLE001 - fail-soft
        ast_detail = f"non_deletion_ok raised {type(exc).__name__}: {exc}"

    layers.append(LayerResult("ast_non_deletion", not_deleted, ast_detail))

    # ------------------------------------------------------------------ #
    # Assemble the canonical verdict (layers already in canonical order).
    # ------------------------------------------------------------------ #
    return GateVerdict(
        bug_id=bug.id,
        compiles=compiles,
        regression_pass=regression_pass,
        pov_flipped=pov_flipped,
        semgrep_clean=semgrep_clean,
        codeql_clean=codeql_clean,
        not_deleted=not_deleted,
        layers=layers,
    )


# --------------------------------------------------------------------------- #
# JSON (de)serialization for the CLI
# --------------------------------------------------------------------------- #
def _load_json(path: str) -> Dict[str, Any]:
    """Read a JSON file into a dict, with a clear error on failure."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object, got {type(data).__name__}")
    return data


def _bug_from_dict(d: Dict[str, Any]) -> BugRecord:
    """Construct a BugRecord from a plain dict (CLI input), tolerating absences."""
    return BugRecord(
        id=str(d["id"]),
        project=str(d.get("project", "")),
        cwe=str(d.get("cwe", "")),
        source=d.get("source", "vul4j"),  # type: ignore[arg-type]
        checkout_dir=str(d.get("checkout_dir", "")),
        pov_tests=list(d.get("pov_tests", []) or []),
        vulnerable_file=str(d.get("vulnerable_file", "")),
    )


def _patch_from_dict(d: Dict[str, Any]) -> Patch:
    """Construct a Patch from a plain dict (CLI input)."""
    return Patch(
        bug_id=str(d["bug_id"]),
        patched_file_path=str(d.get("patched_file_path", "")),
        patched_code=str(d.get("patched_code", "")),
        model=str(d.get("model", "")),
        attempt=int(d.get("attempt", 0)),
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the gate CLI."""
    p = argparse.ArgumentParser(
        prog="python -m harness.gate",
        description=(
            "Run the DualGuard 5-layer verification gate on one (bug, patch) pair "
            "and emit the GateVerdict as JSON. Exit 0 iff the patch is cleared."
        ),
    )
    p.add_argument(
        "--bug-json",
        required=True,
        help="Path to a JSON file describing the BugRecord.",
    )
    p.add_argument(
        "--patch-json",
        required=True,
        help="Path to a JSON file describing the candidate Patch.",
    )
    p.add_argument(
        "--config",
        default="config/gate.yaml",
        help="Path to gate.yaml thresholds (default: config/gate.yaml).",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help="Optional path to write verdict.to_dict() JSON (also printed to stdout).",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns the process exit code.

    Exit codes:
        0 -> verdict.cleared is True
        1 -> verdict produced but not cleared
        3 -> infrastructure / argument / IO error (could not produce a verdict)
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        bug = _bug_from_dict(_load_json(args.bug_json))
        patch = _patch_from_dict(_load_json(args.patch_json))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"[gate] error: could not load inputs: {exc}\n")
        return 3

    cfg = GateConfig.from_yaml(args.config)

    try:
        verdict = run_gate(bug, patch, cfg)
    except Exception as exc:  # noqa: BLE001 - last-resort guard; gate is fail-soft
        sys.stderr.write(
            f"[gate] fatal: run_gate raised {type(exc).__name__}: {exc}\n"
        )
        traceback.print_exc(file=sys.stderr)
        return 3

    payload = verdict.to_dict()
    text = json.dumps(payload, indent=2, sort_keys=True)
    print(text)

    if args.output:
        try:
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            sys.stderr.write(f"[gate] warning: could not write {args.output}: {exc}\n")

    return 0 if verdict.cleared else 1


if __name__ == "__main__":
    raise SystemExit(main())
