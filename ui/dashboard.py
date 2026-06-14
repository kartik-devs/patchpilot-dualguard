"""Streamlit dashboard for DualGuard eval results (MG5).

Four panels, fed by a ``results/eval_<tag>.json`` produced by :mod:`eval.run_eval`:
  1. Bug selector + side-by-side diff (original vs patched_code).
  2. A 4-part badge from one ``GateVerdict.to_dict()``: compiles, regression_pass,
     pov_flipped, and (semgrep_clean AND codeql_clean).
  3. Live ``rocm-smi`` occupancy via ``scripts/rocm_smi_watch.sh`` (subprocess).
  4. The strata ``RateStat`` table (rate +/- Wilson CI by source / coverage).

Run::

    streamlit run ui/dashboard.py -- --results results/eval_finetuned.json

The success oracle shown is ``GateVerdict.cleared`` — identical to the gate/eval.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse the args passed after ``--`` to ``streamlit run``."""
    p = argparse.ArgumentParser(prog="ui/dashboard.py")
    p.add_argument(
        "--results",
        default="results/eval_finetuned.json",
        help="Path to an eval results JSON from eval.run_eval.",
    )
    # Streamlit may inject its own args; ignore unknowns.
    args, _unknown = p.parse_known_args(argv if argv is not None else sys.argv[1:])
    return args


def load_results(path: str) -> Dict[str, Any]:
    """Load the results document, returning {} (with a UI warning) if missing."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def rocm_smi_snapshot(repo_root: str) -> str:
    """Capture one rocm-smi snapshot via scripts/rocm_smi_watch.sh --once (best-effort)."""
    script = os.path.join(repo_root, "scripts", "rocm_smi_watch.sh")
    if not os.path.isfile(script):
        return "scripts/rocm_smi_watch.sh not found."
    try:
        proc = subprocess.run(
            ["bash", script, "--once"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return (proc.stdout or proc.stderr or "").strip() or "(no rocm-smi output)"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"rocm-smi unavailable: {exc}"


def _unified_diff(original: str, patched: str) -> str:
    """Return a unified diff string between original and patched sources."""
    diff = difflib.unified_diff(
        (original or "").splitlines(keepends=True),
        (patched or "").splitlines(keepends=True),
        fromfile="original",
        tofile="patched",
    )
    return "".join(diff) or "(identical)"


def _render(st: Any, args: argparse.Namespace) -> None:
    """Render the dashboard given an imported ``streamlit`` module."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    st.set_page_config(page_title="PatchPilot DualGuard", layout="wide")
    st.title("PatchPilot v2 — DualGuard")

    doc = load_results(args.results)
    if not doc:
        st.warning(
            f"No results loaded from {args.results!r}. Run `make eval` first, or pass "
            "--results <path>."
        )
        return

    st.caption(f"results: {args.results}  ·  model_tag: {doc.get('model_tag', '?')}")

    # --- Panel 4 (top): strata rate table ---------------------------------- #
    st.subheader("FP&VC-Rate by stratum (Wilson 95% CI)")
    strata = doc.get("strata", {})
    if strata:
        rows = [
            {
                "stratum": name,
                "rate": round(stat.get("rate", 0.0), 3),
                "ci_low": round(stat.get("ci_low", 0.0), 3),
                "ci_high": round(stat.get("ci_high", 0.0), 3),
                "cleared": stat.get("cleared", 0),
                "n": stat.get("n", 0),
            }
            for name, stat in strata.items()
        ]
        st.table(rows)
    else:
        st.info("No strata in this results file.")

    # --- Panel 1: bug selector + diff -------------------------------------- #
    per_bug = doc.get("per_bug", [])
    if not per_bug:
        st.info("No per-bug rows in this results file.")
        return
    ids = [row.get("bug", {}).get("id", f"row-{i}") for i, row in enumerate(per_bug)]
    choice = st.selectbox("Bug", ids)
    row = per_bug[ids.index(choice)]
    bug = row.get("bug", {})
    verdict = row.get("verdict", {})

    # --- Panel 2: 4-part badge --------------------------------------------- #
    st.subheader(f"Verdict for {choice}  (cleared={verdict.get('cleared', False)})")
    badges = [
        ("compiles", verdict.get("compiles", False)),
        ("regression_pass", verdict.get("regression_pass", False)),
        ("pov_flipped", verdict.get("pov_flipped", False)),
        (
            "sast_clean",
            bool(verdict.get("semgrep_clean", False))
            and bool(verdict.get("codeql_clean", False)),
        ),
    ]
    cols = st.columns(len(badges))
    for col, (label, ok) in zip(cols, badges):
        col.metric(label, "PASS" if ok else "FAIL")

    st.subheader("Diff (original -> patched)")
    original = row.get("original_code", bug.get("original_code", ""))
    patched = row.get("patched_code", "")
    st.code(_unified_diff(original, patched), language="diff")

    # --- Panel 3: rocm-smi co-residency ------------------------------------ #
    st.subheader("GPU co-residency (rocm-smi)")
    if st.button("Refresh rocm-smi"):
        st.text(rocm_smi_snapshot(repo_root))
    else:
        st.caption("Click to capture a one-shot rocm-smi VRAM/util snapshot.")


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Imports streamlit lazily so the module stays importable on CPU hosts."""
    args = parse_args(argv)
    try:
        import streamlit as st  # type: ignore
    except ImportError:
        sys.stderr.write(
            "streamlit is not installed. Install the harness extras "
            "(pip install -r requirements-harness.txt) and run with:\n"
            "  streamlit run ui/dashboard.py -- --results results/eval_finetuned.json\n"
        )
        return 2
    _render(st, args)
    return 0


# Streamlit executes the script top-to-bottom (not via __main__), so render on import
# when running under `streamlit run`. Guard so plain `python ui/dashboard.py` also works.
if __name__ == "__main__":
    raise SystemExit(main())
else:  # pragma: no cover - executed under `streamlit run`
    try:
        import streamlit as _st  # type: ignore

        _render(_st, parse_args())
    except Exception:
        # Not running under streamlit (e.g. plain import for tests) — do nothing.
        pass
