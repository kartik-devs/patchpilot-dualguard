"""Streamlit dashboard — PatchPilot's unified verified-remediation demo surface.

Renders the SAME badge layout for two domains, proving "one proof engine, many
domains" on screen:

  * Security (from ``results/eval_<tag>.json``, written by :mod:`eval.run_eval`):
    strata FP&VC table + per-bug GateVerdict badges (compiles / regression /
    pov_flipped / sast_clean / not_deleted) and the per-layer detail.
  * Accessibility (from an A11yVerdict JSON written by
    ``python -m harness.webgate -o results/webgate_positive.json``): the RED→GREEN
    axe-core flip + the DOM non-deletion guard.
  * Live ``rocm-smi`` co-residency snapshot (the AMD >80 GB proof).

The success oracle shown is ``cleared`` — identical to the gate/eval logic.

Run::

    streamlit run ui/dashboard.py -- --results results/eval_finetuned.json \
        --webgate results/webgate_positive.json
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
    p.add_argument("--results", default="results/eval_finetuned.json",
                   help="Security eval results JSON from eval.run_eval.")
    p.add_argument("--webgate", default="results/webgate_positive.json",
                   help="A11y verdict JSON from `python -m harness.webgate -o ...`.")
    args, _unknown = p.parse_known_args(argv if argv is not None else sys.argv[1:])
    return args


def load_json(path: str) -> Dict[str, Any]:
    """Load a JSON doc, returning {} if missing/unreadable."""
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
        proc = subprocess.run(["bash", script, "--once"], capture_output=True,
                              text=True, timeout=15)
        return (proc.stdout or proc.stderr or "").strip() or "(no rocm-smi output)"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"rocm-smi unavailable: {exc}"


def _unified_diff(original: str, patched: str) -> str:
    diff = difflib.unified_diff(
        (original or "").splitlines(keepends=True),
        (patched or "").splitlines(keepends=True),
        fromfile="original", tofile="patched",
    )
    return "".join(diff) or "(diff unavailable — code not stored in this results file)"


def _badges(st: Any, items: List[tuple]) -> None:
    """Render a row of PASS/FAIL metric badges from (label, bool) tuples."""
    cols = st.columns(len(items))
    for col, (label, ok) in zip(cols, items):
        col.metric(label, "✅ PASS" if ok else "❌ FAIL")


# --------------------------------------------------------------------------- #
# Security panel (GateVerdict)
# --------------------------------------------------------------------------- #
def _render_security(st: Any, doc: Dict[str, Any]) -> None:
    st.header("🔒 Security — Java vulnerability repair")
    st.caption(f"model_tag: {doc.get('model_tag', '?')}  ·  n={doc.get('n', 0)}")

    overall = doc.get("overall", {})
    if overall:
        st.metric(
            "Functionality-Preserved & Vuln-Cleared Rate",
            f"{overall.get('rate', 0.0)*100:.1f}%",
            f"{overall.get('cleared', 0)}/{overall.get('n', 0)} cleared · "
            f"95% CI [{overall.get('ci_low', 0)*100:.1f}%, {overall.get('ci_high', 0)*100:.1f}%]",
        )

    strata = doc.get("strata", {})
    if strata:
        st.subheader("FP&VC-Rate by stratum (Wilson 95% CI)")
        st.table([
            {"stratum": name, "rate": round(s.get("rate", 0.0), 3),
             "ci_low": round(s.get("ci_low", 0.0), 3), "ci_high": round(s.get("ci_high", 0.0), 3),
             "cleared": s.get("cleared", 0), "n": s.get("n", 0)}
            for name, s in strata.items()
        ])

    # NOTE: run_eval writes "rows" (each {bug, verdict, tag, cleared}); no per_bug.
    rows = doc.get("rows", [])
    if not rows:
        st.info("No per-bug rows in this results file. Run `make eval` to populate.")
        return
    ids = [r.get("bug", {}).get("id", f"row-{i}") for i, r in enumerate(rows)]
    choice = st.selectbox("Bug", ids, key="sec_bug")
    row = rows[ids.index(choice)]
    verdict = row.get("verdict", {})

    st.subheader(f"GateVerdict for {choice}  ·  cleared={verdict.get('cleared', False)}")
    _badges(st, [
        ("compiles", verdict.get("compiles", False)),
        ("regression", verdict.get("regression_pass", False)),
        ("pov fail→pass", verdict.get("pov_flipped", False)),
        ("Semgrep+CodeQL", bool(verdict.get("semgrep_clean")) and bool(verdict.get("codeql_clean"))),
        ("not deleted", verdict.get("not_deleted", False)),
    ])

    layers = verdict.get("layers", [])
    if layers:
        st.caption("Per-layer detail (the executable proof)")
        st.table([{"layer": l.get("name"), "passed": l.get("passed"),
                   "detail": (l.get("detail", "") or "")[:140]} for l in layers])

    original = row.get("original_code", "")
    patched = row.get("patched_code", "")
    if original or patched:
        st.subheader("Diff (original → patched)")
        st.code(_unified_diff(original, patched), language="diff")


# --------------------------------------------------------------------------- #
# Accessibility panel (A11yVerdict)
# --------------------------------------------------------------------------- #
def _render_a11y(st: Any, doc: Dict[str, Any]) -> None:
    st.header("♿ Accessibility — same engine, axe-core oracle")
    st.caption(f"page: {doc.get('page_id', '?')}  ·  violations after fix: {doc.get('violations_after', '?')}")

    st.subheader(f"A11yVerdict  ·  cleared={doc.get('cleared', False)}")
    _badges(st, [
        ("had violations", doc.get("had_baseline_violations", False)),
        ("axe RED→GREEN", doc.get("a11y_flipped", False)),
        ("not deleted (DOM)", doc.get("not_deleted", False)),
    ])

    base = doc.get("baseline_by_rule", {}) or {}
    after = doc.get("after_by_rule", {}) or {}
    rules = sorted(set(base) | set(after))
    if rules:
        st.caption("axe-core violations: before (RED) → after (GREEN)")
        st.table([{"rule": r, "before": base.get(r, 0), "after": after.get(r, 0)} for r in rules])

    layers = doc.get("layers", [])
    if layers:
        st.table([{"layer": l.get("name"), "passed": l.get("passed"),
                   "detail": (l.get("detail", "") or "")[:140]} for l in layers])


# --------------------------------------------------------------------------- #
def _render(st: Any, args: argparse.Namespace) -> None:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    st.set_page_config(page_title="PatchPilot — Verified Remediation", layout="wide")
    st.title("PatchPilot v2 — Verified Remediation")
    st.caption("One proof engine, multiple domains. The success oracle is `cleared` — proven by running the artifact.")

    sec = load_json(args.results)
    a11y = load_json(args.webgate)

    if not sec and not a11y:
        st.warning(
            f"No results loaded. Provide --results {args.results!r} (run `make eval`) and/or "
            f"--webgate {args.webgate!r} (run `python -m harness.webgate -o ...`)."
        )

    if sec:
        _render_security(st, sec)
        st.divider()
    if a11y:
        _render_a11y(st, a11y)
        st.divider()

    st.header("⚡ GPU co-residency (rocm-smi) — the >80 GB AMD proof")
    if st.button("Capture rocm-smi snapshot"):
        st.text(rocm_smi_snapshot(repo_root))
    else:
        st.caption("Click to capture VRAM/util — expect >80 GB with the co-resident fixer+judge.")


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        import streamlit as st  # type: ignore
    except ImportError:
        sys.stderr.write(
            "streamlit is not installed. pip install -r requirements-harness.txt, then:\n"
            "  streamlit run ui/dashboard.py -- --results results/eval_finetuned.json "
            "--webgate results/webgate_positive.json\n"
        )
        return 2
    _render(st, args)
    return 0


# Streamlit executes top-to-bottom (not via __main__); render on import under `streamlit run`.
if __name__ == "__main__":
    raise SystemExit(main())
else:  # pragma: no cover - executed under `streamlit run`
    try:
        import streamlit as _st  # type: ignore

        _render(_st, parse_args())
    except Exception:
        pass
