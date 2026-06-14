"""MG5 · Eval orchestrator: generate -> gate -> aggregate over the eval set.

For each bug in the manifest:
  1. checkout the vulnerable revision (Vul4J),
  2. generate a full-file patch with the fixer (best-of-n; judge ranks if given),
  3. run the 5-layer DualGuard gate (``harness.gate.run_gate``),
  4. on failure, retry up to ``n_retries`` with the gate-failure detail fed back,
  5. record an :class:`eval.metrics.EvalRow`.

Then aggregate the Functionality-Preserved & Vuln-Cleared Rate with strata and
write a results JSON. ``GateVerdict.cleared`` is the ONLY success oracle; the
judge model only ranks candidates, it never decides success.

The public ``run(...)`` function is also called by :mod:`eval.baselines` so the
baseline and fine-tuned runs share one identical loop (only prompt/weights differ).

Heavy deps (requests via serve.dualguard, Vul4J) are imported lazily inside
``run`` so importing this module stays cheap.

CLI (see the Makefile ``eval`` target)::

    python -m eval.run_eval --eval-set data/eval/manifest.jsonl --model-tag finetuned \\
        --fixer-url http://localhost:8000/v1 --fixer-model fixer \\
        [--judge-url http://localhost:8001/v1 --judge-model judge] \\
        [--n-retries 1] [--config config/eval.yaml] -o results/eval_finetuned.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from eval.metrics import (
    STRATUM_OVERALL,
    EvalRow,
    compare_tags,
    fp_vc_rate,
    stratified_rates,
)
from harness.verdict import BugRecord, Patch


# --------------------------------------------------------------------------- #
# Manifest loading
# --------------------------------------------------------------------------- #
def load_manifest(path: str) -> List[Dict[str, Any]]:
    """Load a JSONL eval manifest into a list of entry dicts."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"eval manifest not found: {path}")
    entries: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def _bug_from_entry(entry: Dict[str, Any], checkout_dir: str) -> BugRecord:
    """Inflate a manifest entry + checkout path into a BugRecord."""
    return BugRecord(
        id=str(entry["id"]),
        project=str(entry.get("project", "")),
        cwe=str(entry.get("cwe", "")),
        source=entry.get("source", "vul4j"),  # type: ignore[arg-type]
        checkout_dir=checkout_dir,
        pov_tests=list(entry.get("pov_tests", []) or []),
        vulnerable_file=str(entry.get("vulnerable_file", "")),
    )


# --------------------------------------------------------------------------- #
# The shared run loop
# --------------------------------------------------------------------------- #
def run(
    manifest: str,
    model_tag: str,
    fixer_url: str,
    fixer_model: str,
    judge_url: Optional[str] = None,
    judge_model: str = "judge",
    n_retries: int = 1,
    best_of_n: int = 1,
    checkout_root: str = "data/checkouts",
    temperature: float = 0.2,
    out_path: str = "results/eval_finetuned.json",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the full eval and write ``out_path``; returns the results dict.

    Args mirror the Makefile/baseline call convention exactly so eval.baselines can
    delegate here unchanged.
    """
    # Lazy imports: keep module import cheap and avoid requiring vLLM/requests/Vul4J
    # just to import this module (eval.baselines imports `run` at module load).
    from harness import gate as gate_mod
    from harness.layers import vul4j_runner

    entries = load_manifest(manifest)
    if limit is not None:
        entries = entries[: max(0, int(limit))]

    cfg = gate_mod.GateConfig.from_yaml("config/gate.yaml")
    os.makedirs(checkout_root, exist_ok=True)

    rows: List[EvalRow] = []
    errors: List[Dict[str, str]] = []

    for entry in entries:
        bug_id = str(entry.get("id", "<unknown>"))
        dest = os.path.join(checkout_root, bug_id)
        # 1. Checkout (idempotent-ish; if it fails we record an error row).
        try:
            if not os.path.isdir(dest) or not os.listdir(dest):
                vul4j_runner.checkout(bug_id, dest)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            errors.append({"bug_id": bug_id, "stage": "checkout", "error": str(exc)})
            continue

        bug = _bug_from_entry(entry, dest)

        # 2-4. Generate -> gate -> retry-with-feedback.
        verdict = _generate_and_gate(
            bug=bug,
            gate_mod=gate_mod,
            cfg=cfg,
            fixer_url=fixer_url,
            fixer_model=fixer_model,
            judge_url=judge_url,
            judge_model=judge_model,
            n_retries=n_retries,
            best_of_n=best_of_n,
            temperature=temperature,
        )
        rows.append(
            EvalRow(bug=bug, verdict=verdict, tag=model_tag, cleared=verdict.cleared)
        )
        print(
            f"[eval] {bug_id:<14} cleared={verdict.cleared} "
            f"(compile={verdict.compiles} reg={verdict.regression_pass} "
            f"pov={verdict.pov_flipped} sast={verdict.semgrep_clean and verdict.codeql_clean} "
            f"not_deleted={verdict.not_deleted})"
        )

    results = _assemble_results(manifest, model_tag, rows, errors)
    _write_results(out_path, results)
    _print_summary(results)
    return results


def _generate_and_gate(
    bug: BugRecord,
    gate_mod: Any,
    cfg: Any,
    fixer_url: str,
    fixer_model: str,
    judge_url: Optional[str],
    judge_model: str,
    n_retries: int,
    best_of_n: int,
    temperature: float,
):
    """Generate (best-of-n, judge-ranked) and gate with retry-on-failure feedback."""
    from eval import fixer_client

    feedback: Optional[str] = None
    last_verdict = None
    for attempt in range(max(1, n_retries + 1)):
        candidates: List[Patch] = []
        for k in range(max(1, best_of_n)):
            try:
                patch = fixer_client.generate_patch(
                    bug=bug,
                    attempt=attempt,
                    base_url=fixer_url,
                    model=fixer_model,
                    feedback=feedback,
                    temperature=temperature,
                )
                candidates.append(patch)
            except Exception as exc:  # noqa: BLE001 - fixer/transport failure
                # Record a synthetic empty patch so the gate yields a clean False.
                candidates.append(
                    Patch(
                        bug_id=bug.id,
                        patched_file_path=bug.vulnerable_file,
                        patched_code="",
                        model=f"{fixer_model}(error:{type(exc).__name__})",
                        attempt=attempt,
                    )
                )

        chosen = _choose_candidate(bug, candidates, judge_url, judge_model)
        verdict = gate_mod.run_gate(bug, chosen, cfg)
        last_verdict = verdict
        if verdict.cleared:
            return verdict
        # Build feedback from failing layers for the next attempt.
        feedback = _feedback_from_verdict(verdict)
    return last_verdict


def _choose_candidate(
    bug: BugRecord, candidates: List[Patch], judge_url: Optional[str], judge_model: str
) -> Patch:
    """Pick a candidate: judge-ranked if a judge URL is set, else the first."""
    candidates = [c for c in candidates if c is not None]
    if not candidates:
        return Patch(bug.id, bug.vulnerable_file, "", "no-candidate", 0)
    if len(candidates) == 1 or not judge_url:
        return candidates[0]
    try:
        from eval import judge_client

        return judge_client.rank(bug, candidates, base_url=judge_url, model=judge_model)
    except Exception:  # noqa: BLE001 - judge optional; fall back to first
        return candidates[0]


def _feedback_from_verdict(verdict) -> str:
    """Compose a short feedback string from the failing gate layers."""
    fails = []
    for lr in getattr(verdict, "layers", []) or []:
        if not lr.passed:
            fails.append(f"- {lr.name}: {lr.detail}")
    if not fails:
        return "The previous patch did not pass the verification gate."
    return (
        "Your previous patch failed these checks; fix them while preserving "
        "behavior:\n" + "\n".join(fails)
    )


# --------------------------------------------------------------------------- #
# Results assembly / IO
# --------------------------------------------------------------------------- #
def _assemble_results(
    manifest: str,
    model_tag: str,
    rows: List[EvalRow],
    errors: List[Dict[str, str]],
) -> Dict[str, Any]:
    overall = fp_vc_rate([r.verdict for r in rows])
    strata = stratified_rates(rows)
    return {
        "model_tag": model_tag,
        "manifest": manifest,
        "n": len(rows),
        "errors": errors,
        "overall": overall.to_dict(),
        "strata": {k: v.to_dict() for k, v in strata.items()},
        "compare": compare_tags(rows),
        "rows": [r.to_dict() for r in rows],
    }


def _write_results(out_path: str, results: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    print(f"[eval] wrote {out_path}")


def _print_summary(results: Dict[str, Any]) -> None:
    o = results["overall"]
    print(
        f"\n[eval] {results['model_tag']}: "
        f"Functionality-Preserved & Vuln-Cleared = "
        f"{o['cleared']}/{o['n']} = {o['rate']*100:.1f}% "
        f"[95% CI {o['ci_low']*100:.1f}%, {o['ci_high']*100:.1f}%]"
    )
    if results["errors"]:
        print(f"[eval] {len(results['errors'])} bug(s) errored (see results.errors).")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _load_eval_yaml(path: Optional[str]) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {}
    try:
        import yaml  # type: ignore

        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:  # noqa: BLE001 - config is best-effort
        return {}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m eval.run_eval",
        description=(
            "Generate + gate patches over the eval set and write stratified "
            "Functionality-Preserved & Vuln-Cleared results."
        ),
    )
    p.add_argument("--eval-set", required=True, help="Path to manifest.jsonl.")
    p.add_argument("--model-tag", default="finetuned", help="Run tag (finetuned/baseline).")
    p.add_argument("--fixer-url", required=True, help="vLLM fixer /v1 base URL.")
    p.add_argument("--fixer-model", required=True, help="Served fixer model name.")
    p.add_argument("--judge-url", default=None, help="Optional vLLM judge /v1 base URL.")
    p.add_argument("--judge-model", default="judge", help="Served judge model name.")
    p.add_argument("--n-retries", type=int, default=1, help="Retries with gate feedback.")
    p.add_argument("--best-of-n", type=int, default=1, help="Candidates per attempt.")
    p.add_argument("--checkout-root", default="data/checkouts", help="Checkout root dir.")
    p.add_argument("--temperature", type=float, default=0.2, help="Fixer temperature.")
    p.add_argument("--limit", type=int, default=None, help="Evaluate only the first N bugs.")
    p.add_argument("--config", default="config/eval.yaml", help="eval.yaml defaults.")
    p.add_argument("-o", "--output", default=None, help="Results JSON path.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    ydef = _load_eval_yaml(args.config)

    out_path = args.output or f"results/eval_{args.model_tag}.json"
    try:
        run(
            manifest=args.eval_set,
            model_tag=args.model_tag,
            fixer_url=args.fixer_url or ydef.get("fixer_url", ""),
            fixer_model=args.fixer_model or ydef.get("fixer_model", "fixer"),
            judge_url=args.judge_url or ydef.get("judge_url"),
            judge_model=args.judge_model or ydef.get("judge_model", "judge"),
            n_retries=args.n_retries,
            best_of_n=args.best_of_n if args.best_of_n else int(ydef.get("best_of_n", 1)),
            checkout_root=ydef.get("checkout_root", args.checkout_root),
            temperature=args.temperature,
            out_path=out_path,
            limit=args.limit,
        )
    except FileNotFoundError as exc:
        sys.stderr.write(f"[eval] error: {exc}\n")
        return 2
    except ValueError as exc:
        sys.stderr.write(f"[eval] error: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["run", "load_manifest", "build_arg_parser", "main"]
