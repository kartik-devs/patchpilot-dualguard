"""Fair few-shot+retry baseline driver (MG5): ``python -m eval.baselines``.

Runs the EXACT same flow as :mod:`eval.run_eval` — identical bug set, identical
retries, identical 5-layer gate (``GateVerdict.cleared`` is the only oracle) —
but tags the run ``baseline`` and points the fixer at a non-fine-tuned model /
few-shot prompt. The only thing that differs from the fine-tuned run is the
prompt/weights, so the two ``results/eval_*.json`` files are directly comparable.

Fairness rule (spec): same bugs, same retries, same gate; only prompt/weights
vary. We therefore delegate straight to ``eval.run_eval.run`` rather than forking
the loop.

CLI::

    python -m eval.baselines --eval-set data/eval/manifest.jsonl \\
        --fixer-url http://localhost:8000/v1 --fixer-model baseline \\
        [--judge-url http://localhost:8001/v1 --judge-model judge] \\
        [--n-retries 1] -o results/eval_baseline.json
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Dict, List, Optional

from eval.run_eval import run


def run_fewshot_baseline(
    manifest: str,
    fixer_url: str,
    fixer_model: str = "baseline",
    judge_url: Optional[str] = None,
    judge_model: str = "judge",
    n_retries: int = 1,
    best_of_n: int = 1,
    checkout_root: str = "data/checkouts",
    temperature: float = 0.2,
    out_path: str = "results/eval_baseline.json",
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute the baseline run with ``model_tag='baseline'`` over the identical set."""
    return run(
        manifest=manifest,
        model_tag="baseline",
        fixer_url=fixer_url,
        fixer_model=fixer_model,
        judge_url=judge_url,
        judge_model=judge_model,
        n_retries=n_retries,
        best_of_n=best_of_n,
        checkout_root=checkout_root,
        temperature=temperature,
        out_path=out_path,
        limit=limit,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the baseline CLI."""
    p = argparse.ArgumentParser(
        prog="eval.baselines",
        description=(
            "Fair few-shot+retry baseline: same bugs/retries/gate as the fine-tuned "
            "run, only the prompt/weights differ. Produces a comparable results file."
        ),
    )
    p.add_argument("--eval-set", required=True, help="Path to manifest.jsonl.")
    p.add_argument("--fixer-url", required=True, help="vLLM fixer /v1 base URL.")
    p.add_argument("--fixer-model", default="baseline", help="Served baseline model name.")
    p.add_argument("--judge-url", default=None, help="Optional vLLM judge /v1 base URL.")
    p.add_argument("--judge-model", default="judge", help="Served judge model name.")
    p.add_argument("--n-retries", type=int, default=1, help="Max retries with gate feedback.")
    p.add_argument("--best-of-n", type=int, default=1, help="Candidates per attempt (needs a judge).")
    p.add_argument("--checkout-root", default="data/checkouts", help="Checkout root directory.")
    p.add_argument("--temperature", type=float, default=0.2, help="Fixer sampling temperature.")
    p.add_argument("--limit", type=int, default=None, help="Evaluate only the first N bugs.")
    p.add_argument("-o", "--out", default="results/eval_baseline.json", help="Results JSON output path.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Exits 0 on a completed run, nonzero only on infra error."""
    args = build_arg_parser().parse_args(argv)
    try:
        run_fewshot_baseline(
            manifest=args.eval_set,
            fixer_url=args.fixer_url,
            fixer_model=args.fixer_model,
            judge_url=args.judge_url,
            judge_model=args.judge_model,
            n_retries=args.n_retries,
            best_of_n=args.best_of_n,
            checkout_root=args.checkout_root,
            temperature=args.temperature,
            out_path=args.out,
            limit=args.limit,
        )
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
