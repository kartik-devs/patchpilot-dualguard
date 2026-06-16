"""Quick "does it actually fix real code?" eval — Semgrep oracle, no Vul4J needed.

For each held-out vulnerable Java sample (eval/samples/, written by
eval.build_samples): the served fixer patches it, then we prove the result on REAL
code with two objective checks:

  * RED -> GREEN: Semgrep flags the original (RED) and is clean on the patch (GREEN).
  * not-deleted: the AST non-deletion guard rejects "fixes" that just delete the code.

cleared = RED(before) AND GREEN(after) AND not_deleted. The rate over the held-out
set (with a Wilson CI) is a real, defensible "it fixes real vulnerabilities" number
you can run in ~minutes. (The full Vul4J FP&VC rate adds compile + exploit tests on
top; this is the fast first proof.)

CLI::

    python -m eval.quick_eval --fixer-url http://localhost:8000/v1 \
        --fixer-model fixer --model-tag base   -o results/quick_base.json
    # then, against the fine-tuned adapter served as fixer-ft:
    python -m eval.quick_eval --fixer-url http://localhost:8000/v1 \
        --fixer-model fixer-ft --model-tag finetuned -o results/quick_finetuned.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional

from eval.metrics import wilson_ci
from harness.layers.ast_guard import non_deletion_ok

_FIX_SYSTEM = (
    "You are a secure-code remediation assistant. Given a Java file with a {cwe} "
    "vulnerability, return the COMPLETE corrected file. Fix ONLY the vulnerability, "
    "preserve all other behavior, and do NOT delete the functionality. Output only "
    "the fixed Java in a single ```java code block."
)


def _extract_java(text: str) -> str:
    m = re.search(r"```(?:java)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    return m.group(1).strip() if m else text.strip()


def fix(cwe: str, code: str, base_url: str, model: str, temperature: float = 0.0,
        timeout: int = 180) -> str:
    """Call the served (OpenAI-compatible) fixer and return the patched Java."""
    import requests  # lazy

    resp = requests.post(
        f"{base_url.rstrip('/')}/chat/completions",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": _FIX_SYSTEM.format(cwe=cwe)},
                {"role": "user", "content": f"```java\n{code}\n```"},
            ],
            "temperature": temperature,
            "max_tokens": 1024,
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    return _extract_java(resp.json()["choices"][0]["message"]["content"])


def semgrep_findings(path: str, config: str = "p/java", timeout: int = 180) -> int:
    """Return the number of Semgrep findings on a file (-1 on error)."""
    try:
        proc = subprocess.run(
            ["semgrep", "--config", config, "--json", "--quiet", "--no-git-ignore", path],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("semgrep not installed. pip install semgrep==1.86.0")
    except subprocess.SubprocessError as exc:
        sys.stderr.write(f"[quick_eval] semgrep error on {path}: {exc}\n")
        return -1
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError:
        return -1
    return len(data.get("results", []) or [])


def evaluate_one(sample_dir: str, entry: Dict[str, str], base_url: str, model: str,
                 temperature: float) -> Dict[str, Any]:
    fname, cwe = entry["file"], entry.get("cwe", "")
    original = open(os.path.join(sample_dir, fname), encoding="utf-8").read()

    before = semgrep_findings(os.path.join(sample_dir, fname))
    red = before > 0  # the sample must actually be flagged, else the test is void

    try:
        patched = fix(cwe, original, base_url, model, temperature)
    except Exception as exc:  # noqa: BLE001 - transport/model failure
        return {"file": fname, "cwe": cwe, "red": red, "green": False,
                "not_deleted": False, "cleared": False, "before": before,
                "after": None, "error": f"fixer failed: {exc}"}

    fd, tmp = tempfile.mkstemp(prefix="qeval_", suffix=".java")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(patched)
        after = semgrep_findings(tmp)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    green = after == 0
    nd = non_deletion_ok(original, patched)
    not_deleted = bool(getattr(nd, "ok", False))
    cleared = red and green and not_deleted
    return {"file": fname, "cwe": cwe, "red": red, "green": green,
            "not_deleted": not_deleted, "cleared": cleared,
            "before": before, "after": after,
            "retained_ratio": round(float(getattr(nd, "retained_ratio", 0.0) or 0.0), 3)}


def run(samples_dir: str, base_url: str, model: str, model_tag: str,
        temperature: float, out_path: Optional[str]) -> Dict[str, Any]:
    manifest = json.load(open(os.path.join(samples_dir, "manifest.json"), encoding="utf-8"))
    rows = []
    for entry in manifest:
        r = evaluate_one(samples_dir, entry, base_url, model, temperature)
        rows.append(r)
        flag = "✅" if r["cleared"] else "❌"
        print(f"  {flag} {r['file']:<24} {r['cwe']:<9} "
              f"red={r['red']} green={r['green']} not_deleted={r['not_deleted']} "
              f"(semgrep {r['before']}->{r['after']})")

    n = len(rows)
    cleared = sum(1 for r in rows if r["cleared"])
    rate = cleared / n if n else 0.0
    lo, hi = wilson_ci(cleared, n)
    summary = {"model_tag": model_tag, "model": model, "n": n, "cleared": cleared,
               "rate": rate, "ci_low": lo, "ci_high": hi, "rows": rows}
    print(f"\n[quick_eval] {model_tag}: Vuln-Cleared (Semgrep + non-deletion) = "
          f"{cleared}/{n} = {rate*100:.1f}%  [95% CI {lo*100:.1f}%, {hi*100:.1f}%]")
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        json.dump(summary, open(out_path, "w", encoding="utf-8"), indent=2)
        print(f"[quick_eval] wrote {out_path}")
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m eval.quick_eval",
                                description="Quick Semgrep red->green eval on held-out vulnerable Java.")
    p.add_argument("--fixer-url", required=True, help="vLLM /v1 base URL.")
    p.add_argument("--fixer-model", default="fixer", help="Served model name.")
    p.add_argument("--model-tag", default="finetuned", help="Label for the run (base/finetuned).")
    p.add_argument("--samples-dir", default=None, help="Dir of vulnerable Java + manifest.json.")
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("-o", "--output", default=None, help="Results JSON path.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    samples_dir = args.samples_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
    if not os.path.isfile(os.path.join(samples_dir, "manifest.json")):
        sys.stderr.write(f"[quick_eval] no manifest in {samples_dir}; run `python -m eval.build_samples` first.\n")
        return 2
    run(samples_dir, args.fixer_url, args.fixer_model, args.model_tag, args.temperature, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
