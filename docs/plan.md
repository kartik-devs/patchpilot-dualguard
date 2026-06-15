# PatchPilot v2 "DualGuard" — Plan & Thesis

**Track:** Fine-tuning · **Hardware:** AMD Instinct MI300X (192 GB) · **Team:** team-2497
· **Deadline:** 2026-06-17 8:30 PM IST.

## Thesis
A fine-tuned Java vulnerability-repair LLM whose patches are proven **secure AND
behavior-preserved** — confirmed by executable exploit + regression tests and a
dual-SAST AND-gate — running a co-resident fixer+judge pipeline that genuinely
needs the MI300X's 192 GB on a single card.

## Why it scores (rubric: Technical 40 / Impact 20 / Innovation 15 / Demo 15 / Problem 10)
- **40% Technical** — correctness is proven by *executable tests*, not similarity or
  self-grading. A working, verifiable solution is the whole point.
- **15% Demo** — the red→green / fail→pass flip on identical input is instantly legible.
- **15% Innovation** — "ungameable executable gate" + judge-co-resident-on-one-card.
- **20% Impact** — on-prem sovereign remediation; maps to the TCS–AMD enterprise thesis.
- **10% Problem** — a 30-second stakes hook in TCS's own regulated-enterprise language.

## The DualGuard gate (a patch is "cleared" only if ALL pass)
1. **Compiles** (Vul4J).
2. **Regression suite passes** — behavior preserved.
3. **PoV exploit test flips fail → pass** — the vuln is genuinely closed.
4. **Semgrep AND CodeQL both clean** (version-pinned dual SAST).
5. **AST non-deletion guard** — rejects the "delete-the-sink" cheat.

Metric: **Functionality-Preserved & Vuln-Cleared Rate** on a leakage-free, temporal
split (Vul4J / VJBench), with Wilson 95% CI, split by source and Semgrep-coverage.
Report a sober honest number (35–50% is a win with this gate) vs a FAIR
few-shot+retry baseline.

## The AMD angle
Fixer (32B Qwen2.5-Coder) + a separate 32B **judge** co-resident in one vLLM process
(~128 GB before KV cache) on a single MI300X — impossible on an 80 GB card. Prove it
live with `rocm-smi`.

## Architecture (where things run)
- **CPU/JVM (laptop or pod):** the verification gate — Vul4J (compile/regression/PoV),
  Semgrep + CodeQL, the javalang AST guard. Runs today; 18/18 unit tests green.
- **MI300X (pod):** serve the fixer (+judge), LoRA fine-tune, generate patches,
  capture rocm-smi. Cache all generations so metrics recompute on CPU.

## Status & next steps
Harness works end-to-end offline (the gate accepts the human patch and rejects
delete-the-sink). Remaining critical path is on the MI300X — see
[`RUNBOOK.md`](RUNBOOK.md): serve → one bug red→green → rocm-smi → LoRA → eval → demo.

## Scope discipline
Protect the demo over breadth. Fallback ladder: 7B instead of 32B → pre-recorded
rocm-smi → drop DPO + retry loop. Never cut the fail→pass flip.
