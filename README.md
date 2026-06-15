# PatchPilot v2 "DualGuard"

**The AI that proves its own security fixes.** A fine-tuned Java vulnerability-repair
LLM whose every patch must pass an **executable, ungameable verification gate** before
it's accepted — compile + regression tests + the real exploit flipping fail→pass +
Semgrep **and** CodeQL clean + an AST non-deletion guard. Built for the **TCS × AMD AI
Hackathon** (Fine-tuning track) on a single **AMD Instinct MI300X**.

> Every other AI patch tool asks you to trust it. PatchPilot makes you watch the
> exploit die — and it runs the fixer *and its own judge* on one AMD card.

---

## Why it's different
Generic LLM patches are scored by *similarity to a gold fix* or by the model grading
itself — neither proves the vulnerability is closed or that behavior is preserved.
PatchPilot's success metric is **executable**: the **Functionality-Preserved &
Vuln-Cleared Rate**. See [`docs/plan.md`](docs/plan.md).

## The DualGuard gate (a patch is `cleared` only if ALL pass)
1. **Compiles** · 2. **Regression suite passes** (behavior preserved) ·
3. **PoV exploit flips fail→pass** (vuln closed) · 4. **Semgrep AND CodeQL clean** ·
5. **AST non-deletion guard** (no "delete-the-sink" cheat).

## Quickstart — the CPU harness (no GPU, runs today)
```bash
python -m pip install -e .
python -m pip install -r requirements-harness.txt
make test            # 18/18 unit tests: verdict truth table, Wilson CI, AST guard, SAST parsing
make smoke           # offline end-to-end: human patch -> cleared; delete-the-sink -> rejected
```
External tools the full gate uses (install where the gate runs):
- **Vul4J** — `pip install vul4j` (needs JDK 7/8/11/16) **or** `docker pull tuhhsoftsec/vul4j`
- **Semgrep** — `bash scripts/setup_semgrep.sh`
- **CodeQL** — `bash scripts/setup_codeql.sh`

## On the MI300X (cloud)
Full step-by-step in **[`docs/RUNBOOK.md`](docs/RUNBOOK.md)**. In short:
```bash
bash scripts/setup_cloud.sh                  # pip install -r requirements-cloud.txt + hf + git
bash serve/launch_vllm.sh single             # serve the fixer (7B to start)
make build-eval                              # assemble a small Vul4J/VJBench eval manifest
make eval MODEL_TAG=base                      # generate -> gate -> rate (find the demo bug)
make train                                   # LoRA SFT the fixer
make eval MODEL_TAG=finetuned FIXER_MODEL=fixer-ft   # the money number
bash serve/launch_vllm.sh dual               # fixer + judge co-resident -> rocm-smi proof
make ui RESULTS=results/eval_finetuned.json   # the demo dashboard
```

## Repo layout
```
harness/        verdict contracts + gate orchestrator
harness/layers/ vul4j_runner · sast (Semgrep+CodeQL) · ast_guard (javalang)  [canonical]
harness/*.py    flat back-compat shims re-exporting harness.layers.*
eval/           run_eval (generate->gate->aggregate) · metrics (FP&VC rate, Wilson CI)
                · fixer_client · judge_client · baselines
data/prep/      prepare_sft (dedup + leakage-free temporal split) · build_eval_set
train/          finetune_lora (PEFT/TRL BF16 LoRA) · dpo_stub (stretch)
serving/        launch_vllm.py · prompts        serve/  dualguard client + launch_vllm.sh
ui/             dashboard.py (Streamlit: 5 badges + fail->pass + rocm-smi tile)
config/         cwe_focus.yaml · gate/eval/train/serve.yaml · versions.yaml
scripts/        setup_cloud · setup_semgrep · setup_codeql · run_harness_demo · rocm_smi_watch · push_to_github
tests/          unit suite + fixtures
docs/           plan.md · RUNBOOK.md · mentor_message.md
```

## Submission mapping (handbook 5-slide deck + demo video + code)
- **Technical (40%)** — the executable gate; a genuinely working, verifiable solution.
- **Demo (15%)** — the red→green / fail→pass flip on identical input (`make ui`).
- **Innovation (15%)** — ungameable gate + judge-co-resident-on-one-card.
- **Impact (20%)** — on-prem sovereign remediation; TCS–AMD enterprise thesis.
- **Problem (10%)** — the 30-second stakes hook (see the pitch).

**Public datasets only. Nothing proprietary to TCS.** `make`-based entrypoints; run
`make help` for all targets.

— team-2497 · deadline 2026-06-17 8:30 PM IST
