#!/usr/bin/env bash
# ONE-COMMAND pod bootstrap for PatchPilot v2 "DualGuard".
# The MI300X pod's /root is EPHEMERAL — every fresh pod loses vul4j, Semgrep, and
# the model cache. This rebuilds ALL of it so a short GPU window can finish the eval.
#
#   git clone https://<TOKEN>@github.com/kartik-devs/patchpilot-dualguard.git
#   cd patchpilot-dualguard && bash scripts/bootstrap_pod.sh
#
# Idempotent: skips what already exists. GPU is used ONLY for the optional LoRA
# (re)train (~30 min); everything else is CPU/network. Run to completion, then
# follow the SERVER/WORK steps it prints at the end.
set -uo pipefail
log(){ printf '\033[1;36m[bootstrap]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*"; }
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"

# 1) harness + train/serve deps (system python) -------------------------------
log "1/6 harness + train/serve deps ..."
pip install -q -e . && pip install -q "peft>=0.13" "trl>=0.12" datasets accelerate

# 2) vul4j toolchain (JDKs + Maven + framework venv) --------------------------
if [ ! -d /opt/jdks/jdk8 ] || [ ! -d /root/vul4j ]; then
  log "2/6 setup_vul4j.sh (JDKs + Maven + vul4j clone + uv sync) ..."
  bash scripts/setup_vul4j.sh || warn "setup_vul4j.sh returned non-zero; check output above."
else
  log "2/6 JDKs + vul4j clone present; re-syncing the vul4j venv ..."
  ( cd /root/vul4j \
    && { command -v uv >/dev/null 2>&1 || { curl -LsSf https://astral.sh/uv/install.sh | sh; . "$HOME/.local/bin/env"; }; } \
    && uv sync ) || warn "uv sync failed; if vul4j is missing, delete /root/vul4j and re-run."
fi
log "    applying fix_vul4j.sh (config format + branches) ..."
bash scripts/fix_vul4j.sh || warn "fix_vul4j.sh returned non-zero; check output above."

# 3) isolated Semgrep (robust install, verified with a REAL scan) -------------
if ! /opt/semgrep-venv/bin/semgrep --version >/dev/null 2>&1; then
  log "3/6 installing Semgrep in a clean isolated venv ..."
  rm -rf /opt/semgrep-venv
  python3 -m venv /opt/semgrep-venv
  /opt/semgrep-venv/bin/pip install -q --upgrade pip setuptools wheel
  /opt/semgrep-venv/bin/pip install -q semgrep || /opt/semgrep-venv/bin/pip install -q "semgrep==1.86.0"
fi
printf 'class T { void m(){ Runtime.getRuntime().exec("x"); } }\n' > /tmp/_sg_probe.java
if /opt/semgrep-venv/bin/semgrep --config p/java --json --quiet /tmp/_sg_probe.java >/dev/null 2>&1; then
  log "    Semgrep OK (real scan succeeded)."
else
  warn "Semgrep still won't scan. The eval can still run the EXECUTABLE proof:"
  warn "  set 'semgrep_required: false' in config/gate.yaml -> PoV-flip + regression + AST are the binding gates."
fi

# 4) model (32B) --------------------------------------------------------------
if [ ! -d "$HOME/.cache/huggingface/hub/models--Qwen--Qwen2.5-Coder-32B-Instruct" ]; then
  log "4/6 downloading Qwen2.5-Coder-32B-Instruct (~62 GB) ..."
  huggingface-cli download Qwen/Qwen2.5-Coder-32B-Instruct >/dev/null || warn "model download failed; retry."
else
  log "4/6 32B model already cached."
fi

# 5) eval manifest (13 curated bugs, offline from the committed meta) ----------
log "5/6 building the eval manifest ..."
mkdir -p data/raw data/eval results
grep -oE '^VUL4J-[0-9]+' config/vul4j_eval_ids.txt > data/raw/vul4j_ids.txt
python -m data.prep.build_eval_set --vul4j-ids data/raw/vul4j_ids.txt \
  --vul4j-meta config/vul4j_meta.json --out data/eval/manifest.jsonl --cwe-focus config/cwe_focus.yaml

# 6) LoRA adapter (re-train only if missing) ----------------------------------
if [ ! -f models/fixer-lora-real/adapter_model.safetensors ]; then
  log "6/6 LoRA adapter missing -> (re)training on the MI300X (~30 min) ..."
  python -m train.finetune_lora --config config/train_quick.yaml \
    --model Qwen/Qwen2.5-Coder-32B-Instruct --data data/sft/train.jsonl --out models/fixer-lora-real \
    && rm -rf models/fixer-lora-real/checkpoint-*
else
  log "6/6 LoRA adapter present; skipping training."
fi

cat <<'NEXT'

============================================================================
 BOOTSTRAP COMPLETE. Now, in TWO terminals (neither in the vul4j venv):

 [SERVER tab]
   vllm serve Qwen/Qwen2.5-Coder-32B-Instruct \
     --enable-lora --lora-modules fixer-ft=models/fixer-lora-real \
     --max-lora-rank 16 --served-model-name fixer \
     --port 8000 --max-model-len 16384 --gpu-memory-utilization 0.90 --dtype bfloat16
   # wait for "Application startup complete"

 [WORK tab]
   source scripts/setup_eval_env.sh          # VUL4J_BIN/SEMGREP_BIN/JDK8/Maven
   make eval EVAL_SET=data/eval/manifest.jsonl MODEL_TAG=base      FIXER_MODEL=fixer    N_RETRIES=0
   make eval EVAL_SET=data/eval/manifest.jsonl MODEL_TAG=finetuned FIXER_MODEL=fixer-ft N_RETRIES=0
   python -m eval.metrics --results results/eval_finetuned.json

 SHORT on time? Eval the 6 cleanest bugs only:
   printf 'VUL4J-50\nVUL4J-59\nVUL4J-47\nVUL4J-64\nVUL4J-65\nVUL4J-41\n' > data/raw/vul4j_ids.txt
   make build-eval && (then the two `make eval` lines above)
============================================================================
NEXT
