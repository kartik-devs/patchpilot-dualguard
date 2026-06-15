#!/usr/bin/env bash
# PatchPilot v2 — vLLM launch helpers for the AMD MI300X (ROCm).
#
# Three modes:
#   single   : one fixer model (start here — de-risk).
#   ft       : the fine-tuned fixer (base + LoRA adapter via --enable-lora).
#   dual     : the DualGuard WOW — fixer + a separate judge model CO-RESIDENT on one
#              MI300X (the ~128GB-on-one-card story; capture rocm-smi while it runs).
#
# Usage:
#   ./serve/launch_vllm.sh single [MODEL]
#   ./serve/launch_vllm.sh ft     [BASE] [ADAPTER_DIR]
#   ./serve/launch_vllm.sh dual   [FIXER] [JUDGE]
#
# Each server logs to /tmp/vllm_<name>.log and prints its PID. Tail the log until
# "Application startup complete", then hit the /v1/models endpoint to confirm.
set -uo pipefail

MODE="${1:-single}"
FIXER_DEFAULT="Qwen/Qwen2.5-Coder-7B-Instruct"     # safe start; swap to -32B- when budget allows
JUDGE_DEFAULT="Qwen/Qwen2.5-32B-Instruct"

wait_ready() {  # $1=port $2=name
  echo "[serve] waiting for $2 on :$1 ..."
  for _ in $(seq 1 120); do
    if curl -s "localhost:$1/v1/models" >/dev/null 2>&1; then
      echo "[serve] $2 READY on :$1"; curl -s "localhost:$1/v1/models" | python -m json.tool; return 0
    fi
    sleep 5
  done
  echo "[serve] $2 did NOT become ready; see /tmp/vllm_$2.log" >&2; return 1
}

case "$MODE" in
  single)
    MODEL="${2:-$FIXER_DEFAULT}"
    echo "[serve] single fixer: $MODEL"
    nohup vllm serve "$MODEL" \
      --served-model-name fixer --port 8000 \
      --max-model-len 16384 --gpu-memory-utilization 0.90 \
      --enable-auto-tool-choice --tool-call-parser hermes \
      > /tmp/vllm_fixer.log 2>&1 &
    echo "[serve] fixer PID $!  (log: /tmp/vllm_fixer.log)"
    wait_ready 8000 fixer
    ;;

  ft)
    BASE="${2:-$FIXER_DEFAULT}"
    ADAPTER="${3:-models/fixer-lora}"
    echo "[serve] fine-tuned fixer: base=$BASE adapter=$ADAPTER"
    nohup vllm serve "$BASE" \
      --enable-lora --lora-modules "fixer-ft=$ADAPTER" \
      --served-model-name fixer-ft --port 8000 \
      --max-model-len 16384 --gpu-memory-utilization 0.90 \
      > /tmp/vllm_fixer-ft.log 2>&1 &
    echo "[serve] fixer-ft PID $!  (log: /tmp/vllm_fixer-ft.log)"
    wait_ready 8000 fixer-ft
    ;;

  dual)
    # The 192GB story: two big models resident at once on ONE card.
    FIXER="${2:-Qwen/Qwen2.5-Coder-32B-Instruct}"
    JUDGE="${3:-$JUDGE_DEFAULT}"
    echo "[serve] CO-RESIDENT  fixer=$FIXER (:8000)  +  judge=$JUDGE (:8001)"
    echo "[serve] split gpu-memory-utilization so BOTH fit on one MI300X."
    nohup vllm serve "$FIXER" \
      --served-model-name fixer --port 8000 \
      --max-model-len 16384 --gpu-memory-utilization 0.45 \
      > /tmp/vllm_fixer.log 2>&1 &
    echo "[serve] fixer PID $!"
    nohup vllm serve "$JUDGE" \
      --served-model-name judge --port 8001 \
      --max-model-len 8192 --gpu-memory-utilization 0.45 \
      > /tmp/vllm_judge.log 2>&1 &
    echo "[serve] judge PID $!"
    wait_ready 8000 fixer && wait_ready 8001 judge
    echo "[serve] >>> NOW capture the proof:  bash scripts/rocm_smi_watch.sh  <<<"
    echo "[serve] (expect ~120-140 GB used across both models — impossible on an 80GB card)"
    ;;

  *)
    echo "usage: $0 {single|ft|dual} [args...]" >&2; exit 2 ;;
esac
