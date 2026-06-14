#!/usr/bin/env bash
# Validate the AMD MI300X pod for PatchPilot v2: ROCm visibility + a quick vLLM smoke test.
#
# Run this AFTER scripts/setup_cloud.sh, before launching the co-resident fixer+judge.
# It answers three questions, loudly and fast:
#   1. Is the GPU visible?            (amd-smi / rocm-smi list devices + VRAM)
#   2. Can torch see ROCm?            (torch.cuda.is_available() on the ROCm build)
#   3. Does vLLM import & (optionally) serve a tiny model?   (smoke test)
#
# It is NON-DESTRUCTIVE and degrades gracefully: any missing tool produces a clear
# remediation message and a non-zero summary, never a cryptic stack trace.
#
# Usage:
#   ./scripts/validate_pod.sh [--full] [--model <hf-id>] [--port <n>] [--timeout <s>] [--no-vllm]
#
# Flags:
#   --full            Actually boot a tiny vLLM server and hit /v1/models (heavier; needs weights).
#                     Without --full, vLLM is only import-checked (fast, no download).
#   --model <hf-id>   Model to use for the --full serve test (default: facebook/opt-125m, tiny+ungated).
#   --port <n>        Port for the --full serve test (default: 8009).
#   --timeout <s>     Seconds to wait for the --full server to come up (default: 180).
#   --no-vllm         Skip all vLLM checks (only do ROCm + torch).
#   -h | --help       Show this help and exit.
#
# Exit code: 0 if every REQUIRED check passed, 1 otherwise (a summary table is always printed).
set -uo pipefail   # NOTE: no -e; we want to run ALL checks and summarise, not abort on first failure.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Flags.
# ---------------------------------------------------------------------------
FULL=0
SMOKE_MODEL="facebook/opt-125m"
SMOKE_PORT=8009
SMOKE_TIMEOUT=180
DO_VLLM=1

usage() { sed -n '2,28p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --full)     FULL=1 ;;
    --model)    SMOKE_MODEL="${2:?--model needs a value}"; shift ;;
    --port)     SMOKE_PORT="${2:?--port needs a value}"; shift ;;
    --timeout)  SMOKE_TIMEOUT="${2:?--timeout needs a value}"; shift ;;
    --no-vllm)  DO_VLLM=0 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

PY="${PYTHON:-python3}"
command -v "${PY}" >/dev/null 2>&1 || PY="python"

# ---------------------------------------------------------------------------
# Pretty output + result accounting.
# ---------------------------------------------------------------------------
log()  { printf '\033[1;34m[validate_pod]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[validate_pod][warn]\033[0m %s\n' "$*" >&2; }
sec()  { printf '\n\033[1;36m==== %s ====\033[0m\n' "$*"; }

# Result table rows: "NAME|STATUS|NOTE" ; STATUS in {PASS,FAIL,SKIP,WARN}.
RESULTS=()
REQUIRED_FAIL=0
record() {
  # record <name> <status> <note...>
  local name="$1" status="$2"; shift 2
  RESULTS+=("${name}|${status}|$*")
  if [ "${status}" = "FAIL" ]; then REQUIRED_FAIL=1; fi
}

# ---------------------------------------------------------------------------
# Check 1: GPU device visibility via amd-smi (preferred) or rocm-smi.
# ---------------------------------------------------------------------------
sec "1. GPU device visibility (amd-smi / rocm-smi)"
SMI_TOOL=""
if command -v amd-smi >/dev/null 2>&1; then
  SMI_TOOL="amd-smi"
  log "amd-smi found at $(command -v amd-smi)"
  amd-smi list      2>/dev/null || warn "'amd-smi list' returned non-zero"
  amd-smi monitor -v -u 2>/dev/null | head -20 || true
  if amd-smi static >/dev/null 2>&1 || amd-smi list >/dev/null 2>&1; then
    record "gpu_visible(amd-smi)" PASS "device(s) enumerated"
  else
    record "gpu_visible(amd-smi)" FAIL "amd-smi present but no device reported"
  fi
elif command -v rocm-smi >/dev/null 2>&1; then
  SMI_TOOL="rocm-smi"
  log "rocm-smi found at $(command -v rocm-smi)"
  rocm-smi --showproductname --showmeminfo vram --showuse 2>/dev/null || \
    warn "'rocm-smi --showmeminfo vram' returned non-zero"
  if rocm-smi >/dev/null 2>&1; then
    record "gpu_visible(rocm-smi)" PASS "device(s) enumerated"
  else
    record "gpu_visible(rocm-smi)" FAIL "rocm-smi present but no device reported"
  fi
else
  warn "neither amd-smi nor rocm-smi found on PATH."
  warn "On the AMD MI300X pod these ship with ROCm. If absent, ROCm is not initialised:"
  warn "  - confirm you are on the GPU pod (not the CPU login node)"
  warn "  - source the ROCm env (e.g. /opt/rocm/bin on PATH)"
  record "gpu_visible" FAIL "no amd-smi/rocm-smi on PATH"
fi

# ---------------------------------------------------------------------------
# Check 2: torch sees ROCm (HIP). torch.cuda.* is the ROCm HIP API on AMD builds.
# ---------------------------------------------------------------------------
sec "2. PyTorch + ROCm"
TORCH_OUT="$("${PY}" - <<'PYEOF' 2>&1
try:
    import torch
except Exception as e:  # noqa: BLE001
    print("NO_TORCH:%s" % e)
    raise SystemExit(0)
avail = torch.cuda.is_available()
hip = getattr(getattr(torch, "version", None), "hip", None)
n = torch.cuda.device_count() if avail else 0
names = []
for i in range(n):
    try:
        names.append(torch.cuda.get_device_name(i))
    except Exception:  # noqa: BLE001
        names.append("device%d" % i)
print("TORCH_VERSION:%s" % torch.__version__)
print("HIP_VERSION:%s" % hip)
print("CUDA_AVAILABLE:%s" % avail)
print("DEVICE_COUNT:%d" % n)
print("DEVICES:%s" % "; ".join(names))
PYEOF
)"
echo "${TORCH_OUT}"
if echo "${TORCH_OUT}" | grep -q '^NO_TORCH:'; then
  warn "torch not importable. On a ROCm pod torch is usually pre-installed; otherwise install"
  warn "the ROCm-matched torch wheel per your pod docs."
  record "torch_rocm" FAIL "torch not importable"
elif echo "${TORCH_OUT}" | grep -q '^CUDA_AVAILABLE:True'; then
  record "torch_rocm" PASS "$(echo "${TORCH_OUT}" | grep '^DEVICE_COUNT:')"
else
  warn "torch imported but reports no GPU (torch.cuda.is_available()==False)."
  warn "Check HIP_VISIBLE_DEVICES / ROCR_VISIBLE_DEVICES and that this is the GPU pod."
  record "torch_rocm" FAIL "torch sees no ROCm device"
fi

# ---------------------------------------------------------------------------
# Check 3a: vLLM importable (always, unless --no-vllm).
# ---------------------------------------------------------------------------
if [ "${DO_VLLM}" -eq 1 ]; then
  sec "3a. vLLM import"
  VLLM_OUT="$("${PY}" - <<'PYEOF' 2>&1
try:
    import vllm
    print("VLLM_VERSION:%s" % getattr(vllm, "__version__", "unknown"))
except Exception as e:  # noqa: BLE001
    print("NO_VLLM:%s" % e)
PYEOF
)"
  echo "${VLLM_OUT}"
  if echo "${VLLM_OUT}" | grep -q '^VLLM_VERSION:'; then
    record "vllm_import" PASS "$(echo "${VLLM_OUT}" | grep '^VLLM_VERSION:')"
  else
    warn "vLLM not importable. Install with requirements-cloud.txt (vllm==0.6.3) or use the"
    warn "ROCm-prebuilt vLLM in the pod image."
    record "vllm_import" FAIL "vllm not importable"
  fi
else
  log "--no-vllm set; skipping all vLLM checks."
  record "vllm_import" SKIP "skipped via --no-vllm"
fi

# ---------------------------------------------------------------------------
# Check 3b: vLLM serve smoke test (only with --full). Boots a tiny model and
# hits the OpenAI-compatible /v1/models endpoint, then tears it down.
# ---------------------------------------------------------------------------
if [ "${DO_VLLM}" -eq 1 ] && [ "${FULL}" -eq 1 ]; then
  sec "3b. vLLM serve smoke test (--full)"
  if ! command -v vllm >/dev/null 2>&1; then
    warn "'vllm' CLI not on PATH; cannot run the serve smoke test."
    record "vllm_serve" FAIL "vllm CLI missing"
  else
    LOG_FILE="$(mktemp -t vllm_smoke.XXXXXX.log)"
    log "booting '${SMOKE_MODEL}' on port ${SMOKE_PORT} (log: ${LOG_FILE}) ..."
    # Small footprint: low gpu-memory-utilization, short context, eager mode.
    vllm serve "${SMOKE_MODEL}" \
      --port "${SMOKE_PORT}" \
      --gpu-memory-utilization 0.20 \
      --max-model-len 2048 \
      --enforce-eager \
      --served-model-name smoke \
      >"${LOG_FILE}" 2>&1 &
    VLLM_PID=$!

    # Ensure we always reap the server, even on Ctrl-C / errors.
    cleanup() {
      if kill -0 "${VLLM_PID}" 2>/dev/null; then
        log "stopping vLLM smoke server (pid ${VLLM_PID}) ..."
        kill "${VLLM_PID}" 2>/dev/null || true
        wait "${VLLM_PID}" 2>/dev/null || true
      fi
    }
    trap cleanup EXIT INT TERM

    URL="http://127.0.0.1:${SMOKE_PORT}/v1/models"
    log "waiting up to ${SMOKE_TIMEOUT}s for ${URL} ..."
    UP=0
    elapsed=0
    while [ "${elapsed}" -lt "${SMOKE_TIMEOUT}" ]; do
      if ! kill -0 "${VLLM_PID}" 2>/dev/null; then
        warn "vLLM process exited early. Last log lines:"
        tail -n 30 "${LOG_FILE}" >&2 || true
        break
      fi
      if command -v curl >/dev/null 2>&1; then
        if curl -fsS "${URL}" >/dev/null 2>&1; then UP=1; break; fi
      else
        if "${PY}" - "$URL" <<'PYEOF' >/dev/null 2>&1
import sys, urllib.request
urllib.request.urlopen(sys.argv[1], timeout=3).read()
PYEOF
        then UP=1; break; fi
      fi
      sleep 3
      elapsed=$((elapsed + 3))
    done

    if [ "${UP}" -eq 1 ]; then
      log "vLLM is serving. /v1/models response:"
      if command -v curl >/dev/null 2>&1; then curl -fsS "${URL}" || true; echo; fi
      record "vllm_serve" PASS "${SMOKE_MODEL} served on :${SMOKE_PORT}"
    else
      warn "vLLM did not become healthy within ${SMOKE_TIMEOUT}s. Inspect ${LOG_FILE}."
      record "vllm_serve" FAIL "server did not come up (see ${LOG_FILE})"
    fi
    cleanup
    trap - EXIT INT TERM
  fi
elif [ "${DO_VLLM}" -eq 1 ]; then
  log "(serve smoke test skipped; pass --full to actually boot a tiny model)"
  record "vllm_serve" SKIP "not run (no --full)"
fi

# ---------------------------------------------------------------------------
# Summary table + exit code.
# ---------------------------------------------------------------------------
sec "SUMMARY"
printf '%-26s %-6s %s\n' "CHECK" "STATUS" "NOTE"
printf '%-26s %-6s %s\n' "-----" "------" "----"
for row in "${RESULTS[@]}"; do
  name="${row%%|*}"; rest="${row#*|}"; status="${rest%%|*}"; note="${rest#*|}"
  case "${status}" in
    PASS) color="\033[1;32m" ;;
    FAIL) color="\033[1;31m" ;;
    WARN) color="\033[1;33m" ;;
    *)    color="\033[1;37m" ;;
  esac
  printf '%-26s '"${color}"'%-6s\033[0m %s\n' "${name}" "${status}" "${note}"
done

if [ "${REQUIRED_FAIL}" -eq 0 ]; then
  log "pod validation PASSED. Ready to launch co-resident fixer+judge:"
  log "  ./serve/launch_vllm.sh print        # show exact commands, run nothing"
  log "  ./serve/launch_vllm.sh coresident   # spawn fixer:8000 + judge:8001 on one MI300X"
  exit 0
else
  warn "pod validation FAILED (see FAIL rows above). Fix the remediation hints and re-run."
  exit 1
fi
