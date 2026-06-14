#!/usr/bin/env bash
# Provision the AMD MI300X cloud notebook for PatchPilot v2 "DualGuard": pip deps, HF auth, git identity.
#
# Run this ONCE at the top of a fresh AMD/ROCm notebook session (the 192GB MI300X pod).
# It installs the CPU harness deps + the GPU-only cloud deps (vLLM/PEFT/TRL/...), logs into
# Hugging Face so the fixer/judge weights can be pulled, and configures a git identity so the
# repo can later be pushed via scripts/push_to_github.sh.
#
# Secrets are taken from the environment ONLY (never hard-coded, never committed):
#   HF_TOKEN          - Hugging Face access token (read scope) used for `huggingface-cli login`.
#   GIT_USER_NAME     - git commit author name      (default: "PatchPilot Bot").
#   GIT_USER_EMAIL    - git commit author email     (default: "bot@patchpilot.local").
#
# Usage:
#   HF_TOKEN=hf_xxx ./scripts/setup_cloud.sh [--cpu-only] [--no-hf] [--no-git] [--skip-rocm-check]
#
# Flags:
#   --cpu-only         Install only requirements.txt (skip the GPU cloud deps). Useful for a
#                      laptop / CI dry run of the harness.
#   --no-hf            Skip `huggingface-cli login` (e.g. weights already cached locally).
#   --no-git           Skip git identity configuration.
#   --skip-rocm-check  Do not warn when ROCm/amd-smi is absent (e.g. CPU-only box).
#   -h | --help        Show this help and exit.
#
# Idempotent: safe to re-run. It upgrades pip deps in place and re-applies config.
set -euo pipefail

# ---------------------------------------------------------------------------
# Locate the repo root (this script lives in <root>/scripts/).
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults & flag parsing.
# ---------------------------------------------------------------------------
CPU_ONLY=0
DO_HF=1
DO_GIT=1
SKIP_ROCM_CHECK=0
GIT_USER_NAME="${GIT_USER_NAME:-PatchPilot Bot}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-bot@patchpilot.local}"

usage() {
  sed -n '2,33p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cpu-only)        CPU_ONLY=1 ;;
    --no-hf)           DO_HF=0 ;;
    --no-git)          DO_GIT=0 ;;
    --skip-rocm-check) SKIP_ROCM_CHECK=1 ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

log()  { printf '\033[1;34m[setup_cloud]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup_cloud][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[setup_cloud][error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Sanity: python + pip present.
# ---------------------------------------------------------------------------
PY="${PYTHON:-python3}"
if ! command -v "${PY}" >/dev/null 2>&1; then
  if command -v python >/dev/null 2>&1; then PY="python"; else
    die "no python interpreter found (tried '${PY}' and 'python'). Install Python 3.10+ first."
  fi
fi
PY_VER="$("${PY}" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "?")"
log "using python ${PY} (version ${PY_VER}) at $(command -v "${PY}")"
case "${PY_VER}" in
  3.10|3.11|3.12|3.13) : ;;
  *) warn "Python ${PY_VER} detected; spec targets 3.10+. Continuing anyway." ;;
esac

# ---------------------------------------------------------------------------
# 1. Upgrade pip tooling.
# ---------------------------------------------------------------------------
log "upgrading pip / setuptools / wheel ..."
"${PY}" -m pip install --upgrade pip setuptools wheel

# ---------------------------------------------------------------------------
# 2. Install CPU harness deps (always). The harness requirements file is named
#    requirements-harness.txt in this repo; we also accept requirements.txt for
#    forward-compat with the spec's filename.
# ---------------------------------------------------------------------------
REQ_CPU=""
for cand in "${REPO_ROOT}/requirements-harness.txt" "${REPO_ROOT}/requirements.txt"; do
  if [ -f "${cand}" ]; then REQ_CPU="${cand}"; break; fi
done
if [ -n "${REQ_CPU}" ]; then
  log "installing CPU harness deps from $(basename "${REQ_CPU}") ..."
  "${PY}" -m pip install -r "${REQ_CPU}"
else
  warn "no requirements-harness.txt / requirements.txt found; installing the known minimal set."
  "${PY}" -m pip install \
    "pyyaml==6.0.2" "javalang==0.13.0" "semgrep==1.86.0" "requests==2.32.3" \
    "streamlit==1.39.0" "numpy==2.1.2" "pytest==8.3.3"
fi

# ---------------------------------------------------------------------------
# 3. Install GPU cloud deps (vLLM / PEFT / TRL / ...), unless --cpu-only.
#    On ROCm these wheels typically come from the AMD-provided index already
#    present in the pod image; we install the pinned versions on top.
# ---------------------------------------------------------------------------
if [ "${CPU_ONLY}" -eq 1 ]; then
  log "--cpu-only set; skipping GPU cloud deps."
else
  REQ_CLOUD="${REPO_ROOT}/requirements-cloud.txt"
  if [ -f "${REQ_CLOUD}" ]; then
    log "installing GPU cloud deps from requirements-cloud.txt ..."
    if ! "${PY}" -m pip install -r "${REQ_CLOUD}"; then
      warn "GPU cloud deps failed to install. On a ROCm pod, vLLM/torch are usually pre-baked"
      warn "into the image; you may not need to reinstall them. Re-run with --cpu-only to skip,"
      warn "or install the ROCm-matched wheels per your pod's documentation."
    fi
  else
    warn "requirements-cloud.txt not found at ${REQ_CLOUD}; skipping GPU deps."
    warn "Expected cloud deps: vllm, transformers, peft, trl, datasets, accelerate, bitsandbytes."
  fi
fi

# ---------------------------------------------------------------------------
# 4. Install this package in editable mode so `python -m harness.gate` etc. and
#    the console_scripts (pp-gate/pp-eval/...) resolve from anywhere.
# ---------------------------------------------------------------------------
if [ -f "${REPO_ROOT}/pyproject.toml" ]; then
  log "installing patchpilot-dualguard in editable mode ..."
  if ! "${PY}" -m pip install -e "${REPO_ROOT}"; then
    warn "editable install failed (pyproject.toml may not have landed yet). You can still run"
    warn "modules via 'PYTHONPATH=${REPO_ROOT} python -m harness.gate ...'."
  fi
else
  warn "pyproject.toml not found yet; skipping editable install."
  warn "Run modules with: PYTHONPATH=${REPO_ROOT} python -m harness.gate ..."
fi

# ---------------------------------------------------------------------------
# 5. Hugging Face auth (so the fixer/judge weights can be pulled).
# ---------------------------------------------------------------------------
if [ "${DO_HF}" -eq 1 ]; then
  if ! command -v huggingface-cli >/dev/null 2>&1; then
    warn "huggingface-cli not on PATH; installing huggingface_hub[cli] ..."
    "${PY}" -m pip install --upgrade "huggingface_hub[cli]" || \
      warn "could not install huggingface_hub; HF auth skipped."
  fi
  if command -v huggingface-cli >/dev/null 2>&1; then
    if [ -n "${HF_TOKEN:-}" ]; then
      log "logging into Hugging Face via HF_TOKEN ..."
      # --add-to-git-credential lets `git clone` of gated model repos work too.
      huggingface-cli login --token "${HF_TOKEN}" --add-to-git-credential \
        || warn "huggingface-cli login failed; check that HF_TOKEN is valid."
    else
      warn "HF_TOKEN not set; skipping non-interactive HF login."
      warn "Either export HF_TOKEN=hf_xxx and re-run, or run 'huggingface-cli login' by hand."
    fi
  fi
else
  log "--no-hf set; skipping Hugging Face login."
fi

# ---------------------------------------------------------------------------
# 6. Git identity (needed by scripts/push_to_github.sh later).
# ---------------------------------------------------------------------------
if [ "${DO_GIT}" -eq 1 ]; then
  if command -v git >/dev/null 2>&1; then
    log "configuring global git identity: ${GIT_USER_NAME} <${GIT_USER_EMAIL}>"
    git config --global user.name  "${GIT_USER_NAME}"
    git config --global user.email "${GIT_USER_EMAIL}"
    # Make the default branch 'main' and silence detached-HEAD noise.
    git config --global init.defaultBranch main
    git config --global --add safe.directory "${REPO_ROOT}" 2>/dev/null || true
  else
    warn "git not installed; skipping git identity config. Install git to push the repo."
  fi
else
  log "--no-git set; skipping git identity config."
fi

# ---------------------------------------------------------------------------
# 7. ROCm visibility hint (non-fatal): confirm the MI300X is reachable.
# ---------------------------------------------------------------------------
if [ "${SKIP_ROCM_CHECK}" -eq 0 ] && [ "${CPU_ONLY}" -eq 0 ]; then
  if command -v amd-smi >/dev/null 2>&1; then
    log "amd-smi present; run ./scripts/validate_pod.sh for a full GPU + vLLM smoke test."
  elif command -v rocm-smi >/dev/null 2>&1; then
    log "rocm-smi present; run ./scripts/validate_pod.sh for a full GPU + vLLM smoke test."
  else
    warn "neither amd-smi nor rocm-smi found on PATH. If this is the AMD pod, ROCm may not be"
    warn "initialised yet. Validate with ./scripts/validate_pod.sh once ROCm is available."
  fi
fi

log "done. Next steps:"
log "  1) ./scripts/validate_pod.sh           # confirm MI300X + vLLM"
log "  2) ./serve/launch_vllm.sh print        # co-resident fixer+judge commands (run nothing)"
log "     ./serve/launch_vllm.sh coresident   # actually spawn both on one MI300X + rocm-smi proof"
log "  3) ./scripts/run_harness_demo.sh       # prove the CPU gate end-to-end"
