#!/usr/bin/env bash
# Single-card co-residency proof: a 1 Hz rocm-smi VRAM/util loop (DualGuard MG8).
#
# Two co-resident vLLM servers (fixer + judge) on ONE MI300X should show a single
# GPU with high VRAM use. This loop captures that for the demo / the UI panel.
#
# Usage:
#   ./scripts/rocm_smi_watch.sh            # loop at 1 Hz until Ctrl-C
#   ./scripts/rocm_smi_watch.sh --once     # single snapshot (used by ui/dashboard.py)
#   ./scripts/rocm_smi_watch.sh --interval 2
set -uo pipefail   # no -e: a transient rocm-smi non-zero must not kill the loop.

ONCE=0
INTERVAL=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --once)     ONCE=1 ;;
    --interval) INTERVAL="${2:?--interval needs a value}"; shift ;;
    -h|--help)  sed -n '2,11p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if ! command -v rocm-smi >/dev/null 2>&1; then
  echo "[rocm_smi_watch] rocm-smi not found on PATH. This runs on the AMD MI300X pod;" >&2
  echo "[rocm_smi_watch] on a CPU host there is no GPU to show." >&2
  exit 1
fi

snapshot() {
  echo "==== rocm-smi $(date '+%H:%M:%S') ===="
  rocm-smi --showmeminfo vram --showuse 2>/dev/null || rocm-smi 2>/dev/null || true
}

if [ "${ONCE}" -eq 1 ]; then
  snapshot
  exit 0
fi

echo "[rocm_smi_watch] watching at ${INTERVAL}s intervals (Ctrl-C to stop) ..."
while true; do
  snapshot
  sleep "${INTERVAL}"
done
