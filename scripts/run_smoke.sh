#!/usr/bin/env bash
# End-to-end CPU smoke test on one bug (DualGuard MG8) — spec name `run_smoke.sh`.
#
# The complete smoke/demo logic lives in scripts/run_harness_demo.sh (checkout
# VUL4J-10 -> baseline PoV fails -> human patch gives cleared=True; delete-the-sink
# control gives not_deleted=False). This wrapper exists because the spec/Makefile/
# README reference `scripts/run_smoke.sh`; it delegates verbatim (no duplication),
# enabling the negative control by default.
#
# Usage:  ./scripts/run_smoke.sh [--id VUL4J-10] [--offline] [extra run_harness_demo args...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
DEMO="${SCRIPT_DIR}/run_harness_demo.sh"

if [ ! -f "${DEMO}" ]; then
  echo "[run_smoke] error: ${DEMO} not found." >&2
  exit 1
fi

# Default to the canonical smoke bug + the delete-the-sink negative control.
exec bash "${DEMO}" --negative "$@"
