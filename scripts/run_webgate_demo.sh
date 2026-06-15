#!/usr/bin/env bash
# WebGate demo — the accessibility arm of PatchPilot's verified-remediation engine.
#
# Proves, CPU-side and in seconds (no GPU):
#   1. axe-core finds real a11y violations on a broken page          -> RED
#   2. the gate confirms the human/LLM fix flipped them fail->pass    -> GREEN (cleared=True)
#   3. a "gamed" fix that just DELETES the elements is rejected by the
#      DOM non-deletion guard                                          -> cleared=False
#
# With --auto <FIXER_URL>, the fix is generated live by a served model instead of
# using the bundled fixed.html (the full autonomous loop: scan -> fix -> re-gate).
#
# Usage:
#   ./scripts/run_webgate_demo.sh                          # human-fix demo
#   ./scripts/run_webgate_demo.sh --auto http://localhost:8000/v1 fixer
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO="$(cd "${SCRIPT_DIR}/.." && pwd)"
export PYTHONPATH="${REPO}${PYTHONPATH:+:${PYTHONPATH}}"
PY="${PYTHON:-python3}"; command -v "$PY" >/dev/null 2>&1 || PY="python"
DEMO="${REPO}/webgate/demo"
AUTO_URL=""; AUTO_MODEL="fixer"
[ "${1:-}" = "--auto" ] && { AUTO_URL="${2:?--auto needs a FIXER_URL}"; AUTO_MODEL="${3:-fixer}"; }

sec(){ printf '\n\033[1;36m==== %s ====\033[0m\n' "$*"; }
log(){ printf '\033[1;34m[webgate]\033[0m %s\n' "$*"; }

# Ensure node deps are present.
if ! "$PY" -c "from harness import webgate; webgate.run_axe('${DEMO}/fixed.html')" >/dev/null 2>&1; then
  log "axe-core not ready — installing webgate node deps ..."
  ( cd "${REPO}/webgate" && npm install --no-audit --no-fund >/dev/null 2>&1 ) || {
    echo "[webgate] could not 'npm install' in webgate/. Install Node 18+ then retry." >&2; exit 1; }
fi

sec "1. Scan the BROKEN page (axe-core oracle) — expect violations (RED)"
node "${REPO}/webgate/axe_scan.mjs" "${DEMO}/broken.html" --quiet

sec "2. GATE: broken -> fixed — expect cleared=True (fail->pass, GREEN)"
if [ -n "${AUTO_URL}" ]; then
  log "auto mode: generating the fix live via ${AUTO_URL} (${AUTO_MODEL})"
  "$PY" -m harness.webgate --original "${DEMO}/broken.html" \
    --fixer-url "${AUTO_URL}" --fixer-model "${AUTO_MODEL}" --page-id acme-home -o "${REPO}/results/webgate_positive.json"
else
  "$PY" -m harness.webgate --original "${DEMO}/broken.html" --patched "${DEMO}/fixed.html" \
    --page-id acme-home -o "${REPO}/results/webgate_positive.json"
fi
POS_RC=$?

sec "3. NEGATIVE CONTROL: broken -> gutted/deleted — expect cleared=False (DOM guard trips)"
"$PY" -m harness.webgate --original "${DEMO}/broken.html" --patched "${DEMO}/gamed.html" --page-id acme-home
NEG_RC=$?

sec "WEBGATE DEMO SUMMARY"
[ "${POS_RC}" -eq 0 ] && log "PASS: the fix flipped a11y violations fail->pass (cleared=True)." \
                      || log "NOTE: positive case not cleared (rc=${POS_RC}) — see the verdict above."
[ "${NEG_RC}" -ne 0 ] && log "PASS: the delete-the-elements cheat was rejected (cleared=False)." \
                      || log "WARN: negative control unexpectedly cleared."
log "WebGate proves the SAME verified-remediation engine works for accessibility, not just code."
[ "${POS_RC}" -eq 0 ] && [ "${NEG_RC}" -ne 0 ] && exit 0 || exit 1
