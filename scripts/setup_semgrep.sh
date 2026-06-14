#!/usr/bin/env bash
# Install/pin Semgrep and warm the p/java rule cache (DualGuard MG8).
#
# Reads the pinned version from config/versions.yaml (key: semgrep) and installs it
# via pip, then pulls the p/java pack so the first real scan is fast and offline-safe.
#
# Usage:  ./scripts/setup_semgrep.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS="${REPO_ROOT}/config/versions.yaml"
PY="${PYTHON:-python3}"
command -v "${PY}" >/dev/null 2>&1 || PY="python"

log() { printf '\033[1;34m[setup_semgrep]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup_semgrep][warn]\033[0m %s\n' "$*" >&2; }

# Resolve the pinned semgrep version (fallback to the requirements pin).
SEMGREP_VER="1.86.0"
if [ -f "${VERSIONS}" ]; then
  parsed="$("${PY}" - "${VERSIONS}" <<'PYEOF' 2>/dev/null || true
import sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
    print(d.get("semgrep", ""))
except Exception:
    print("")
PYEOF
)"
  [ -n "${parsed}" ] && SEMGREP_VER="${parsed}"
fi

log "installing semgrep==${SEMGREP_VER} ..."
"${PY}" -m pip install "semgrep==${SEMGREP_VER}"

if command -v semgrep >/dev/null 2>&1; then
  log "semgrep $(semgrep --version 2>/dev/null | head -1) installed."
  log "warming the p/java rule cache (network may be required) ..."
  # --error makes a non-zero exit only on a real failure; an empty scan over /dev/null
  # just downloads + caches the pack.
  semgrep --config p/java --quiet /dev/null >/dev/null 2>&1 \
    || warn "could not warm the p/java cache (offline?). It will download on first use."
else
  warn "semgrep not on PATH after install; check your pip environment."
fi

log "done. The dual-SAST AND-gate will use Semgrep CE (p/java) + CodeQL."
