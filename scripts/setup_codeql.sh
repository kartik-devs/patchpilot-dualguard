#!/usr/bin/env bash
# Download + verify the pinned CodeQL bundle and put `codeql` on PATH (DualGuard MG8).
#
# Reads codeql_bundle / codeql_bundle_url / codeql_bundle_sha256 from
# config/versions.yaml. Verifies the SHA-256 when one is configured (warns if blank),
# extracts the bundle under <repo>/codeql-bundle/, and prints the PATH export.
#
# Usage:  ./scripts/setup_codeql.sh [--dest <dir>]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSIONS="${REPO_ROOT}/config/versions.yaml"
PY="${PYTHON:-python3}"
command -v "${PY}" >/dev/null 2>&1 || PY="python"
DEST="${REPO_ROOT}/codeql-bundle"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dest) DEST="${2:?--dest needs a value}"; shift ;;
    -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '\033[1;34m[setup_codeql]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[setup_codeql][warn]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[setup_codeql][error]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "${VERSIONS}" ] || die "config/versions.yaml not found; cannot resolve the pinned CodeQL bundle."

read_key() {
  "${PY}" - "${VERSIONS}" "$1" <<'PYEOF' 2>/dev/null || true
import sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
    print(d.get(sys.argv[2], ""))
except Exception:
    print("")
PYEOF
}

BUNDLE_NAME="$(read_key codeql_bundle)"
URL="$(read_key codeql_bundle_url)"
SHA="$(read_key codeql_bundle_sha256)"

[ -n "${URL}" ] || die "codeql_bundle_url missing in config/versions.yaml."
log "pinned bundle: ${BUNDLE_NAME:-<unnamed>}"
mkdir -p "${DEST}"
TARBALL="${DEST}/codeql-bundle.tar.gz"

if [ ! -f "${TARBALL}" ]; then
  log "downloading ${URL} ..."
  if command -v curl >/dev/null 2>&1; then
    curl -fSL "${URL}" -o "${TARBALL}"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "${TARBALL}" "${URL}"
  else
    die "neither curl nor wget available to download the bundle."
  fi
else
  log "tarball already present at ${TARBALL}; skipping download."
fi

if [ -n "${SHA}" ]; then
  log "verifying SHA-256 ..."
  ACTUAL="$("${PY}" - "${TARBALL}" <<'PYEOF'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PYEOF
)"
  if [ "${ACTUAL}" != "${SHA}" ]; then
    die "checksum mismatch: expected ${SHA}, got ${ACTUAL}. Refusing to use the bundle."
  fi
  log "checksum OK."
else
  warn "codeql_bundle_sha256 is blank in config/versions.yaml — skipping integrity check."
  warn "Set the published SHA-256 to harden this download."
fi

log "extracting into ${DEST} ..."
tar -xzf "${TARBALL}" -C "${DEST}"

CODEQL_BIN="$(find "${DEST}" -maxdepth 2 -type f -name codeql 2>/dev/null | head -1 || true)"
if [ -n "${CODEQL_BIN}" ]; then
  CODEQL_DIR="$(dirname "${CODEQL_BIN}")"
  log "codeql extracted at: ${CODEQL_BIN}"
  log "add it to PATH for this session:"
  echo "    export PATH=\"${CODEQL_DIR}:\$PATH\""
  "${CODEQL_BIN}" --version 2>/dev/null || warn "could not run codeql --version (check platform)."
else
  warn "could not locate the extracted `codeql` binary under ${DEST}."
fi

log "done. The dual-SAST AND-gate will use CodeQL (${BUNDLE_NAME:-bundle}) + Semgrep CE."
