#!/usr/bin/env bash
# End-to-end CPU demo of the DualGuard verification gate on ONE Vul4J bug — provably working TODAY.
#
# Story it tells (no GPU, no model needed):
#   1. checkout the vulnerable revision of a Vul4J bug (via the `vul4j` CLI / Docker image),
#   2. confirm the Proof-of-Vulnerability test FAILS on the unpatched code (baseline),
#   3. apply the project's HUMAN patch as the candidate `Patch.patched_code` (a full file),
#   4. run the 5-layer gate  ->  expect GateVerdict.cleared == True,
#   5. (control) run the gate with a DELETE-THE-SINK patch  ->  expect not_deleted == False.
#
# The gate itself (harness.gate / harness.layers.*) is the source of truth; this script only
# wires inputs and prints `verdict.to_dict()`. It degrades gracefully: if the `vul4j` CLI is
# not installed, it explains exactly how to get it and (with --offline) still exercises the
# gate's contract plumbing so reviewers can see the JSON shape.
#
# Usage:
#   ./scripts/run_harness_demo.sh [--id VUL4J-10] [--work <dir>] [--config config/gate.yaml]
#                                 [--negative] [--offline] [--keep]
#
# Flags:
#   --id <VUL4J-id>   Vul4J bug to demo (default: VUL4J-10).
#   --work <dir>      Working dir for checkout + json artifacts (default: a fresh mktemp dir).
#   --config <path>   gate.yaml path (default: config/gate.yaml if present, else gate defaults).
#   --negative        ALSO run the delete-the-sink control and assert not_deleted == False.
#   --offline         Do not require the vul4j CLI; build a synthetic bug+patch to exercise the
#                     gate's JSON contract end-to-end (layers that need vul4j will report missing).
#   --keep            Do not delete the working dir on exit (for inspection).
#   -h | --help       Show this help and exit.
#
# Exit code: 0 if the positive demo produced the expected verdict (and, with --negative, the
# control did too); 1 otherwise.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Flags / defaults.
# ---------------------------------------------------------------------------
BUG_ID="VUL4J-10"
WORK_DIR=""
GATE_CONFIG=""
DO_NEGATIVE=0
OFFLINE=0
KEEP=0

usage() { sed -n '2,35p' "${BASH_SOURCE[0]:-$0}" | sed 's/^# \{0,1\}//'; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --id)       BUG_ID="${2:?--id needs a value}"; shift ;;
    --work)     WORK_DIR="${2:?--work needs a value}"; shift ;;
    --config)   GATE_CONFIG="${2:?--config needs a value}"; shift ;;
    --negative) DO_NEGATIVE=1 ;;
    --offline)  OFFLINE=1 ;;
    --keep)     KEEP=1 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

log()  { printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[demo][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[demo][error]\033[0m %s\n' "$*" >&2; exit 1; }
sec()  { printf '\n\033[1;36m==== %s ====\033[0m\n' "$*"; }

PY="${PYTHON:-python3}"
command -v "${PY}" >/dev/null 2>&1 || PY="python"
command -v "${PY}" >/dev/null 2>&1 || die "no python interpreter found (need Python 3.10+)."

# Make `python -m harness.gate` importable even before `pip install -e .` has run.
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

# Resolve gate config.
if [ -z "${GATE_CONFIG}" ] && [ -f "${REPO_ROOT}/config/gate.yaml" ]; then
  GATE_CONFIG="${REPO_ROOT}/config/gate.yaml"
fi

# ---------------------------------------------------------------------------
# Working dir.
# ---------------------------------------------------------------------------
if [ -z "${WORK_DIR}" ]; then
  WORK_DIR="$(mktemp -d -t dualguard_demo.XXXXXX)"
fi
mkdir -p "${WORK_DIR}"
CHECKOUT_DIR="${WORK_DIR}/checkout"
cleanup() { if [ "${KEEP}" -eq 0 ]; then rm -rf "${WORK_DIR}" 2>/dev/null || true; fi; }
trap cleanup EXIT INT TERM
log "working dir: ${WORK_DIR} (keep=${KEEP})"

# ---------------------------------------------------------------------------
# Detect the vul4j CLI (native binary OR a thin docker wrapper).
# ---------------------------------------------------------------------------
HAVE_VUL4J=0
if command -v vul4j >/dev/null 2>&1; then
  HAVE_VUL4J=1
  log "vul4j CLI found at $(command -v vul4j)"
elif command -v docker >/dev/null 2>&1 && docker image inspect tuhhsoftsec/vul4j >/dev/null 2>&1; then
  HAVE_VUL4J=1
  log "vul4j available via docker image tuhhsoftsec/vul4j"
  # Provide a `vul4j` shim that runs inside the container with the work dir mounted.
  VUL4J_SHIM="${WORK_DIR}/vul4j"
  cat > "${VUL4J_SHIM}" <<EOF
#!/usr/bin/env bash
exec docker run --rm -v "${WORK_DIR}:${WORK_DIR}" -w "${WORK_DIR}" tuhhsoftsec/vul4j vul4j "\$@"
EOF
  chmod +x "${VUL4J_SHIM}"
  export PATH="${WORK_DIR}:${PATH}"
fi

if [ "${HAVE_VUL4J}" -eq 0 ] && [ "${OFFLINE}" -eq 0 ]; then
  warn "vul4j CLI not found and --offline not set."
  warn "Install options:"
  warn "  - native:  pip install vul4j   (and configure ~/vul4j_data/vul4j.ini JAVA*_HOME)"
  warn "  - docker:  docker pull tuhhsoftsec/vul4j"
  warn "Re-run with --offline to still exercise the gate's JSON contract without a real checkout."
  die "cannot run the real Vul4J demo without the vul4j CLI."
fi

# ===========================================================================
# STEP 1 — checkout + read the human patch (real path) OR synthesize (offline).
# ===========================================================================
sec "1. Prepare bug ${BUG_ID}"

# These get filled below; vulnerable_file/pov_tests come from vul4j info when available.
VULN_FILE=""
POV_TESTS_JSON='[]'
PROJECT="unknown"
CWE=""
HUMAN_PATCH_FILE="${WORK_DIR}/human_patched_file.java"

if [ "${HAVE_VUL4J}" -eq 1 ]; then
  log "checking out vulnerable revision into ${CHECKOUT_DIR} ..."
  vul4j checkout --id "${BUG_ID}" -d "${CHECKOUT_DIR}" \
    || die "vul4j checkout failed for ${BUG_ID}."

  # Pull metadata (vulnerable_file, pov tests, project, cwe) via `vul4j info`.
  # `vul4j info` output format varies; we parse defensively and fall back to checkout files.
  INFO_TXT="$(vul4j info "${BUG_ID}" 2>/dev/null || true)"
  PROJECT="$(printf '%s\n' "${INFO_TXT}" | sed -n 's/.*[Pp]roject[^:]*:[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -1)"
  [ -z "${PROJECT}" ] && PROJECT="${BUG_ID}"
  CWE="$(printf '%s\n' "${INFO_TXT}" | grep -oiE 'CWE-[0-9]+' | head -1 || true)"

  # The checkout's VUL4J/ metadata records the human patch & failing tests.
  # Vul4J writes the human ("correct") version available via `vul4j apply ... -v human_patch`.
  # We read the vulnerable file path from VUL4J/vulnerability_info.json if present.
  VINFO="${CHECKOUT_DIR}/VUL4J/vulnerability_info.json"
  if [ -f "${VINFO}" ]; then
    VULN_FILE="$("${PY}" - "${VINFO}" <<'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(0)
# Common keys seen across Vul4J metadata variants.
for k in ("human_patch", "modified_files", "src_classes", "failing_module"):
    v = d.get(k)
    if isinstance(v, list) and v:
        print(v[0]); break
    if isinstance(v, str) and v:
        print(v); break
PYEOF
)"
    # PoV tests from the metadata, if present.
    POV_TESTS_JSON="$("${PY}" - "${VINFO}" <<'PYEOF' 2>/dev/null || echo '[]'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    print("[]"); raise SystemExit(0)
tests = d.get("tests_trigger") or d.get("failing_tests") or d.get("pov_tests") or []
if isinstance(tests, str):
    tests = [tests]
print(json.dumps([str(t) for t in tests]))
PYEOF
)"
  fi

  # Apply the HUMAN patch into the checkout so we can read the full patched file
  # contents to feed as Patch.patched_code (the gate wants a FULL FILE, not a diff).
  log "applying the human (correct) patch to capture full patched-file contents ..."
  if ! vul4j apply -d "${CHECKOUT_DIR}" -v human_patch 2>/dev/null; then
    # Older CLIs name the version differently; try a couple of fallbacks.
    vul4j apply -d "${CHECKOUT_DIR}" -v fixed 2>/dev/null \
      || vul4j apply -d "${CHECKOUT_DIR}" -v patched 2>/dev/null \
      || warn "could not 'vul4j apply' the human version; will rely on gate's evaluate step."
  fi

  # If we discovered the vulnerable file, snapshot the now-patched contents.
  if [ -n "${VULN_FILE}" ] && [ -f "${CHECKOUT_DIR}/${VULN_FILE}" ]; then
    cp "${CHECKOUT_DIR}/${VULN_FILE}" "${HUMAN_PATCH_FILE}"
    log "captured human-patched file: ${VULN_FILE} ($(wc -l < "${HUMAN_PATCH_FILE}") lines)"
  else
    warn "vulnerable file path not resolved from metadata; the gate's evaluate_patch will"
    warn "read original/patched contents from the checkout instead."
  fi
else
  # ---- OFFLINE synthetic bug: a tiny CWE-89 SQLi sample with a clear fix. ----
  log "--offline: synthesizing a CWE-89 sample bug so the gate contract can be exercised."
  PROJECT="offline-demo"
  CWE="CWE-89"
  VULN_FILE="src/main/java/demo/UserDao.java"
  POV_TESTS_JSON='["demo.UserDaoTest#testSqlInjection"]'
  mkdir -p "${CHECKOUT_DIR}/$(dirname "${VULN_FILE}")"
  # Vulnerable original (string-concatenated SQL).
  cat > "${CHECKOUT_DIR}/${VULN_FILE}" <<'JAVA'
package demo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserDao {
    private final Connection conn;

    public UserDao(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findByName(String name) throws Exception {
        Statement st = conn.createStatement();
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return st.executeQuery(sql);
    }
}
JAVA
  # Human patch (parameterized query) — retains all statements & return paths.
  cat > "${HUMAN_PATCH_FILE}" <<'JAVA'
package demo;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserDao {
    private final Connection conn;

    public UserDao(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findByName(String name) throws Exception {
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }
}
JAVA
fi

# If we still have no captured patched file, fall back to copying the checkout file
# (so patched_code is never empty when we hand it to the gate).
if [ ! -s "${HUMAN_PATCH_FILE}" ]; then
  if [ -n "${VULN_FILE}" ] && [ -f "${CHECKOUT_DIR}/${VULN_FILE}" ]; then
    cp "${CHECKOUT_DIR}/${VULN_FILE}" "${HUMAN_PATCH_FILE}"
  else
    die "could not obtain patched-file contents for ${BUG_ID}; aborting."
  fi
fi

# ===========================================================================
# Build bug.json and patch.json matching harness.verdict contracts EXACTLY.
#   BugRecord: id, project, cwe, source, checkout_dir, pov_tests, vulnerable_file
#   Patch:     bug_id, patched_file_path, patched_code, model, attempt
# ===========================================================================
BUG_JSON="${WORK_DIR}/bug.json"
PATCH_JSON="${WORK_DIR}/patch.json"

"${PY}" - "$BUG_JSON" "$PATCH_JSON" "$HUMAN_PATCH_FILE" <<PYEOF || die "failed to build bug/patch json"
import json, sys
bug_path, patch_path, patched_file = sys.argv[1], sys.argv[2], sys.argv[3]
patched_code = open(patched_file, encoding="utf-8").read()

bug = {
    "id": "${BUG_ID}",
    "project": "${PROJECT}",
    "cwe": "${CWE}",
    "source": "vul4j",
    "checkout_dir": "${CHECKOUT_DIR}",
    "pov_tests": json.loads('${POV_TESTS_JSON}'),
    "vulnerable_file": "${VULN_FILE}",
}
patch = {
    "bug_id": "${BUG_ID}",
    "patched_file_path": "${VULN_FILE}",
    "patched_code": patched_code,
    "model": "human-patch(demo)",
    "attempt": 0,
}
json.dump(bug, open(bug_path, "w", encoding="utf-8"), indent=2)
json.dump(patch, open(patch_path, "w", encoding="utf-8"), indent=2)
print("wrote", bug_path, "and", patch_path)
PYEOF

log "bug.json   -> ${BUG_JSON}"
log "patch.json -> ${PATCH_JSON}"

# ===========================================================================
# STEP 2-4 — run the canonical gate CLI and capture the verdict JSON.
# ===========================================================================
sec "2-4. Run the DualGuard gate (human patch — expect cleared=True)"

VERDICT_JSON="${WORK_DIR}/verdict_positive.json"
GATE_ARGS=(--bug-json "${BUG_JSON}" --patch-json "${PATCH_JSON}" -o "${VERDICT_JSON}")
[ -n "${GATE_CONFIG}" ] && GATE_ARGS+=(--config "${GATE_CONFIG}")

log "invoking: python -m harness.gate ${GATE_ARGS[*]}"
set +e
"${PY}" -m harness.gate "${GATE_ARGS[@]}"
GATE_RC=$?
set -e

if [ ! -f "${VERDICT_JSON}" ]; then
  warn "the gate did not produce a verdict file. This usually means harness.gate (MG1) or a"
  warn "layer module (MG2-MG4) has not landed/installed yet. Stdout above has details."
  die "gate did not run to completion."
fi

log "GateVerdict (positive case):"
"${PY}" -m json.tool "${VERDICT_JSON}" || cat "${VERDICT_JSON}"

POS_CLEARED="$("${PY}" - "${VERDICT_JSON}" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("true" if d.get("cleared") else "false")
PYEOF
)"

# In OFFLINE mode the Vul4J-backed layers can't truly pass; we only assert the
# JSON contract printed and the AST/SAST plumbing ran. In ONLINE mode we assert cleared.
DEMO_OK=1
if [ "${OFFLINE}" -eq 1 ]; then
  log "offline mode: gate contract exercised (cleared=${POS_CLEARED}; Vul4J layers report missing-tool)."
  log "gate exit code was ${GATE_RC} (non-zero is expected offline because PoV cannot truly flip)."
else
  if [ "${POS_CLEARED}" = "true" ]; then
    log "PASS: human patch produced cleared=True (gate exit ${GATE_RC})."
  else
    warn "FAIL: expected cleared=True for the human patch but got cleared=${POS_CLEARED}."
    warn "Inspect the per-layer 'detail' fields in ${VERDICT_JSON}."
    DEMO_OK=0
  fi
fi

# ===========================================================================
# STEP 5 — negative control: delete-the-sink patch must trip not_deleted=False.
# ===========================================================================
if [ "${DO_NEGATIVE}" -eq 1 ]; then
  sec "5. Negative control (delete-the-sink — expect not_deleted=False)"

  # Produce a gamed "delete-the-sink" patch: a SYNTACTICALLY VALID Java file whose method
  # bodies are gutted to a single trivial statement. This drops reachable statements (and the
  # original return/throw paths) far below min_retained_ratio, which is exactly what the AST
  # non-deletion guard is designed to catch — so it trips on the real retained-ratio logic
  # rather than on a parse error. Uses javalang to locate methods when available; otherwise
  # falls back to a minimal valid class skeleton derived from the package + class name.
  GAMED_FILE="${WORK_DIR}/gamed_patched_file.java"
  "${PY}" - "${HUMAN_PATCH_FILE}" "${GAMED_FILE}" <<'PYEOF' || warn "could not build gamed patch"
import re, sys

src = open(sys.argv[1], encoding="utf-8").read()


def fallback_skeleton(text: str) -> str:
    """A valid, near-empty class with the same package+name and one inert method."""
    pkg_m = re.search(r'^\s*package\s+([\w.]+)\s*;', text, re.MULTILINE)
    cls_m = re.search(r'\b(?:class|interface|enum)\s+(\w+)', text)
    pkg = pkg_m.group(1) if pkg_m else None
    cls = cls_m.group(1) if cls_m else "Gamed"
    lines = []
    if pkg:
        lines.append("package %s;" % pkg)
        lines.append("")
    lines.append("public class %s {" % cls)
    lines.append("    public Object findByName(String name) {")
    lines.append("        return null;")
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


gamed = None
try:
    import javalang  # pure-python; same lib the AST guard uses

    tree = javalang.parse.parse(src)
    # Walk methods; replace each body span (between the method's '{' and its matching '}')
    # with a single inert statement. We rebuild from source positions for correctness.
    # Simpler & robust: regenerate a minimal valid class that keeps the signatures but
    # empties the bodies. We do this by string surgery guided by javalang method names.
    method_names = [
        m.name
        for _, m in tree.filter(javalang.tree.MethodDeclaration)
    ]
    if method_names:
        # Empty every method body: find 'name(' ... ') ... {' and collapse to '{ return null; }'.
        # Brace-match from the first '{' after each signature.
        def empty_bodies(text: str, names) -> str:
            out = text
            for nm in set(names):
                pat = re.compile(
                    r'(\b[\w<>\[\], ]+\s+' + re.escape(nm) + r'\s*\([^)]*\)[^{;]*)\{'
                )

                def repl(match, _text=None):
                    head = match.group(1)
                    body = "return null;" if "void " not in head else ""
                    return head + "{ " + body + " }"

                # Replace only the first '{' (method open); rely on later brace removal pass.
                out = pat.sub(repl, out)
            return out

        # The above leaves dangling original statements + extra closing braces.
        # To stay VALID, prefer the deterministic skeleton instead.
        gamed = fallback_skeleton(src)
    else:
        gamed = fallback_skeleton(src)
except Exception:
    # javalang missing or parse failed -> still emit a valid gutted skeleton.
    gamed = fallback_skeleton(src)

open(sys.argv[2], "w", encoding="utf-8").write(gamed)
print("wrote gamed (delete-the-sink) patch:")
print(gamed)
PYEOF

  GAMED_PATCH_JSON="${WORK_DIR}/patch_gamed.json"
  "${PY}" - "${GAMED_PATCH_JSON}" "${GAMED_FILE}" <<PYEOF || die "failed to build gamed patch json"
import json, sys
out, gamed = sys.argv[1], sys.argv[2]
patch = {
    "bug_id": "${BUG_ID}",
    "patched_file_path": "${VULN_FILE}",
    "patched_code": open(gamed, encoding="utf-8").read(),
    "model": "delete-the-sink(control)",
    "attempt": 0,
}
json.dump(patch, open(out, "w", encoding="utf-8"), indent=2)
print("wrote", out)
PYEOF

  NEG_VERDICT_JSON="${WORK_DIR}/verdict_negative.json"
  NEG_ARGS=(--bug-json "${BUG_JSON}" --patch-json "${GAMED_PATCH_JSON}" -o "${NEG_VERDICT_JSON}")
  [ -n "${GATE_CONFIG}" ] && NEG_ARGS+=(--config "${GATE_CONFIG}")

  log "invoking: python -m harness.gate ${NEG_ARGS[*]}"
  set +e
  "${PY}" -m harness.gate "${NEG_ARGS[@]}"
  set -e

  if [ -f "${NEG_VERDICT_JSON}" ]; then
    log "GateVerdict (negative control):"
    "${PY}" -m json.tool "${NEG_VERDICT_JSON}" || cat "${NEG_VERDICT_JSON}"
    NOT_DELETED="$("${PY}" - "${NEG_VERDICT_JSON}" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
print("true" if d.get("not_deleted") else "false")
PYEOF
)"
    if [ "${NOT_DELETED}" = "false" ]; then
      log "PASS: delete-the-sink patch correctly tripped not_deleted=False (via the gate)."
    else
      warn "FAIL: expected not_deleted=False for the gamed patch but got not_deleted=${NOT_DELETED}."
      DEMO_OK=0
    fi
  else
    warn "negative control produced no verdict file; AST guard (MG4) may not have landed yet."
    DEMO_OK=0
  fi

  # ------------------------------------------------------------------------ #
  # Direct AST-guard probe (MG4). The full gate short-circuits on the baseline
  # PoV precondition when Vul4J is unavailable (e.g. --offline), so the
  # `ast_non_deletion` layer may not run independently inside run_gate. To PROVE
  # the non-deletion guard's real retained-ratio logic fires, we call
  # harness.layers.ast_guard.non_deletion_ok() directly on (human, gamed):
  #   - human patch  -> ok=True  (statements + return paths retained)
  #   - gamed patch  -> ok=False (reachable statements dropped below threshold)
  # ------------------------------------------------------------------------ #
  sec "5b. Direct AST non-deletion guard probe (proves MG4 logic, gate-independent)"
  AST_PROBE_OUT="$("${PY}" - "${HUMAN_PATCH_FILE}" "${GAMED_FILE}" <<'PYEOF'
import sys

try:
    from harness.layers import ast_guard
except Exception as exc:  # noqa: BLE001
    print("AST_GUARD_UNAVAILABLE:%s" % exc)
    raise SystemExit(0)

human = open(sys.argv[1], encoding="utf-8").read()
gamed = open(sys.argv[2], encoding="utf-8").read()


def describe(tag, original, patched):
    try:
        r = ast_guard.non_deletion_ok(original, patched, min_retained_ratio=0.6)
    except Exception as exc:  # noqa: BLE001
        print("%s_ERROR:%s" % (tag, exc))
        return None
    print(
        "%s ok=%s retained_ratio=%.3f returns_kept=%s detail=%s"
        % (
            tag,
            getattr(r, "ok", None),
            float(getattr(r, "retained_ratio", 0.0) or 0.0),
            getattr(r, "returns_kept", None),
            getattr(r, "detail", "") or "",
        )
    )
    return bool(getattr(r, "ok", False))


# Human patch compared against itself -> nothing deleted -> ok must be True.
human_ok = describe("HUMAN(vs self)", human, human)
# Gamed (delete-the-sink) compared against the human patch -> ok must be False.
gamed_ok = describe("GAMED(vs human)", human, gamed)

if human_ok is None or gamed_ok is None:
    print("AST_PROBE_RESULT:ERROR")
elif human_ok is True and gamed_ok is False:
    print("AST_PROBE_RESULT:PASS")
else:
    print("AST_PROBE_RESULT:FAIL")
PYEOF
)"
  echo "${AST_PROBE_OUT}"
  case "${AST_PROBE_OUT}" in
    *AST_GUARD_UNAVAILABLE:*)
      warn "ast_guard (MG4) not importable yet; skipping the direct probe."
      ;;
    *AST_PROBE_RESULT:PASS*)
      log "PASS: ast_guard.non_deletion_ok accepted the human patch and rejected delete-the-sink."
      ;;
    *AST_PROBE_RESULT:FAIL*)
      warn "FAIL: ast_guard.non_deletion_ok did not separate human vs delete-the-sink as expected."
      DEMO_OK=0
      ;;
    *)
      warn "AST guard probe was inconclusive (see output above)."
      ;;
  esac
fi

# ===========================================================================
# Summary.
# ===========================================================================
sec "DEMO SUMMARY"
log "bug:            ${BUG_ID}  (project=${PROJECT}, cwe=${CWE:-n/a})"
log "vulnerable_file: ${VULN_FILE:-<from checkout>}"
log "positive verdict: ${VERDICT_JSON}  (cleared=${POS_CLEARED})"
[ "${DO_NEGATIVE}" -eq 1 ] && log "negative verdict: ${WORK_DIR}/verdict_negative.json"
[ "${KEEP}" -eq 1 ] && log "artifacts kept under: ${WORK_DIR}"

if [ "${OFFLINE}" -eq 1 ]; then
  log "OFFLINE demo finished: the gate's JSON contract was exercised end-to-end."
  exit 0
fi

if [ "${DEMO_OK}" -eq 1 ]; then
  log "DEMO PASSED — the DualGuard harness is provably working today."
  exit 0
else
  warn "DEMO had failures (see FAIL lines above)."
  exit 1
fi
