#!/usr/bin/env bash
# Prepare a shell to RUN the executable eval. Run in a FRESH terminal that is NOT
# inside the vul4j venv (the eval uses the SYSTEM python, where the patchpilot
# package + vLLM live; the vul4j CLI is reached by path via VUL4J_BIN).
#
#   source scripts/setup_eval_env.sh        # MUST be `source`, not `bash`
#
# Installs an ISOLATED Semgrep (subprocess-only, so it can't downgrade vLLM's
# pydantic) and exports the tool paths the gate needs.

# --- isolated Semgrep (the gate shells out to it; keeps the main env intact) ---
if [ ! -x /opt/semgrep-venv/bin/semgrep ]; then
  echo "[setup_eval] installing Semgrep in an isolated venv (~1-2 min) ..."
  python3 -m venv /opt/semgrep-venv
  /opt/semgrep-venv/bin/pip install -q --upgrade pip
  /opt/semgrep-venv/bin/pip install -q "semgrep==1.86.0" \
    || /opt/semgrep-venv/bin/pip install -q semgrep   # fall back to latest if the pin fails
fi
export SEMGREP_BIN=/opt/semgrep-venv/bin/semgrep

# --- vul4j CLI: auto-detect (path varies: project venv, uv tool bin, ~/.local) --
if [ -z "${VUL4J_BIN:-}" ] || [ ! -x "${VUL4J_BIN:-}" ]; then
  for _cand in /root/vul4j/.venv/bin/vul4j "$HOME/.local/bin/vul4j" \
               /root/.local/bin/vul4j "$(command -v vul4j 2>/dev/null)"; do
    if [ -n "$_cand" ] && [ -x "$_cand" ]; then VUL4J_BIN="$_cand"; break; fi
  done
fi
if [ -z "${VUL4J_BIN:-}" ] || [ ! -x "${VUL4J_BIN:-}" ]; then
  VUL4J_BIN="$(find /root /usr/local /opt -path '*/bin/vul4j' -type f 2>/dev/null | head -1)"
fi
export VUL4J_BIN

# --- JDK8 + Maven (vul4j picks the per-bug JDK from vul4j.ini; needs mvn on PATH) ---
export JAVA_HOME=/opt/jdks/jdk8
export MAVEN_HOME=/opt/apache-maven-3.3.9
export M2_HOME=/opt/apache-maven-3.3.9
export PATH=$JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH

# --- sanity checks --------------------------------------------------------------
echo "[setup_eval] checks:"
python -c "import harness.gate, javalang, requests; print('  harness import : OK')" \
  || echo "  harness import : FAIL  -> you are likely in the vul4j venv; run 'deactivate' then re-source"
[ -x "$VUL4J_BIN" ] && echo "  vul4j CLI      : OK ($VUL4J_BIN)" || echo "  vul4j CLI      : MISSING at $VUL4J_BIN"
"$SEMGREP_BIN" --version >/dev/null 2>&1 \
  && echo "  semgrep        : OK ($("$SEMGREP_BIN" --version 2>/dev/null))" \
  || echo "  semgrep        : FAIL"
command -v mvn >/dev/null 2>&1 && echo "  maven          : OK" || echo "  maven          : MISSING on PATH"
echo "[setup_eval] done. SEMGREP_BIN + VUL4J_BIN + JDK8/Maven exported into THIS shell."
