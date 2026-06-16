#!/usr/bin/env bash
# Fix vul4j 2.0.0 setup on a fresh pod so `vul4j status` is GREEN and
# `vul4j reproduce` works. Two root causes (source-verified against
# tuhh-softsec/vul4j main == v2.0.0):
#   (1) vul4j.ini was written in the wrong format. The JDK homes live under a
#       [JAVA] section (case-sensitive); VUL4J_GIT must point at the cloned repo
#       so DATASET_PATH (=<VUL4J_GIT>/dataset/vul4j_dataset.csv) resolves.
#   (2) reset_vul4j_git() hard-codes `git checkout -f main`, but the --depth 1
#       clone only fetched the default branch and not the per-bug VUL4J-* branches
#       that `vul4j checkout` needs. De-shallow + fetch all branches.
#
# Usage (with the vul4j venv active):
#   bash scripts/fix_vul4j.sh
#   # then, in your shell (exports must be in the shell that runs vul4j):
#   export JAVA_HOME=/opt/jdks/jdk8
#   export PATH=$JAVA_HOME/bin:/opt/apache-maven-3.3.9/bin:$PATH
#   vul4j status
#   vul4j reproduce --id VUL4J-50
set -uo pipefail
log(){ printf '\033[1;34m[fix_vul4j]\033[0m %s\n' "$*"; }

VUL4J_GIT="${VUL4J_GIT:-/root/vul4j}"
VUL4J_DATA="${VUL4J_DATA:-/root/vul4j_data}"

# ---------------------------------------------------------------------------
# (1) Correct config: [JAVA] holds the JDK homes; VUL4J_GIT points at the repo.
# ---------------------------------------------------------------------------
log "writing corrected ${VUL4J_DATA}/vul4j.ini ..."
mkdir -p "$VUL4J_DATA"
cat > "${VUL4J_DATA}/vul4j.ini" <<EOF
[VUL4J]
VUL4J_GIT = ${VUL4J_GIT}
DATASET_PATH =
VUL4J_COMMITS_URL = https://github.com/tuhh-softsec/vul4j/commits/
LOG_TO_FILE = 1
FILE_LOG_LEVEL = INFO

[DIRS]
VUL4J_WORKDIR = VUL4J
REPRODUCTION_DIR =
TEMP_CLONE_DIR =

[JAVA]
JAVA_ARGS =
MVN_ARGS =
JAVA7_HOME = /opt/jdks/jdk7
JAVA8_HOME = /opt/jdks/jdk8
JAVA11_HOME = /opt/jdks/jdk11
JAVA16_HOME = /opt/jdks/jdk16

[SPOTBUGS]
SPOTBUGS_VERSION = 4.8.5
SPOTBUGS_PATH =
MODIFICATION_EXTRACTOR_PATH =
EOF

# ---------------------------------------------------------------------------
# (2) Fix the framework git repo: real `main` branch + all per-bug branches.
# ---------------------------------------------------------------------------
if [ -d "${VUL4J_GIT}/.git" ]; then
  log "de-shallowing + fetching all VUL4J-* branches in ${VUL4J_GIT} ..."
  cd "$VUL4J_GIT"
  git config remote.origin.fetch '+refs/heads/*:refs/remotes/origin/*' || true
  git remote set-branches origin '*' || true
  git fetch --unshallow origin 2>/dev/null || git fetch origin || true
  git fetch origin '+refs/heads/*:refs/remotes/origin/*' || true
  # guarantee a local branch literally named "main" (stops the utils.py:56 crash)
  git checkout -f main 2>/dev/null || git branch -m "$(git rev-parse --abbrev-ref HEAD)" main || true
  # create local branches for every VUL4J-* so `vul4j checkout` uses the curated branch
  for b in $(git branch -r 2>/dev/null | sed 's#origin/##' | grep -E '^VUL4J-' || true); do
    git branch -f "$b" "origin/$b" 2>/dev/null || true
  done
  log "branches now: $(git branch 2>/dev/null | grep -cE 'VUL4J-' || echo 0) VUL4J-* + main"
else
  log "WARNING: ${VUL4J_GIT}/.git not found — is vul4j cloned there? Adjust VUL4J_GIT and re-run."
fi

log "done. Now run IN YOUR SHELL (exports must persist for vul4j status/reproduce):"
echo "  export JAVA_HOME=/opt/jdks/jdk8"
echo "  export PATH=\$JAVA_HOME/bin:/opt/apache-maven-3.3.9/bin:\$PATH"
echo "  vul4j status                  # expect Java 7/8/11/16 + Maven + dataset = OK"
echo "  vul4j reproduce --id VUL4J-50 # PoV fails on vuln, passes on patch"
