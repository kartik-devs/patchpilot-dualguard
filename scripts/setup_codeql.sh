#!/usr/bin/env bash
# Install the CodeQL CLI bundle (precompiled java-queries) for the gate's 2nd SAST.
# Verified: codeql-bundle v2.25.6. CodeQL is a STRETCH in the merit plan — per-bug DB
# build is a ~10-20 min/candidate multiplier, so run it on a 3-5 bug subset
# (XXE / path-traversal / deserialization where CodeQL dataflow shines) as
# corroboration; Semgrep + the executable PoV/regression tests are the core across
# all bugs. See docs/MERIT_RUNBOOK.md.
#
# Usage:  bash scripts/setup_codeql.sh   ->  adds /opt/codeql to PATH (export it after)
set -euo pipefail
log(){ printf '\033[1;34m[setup_codeql]\033[0m %s\n' "$*"; }

cd /opt
log "downloading codeql-bundle v2.25.6 (~810 MB) ..."
curl -L -o codeql-bundle.tar.gz \
  https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.25.6/codeql-bundle-linux64.tar.gz
tar -xzf codeql-bundle.tar.gz
export PATH=/opt/codeql:$PATH
codeql --version
codeql resolve qlpacks | grep -i java || true   # confirm codeql/java-queries present

log "done. Per-bug usage (after the bug's checkout dir exists):"
cat <<'USAGE'
  export PATH=/opt/codeql:$PATH
  export JAVA_HOME=/opt/jdks/jdk8        # match the bug's pinned JDK from vul4j.ini
  CK=<vul4j checkout dir>; ID=VUL4J-XX
  # Prefer --build-mode none (no full compile; still runs mvn to resolve dep JARs):
  codeql database create /tmp/db_$ID --language=java --source-root="$CK" \
      --build-mode none --overwrite -j 0
  # Fallback if dep resolution fails on old-Apache projects: explicit compile trace
  #   codeql database create /tmp/db_$ID --language=java --source-root="$CK" \
  #       --command='mvn -B -DskipTests clean compile' --overwrite -j 0
  codeql database analyze /tmp/db_$ID \
      codeql/java-queries:codeql-suites/java-security-extended.qls \
      --format=sarif-latest --output=/tmp/$ID.sarif -j 0
  # The gate's SARIF parser (harness.layers.sast.parse_codeql_sarif) reads /tmp/$ID.sarif.
USAGE
