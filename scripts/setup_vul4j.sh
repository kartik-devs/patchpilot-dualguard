#!/usr/bin/env bash
# Set up Vul4J (native) on a fresh ROOT Ubuntu pod so the full gate can run real
# Java vulnerabilities: checkout + compile + the project's regression suite + the
# PoV exploit test (fail->pass). Recipe verified live (Azul Zulu 7 CDN, Temurin
# 8/16, Maven 3.3.9, tuhh-softsec/vul4j uv-sync flow) — see docs/MERIT_RUNBOOK.md.
#
# The JDK7 install is THE blocker on Ubuntu 24.04 (no apt package) -> Azul Zulu CDN.
#
# Usage:  bash scripts/setup_vul4j.sh        # then: source /root/vul4j/.venv/bin/activate && vul4j status
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
log(){ printf '\033[1;34m[setup_vul4j]\033[0m %s\n' "$*"; }

log "apt deps ..."
apt-get update -qq
apt-get install -y --no-install-recommends git wget curl ca-certificates tar python3 python3-venv unzip >/dev/null

# ---------------------------------------------------------------------------
# JDKs 7/8/11/16 (Vul4J needs all four; the bug's pinned JDK comes from vul4j.ini)
# ---------------------------------------------------------------------------
mkdir -p /opt/jdks && cd /opt/jdks
log "JDK7 (Azul Zulu CDN — the one with no apt package) ..."
wget -qO jdk7.tgz https://cdn.azul.com/zulu/bin/zulu7.44.0.11-ca-jdk7.0.292-linux_x64.tar.gz
mkdir -p jdk7 && tar -xzf jdk7.tgz -C jdk7 --strip-components=1
log "JDK8 / JDK11 (Adoptium latest GA) ..."
wget -qO jdk8.tgz  'https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse'
wget -qO jdk11.tgz 'https://api.adoptium.net/v3/binary/latest/11/ga/linux/x64/jdk/hotspot/normal/eclipse'
log "JDK16 (EOL — pinned Temurin archive) ..."
wget -qO jdk16.tgz 'https://github.com/adoptium/temurin16-binaries/releases/download/jdk-16.0.2%2B7/OpenJDK16U-jdk_x64_linux_hotspot_16.0.2_7.tar.gz'
for v in 8 11 16; do mkdir -p "jdk$v" && tar -xzf "jdk$v.tgz" -C "jdk$v" --strip-components=1; done

# ---------------------------------------------------------------------------
# Maven 3.3.9 (matches the official Vul4J Dockerfile)
# ---------------------------------------------------------------------------
log "Maven 3.3.9 ..."
wget -qO- https://archive.apache.org/dist/maven/maven-3/3.3.9/binaries/apache-maven-3.3.9-bin.tar.gz | tar -xz -C /opt
export PATH=/opt/apache-maven-3.3.9/bin:$PATH

# ---------------------------------------------------------------------------
# Vul4J framework (current main = uv flow)
# ---------------------------------------------------------------------------
log "Vul4J framework (uv sync) ..."
cd /root && [ -d vul4j ] || git clone --depth 1 https://github.com/tuhh-softsec/vul4j
cd /root/vul4j
command -v uv >/dev/null 2>&1 || { curl -LsSf https://astral.sh/uv/install.sh | sh; . "$HOME/.local/bin/env"; }
uv sync
# shellcheck disable=SC1091
source .venv/bin/activate
vul4j init || true   # creates ~/vul4j_data/ and a template vul4j.ini

log "writing JDK paths into ~/vul4j_data/vul4j.ini ..."
# NOTE: open ~/vul4j_data/vul4j.ini first and confirm the section/key style matches;
# adjust if the template differs. Paths must be the JDK HOME (contains bin/ + lib/).
mkdir -p ~/vul4j_data
cat > ~/vul4j_data/vul4j.ini <<EOF
[vul4j]
JAVA7_HOME = /opt/jdks/jdk7
JAVA8_HOME = /opt/jdks/jdk8
JAVA11_HOME = /opt/jdks/jdk11
JAVA16_HOME = /opt/jdks/jdk16
EOF

# ---------------------------------------------------------------------------
# Maven cache: keep it on the big ephemeral overlay (re-downloads per session;
# the 25 GB persistent home is too small for ~/.m2). Do the Vul4J eval in ONE
# session so the cache stays warm across bugs.
# ---------------------------------------------------------------------------
log "done. Activate + verify:"
echo "  source /root/vul4j/.venv/bin/activate"
echo "  export PATH=/opt/apache-maven-3.3.9/bin:\$PATH"
echo "  vul4j status                       # expect Java 7/8/11/16 + Maven all GREEN"
echo "  vul4j reproduce --id VUL4J-50      # smoke test: PoV fails on vuln, passes on patch"
