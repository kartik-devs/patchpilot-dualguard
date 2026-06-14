#!/usr/bin/env bash
# Push the DualGuard repo to GitHub from the AMD cloud notebook (the TCS laptop blocks transfers).
#
# The token is supplied via the environment ONLY and is never written to a tracked file:
# it is injected into the remote URL at push time and the remote is rewritten to a
# token-free URL immediately afterwards, so it cannot leak into `git remote -v` history.
#
# Required environment:
#   GITHUB_TOKEN   - a GitHub PAT (classic: 'repo' scope; fine-grained: contents:read/write).
#   GITHUB_REPO    - "owner/name", e.g. "kartik/patchpilot-dualguard".
#
# Optional:
#   GIT_USER_NAME  - commit author name  (default "PatchPilot Bot").
#   GIT_USER_EMAIL - commit author email (default "bot@patchpilot.local").
#   GIT_BRANCH     - branch to push      (default "main").
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx GITHUB_REPO=owner/repo ./scripts/push_to_github.sh ["commit message"]
#
# A commit message may be passed as $1 (default: "DualGuard snapshot").
# Safe to re-run: re-inits if needed, re-commits only when there are changes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

log()  { printf '\033[1;34m[push_to_github]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[push_to_github][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[push_to_github][error]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preconditions.
# ---------------------------------------------------------------------------
command -v git >/dev/null 2>&1 || die "git not installed."
: "${GITHUB_TOKEN:?set GITHUB_TOKEN (a GitHub PAT) in the environment, never on the command line history}"
: "${GITHUB_REPO:?set GITHUB_REPO e.g. owner/patchpilot-dualguard}"

GIT_USER_NAME="${GIT_USER_NAME:-PatchPilot Bot}"
GIT_USER_EMAIL="${GIT_USER_EMAIL:-bot@patchpilot.local}"
GIT_BRANCH="${GIT_BRANCH:-main}"
COMMIT_MSG="${1:-DualGuard snapshot}"

# Operate strictly inside the repo root.
cd "${REPO_ROOT}"

# ---------------------------------------------------------------------------
# Guard: a .gitignore that excludes secrets & proprietary data MUST exist, or we
# refuse to push (a missing .gitignore is how tokens/handbooks leak).
# ---------------------------------------------------------------------------
if [ ! -f "${REPO_ROOT}/.gitignore" ]; then
  die ".gitignore missing at repo root. Refusing to push without it (would risk committing
       data/, models/, secrets/, *.token, handbook*, problem-statement*). Add .gitignore first."
fi

# ---------------------------------------------------------------------------
# Init repo if needed and set identity.
# ---------------------------------------------------------------------------
if [ ! -d "${REPO_ROOT}/.git" ]; then
  log "no .git found; initialising repository ..."
  git init -q
fi
git config user.name  "${GIT_USER_NAME}"
git config user.email "${GIT_USER_EMAIL}"
git config --global --add safe.directory "${REPO_ROOT}" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage everything (respecting .gitignore), then sanity-scan staged files for
# obvious secrets/proprietary artifacts that .gitignore should have excluded.
# ---------------------------------------------------------------------------
git add -A

# Refuse if anything matching a forbidden pattern slipped into the index.
FORBIDDEN_RE='(^|/)(\.env$|secrets/|.*\.token$|.*\.key$|.*\.pptx?$|handbook|problem-statement|photos/)'
STAGED="$(git diff --cached --name-only || true)"
if [ -n "${STAGED}" ]; then
  OFFENDERS="$(printf '%s\n' "${STAGED}" | grep -Ei "${FORBIDDEN_RE}" || true)"
  if [ -n "${OFFENDERS}" ]; then
    warn "the following staged paths look like secrets / proprietary data:"
    printf '  %s\n' ${OFFENDERS} >&2
    die "refusing to push. Add these to .gitignore and run 'git rm --cached <path>' first."
  fi
fi

# ---------------------------------------------------------------------------
# Commit (only if there is something to commit).
# ---------------------------------------------------------------------------
if git diff --cached --quiet; then
  log "no staged changes to commit; will push existing HEAD (if any)."
else
  log "committing: ${COMMIT_MSG}"
  git commit -qm "${COMMIT_MSG}"
fi

# Ensure there is at least one commit before pushing.
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  die "no commits exist to push."
fi

git branch -M "${GIT_BRANCH}"

# ---------------------------------------------------------------------------
# Push with a token-bearing URL, then immediately scrub the token from the remote.
# ---------------------------------------------------------------------------
TOKEN_URL="https://${GITHUB_TOKEN}@github.com/${GITHUB_REPO}.git"
CLEAN_URL="https://github.com/${GITHUB_REPO}.git"

# Always leave a token-free remote configured afterwards.
restore_clean_remote() {
  git remote remove origin >/dev/null 2>&1 || true
  git remote add origin "${CLEAN_URL}" 2>/dev/null || true
}
trap restore_clean_remote EXIT

git remote remove origin >/dev/null 2>&1 || true
git remote add origin "${TOKEN_URL}"

log "pushing branch '${GIT_BRANCH}' to ${CLEAN_URL} ..."
if git push -u origin "${GIT_BRANCH}"; then
  log "push succeeded."
else
  die "push failed. Check that GITHUB_TOKEN has push rights to ${GITHUB_REPO} and the repo exists."
fi

# restore_clean_remote runs via the EXIT trap, leaving no token in the remote URL.
log "remote URL scrubbed to token-free form: ${CLEAN_URL}"
