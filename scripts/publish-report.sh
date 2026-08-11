#!/bin/bash
# =============================================================================
# publish-report.sh — Render the static report and publish it to GitHub Pages
# =============================================================================
# Pushes to an orphan `gh-pages` branch. Nothing inbound is opened on the
# honeypot; this is an outbound push only.
#
# Config lives in /etc/honeypot-report/config (see below). Run via the
# report-publish.timer systemd unit, or by hand:
#
#   sudo /opt/cowrie-honeypot/scripts/publish-report.sh
#
# SECURITY: the deploy key is deliberately NOT stored in the cowrie user's
# home. Cowrie is the most-attacked process on the box; a key readable by
# that account would be reachable from any Cowrie compromise. It lives in
# /etc/honeypot-report/, root-only, and should be a per-repo GitHub deploy
# key with write access — never an account-wide token.
# =============================================================================

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/honeypot-report/config}"
# shellcheck disable=SC1090
[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"

REPO_SSH="${REPO_SSH:-git@github.com:ajcyberdefense/cowrie-honeypot.git}"
BRANCH="${BRANCH:-gh-pages}"
WORKDIR="${WORKDIR:-/var/lib/honeypot-report}"
DEPLOY_KEY="${DEPLOY_KEY:-/etc/honeypot-report/deploy_key}"
SCRIPTS="${SCRIPTS:-/opt/cowrie-honeypot/scripts}"
COWRIE_JSON_LOG="${COWRIE_JSON_LOG:-/home/cowrie/honeypot/var/log/cowrie/cowrie.json}"
CUSTOM_DOMAIN="${CUSTOM_DOMAIN:-}"
REDACT="${REDACT:-no}"

log() { echo "[$(date -u +%H:%M:%S)] $1"; }

[ -f "$DEPLOY_KEY" ] || { echo "Deploy key not found: $DEPLOY_KEY" >&2; exit 1; }
[ -f "$COWRIE_JSON_LOG" ] || { echo "Cowrie log not found: $COWRIE_JSON_LOG" >&2; exit 1; }

export GIT_SSH_COMMAND="ssh -i $DEPLOY_KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

# -----------------------------------------------------------------------------
# Working copy of the publish branch
# -----------------------------------------------------------------------------
if [ ! -d "$WORKDIR/.git" ]; then
  log "Preparing $WORKDIR"
  rm -rf "$WORKDIR"
  if git clone --quiet --branch "$BRANCH" --single-branch "$REPO_SSH" "$WORKDIR" 2>/dev/null; then
    log "Cloned existing $BRANCH"
  else
    # First run: the branch does not exist yet. An orphan branch keeps the
    # published site out of the source history entirely.
    log "Branch $BRANCH does not exist — creating it"
    git clone --quiet "$REPO_SSH" "$WORKDIR"
    git -C "$WORKDIR" checkout --quiet --orphan "$BRANCH"
    git -C "$WORKDIR" rm -rqf . >/dev/null 2>&1 || true
  fi
else
  log "Refreshing existing working copy"
  git -C "$WORKDIR" fetch --quiet origin "$BRANCH" 2>/dev/null \
    && git -C "$WORKDIR" reset --quiet --hard "origin/$BRANCH" \
    || log "  (no remote branch yet — keeping local state)"
fi

# -----------------------------------------------------------------------------
# Render
# -----------------------------------------------------------------------------
log "Generating report"
REDACT_FLAG=""
[ "$REDACT" = "yes" ] && REDACT_FLAG="--redact"
# shellcheck disable=SC2086
python3 "$SCRIPTS/generate_report.py" --out "$WORKDIR" --log "$COWRIE_JSON_LOG" $REDACT_FLAG

# GitHub Pages runs Jekyll unless told otherwise, which would mangle the output.
touch "$WORKDIR/.nojekyll"

# A CNAME file is what binds the custom domain to the Pages site.
if [ -n "$CUSTOM_DOMAIN" ]; then
  echo "$CUSTOM_DOMAIN" > "$WORKDIR/CNAME"
  log "CNAME set to $CUSTOM_DOMAIN"
fi

# -----------------------------------------------------------------------------
# Publish
# -----------------------------------------------------------------------------
cd "$WORKDIR"
git config user.email "honeypot@localhost"
git config user.name  "honeypot-report"
git add -A

if git diff --cached --quiet; then
  log "No changes since last run — nothing to publish"
  exit 0
fi

git commit --quiet -m "report: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git push --quiet origin "$BRANCH"
log "Published to $BRANCH"
[ -n "$CUSTOM_DOMAIN" ] && log "Live at https://$CUSTOM_DOMAIN"
exit 0
