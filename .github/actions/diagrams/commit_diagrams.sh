#!/usr/bin/env bash
# Commit regenerated diagram files to a branch through the GitHub contents API.
#
# Pushing over git with GITHUB_TOKEN produces unsigned commits. The contents
# API commits with GitHub's web-flow key instead, so the result shows as
# Verified. One commit per file is the cost of that.
#
# Usage: commit_diagrams.sh <branch> <path>...
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN must be set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY must be set}"

branch="${1:?branch required}"
shift

if [ "$#" -eq 0 ]; then
  echo "nothing to commit"
  exit 0
fi

for path in "$@"; do
  # Percent-encode each path segment; runbook filenames contain spaces.
  encoded=$(jq -rn --arg p "$path" '$p | split("/") | map(@uri) | join("/")')

  # An existing file needs its current blob sha to be replaced rather than
  # rejected as a conflict.
  sha=$(gh api "repos/$GITHUB_REPOSITORY/contents/$encoded?ref=$branch" \
    --jq '.sha' 2>/dev/null || true)

  jq -n \
    --arg message "chore(diagrams): regenerate ${path##*/}" \
    --arg content "$(openssl base64 -A -in "$path")" \
    --arg branch "$branch" \
    --arg sha "$sha" \
    '{message: $message, content: $content, branch: $branch}
     + (if $sha == "" then {} else {sha: $sha} end)' \
    | gh api -X PUT "repos/$GITHUB_REPOSITORY/contents/$encoded" --input - \
      --jq '"\(.commit.sha[0:8]) verified=\(.commit.verification.verified)"' \
    | xargs -I{} echo "  committed $path as {}"
done
