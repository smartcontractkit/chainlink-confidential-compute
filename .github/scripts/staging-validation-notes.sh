#!/usr/bin/env bash
# Prints a "Staging validation" release-notes section built from the
# staging-validation/*.md files that differ between two refs.
#
# Usage: staging-validation-notes.sh PREV REF
#   e.g. staging-validation-notes.sh origin/release/1.4.9 release/1.4.10
set -euo pipefail

prev="${1:?usage: $0 PREV REF}"
ref="${2:?usage: $0 PREV REF}"
dir="staging-validation"

files=()
while IFS= read -r f; do
  case "$(basename "$f")" in
    TEMPLATE.md | README.md) ;;
    *) files+=("$f") ;;
  esac
done < <(git diff --name-only --diff-filter=AM "$prev" "$ref" -- "${dir}/*.md")

echo "## Staging validation"
echo
if [ "${#files[@]}" -eq 0 ]; then
  echo "_No staging validation files changed in this release._"
  exit 0
fi

for f in "${files[@]}"; do
  content="$(git show "${ref}:${f}" | perl -0777 -pe 's/<!--.*?-->//gs')"
  title="$(printf '%s\n' "$content" | sed -n 's/^# \(Staging validation: \)\{0,1\}//p' | head -1)"
  pr="$(git log -1 --format=%s "$ref" -- "$f" | grep -oE '\(#[0-9]+\)$' | tr -d '()' || true)"
  echo "### ${title:-$(basename "$f" .md)}${pr:+ ($pr)}"
  echo
  # Drop the H1 and empty sections, demote "## X" to bold labels.
  printf '%s\n' "$content" |
    awk '
      /^# / { next }
      /^## / { sub(/^## /, ""); pending = "**" $0 "**"; next }
      NF && pending != "" { print pending; print ""; pending = "" }
      pending == "" { print }
    ' | cat -s | sed '/./,$!d'
  echo
done
