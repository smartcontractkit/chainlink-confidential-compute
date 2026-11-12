#!/usr/bin/env bash
# Verifies the current branch adds or updates a staging-validation/*.md file
# (relative to BASE) and that its required sections have content.
#
# Usage: check-staging-validation.sh [BASE]   (default: origin/main)
set -euo pipefail

base="${1:-origin/main}"
dir="staging-validation"
required=("Change" "Validation steps" "Success criteria" "Edge cases and risks")

files=()
while IFS= read -r f; do
  case "$(basename "$f")" in
    TEMPLATE.md | README.md) ;;
    *) files+=("$f") ;;
  esac
done < <(git diff --name-only --diff-filter=AM "${base}...HEAD" -- "${dir}/*.md")

if [ "${#files[@]}" -eq 0 ]; then
  echo "::error::No ${dir}/*.md file added or modified in this PR."
  echo "Run 'make staging-validation', fill in the generated file, and commit it."
  echo "See ${dir}/README.md. Docs/CI/test-only PRs can use the 'no-staging-validation' label."
  exit 1
fi

# Prints the body of "## <heading>" with HTML comments and blank lines removed.
section_body() {
  perl -0777 -pe 's/<!--.*?-->//gs' "$1" |
    awk -v h="## $2" '
      $0 == h { on = 1; next }
      on && /^## / { exit }
      on && NF { print }
    '
}

failed=0
for f in "${files[@]}"; do
  echo "Checking ${f}"
  for h in "${required[@]}"; do
    if ! grep -qxF "## ${h}" "$f"; then
      echo "::error file=${f}::Missing required section '## ${h}'."
      failed=1
    elif [ -z "$(section_body "$f" "$h")" ]; then
      echo "::error file=${f}::Section '## ${h}' is empty."
      failed=1
    fi
  done
done

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "OK staging validation present: ${files[*]}"
