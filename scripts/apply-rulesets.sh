#!/usr/bin/env bash
# Applies the server-side GitHub rulesets in .github/rulesets/*.json to this
# repository (create or update by name), then prints the rules GitHub reports
# as active for main and develop.
#
# Requirements:
#   - GitHub CLI authenticated as a repository admin: `gh auth login`
#   - A plan that enforces rulesets on this repository. Private repositories
#     owned by a personal account need GitHub Pro; organization-owned private
#     repositories need GitHub Team or Enterprise. Public repositories: any plan.
#
# Usage: scripts/apply-rulesets.sh [owner/repo]
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
echo "Repository: $REPO"

for file in .github/rulesets/*.json; do
  name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$file")"
  id="$(gh api "repos/$REPO/rulesets" --jq ".[] | select(.name == \"$name\") | .id" 2>/dev/null || true)"
  if [ -n "$id" ]; then
    gh api --method PUT "repos/$REPO/rulesets/$id" --input "$file" >/dev/null
    echo "updated  ruleset '$name' (id $id)"
  else
    gh api --method POST "repos/$REPO/rulesets" --input "$file" >/dev/null
    echo "created  ruleset '$name'"
  fi
done

echo
for branch in main develop; do
  echo "Active rules on $branch:"
  gh api "repos/$REPO/rules/branches/$branch" --jq '.[] | "  - \(.type)"'
done
