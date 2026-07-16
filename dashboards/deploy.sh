#!/usr/bin/env bash
set -euo pipefail

# Usage: ./deploy.sh [file.json ...]
# If no files specified, deploys all JSON files in this directory.
#
# Requires:
#   GRAFANA_URL   - e.g. https://<your-grafana-host>
#   GRAFANA_TOKEN - Grafana service account token

if [[ -z "${GRAFANA_URL:-}" || -z "${GRAFANA_TOKEN:-}" ]]; then
  echo "Error: GRAFANA_URL and GRAFANA_TOKEN must be set" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

files=("$@")
if [[ ${#files[@]} -eq 0 ]]; then
  files=("$SCRIPT_DIR"/*.json)
fi

for file in "${files[@]}"; do
  title=$(jq -r '.title' "$file")
  uid=$(jq -r '.uid' "$file")
  echo "Deploying: $title (uid: $uid) ..."

  payload=$(jq -n --slurpfile dashboard "$file" '{
    dashboard: $dashboard[0],
    overwrite: true
  }')

  response=$(curl -s -w "\n%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${GRAFANA_TOKEN}" \
    "${GRAFANA_URL}/api/dashboards/db" \
    -d "$payload")

  http_code=$(echo "$response" | tail -1)
  body=$(echo "$response" | sed '$d')

  if [[ "$http_code" == "200" ]]; then
    echo "  OK: $(echo "$body" | jq -r '.url')"
  else
    echo "  FAILED ($http_code): $body" >&2
    exit 1
  fi
done
