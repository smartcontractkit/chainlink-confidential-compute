# Grafana Dashboards

Dashboard JSON files for Confidential HTTP, stored here for version control.

| File | Dashboard |
|------|-----------|
| `business-logic.json` | Confidential HTTP Business Logic Dashboard |
| `enclave-resources.json` | Confidential HTTP Enclave Hardware Dashboard |

## Updating a dashboard from JSON

Grafana does not have a direct "import JSON" for existing dashboards. To bulk-edit:

1. Open the dashboard in Grafana and click **Edit** (top-right corner).
2. Once in edit mode, a **Settings** button appears next to "Exit edit" in the top bar.
3. In the Settings view, select the **JSON Model** tab (last tab on the left sidebar).
4. Replace the JSON with the contents of the file from this folder, then click **Save dashboard**.

When making manual changes in Grafana, copy the updated JSON Model back into this folder and commit it.

## Scripted deployment

`deploy.sh` can push dashboard JSON files to Grafana via the API:

```bash
GRAFANA_URL=https://<your-grafana-host> GRAFANA_TOKEN=<token> ./dashboards/deploy.sh
```

The token is a Grafana service account token, created under Administration > Service accounts with Editor role.
