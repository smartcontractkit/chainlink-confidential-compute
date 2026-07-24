# Confidential-workflows load test — operator runbook (staging)

End-to-end commands to deploy the load workflow, drive it, and check/recover the
enclaves. Companion to `README.md` (which documents the driver's env knobs).

> Secrets are referenced by **source**, never inlined. Do not paste key material
> into this file or into shell history you keep.

## 0. Setup

```bash
# Owner deploy key — /tmp/chris.env.key holds `CRE_ETH_PRIVATE_KEY=<64hex>`
# (env-file format; owner address 0xbb62d7…). Extract the value:
export K=$(cut -d= -f2 /tmp/chris.env.key | tr -d '[:space:]')

export CRE_CLI_ENV=STAGING          # staging environment (requires tailscale/VPN up)

# Trigger signing key: the load-test secp256k1 key (1Password "CRE Staging
# Canary Workflows"). Its address 0xd11673… is the workflow's on-chain AuthorizedKey
# and is committed as `authKey` in config.staging.json.
export TRIG=<load-test-private-key>         # 0x-prefixed; keep OUT of git

export GW=https://cre-gateway-one-zone-a.main.stage.cldev.sh/
export OWNER=0xbb62d78235e4b770618d06bc2fa71daca6b7dc0a   # must be lowercase

# Repo paths (adjust to your checkout)
export WFDIR=<chainlink-deployments>/domains/cre/pkg/workflows/canary
export DRV=<chainlink-confidential-compute>/tests           # this module

cre whoami        # confirm "Deploy Access: Enabled"; refresh with `cre login`
```

## 1. Deploy a workflow

The CLI is **directory-based**: it reads `confidential_workflows_load/workflow.yaml`
(`workflow-name`) and `config.staging.json`. For a distinct workflowID, set a
distinct `variant` in the config (the workflow ignores it; it only changes the
config hash → the ID).

```bash
cd "$WFDIR"
sed -i '' 's|workflow-name: ".*"|workflow-name: "cn_cwload_vault"|' \
    confidential_workflows_load/workflow.yaml

CRE_ETH_PRIVATE_KEY=$K cre workflow deploy confidential_workflows_load \
    --target staging-zone-a --yes
# prints "Workflow hash: <64hex>" = the workflowID you fire against
```

Delete (frees a slot — the DON caps at **50/50 active workflows**):

```bash
CRE_ETH_PRIVATE_KEY=$K cre workflow delete confidential_workflows_load \
    --target staging-zone-a --yes
```

## 2. Seed the VaultDON secret (once per owner)

`GetSecret` is **owner-scoped**. Seed `infurasecret` under our owner; a dummy
value is fine (the workflow fetches it but never reads the value).

```bash
cat > /tmp/loadtest-secrets.yaml <<'EOF'
secretsNames:
    infurasecret:
        - INFURA_API_KEY
EOF

cd "$WFDIR"
INFURA_API_KEY="loadtest-dummy-not-a-real-key" CRE_ETH_PRIVATE_KEY=$K \
  cre secrets create /tmp/loadtest-secrets.yaml \
      --target staging-zone-a --yes --non-interactive
# other verbs: cre secrets list | update | delete
```

## 3. Trigger the workflow (fire)

The standalone Go driver (`TestBurst_Concurrent`) signs the `workflows.execute`
JSON-RPC with `$TRIG` and POSTs to the gateway. `BURST_N` = concurrent requests;
`LOADTEST_WORKFLOW_IDS` = comma-separated IDs to round-robin across (1 per
workflow avoids the per-workflow rate limit).

```bash
cd "$DRV"
go test -c -o /tmp/loadtest.bin ./loadtest/     # prebuild (heavy module)

LOADTEST_GATEWAY_URL="$GW" \
CRE_LOADTEST_PRIVATE_KEY="$TRIG" \
LOADTEST_WORKFLOW_OWNER="$OWNER" \
LOADTEST_WORKFLOW_IDS="<id1>,<id2>,..." \
BURST_N=20 \
/tmp/loadtest.bin -test.run TestBurst_Concurrent -test.v -test.timeout 5m
```

Per-request output: `http=200 exec=0x<id>` (accepted), `http=429` (per-workflow
rate cap), `http=400 Workflow not found` (fresh-deploy gateway sync lag — refire
after a minute). Single fire = `BURST_N=1` with one ID.

## 4. Check an execution's outcome

```bash
cd "$WFDIR"
CRE_ETH_PRIVATE_KEY=$K cre execution status <exec-id-no-0x>  # SUCCESS/FAILURE + errors
CRE_ETH_PRIVATE_KEY=$K cre execution logs   <exec-id-no-0x>  # per-node incl. "getsecret ok"
CRE_ETH_PRIVATE_KEY=$K cre execution list   cn_cwload_vault  # by workflow name
```

## 5. Enclave health + restart (`kubectl`, namespace `enclave`)

Requires a valid griddle SSO token:
`unset AWS_PROFILE; aws sso login --sso-session griddle-session`
(context `griddle-platform-privacy-stage-teamprivacyengineer`).

```bash
kubectl get pods -n enclave | grep workflows
# healthy = 3/3 Running. Wedged = 2/3 CrashLoopBackOff (host-container).

# restart both (Deployment recreates terminate-first, ~2 min to 3/3):
kubectl delete pod enclave-workflows-1-<hash> enclave-workflows-2-<hash> -n enclave

# which image/version is live:
kubectl get pods -n enclave -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .spec.containers[*]}  {.image}{"\n"}{end}{end}' | grep -E "workflows|sha-"
```

## Gotchas

- **Staging RPC `rpcs.main.stage.cldev.sh` is flaky** (EOF/timeout ~every other
  call) → wrap `cre workflow deploy|delete` and `cre secrets` in a retry loop.
- The `cre` session token expires (~8h) → long deploy loops die mid-run; re-`cre login`.
- DON **50/50** active-workflow cap; **per-workflow** gateway rate limit
  (~burst-3-per-gateway-node) → use many workflows × 1 trigger for real concurrency.
- Firing needs only `$TRIG` + gateway (no `cre login`); status/deploy/secrets
  need the `cre` session.
- **Vault-path executions hold their enclave slot for the whole GetSecret
  round-trip** (enclave → relay DON → VaultDON, seconds), so they saturate the
  enclaves at lower concurrency than a minimal (`rt.Now()`) body. Observed on
  staging (2-enclave, pre-admission-control build): 13 concurrent clean, 20
  wedged (`no live enclaves`), recover via the restart above.
