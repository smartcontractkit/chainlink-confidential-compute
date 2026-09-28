# Confidential-workflows load harness

Standalone load driver for the confidential-workflows enclaves on a live
(staging) DON. It fires HTTP-triggered confidential workflows by POSTing
`workflows.execute` JSON-RPC to the gateway user server, then measures
completion out-of-band. It points at an already-deployed DON and skips unless
the required env is set, so it never runs in normal CI.

## Why multiple workflows

The gateway rate-limits `workflows.execute` **per workflow** (burst ~3, refill
1 token / 30s, per gateway node). So a single workflow can't be driven hard.
Deploy N copies (distinct config `variant` -> distinct workflowID -> own bucket)
and round-robin across their IDs via `LOADTEST_WORKFLOW_IDS`.

## Two-phase measurement

The gateway ACK is async (returns `ACCEPTED` + an execution ID, not the result),
so:
1. **Fire** (`TestBurst_Concurrent`): send N concurrent requests, record ACK
   latency + gateway-returned exec IDs + the send-window start (UTC).
2. **Tally** (out of band): `cre execution list <name> --json` filtered to the
   send window -> SUCCESS/FAILURE counts, completion latency (Finished-Started),
   effective throughput. (`TRIGGERED` siblings are a trigger-delivery artifact;
   count only SUCCESS.)

## Run

```
LOADTEST_GATEWAY_URL="https://<gateway-user-server>/" \
CRE_LOADTEST_PRIVATE_KEY="0x<trigger-key>" \
LOADTEST_WORKFLOW_OWNER="0x<owner-lowercase>" \
LOADTEST_WORKFLOW_IDS="<id0>,<id1>,..." \
BURST_N=30 \
go test -count=1 -run TestBurst_Concurrent -v ./loadtest/
```

`TestLoad_ConfidentialWorkflows_HTTPTrigger` is the stepped-ramp variant (capped
`LOADTEST_MAX_RPS`, self-aborts on rolling failure rate).

## Watching enclave memory

Set `LOADTEST_MEMORY_URLS` (comma-separated enclave `/memory` URLs) and
`LOADTEST_MEMORY_POLL_SECONDS` to sample `usedMB` through the burst + execution
window. The enclave `/memory` is on the host behind the VPC-internal griddle
URL, so point these at a reachable address (e.g. a `kubectl port-forward` to the
`enclave-workflows` host-container).

## Safety

The staging DON/gateway/vault/enclaves are shared. Keep the rate/concurrency
capped and watch the enclave pods, concurrent load can wedge an enclave that
lacks admission control. Confirm with the CRE/privacy owners before driving load.
