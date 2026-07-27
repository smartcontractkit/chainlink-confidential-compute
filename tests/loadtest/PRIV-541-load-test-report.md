# Confidential Workflows Load Test (PRIV-541)

A single ~26-way burst wedged the staging confidential-workflows enclaves with
zero auto-recovery. That was the headline. We fixed it, and here is what the
enclaves can now do.

Staging, us-west-2. Enclaves `enclave-workflows-1` / `-2`, AWS Nitro, 2048 MiB,
`c5.xlarge`. Workload: an HTTP-triggered workflow whose handler runs in the TEE.
Driver: standalone Go (`tests/loadtest`), signs `workflows.execute` and POSTs to
the gateway; outcomes read from `cre execution`. Each request is pinned to one
enclave by `sha256(execID) mod N`, and all F+1 quorum nodes converge on it.

## Gateway limit forces a harness

You cannot load one workflow: the gateway rate-limits `workflows.execute`
per-workflow (burst 3 + trickle, per gateway node, ~6 accepted at once). So we
deploy many copies with distinct config (distinct workflowID to distinct rate
bucket) and round-robin across them. N workflows x 1 hit = N real concurrent
enclave executions.

## Finding 1: the enclave wedges, nothing recovers it

Minimal-workflow sweep, pre-fix:

| concurrent | result |
|---|---|
| 5 to 26 | 100% SUCCESS |
| 28 | wedge (15 SUCCESS / 13 FAILURE, host crash-loop) |

A wedged enclave is `RUNNING` per `nitro-cli` but dead on vsock. Pod sits 2/3,
host crash-loops, no VM re-launch. Recovery was a manual `kubectl delete pod`.
Root cause: no admission control, so N concurrent wasmtime instances exhaust the
fixed 2048 MiB and the VM goes unresponsive.

## Finding 2: the vault path wedges sooner

Add `rt.GetSecret` (VaultDON) to every execution:

| concurrent | result |
|---|---|
| 13 | 13/13 SUCCESS |
| 20 | wedge (all "no live enclaves") |

A GetSecret execution holds its enclave slot for the whole relay-to-VaultDON
round-trip and does a TDH2 decrypt on top. Bigger block, held longer. (This ~20
landed on effectively one enclave; `-2` was flapping at the time.)

## Finding 3: `/memory` measured the wrong memory

`usedMB` came from Go's `runtime/metrics`, blind to the wasmtime WASM memory
(native/CGO). Fixed in CCC #22 with an additive `rssMB` (process RSS). Live:
`{"usedMB":376,"rssMB":678}` idle. RSS is ~2x the Go number; per-execution cost
is ~**63 MB RSS** including wasmtime, vs the ~16 MB Go-side we were watching.

## Fixes

| PR | what | status |
|---|---|---|
| CCC #4 | Admission control: cap concurrent execs at `(T-reserve)/128`, shed with 429 instead of OOMing | live |
| CCC #22 | `/memory` reports real footprint (`rssMB`) | live |
| cc-infra #69 | Self-heal: probe + `preStop` on the launcher, restart + re-launch a wedged VM | live |
| CCC #6 | Load harness (burst + stepped ramp), `/memory` poller, RUNBOOK, this report | open |

## Validation on staging (`sha-358ac81`, all fixes live)

**20 concurrent, both enclaves healthy: 19 SUCCESS, 1 capacity-shed, 0 wedge.**
The one it could not take returned "enclave at capacity" instead of collapsing.
`rssMB` peaked 1377 / 1395 of 2048, clear of the ~1900 danger zone. #4 prevented
the wedge; #69 (caught being applied mid-test) is on the pods.

## What a shed looks like to the DON (the rough edge)

The enclave surviving is not the DON handling it well:

- The app returns 429, but the server hardcodes every app error to **500**
  (`server.go:695` ignores `execErr.Code`). The 429 is lost.
- No pool failover, and all quorum nodes hit the same enclave, so a shed fails
  the whole quorum for that execution.
- The node retries the shed **3x, exponential backoff, no jitter**, in lockstep
  across quorum nodes, so retries re-collide on the saturated enclave, then fail.

So a shed is a mild retry amplifier today. Two small fixes close most of it:
honor `execErr.Code` (one line) so a real 429 reaches the node, and give the
node jittered, status-aware backoff.

## Throughput (measured; exec 4-20s under load, mean ~12s)

| workload | concurrency/enclave | per enclave | aggregate |
|---|---|---|---|
| vault (GetSecret) | ~10 | ~0.8-1 exec/s | ~1.7-2/s |
| minimal (no secret) | ~10 | ~5-7 exec/s | ~10-14/s |

Vault-path is gated by the shared relay/VaultDON, not the enclave, so more
enclaves help it less. The minimal path is enclave-bound.

## Open items

- **429 propagation + jittered node backoff.** Turns "shed to retry-storm" into
  "shed to spaced retry."
- **Tune the cap.** Only 1/20 shed, so the effective cap beat the `~7-8`
  estimate; the 128 MB denominator is conservative vs the measured 63 MB/exec.
- **4G enclaves (cc-infra #72, open)** for enclave-bound workloads.

The enclave no longer falls over. Whether the DON handles a shed gracefully is a
different question, and right now the answer is: not yet.
