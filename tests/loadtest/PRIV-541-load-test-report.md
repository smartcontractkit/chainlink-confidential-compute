# Confidential Workflows Load Test (PRIV-541)

The staging confidential-workflows enclaves now shed load instead of falling
over, and recover themselves if they ever do. Here is where things stand.

Staging, us-west-2. Enclaves `enclave-workflows-1` / `-2`, AWS Nitro, 2048 MiB,
`c5.xlarge`, both healthy. Running `sha-358ac81`, which carries admission
control, self-heal, and the RSS `/memory` endpoint.

## What the enclaves do under load

**Validated: 20 concurrent, both enclaves healthy: 19 SUCCESS, 1 capacity-shed,
0 wedge.** The one execution the enclave could not take returned "enclave at
capacity" instead of collapsing the pool. `rssMB` peaked 1377 / 1395 of 2048,
well clear of the ~1900 danger zone. Admission control (CCC #4) held it; the
self-heal (cc-infra #69) is on the pods as a backstop.

Throughput (measured; execution 4-20s under load, mean ~12s):

| workload | concurrency/enclave | per enclave | aggregate |
|---|---|---|---|
| vault (GetSecret) | ~10 | ~0.8-1 exec/s | ~1.7-2/s |
| minimal (no secret) | ~10 | ~5-7 exec/s | ~10-14/s |

Vault-path throughput is gated by the shared relay/VaultDON round-trip, not the
enclave, so adding enclaves helps it less. The minimal path is enclave-bound and
scales with enclaves. Per-execution cost is ~63 MB RSS including wasmtime.

## The remaining gap: a shed is not yet graceful

The enclave surviving is not the same as the DON handling it well. Downstream:

- The app returns 429, but the server hardcodes every app error to **500**
  (`server.go:695` ignores `execErr.Code`). The 429 is lost.
- No pool failover, and all quorum nodes hit the same enclave, so a shed fails
  the whole quorum for that execution.
- The node retries the shed **3x, exponential backoff, no jitter**, in lockstep
  across quorum nodes, so retries re-collide on the saturated enclave, then fail.

So a shed today is a mild retry amplifier, not backpressure. Two small fixes
close most of it: honor `execErr.Code` (one line) so a real 429 reaches the
node, and give the node jittered, status-aware backoff.

## Open items

- **429 propagation + jittered node backoff.** Turns "shed to retry-storm" into
  "shed to spaced retry."
- **Tune the cap.** Only 1/20 shed, so the effective cap beat the `~7-8`
  estimate; the 128 MB denominator is conservative vs the measured 63 MB/exec.
  Read the enclave startup log for the derived value.
- **4G enclaves (cc-infra #72, open)** for the enclave-bound workloads.

## Background: what was broken, and the fixes

A single ~26-way burst used to wedge the enclaves with zero auto-recovery. A
wedged enclave is `RUNNING` per `nitro-cli` but dead on vsock: pod stuck 2/3,
host crash-loops, no VM re-launch, recovery was a manual `kubectl delete pod`.
Root cause: no admission control, so N concurrent wasmtime instances exhausted
the fixed 2048 MiB and the VM went unresponsive.

The sweeps that found it:

| workload | held | wedged |
|---|---|---|
| minimal (no secret) | 26 concurrent | 28 |
| vault (GetSecret) | 13 concurrent | 20 |

The vault path wedged sooner because a `GetSecret` execution holds its enclave
slot for the whole relay-to-VaultDON round-trip and adds a TDH2 decrypt: bigger
block, held longer. (That ~20 landed on effectively one enclave; `-2` was
flapping then, since fixed.)

`/memory` was no help at first: `usedMB` came from Go's `runtime/metrics`, blind
to the wasmtime WASM memory (native/CGO). CCC #22 added `rssMB` (process RSS),
which is what actually tracks the wedge.

Fixes, all merged and live except the harness:

| PR | what | status |
|---|---|---|
| CCC #4 | Admission control: cap concurrent execs, shed 429 instead of OOMing | live |
| CCC #22 | `/memory` reports real footprint (`rssMB`) | live |
| cc-infra #69 | Self-heal: probe + `preStop`, restart a wedged VM | live |
| CCC #6 | Load harness, `/memory` poller, RUNBOOK, this report | open |

Also worth knowing: you cannot load a single workflow (gateway rate-limits it to
~6 concurrent), so the harness deploys many copies with distinct config and
round-robins across them, N workflows x 1 hit = N real concurrent executions.

The enclave no longer falls over. Whether the DON handles a shed gracefully is a
different question, and right now the answer is: not yet.
