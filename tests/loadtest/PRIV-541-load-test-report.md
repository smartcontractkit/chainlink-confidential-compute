# Confidential Workflows Load Test (PRIV-541)

A single ~26-way burst wedged the staging confidential-workflows enclaves with
zero auto-recovery. That is the headline. Everything below is how we found it,
what we fixed, and what the enclaves can actually do now.

_Staging, us-west-2. Enclaves `enclave-workflows-1` / `-2`, each an AWS Nitro
VM with 2048 MiB on a `c5.xlarge`. Workload: an HTTP-triggered workflow whose
handler runs inside the TEE (`cre.HandlerInTee`, Nitro us-west-2)._

## Setup

The workflow is minimal on purpose: an `http.Trigger` fires it, the handler
runs in the enclave and returns a timestamp. A standalone Go driver
(`tests/loadtest`, no wasp dependency) signs the `workflows.execute` JSON-RPC
and POSTs it to the gateway user server; it times ACKs and we read true
outcomes from `cre execution`. Enclave selection is round-robin: each request
is pinned to one enclave by `sha256(workflowExecutionID) mod N`, and every F+1
quorum node converges on the same enclave for a given execution.

## The gateway speed bump

You cannot load one workflow. The gateway rate-limits `workflows.execute`
per-workflow at `Rate(rate.Every(30s), 3)`, so burst 3 plus a trickle, per
gateway node. Two gateway nodes means roughly 6 accepted at once for a single
workflow, then `-32002 rate limit exceeded`. This has nothing to do with
enclave capacity; it is per-workflow abuse protection.

The fix is a harness: deploy many copies of the same binary with a distinct
`variant` in config (distinct config hash to distinct workflowID to distinct
rate bucket), and round-robin the driver across them. N workflows fired one hit
each equals N real concurrent enclave executions, no throttle.

## Finding 1: the enclave wedges, and nothing brings it back

Minimal-workflow concurrency sweep (pre-fix, 2048 MiB enclaves):

| concurrent | result |
|---|---|
| 5, 8, 10, 12, 14, 16, 18, 20, 22, 24 | 100% SUCCESS |
| 26 | clean (26/26) |
| 28 | wedge: 15 SUCCESS / 13 FAILURE, host crash-loop |

A wedged enclave is `RUNNING` per `nitro-cli` but unresponsive on vsock. The
host container's `/publicKeys` probe fails, the pod sits at 2/3, the host
crash-loops forever, and nothing re-launches the VM. Recovery was a manual
`kubectl delete pod`.

Root cause, from the code: the enclave server had no admission control. Every
request spun up a fresh wasmtime WASM instance in a fixed 2048 MiB VM with no
cap. Enough concurrent instances exhaust memory, the VM goes unresponsive, and
because the launcher only checks `describe-enclaves` (VM lifecycle, not
responsiveness), it never notices. Node-side limits (`ExecutionConcurrency=5`,
etc.) are per-node and do not bound the aggregate landing on two shared
enclaves.

## Finding 2: the vault path wedges sooner

Point the workflow at the VaultDON (`rt.GetSecret` on every execution, the same
`infurasecret` the canary uses) and the picture changes:

| concurrent | result |
|---|---|
| 13 | 13/13 SUCCESS |
| 20 | wedge: all "no live enclaves" |

20 wedged where the minimal workflow held 26. Two reasons, both confirmed in
code. A `GetSecret` execution holds its enclave slot for the entire relay to
VaultDON round-trip (the WASM is suspended, its 128 MB linear-memory
reservation resident the whole time), several seconds instead of one. And it
does real extra work the minimal one never touches: a Nitro attestation, then
NaCl per-share decryption plus a TDH2 threshold-combine of the returned secret,
with the buffers to match. Bigger block, held longer.

(Caveat that muddied this number: `enclave-workflows-2` was chronically flapping
at the time, so those ~20 landed on effectively one enclave. Not a clean
two-enclave figure.)

## Finding 3: `/memory` was measuring the wrong memory

We built a `/memory` poller into the driver to watch the wedge coming. It never
moved. The endpoint reported `usedMB` from Go's `runtime/metrics`, but the WASM
runs in wasmtime, which allocates its linear memory in native/CGO memory,
outside Go's accounting. So the endpoint was blind to the allocations that
actually drive the wedge.

Fixed in CCC #22: an additive `rssMB` field (process RSS from
`/proc/self/status`, which includes the wasmtime native memory). Live numbers
after deploy: `{"usedMB":376,"rssMB":678}` at idle. RSS is ~2x the Go number,
and per-execution cost is about **63 MB RSS** including wasmtime, versus the
~16 MB Go-side we were staring at before. That 63 MB is the number that matters.

## The fixes

| PR | what | status |
|---|---|---|
| CCC #4 | Enclave admission control: cap concurrent executions at a memory-derived limit (`memlimit`, `(T-reserve)/128`), shed with 429 instead of OOMing | merged, live |
| CCC #22 | `/memory` reports `rssMB` (real footprint, incl. wasmtime) | merged, live |
| cc-infra #69 | Self-heal: liveness+startup probe and `preStop` on the launcher container, so a wedge restarts and re-launches the VM | merged, live |
| CCC #6 | The load harness (burst + stepped ramp), `/memory` poller, RUNBOOK | open |

The cap is per-app in code, no infra config: the enclave introspects its own
memory at boot and derives the limit. `run.sh` stayed untouched; the self-heal
moved into the chart as a probe plus `preStop` (the VM lives at the hypervisor
level, so killing the container does not stop it, `preStop` terminates it by id
so the restart gets CID 16 back).

## Validation on staging

Staging now runs enclave `sha-358ac81`, which carries all of the above. Both
enclaves healthy, `-2` no longer flapping. The test that matters:

**20 concurrent, both enclaves healthy: 19 SUCCESS, 1 capacity-shed, 0 wedge.**

The one it could not take came back "enclave at capacity: too many concurrent
executions" instead of taking the pool down. `rssMB` peaked at 1377 / 1395 of
2048, it climbed hard and the cap held it clear of the ~1900 danger zone. Both
resilience PRs are live and both did their job: #4 prevented the wedge, and #69
(which we caught being applied mid-test) is on the pods.

## What a shed looks like to the DON (the rough edge)

The enclave surviving is not the same as the DON handling it well. Trace the
shed downstream and it gets rough:

- The app returns a 429, but the enclave server hardcodes every app error to
  **HTTP 500** (`server.go:695` ignores `execErr.Code`). The 429 is lost; only
  the message string and the `execution_rejected_at_capacity` metric survive.
- The pool does not fail over. It fails the batch. And since all quorum nodes
  deterministically hit the same enclave, an at-capacity enclave sheds the whole
  quorum for that execution at once.
- The node classifies the shed as a generic system error and **retries it, 3x,
  exponential backoff, no jitter**. All quorum nodes retry the same still-
  saturated enclave in lockstep, so the retries re-collide and re-shed. After
  three, the execution fails.

So a shed today is a mild retry amplifier: one rejection becomes three more
requests onto the saturated enclave. #4 stops the enclave falling over, but the
user still sees a failed execution, not graceful backpressure.

Two small changes would close most of that gap: honor `execErr.Code` in the
server so a real 429 reaches the node (one line), and give the node status-aware
backoff with jitter so quorum retries de-synchronize. Pool failover to a
different enclave would help too, but it breaks the F+1 same-enclave convergence,
so it is not worth it.

## Throughput

Measured execution durations under the 20-burst: 4s to 20s, mean ~12s (versus
~2-4s for a lone warm fire). The vault path stretches under load because the
shared relay to VaultDON round-trip gets contended.

| workload | concurrency/enclave | service time | per enclave | aggregate (2 enclaves) |
|---|---|---|---|---|
| vault (GetSecret) | ~10 | ~12s | ~0.8-1 exec/s | ~1.7-2/s |
| minimal (no secret) | ~10 | ~1-2s | ~5-7 exec/s | ~10-14/s |

For the vault path the real ceiling is the relay/VaultDON, not the enclave, so
adding enclaves helps that workload less than the raw number suggests. The
minimal path is enclave-bound and scales with enclaves.

## Open items

- **429 propagation + jittered node backoff.** The highest-leverage pair. Turns
  "shed to retry-storm to fail" into "shed to spaced retry to likely succeeds."
- **Tune the cap.** Only 1 of 20 shed, so the effective cap is more generous
  than the `(T-1024)/128 = 7-8` estimate (~10/enclave ran fine). The 128 MB
  denominator is conservative against the measured 63 MB RSS/exec; read the
  enclave startup log for the derived value and retune.
- **4G enclaves (cc-infra #72, open).** `c5.2xlarge` + 4096 MiB roughly triples
  the memory-derived cap, for the minimal-path workloads that are enclave-bound.
- **The `-2` flap.** It looks fixed after the redeploy, but it flapped for days;
  worth confirming it was the pod and not the node.

The enclave no longer falls over. Whether the DON handles a shed gracefully is a
different question, and the answer right now is: not yet.
