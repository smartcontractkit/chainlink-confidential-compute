# Confidential Workflows Load Test (PRIV-541)

## Current state (staging)

- Enclaves `enclave-workflows-1` / `-2`: AWS Nitro, **11 GiB**, `c5.2xlarge`,
  us-west-2, running `sha-358ac81`. Both healthy.
- Live: admission control (memory-derived cap, ~78/enclave at 11 GiB), self-heal
  (probe + `preStop`), and RSS `/memory` (`rssMB`). Sizing came from cc-infra #77.
- The enclave is no longer the bottleneck for the secret-fetch workload; the
  shared VaultDON is (below).

## The ceiling is the VaultDON, ~24 concurrent secret fetches (2026-07-29)

Ramped a vault workflow (`GetSecret` per execution) across 20 workflows,
measuring true SUCCESS per burst:

| achieved concurrency | success rate |
|---|---|
| <=20 | 100% |
| ~24 | 91% |
| ~28 | 85% |
| ~35 | 77% |

- Clean to ~20; first drops at **~24-25**; absolute successful throughput
  **plateaus at ~24** (extra requests just fail past there).
- This is **aggregate across both enclaves** (~12/enclave), all funneling to the
  one shared VaultDON. It is **not per-enclave and does not scale with enclaves**,
  the VaultDON saturates at ~24 total regardless of how many enclaves front it.
- Failure is always `relay quorum unreachable: errors=5` (relay nodes erroring,
  not timing out). The relay just proxies to the VaultDON (`handler.go:291`), so
  it is **vault-first**: the VaultDON saturates, the relay-quorum failure is the
  downstream symptom. (Relay-vs-vault confirmation needs relay-node Loki logs.)
- To lift it: scale the VaultDON, and raise the gateway rate limit for our owner
  (its global cap throttles achieved concurrency to ~28-35/burst, so we can
  barely push past the knee anyway).

## Throughput

Vault (GetSecret) execution is 4-20s under load (mean ~12s, the relay/vault
round-trip); the minimal no-secret path is ~1-2s (pure enclave).

| workload | bound by | ceiling |
|---|---|---|
| vault (GetSecret) | shared VaultDON | ~24 concurrent aggregate, ~2/s |
| minimal (no secret) | enclave (CPU/mem) | per-enclave, scales with enclaves (not yet re-measured at 11 GiB) |

## The remaining gap: a shed is not yet graceful

When an enclave *does* hit its own cap and sheds:

- The app returns 429 but the server hardcodes every app error to **500**
  (`server.go:695`), the 429 is lost.
- No pool failover, and all quorum nodes hit the same enclave, so a shed fails
  the whole execution.
- The node retries **3x, exponential backoff, no jitter**, in lockstep, so
  retries re-collide, then fail.

Two small fixes: honor `execErr.Code` (one line) so a real 429 reaches the node,
and give the node jittered, status-aware backoff. Same lockstep-retry problem
amplifies the VaultDON failures above.

## Fixes that got us here

| PR | what | status |
|---|---|---|
| CCC #4 | Admission control: cap concurrent execs, shed instead of OOMing | live |
| CCC #22 | `/memory` reports real footprint (`rssMB`, incl. wasmtime) | live |
| cc-infra #69 | Self-heal: probe + `preStop`, restart a wedged VM | live |
| cc-infra #77 | Bump enclaves to c5.2xlarge / 11 GiB | live |
| CCC #6 | Load harness, RUNBOOK, this report | open |

## Background: the original wedge (2 GiB era)

A single ~26-way burst used to wedge the 2 GiB enclaves with no auto-recovery
(`RUNNING` per `nitro-cli` but dead on vsock; manual `kubectl delete pod` to
recover). Root cause: no admission control, so N concurrent wasmtime instances
exhausted the fixed memory. Sweeps: minimal held 26 / wedged 28; vault held 13 /
wedged 20 (the vault path holds its slot through the whole relay round-trip plus
a TDH2 decrypt, so it wedged sooner). `/memory` was blind to it (`usedMB` is
Go-only, not the wasmtime native memory) until CCC #22 added `rssMB`. Per-exec
cost measured at ~63 MB RSS. #4 (cap) + #69 (self-heal) + #77 (11 GiB) closed all
of this; the enclave no longer falls over. The open question is now downstream:
the VaultDON ceiling above, and whether the DON handles a shed gracefully (not
yet).
