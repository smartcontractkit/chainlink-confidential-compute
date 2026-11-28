### Real-Enclave Workflow Capacity Test

Run `make e2e-local-workflow-capacity` from the repository root on a dedicated
Nitro-capable test host with Docker, `nitro-cli`, sudo access, and the normal
enclave build prerequisites. The existing launcher reconfigures/restarts the
Nitro allocator; do not run this against a shared or production host.

`TestConfidentialWorkflowsCapacityE2E` in `tests/workflow_capacity_test.go` starts
one 2048 MiB confidential-workflows enclave (4096 MiB allocator pool). No
Chainlink node images or DON deployment are needed. It reads guest RAM over
VSOCK and calls the production `memlimit.ForMemory`. With the current constants,
`available = guest RAM MiB - 1024 - 128`,
`compileCapacity = min(8, floor(available / (128 + 384)))`, and
`executionCapacity = floor((available - compileCapacity * 384) / 128)`.
Guest RAM below 1664 MiB fails startup. Guest RAM is smaller than the Nitro
allocation. `/memory` rounds to MiB while startup truncates, so the test accepts
the minimum/maximum capacities from `ForMemory(totalMB)` and
`ForMemory(totalMB - 1)`; a compile-pool transition can change capacity by more
than one slot. For example, rounded 1992 MiB yields 3 executions / 1 compile
capacity at either endpoint; rounded 2048 MiB permits 3..4 executions / 1 compile.

If a separate development/debug fixture already captured startup logs,
`Confidential workflows concurrency limit` gives exact `totalMemMB`,
`maxConcurrentExecutions` and `compileCapacity`; `compilation admission configured`
gives the installed `maxConcurrentCompilations`. These are supplementary test
evidence, not required by this E2E: release-mode staging does not export guest
stderr. Do not enable Nitro debug mode for the deployment smoke.

The test submits twice the capacity upper bound as distinct, signed workflow
executions to the same host. Artifact downloads wait at a test-controlled
barrier, so admitted slots cannot drain before overload is observed. Excess
requests must report the explicit `enclave at capacity: too many concurrent
executions` error. The app assigns code 429, but the enclave server currently
wraps all app errors in HTTP 500; the host then wraps that error again. The test
checks the capacity reason rather than an HTTP status. Timeouts, EOFs and
unrelated errors fail the test. Releasing the barrier sends the existing Go
`hello` WASM fixture through the single-slot compilation queue, then runs the
guests concurrently. All executions share one binary, so later compilations hit
the Wasmtime cache; this is not a cold-compilation stress test. Every admitted
execution must return its expected, attestation-validated result, and a fresh
execution must succeed after the burst drains.

This is an admission/recovery regression test, not a maximum-memory soak or a
reproduction of customer binaries. It uses one signer with F=0 and no secrets;
the normal request signature, binary hash and Nitro attestation checks remain
enabled. Only artifact storage is a fixture. The test skips fake, legacy and
remote enclaves and is included automatically in the existing real-enclave CI
`go test ./...` run (nightly, release pushes, or the `e2e-real-enclaves` PR label).

Retain the candidate SHA, `guest RAM=... capacity=... burst=...` and
`admitted=... rejected=...` output, and the final
`--- PASS: TestConfidentialWorkflowsCapacityE2E` line. A `SKIP`, timeout, zero
rejections, admission outside the printed bounds, failed admitted result or
failed post-burst request is not a pass. Existing real-enclave CI logs can supply
this evidence only if they ran this test without skipping on the candidate SHA.
For a known run, inspect it without provisioning another host:

```sh
gh run view "$RUN_ID" --repo smartcontractkit/chainlink-confidential-compute --log |
  rg 'TestConfidentialWorkflowsCapacityE2E|guest RAM=|admitted=|slots must be released'
```

Gate reuse and settings rejection are automated separately, not a manual
mid-burst operation. From `enclave/apps/confidential-workflows`:

```sh
GOMAXPROCS=1 go test -p 1 -count=1 ./memlimit ./app \
  -run '^(TestForMemory|TestInjectSettings_MaxConcurrentCompilations|TestExecute_CompilationQueueRetainsAdmissionUntilFailure|TestExecuteWasm_Hello)$'
```

These tests cover budget boundaries, unchanged/omitted settings reusing the
gate, rejected concurrency changes preserving it, queued work retaining
execution slots, the rejection event's `max_concurrent`, and successful WASM
phase events. They do not prove staging's telemetry export is configured; use
the [deployment smoke checks](../../staging-validation/4c9199d1.md) for that.

### Runbook for Bumping Chainlink/v2 in our E2E Tests
1. At the top of our `go.mod`, we have a block of chainlink imports that are all fixed at the same version. Bump the following imports to all have the same updated version:
    - github.com/smartcontractkit/chainlink/core/scripts
	- github.com/smartcontractkit/chainlink/deployment
	- github.com/smartcontractkit/chainlink/system-tests/lib
	- github.com/smartcontractkit/chainlink/system-tests/tests
	- github.com/smartcontractkit/chainlink/v2

2. In our `go.mod` file, make sure any imported modules that are like `github.com/smartcontractkit/chainlink/system-tests/tests/regression/...` are excluded. There could be new ones added after a bump, and those new ones will create `go.mod` errors that require an exclusion to fix. Our existing exclusions are at the bottom of the `go.mod` file.

3. Check our `configs/setup.toml` file against the upstream one: https://github.com/smartcontractkit/chainlink/blob/develop/core/scripts/cre/environment/configs/setup.toml#L1. Make additions or changes if necessary. LLMs are helpful here.

4. Check our `configs/capability_defaults.toml` file against the upstream one: https://github.com/smartcontractkit/chainlink/blob/develop/core/scripts/cre/environment/configs/capability_defaults.toml. Make additions or changes if necessary. LLMs are helpful here.

5. Check our `configs/workflow-don.toml` file against the upstream one: https://github.com/smartcontractkit/chainlink/blob/develop/core/scripts/cre/environment/configs/workflow-don.toml. Make additions or changes if necessary. LLMs are helpful here.

6. Updat the reference to `chainlink-common`, and maybe also to `github.com/smartcontractkit/capabilities/libs` in the go.mod file in `/capabilities/framework`. This is to ensure our capability is compatible with the most recent Chainlink version.

7. Update `CHAINLINK_COMMIT_SHA` in our `/.github/workflows/go-tests.yaml` file.

8. See if the e2e_tests pass with the new version. There may be changes made that break our tests. Reach out to the CRE team in the `topic-dev-environments` channel if you are unable to figure out how to get the version bump to work with our tests.
