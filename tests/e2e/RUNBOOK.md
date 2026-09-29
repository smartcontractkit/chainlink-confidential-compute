### Real-Enclave Workflow Capacity Test

Run `make e2e-local-workflow-capacity` from the repository root on a dedicated
Nitro-capable test host with Docker, `nitro-cli`, sudo access, and the normal
enclave build prerequisites. The existing launcher reconfigures/restarts the
Nitro allocator; do not run this against a shared or production host.

`TestConfidentialWorkflowsCapacityE2E` in `tests/workflow_capacity_test.go` starts
one 2048 MiB confidential-workflows enclave (4096 MiB allocator pool). No
Chainlink node images or DON deployment are needed. It reads guest RAM over
VSOCK and uses the production `memlimit` constants:
`max(1, (guest RAM MiB - 1024) / 128)`. The 1024 MiB value is the reserve, not
the divisor. Guest RAM is smaller than the Nitro allocation; the test permits
the one-slot boundary ambiguity introduced by `/memory` rounding to MiB.

The test submits twice the capacity upper bound as distinct, signed workflow
executions to the same host. Artifact downloads wait at a test-controlled
barrier, so admitted slots cannot drain before overload is observed. Excess
requests must report the enclave's explicit `429 Too Many Requests` capacity
error (the host currently wraps this in HTTP 500). Timeouts, EOFs and unrelated
errors fail the test. Releasing the barrier starts concurrent compilation and
execution of the existing Go `hello` WASM fixture. Every admitted execution must
return its expected, attestation-validated result, and a fresh execution must
succeed after the burst drains.

This is an admission/recovery regression test, not a maximum-memory soak or a
reproduction of customer binaries. It uses one signer with F=0 and no secrets;
the normal request signature, binary hash and Nitro attestation checks remain
enabled. Only artifact storage is a fixture. The test skips fake, legacy and
remote enclaves and is included automatically in the existing real-enclave CI
`go test ./...` run (nightly, release pushes, or the `e2e-real-enclaves` PR label).

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
