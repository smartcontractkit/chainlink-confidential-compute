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
