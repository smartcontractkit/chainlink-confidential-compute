### Runbook for Bumping Chainlink Core in our E2E Tests
The end-to-end tests our repository uses are based on the local CRE testing framework. This framework lives in the core Chainlink repo, so in order for our E2E tests to stay accurate, we need to bump Chainlink core at a regular frequency. 

## Steps

1. **Compute the Go pseudo-version** for the new commit. Clone a bare copy of the chainlink repo and find the correct version tag:
    ```bash
    cd /tmp && git clone --bare --filter=blob:none https://github.com/smartcontractkit/chainlink.git chainlink-bare
    cd /tmp/chainlink-bare
    git log -1 --format="%ci" <NEW_COMMIT>   # Get the timestamp
    git describe --tags --abbrev=0 <NEW_COMMIT>  # Get the base version tag
    ```
    The pseudo-version format is `v<base>.<timestamp>-<12-char-hash>`, e.g. `v0.0.0-20260331164225-8174693bc5a0`. For the `v2` module it uses the base tag like `v2.29.1-cre-beta.0.0.20260331164225-8174693bc5a0`.

2. **Diff upstream config files** between the old and new commits to understand what changed:
    ```bash
    # From the bare clone, compare configs at old vs new commit:
    git show <OLD_COMMIT>:core/scripts/cre/environment/configs/capability_defaults.toml > /tmp/old_capability_defaults.toml
    git show <NEW_COMMIT>:core/scripts/cre/environment/configs/capability_defaults.toml > /tmp/new_capability_defaults.toml
    diff /tmp/old_capability_defaults.toml /tmp/new_capability_defaults.toml
    ```
    Do the same for `setup.toml`, `workflow-gateway-don.toml`, and any test files that changed.

3. **Update `/tests/go.mod`**: At the top of our `go.mod`, bump the block of chainlink replace directives to all point to the same new commit version:
    - `github.com/smartcontractkit/chainlink/v2`
    - `github.com/smartcontractkit/chainlink/core/scripts`
    - `github.com/smartcontractkit/chainlink/deployment`
    - `github.com/smartcontractkit/chainlink/system-tests/lib`
    - `github.com/smartcontractkit/chainlink/system-tests/tests`
    - All CRE submodule replace directives (e.g. `smoke/cre/evm/evmread`, `regression/cre/consensus`, etc.)
    
    Also check for **new submodules** added upstream. Look at the upstream `system-tests/tests/go.mod` for new replace directives. New submodules need both a `replace` directive and possibly an `exclude` for their zeroed-out version. Common new submodules include workflow modules under `core/scripts/cre/environment/examples/`.

4. **Update `chainlink-common`** version in `/tests/go.mod`, `/capabilities/framework/go.mod`, and `/enclave/apps/confidential-http/capability/go.mod` to match whatever the new chainlink commit uses.

5. **Update `gotron-sdk` replace** in `/tests/go.mod` if the upstream version changed (compare with upstream go.mod).

6. **Update config files** by applying the diff from step 2:
    - `tests/e2e/configs/capability_defaults.toml` - watch for field renames (e.g. `binary_path` → `binary_name`), new capability sections, and changed values.
    - `tests/e2e/configs/workflow-don.toml` - watch for new fields like `container_name`, `p2p_port_range_start`, `registry_based_launch_allowlist`, new `env_vars`. Keep our custom port ranges that avoid enclave port conflicts.
    - `tests/e2e/configs/setup.toml` - watch for image tag naming convention changes and new build configs.
    - **New Docker images**: If new components appear in `setup.toml` (e.g. a new `[chip_*.build_config]` or `[chip_*.pull_config]` section), you must also add checkout + build steps for them in `/.github/workflows/go-tests.yaml`. Check the `build_config.repository`, `commit`, `dockerfile`, and `docker_ctx` fields to construct the CI steps. Also add the corresponding image reference to `workflow-don.toml` if upstream `workflow-gateway-don.toml` includes it.

7. **Update `/capabilities/framework/go.mod`** to match `chainlink-common` version used by new chainlink.

8. **Update `CHAINLINK_COMMIT_SHA`** in `/.github/workflows/go-tests.yaml`.

9. **Check for API changes** in CRE library functions. Common breaking changes include:
    - `StartCLIEnvironment` signature changes (added/removed parameters)
    - New vault DON helpers (retry logic, registry config updates)
    - Changes to contract wrapper types
    
    Run `go build ./...` from the `/tests/` directory to catch compile errors.

10. **Run `go mod tidy`** in both `/tests/` and `/capabilities/framework/`. You may need `GONOSUMCHECK="github.com/smartcontractkit/*"` if the version isn't in the Go sum DB yet.

11. **Run e2e tests** with the new version. Reach out to the CRE team in the `topic-dev-environments` channel if you are unable to figure out how to get the version bump to work with our tests.
