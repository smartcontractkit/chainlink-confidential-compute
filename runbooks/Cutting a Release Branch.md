### Runbook for Cutting a Release Branch
We cut release branches as to more easily understand which version of our enclave and capability are running, and for the measurements of the enclave to be easily verifiable.

## Prerequisites
- Write access to the repository
- Determine the version number (e.g., `v0.0.1`)

## Steps

### 1. Update the global Confidential Compute version number [SKIP THIS STEP]
- Merge a PR that updates the `ServiceConfidentialComputeVersion` variable in `types.go` to this new release version.

### 2. Create the release branch
```bash
# Ensure you're on main and up to date
git checkout main
git pull origin main

# Create release branch
git checkout -b release/a.b.c

# Push the release branch
git push -u origin release/a.b.c
```

### 3. Update the go.mod for app capabilities
- In order to run with our E2E tests, our enclave app capability go.mod files use local replaces that point to the current state of our repo. Example: https://github.com/smartcontractkit/chainlink-confidential-compute/blob/c519f08284afe2f97fa5927f490dd801b8585e4c/enclave/apps/confidential-http/capability/go.mod#L5-L7.
- These replaces must be removed, and the `github.com/smartcontractkit/chainlink-confidential-compute`, `github.com/smartcontractkit/chainlink-confidential-compute/capabilities/framework`, and `github.com/smartcontractkit/chainlink-confidential-compute/enclave-client` imports should point to the most recent commit on `main`. Example: https://github.com/smartcontractkit/chainlink-confidential-compute/compare/main...release/v0.0.1.
- If an incorrect version of `smartcontractkit/chainlink-confidential-compute`, `smartcontractkit/chainlink-confidential-compute/capabilities/framework`, or `smartcontractkit/chainlink-confidential-compute/enclave-client` is used, the `go-tests` workflow in our CI should fail. Ensure the CI passes before tagging the release branch.
- If this step is ignored, capabilities in this release branch will fail to build when referenced by Chainlink core's [private plugins list](https://github.com/smartcontractkit/chainlink/blob/develop/plugins/plugins.private.yaml).
- Apply these go.mod changes to **both** capability apps:
  - `enclave/apps/confidential-http/capability/go.mod`
  - `enclave/apps/confidential-workflows/capability/go.mod`

### 4. CI Builds Images
Pushing a new release branch automatically triggers CI workflows:
- `build-deploy-config-tracker.yaml` - Builds config tracker image
- `build-deploy-host.yaml` - Builds host image  
- `build-deploy-nitro-enclave.yaml` - Builds nitro enclave, K8s plugin, and EIF file with PCR measurements for **both** confidential-http and confidential-workflows
- `go-tests.yaml` - Runs all Go tests
- `golangci-lint.yaml` - Runs linting

Monitor the workflow runs at: https://github.com/smartcontractkit/chainlink-confidential-compute/actions

### 5. Verify Build Artifacts
Check the `build-deploy-nitro-enclave.yaml` workflow summary for:
- Docker image names and digests for both confidential-http and confidential-workflows
- PCR measurements (PCR0, PCR1, PCR2) for each enclave
- EIF file artifacts
Also, copy the link for the summary page of the workflow (example: https://github.com/smartcontractkit/chainlink-confidential-compute/actions/runs/19507460619) and use this link in step 6 for the release notes.

### 6. Create Git Tag
```bash
# Tag the commit on the release branch
git tag a.b.c

# Push the tag
git push origin a.b.c
```

### 7. Create GitHub Release
```bash
# Using GitHub CLI
gh release create a.b.c --title "a.b.c" --notes "Enclave measurements for this release can be seen here: [WORKFLOW_SUMMARY_PAGE_LINK_FROM_STEP_5]"
```

### 8. Using this Release
See `Deploying a new Release`.

## Example Release
View the diff for release branch: https://github.com/smartcontractkit/chainlink-confidential-compute/compare/main...release/0.0.1

## Notes
- Release branches are protected and cannot be deleted
- The CI runs on pushes to `release/**` branches automatically
- The CI status from the release branch commit is visible on the tag
