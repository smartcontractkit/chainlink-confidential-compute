### Runbook for deploying a Release (product-specific)
Once a release branch is cut, the capability binary and/or enclave can be deployed into CRE.

#### Deploying the capability binary
- Update `LEGACY_COMMIT_SHA` in the following locations to point to the tip of this release branch:
  - The **previous release branch** (e.g., `release/v0.0.6`): Add a PR updating `LEGACY_COMMIT_SHA` in `.github/workflows/go-tests.yaml`. Ensure CI passes to confirm backward-compatibility between this new capability binary and the prior release's enclaves.
  - **`main`**: Add a PR updating `LEGACY_COMMIT_SHA` in `.github/workflows/go-tests.yaml` so that the next release cut starts with the correct legacy reference.
- Update the gitref link in chainlink: https://github.com/smartcontractkit/chainlink/blob/52bef60002a523cb4434bc80176f52043f201349/plugins/plugins.private.yaml#L56. It should match the commit of the release. Note that this file references **both** the `confidential-http` and `confidential-workflows` capability binaries.
- Merge the PRs.
- Monitor staging as the binary is promoted to ensure there are no issues.
- Monitor production once it is released.
- <b>Note:</b> if the capability binary is not backwards compatible, it can still be deployed, but the enclaves must be upgraded to the newest release first (see next section).

#### Deploying an enclave 
There are now **two** enclave apps to deploy: `confidential-http` and `confidential-workflows`. Each has its own image, PCR measurements, and infra configuration. The steps below apply to each enclave independently.

- Our CI automatically ensures the enclave is backwards compatible with the prior release already; no extra work is required in this regard to deploy.
- Update `LEGACY_ENCLAVE_RELEASE` in `.github/workflows/go-tests.yaml` on the release branch and `main` to point to this new release version (e.g., `v0.0.7`). This ensures the `test-legacy-enclaves` CI job fetches PCR measurements from this release and tests against the deployed enclaves.
- Create a PR in [confidential-compute-infra](https://github.com/smartcontractkit/confidential-compute-infra) to update the dev enclave configs to run with the new enclave image SHA for both "enclave" and "proxy" containers:
  - **confidential-http:**
    - `deploy/config/enclave/dev.yaml`
    - `deploy/config/enclave-secondary/dev.yaml`
  - **confidential-workflows:**
    - `deploy/config/enclave-workflows/dev.yaml`
    - `deploy/config/enclave-workflows-secondary/dev.yaml`
- Once the dev deployment is verified, cut a CLD PR to add the measurements for this new release to the list of accepted measurements. Example: https://github.com/smartcontractkit/chainlink-deployments/pull/10750. Both enclave apps' PCR measurements must be included.
- Get that PR approved, and execute `run-pipelines` to put up an MCMS proposal.
- Get that MCMS proposal signed & deployed.
- Once the on-chain changes are complete, upgrade the enclaves one-at-a-time (blue/green style). First upgrade [this enclave](https://github.com/smartcontractkit/confidential-compute-infra/blob/main/deploy/config/enclave/prod.yaml) to the new release image, then [this one](https://github.com/smartcontractkit/confidential-compute-infra/blob/main/deploy/config/enclave-secondary/prod.yaml). Repeat for the confidential-workflows enclave configs.