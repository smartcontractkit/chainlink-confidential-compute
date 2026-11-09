# Staging validation: confidential-workflows share union

## Change

For each requested secret, the confidential-workflows enclave accepts relay-DON
results backed by at least F+1 distinct signers that agree on the ciphertext and
vault public key. Shares may differ between signers. The enclave combines the
shares from those signers, and during decryption verifies each TDH2 share and
dedupes by node index.

Only the enclave changes. Direct Vault reads require chainlink nodes that
include the direct GetSecrets path (smartcontractkit/chainlink#23946).

## Pre-staging tests

1. Unit tests: `go test ./app/` in `enclave/apps/confidential-workflows` and
   `go test ./util/`.
2. E2E: `make e2e-local-conf-workflows` runs
   `TestConfidentialWorkflowsEngineE2E` (OCR path) and
   `TestConfidentialWorkflowsEngineE2E_DirectSecrets` (direct path). The pinned
   chainlink commit must include the direct GetSecrets path.

## Validation steps

1. Deploy the enclave with `PerWorkflow.FeatureVaultGetSecretsDirectlyActivePeriod`
   disabled. Confirm the confidential-workflows canaries stay green and note
   `mergedShares` in the enclave's `relay-DON secrets quorum reached` log.
2. Enable `PerWorkflow.FeatureVaultGetSecretsDirectlyActivePeriod` for the
   staging canary workflows.
3. Trigger `cn_confidentialworkflows_a`, `cn_cw_httpget_a` and
   `cn_cw_chainwrite_a`. Confirm the vault nodes log
   `served direct get secrets request`. This is a debug-level log.
4. Confirm the enclave logs `relay-DON secrets quorum reached` with a larger
   `mergedShares` than in step 1.
5. Disable `PerWorkflow.FeatureVaultGetSecretsDirectlyActivePeriod` and confirm
   the canaries stay green.

## Success criteria

- Confidential-workflows canaries stay at 100% success with direct reads on.
- No `no relay-DON result reached quorum`,
  `relay-DON secrets results disagree on vault public key` or
  `failed to aggregate decryption shares` errors.
- Secret-read latency is better than with direct reads off.

## Edge cases and risks

- Enable direct reads only after every enclave serving the workflow DON runs
  this version.
- A faulty relay node can add invalid or undecryptable shares. The enclave
  skips them and decrypts once it has `T` valid distinct shares.
- During a DKG reshare, relay nodes can disagree on the vault public key. If no
  group reaches F+1 signers, the request fails with
  `no relay-DON result reached quorum`. If two secrets reach quorum under
  different keys, it fails with
  `relay-DON secrets results disagree on vault public key`. The enclave does
  not retry either error; the next workflow execution does.
- Each signer contributes at most 128 encrypted shares per secret. Extra shares
  are dropped with a `truncating oversized relay share list` warning. Raise the
  cap if honest responses exceed it.
- To roll back, disable `PerWorkflow.FeatureVaultGetSecretsDirectlyActivePeriod`.
  No enclave rollback is needed.

## Staging result

Pending.
