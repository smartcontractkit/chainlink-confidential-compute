# Confidential Compute

A framework for building Confidential Compute applications, which use trusted execution environments (TEEs) and threshold-encrypted secrets in conjunction.

Applications built on this framework receive abstractions for the infrastructure required to implement the Confidential Compute protocol:

- A client for enclave communication.
- An integration test harness that uses a simulated threshold encryption system.
- Cloud-provider-specific enclave environment code (currently AWS Nitro only).
- Core enclave services: a combiner for secret key shares, an ephemeral keychain that issues ephemeral asymmetric keys, and an attestation service that produces remote attestations of request execution inside the enclave.

## Current Applications:

### Confidential HTTP

The `confidential-http` application lets CRE workflow authors make external API requests containing secrets encrypted in the Vault DON. The secrets are never revealed to external parties — only the secret owner and the enclave see plaintext.

It lives at `enclave/apps/confidential-http/`:

```
enclave/apps/confidential-http/
├── app/            # Core application logic that runs inside an enclave.
├── capability/     # Capability source for the Confidential HTTP CRE Capability.
├── environments/   # Supported enclave environments.
│   ├── fake        # Local fake enclave entrypoint (emulates Nitro over loopback).
│   └── nitro       # AWS Nitro Enclave environment entrypoint.
└── types/          # Protobuf types shared by the enclave app and the CRE Capability.
```

### Confidential Workflows

The `confidential-workflows` application lets CRE workflow authors run their workflows entirely in a TEE, once they have been triggered from a public workflow DON.

It lives at `enclave/apps/confidential-workflows/`:

```
enclave/apps/confidential-workflows/
├── app/            # Core logic that runs inside the enclave (WASM execution, fetching, dispatch).
├── capability/     # Capability source for the Confidential Workflows CRE Capability.
├── environments/   # Supported enclave environments.
│   ├── fake        # Local fake enclave entrypoint.
│   └── nitro       # AWS Nitro Enclave environment entrypoint.
├── gateway/        # Client for communicating with the CRE Gateway.
└── httpfetch/      # Helper for sending outbound HTTPS requests.
```

## Reference Application: Confidential Echo

`confidential-echo` is a minimal reference implementation of the `EnclaveApp` interface. It treats the public input as a Go `text/template` and renders it with the injected secrets substituted by name, returning the rendered bytes. It has no network access or external dependencies, so it serves as the canonical example of the secret-injection pattern and end-to-end test.

It lives at `enclave/apps/confidential-echo/`:

```
enclave/apps/confidential-echo/
├── app/            # The EnclaveApp implementation and its unit tests.
└── environments/   # Supported enclave environments.
    ├── fake        # Local fake enclave entrypoint.
    └── nitro       # AWS Nitro Enclave environment entrypoint.
```

Its end-to-end test can be found at: `TestConfidentialEchoEnclave` in `tests/enclave_test.go`.

```bash
cd tests
go test -v . -run '^TestConfidentialEchoEnclave$'
```

## Repository Structure

```
confidential-compute/
├── capabilities/                 # Chainlink CRE-specific resources.
│   ├── examples/                 # Example capabilities for development & demonstration.
│   └── framework/                # Library abstracting CRE capability logic.
├── deploy/                       # Helm charts & configs for Griddle infrastructure.
├── enclave/                      # Enclave apps, environments, examples, and services.
│   ├── apps/                     # Confidential Compute applications.
│   │   ├── confidential-echo/    # Minimal reference app: renders a template with injected secrets.
│   │   ├── confidential-http/    # Executes an HTTP request template with secrets.
│   │   └── confidential-workflows/ # Runs CRE workflows entirely inside a TEE.
│   ├── examples/                 # Informative example enclave setups.
│   │   ├── hello-enclave/        # Basic AWS Nitro "Hello World" enclave.
│   │   └── ticker/               # Nitro enclave demonstrating a reliable system clock.
│   ├── fake/                     # Fake enclave runtime: runs the stack as local processes.
│   ├── vsock/                    # vsock abstraction; emulates vsock over loopback TCP.
│   ├── nitro/                    # AWS Nitro-specific environment code.
│   │   ├── host/                 # Parent host for inbound traffic and outbound tunnels.
│   │   │   └── proxy-server/ # Parent-side VSOCK-to-TCP relay.
│   │   └── proxy-client/ # Enclave-side policy-aware VSOCK egress dialer.
│   ├── server/                   # Trusted enclave server that dispatches requests to an app.
│   └── services/                 # Generic services available to enclave applications.
│       ├── attestor/             # Generates remote attestations.
│       ├── combiner/             # Combines threshold decryption key shares.
│       ├── emitter/              # Exports non-sensitive data to an ingestion service.
│       ├── keychain/             # Generates ephemeral asymmetric keypairs on a schedule.
│       └── signature-verifier/   # Signature verifier service.
├── enclave-client/               # Routing logic and HTTP client for enclave communication.
│   ├── attestation-validator/    # Verifies remote attestations.
│   ├── enclave-selector/         # Chooses enclaves to execute a given request.
│   ├── spec/                     # API spec for communicating with enclaves.
│   └── test-data/                # Test attestations & PCR measurements.
├── tests/                        # Cloud-specific enclave tests & end-to-end tests.
│   └── e2e/                      # End-to-end tests.
├── types/                        # Shared types.
└── util/                         # Shared helper logic.
```

## Developing an Application

Create a folder for your app under `enclave/apps/` (mirroring `confidential-echo`):

```
enclave/apps/<your-app>/
├── app/            # EnclaveApp implementation and its unit tests.
└── environments/   # Enclave environment entrypoints.
    ├── fake        # Local fake enclave entrypoint.
    └── nitro       # AWS Nitro enclave entrypoint.
```

Then:

1. In `app/`, implement the `EnclaveApp` interface, which performs logic over public input bytes and a map of secrets. Add an `AppID` constant in `types/constants.go`.
2. Choose an input encoding. Simple apps can treat the public input as raw bytes (see `confidential-echo`). If you plan to build a CRE Capability, add a `types.proto` defining your input type, with the `SecretIdentifier` type from `types/frameworktypes/framework.proto` at its root.
3. Add enclave environment entrypoints under `environments/`. Create a `fake/main.go` (package `main`) that calls `StartFakeEnclave` from `enclave/fake/runner` (for local dev and tests) and a `nitro/main.go` that calls `StartNitroEnclave` from `enclave/nitro`. Both inject your `EnclaveApp` from step 1.
4. Add an integration test to `tests/enclave_test.go` using the shared harness — `SetupEnclaveApp` starts the enclave and `ExecuteEnclaveAppE2E` drives a request via an `EnclaveExecution` config. See `TestConfidentialEchoEnclave` (fake) and `TestConfidentialHttpEnclave`.
5. Test your application (see [Tests](#tests)).

### Optional: CRE Capability

6. Create a CRE Capability for your application:
   - Generate [CRE SDK](https://github.com/smartcontractkit/cre-sdk-go) code from your `types.proto`.
   - After adding your SDK to the CRE SDK repo and a Capability Server to [Chainlink Common](https://github.com/smartcontractkit/chainlink-common/tree/main/pkg/capabilities/v2), create a `capability/` folder.
   - Implement the `ConfidentialAction` interface and expose a CRE entrypoint via `ServeNew` from `github.com/smartcontractkit/capabilities/libs/loopserver`.
   - Reusing the same `types.proto` for both the enclave app input and the capability SDK gives workflow authors a "virtualized" view of enclave execution — they understand what runs in the enclave from the request they make to the SDK.

7. Add CRE E2E tests:
   - Add your test application struct to the `apps` slice in `tests/e2e/e2e_test.go`, defining the secrets, requests, and response validation to run against your application.
   - Add a `capability_configs` TOML entry in `tests/e2e/configs/capability_defaults.toml` setting `binary_path = "./binaries/[YOUR_APP_NAME]"`. See `capability_configs.confidential-http` for reference.
   - Run your tests.

`confidential-echo` is the smallest reference for steps 1–5; `confidential-http` is a good reference for the full flow including a CRE Capability.

## Tests

Testing happens at two levels:

- **Enclave integration tests** (`tests/enclave_test.go`) exercise a single enclave app in isolation — inject secrets, run a request, check the output.
- **End-to-end suites** (`tests/e2e`) run an app through the full CRE stack (chainlink node, job distributor, capabilities) against a real workflow.

Both run against either **fake enclaves** (no hardware — runs anywhere with Docker) or **real AWS Nitro enclaves**. Fake enclaves emulate the Nitro environment by running the same enclave app, sidecars, and untrusted host as ordinary local processes, with the `enclave/vsock` package emulating vsock over loopback TCP (`VSOCK_BACKEND=tcp`). This exercises the same attestation/keychain/combiner/host code paths as production without Nitro hardware.

### Enclave integration tests (`tests/enclave_test.go`)

The shared harness starts an enclave running your app and drives requests against it:

- `SetupEnclaveApp(t, appName)` builds and starts the enclave for the named app under `enclave/apps/`, returning a cleanup func.
- `ExecuteEnclaveAppE2E(t, EnclaveExecution{...})` configures the threshold parameters, secrets, and public input, then runs one request end-to-end (set config → fetch public keys → execute) and returns the response.

`TestConfidentialEchoEnclave` is the minimal example; `TestConfidentialHttpEnclave` shows a fuller app. To run them:

```bash
cd tests
ENCLAVE_TYPE=FAKE go test -v . -run '^TestConfidentialEchoEnclave$'
```

The environment is selected automatically: the harness uses a real Nitro enclave when `nitro-cli` is on `PATH`, and otherwise falls back to a fake enclave (logging a warning). Set `ENCLAVE_TYPE=FAKE` to force fake and silence the warning, or `ENCLAVE_TYPE=NITRO` to require real hardware.

Pure application logic that doesn't need a running enclave belongs in ordinary unit tests next to the app (see `enclave/apps/confidential-echo/app/app_test.go`).

### Local E2E (fake enclaves)

Requirements: Docker (≥ 24 GB, root disk < 85% full) and an authenticated `gh` CLI. No local chainlink checkout or Nitro hardware needed.

The root [Makefile](Makefile) automates the whole setup:

```bash
make e2e-local-conf-http        # TestConfidentialHTTPE2E
make e2e-local-conf-workflows   # TestConfidentialWorkflowsEngineE2E
```

It shallow-clones chainlink (plus `job-distributor` and, for the engine suite, `chainlink-testing-framework`) into `/tmp/cc-e2e` at the refs pinned in [go-tests.yaml](.github/workflows/go-tests.yaml) — **your own checkouts are never touched** — builds the chainlink node image and CC plugin binaries, symlinks `core` for the chiprouter, then runs the suite with `ENCLAVE_TYPE=FAKE`. Images are cached by tag, so re-runs skip the heavy builds.

- `make e2e-images` — build/cache all required images without running a suite.
- `make clean-e2e` — remove the scratch clones, plugin binaries, and the `core` symlink.
- `make help` — list targets and show the resolved pins.

<details><summary>Manual equivalent (for debugging)</summary>

1. Build the chainlink node image with the CRE capability plugins baked in. The plugins (`cron`, `consensus`, `http_action`, `http_trigger`) come from `plugins/plugins.private.yaml`, so `CL_INSTALL_PRIVATE_PLUGINS` must be `true` (the default). Remove the `confidential-http:` and `confidential-workflows:` blocks from that file first — the e2e supplies them as local binaries, and building them would pull an unrelated CC version:
   ```bash
   cd <chainlink>            # checked out at CHAINLINK_COMMIT_SHA
   # delete the `confidential-http:` and `confidential-workflows:` entries from plugins/plugins.private.yaml
   gh auth token > /tmp/ghtoken
   docker build \
     --secret id=GIT_AUTH_TOKEN,src=/tmp/ghtoken \
     --build-arg CL_INSTALL_PRIVATE_PLUGINS=true \
     --build-arg CL_IS_PROD_BUILD=false \
     -f core/chainlink.Dockerfile -t chainlink:latest .
   rm -f /tmp/ghtoken
   ```
2. The CRE chiprouter loads the environment state file via a path hardcoded four directories above `tests/e2e`. Symlink `core` there to your chainlink checkout (CI does the equivalent):
   ```bash
   ln -sfn <chainlink>/core "$(cd tests/e2e && cd ../../../.. && pwd)/core"   # may need sudo
   ```
3. Run a suite with fake enclaves:
   ```bash
   cd tests/e2e
   CI=1 ENCLAVE_TYPE=FAKE \
     CTF_CONFIGS=configs/workflow-don.toml \
     CTF_CHAINLINK_IMAGE=chainlink:latest \
     CTF_JD_IMAGE=job-distributor:0.22.1 \
     go test -tags e2e -v -timeout 60m -run '^TestConfidentialHTTPE2E$' .
   ```
   For the engine suite, use `CTF_CONFIGS=configs/workflow-don-engine.toml` and `-run '^TestConfidentialWorkflowsEngineE2E$'`.
</details>

### Local E2E (real Nitro enclaves)

On a Nitro-capable host (`nitro-cli` installed, Docker ≥ 24 GB), run the same Makefile targets with `ENCLAVE_TYPE=NITRO`. The harness provisions real Nitro enclaves instead of fake ones; everything else (image build, plugin binaries, `core` symlink) is identical to the fake flow.

```bash
make e2e-local-conf-http ENCLAVE_TYPE=NITRO        # TestConfidentialHTTPE2E
make e2e-local-conf-workflows ENCLAVE_TYPE=NITRO   # TestConfidentialWorkflowsEngineE2E
```

These targets clear stale Nitro state (leftover enclaves and cached EIF/PCR artifacts) automatically before each run. To run that cleanup on its own:

```bash
make clean-e2e-nitro
```

### CI ([go-tests.yaml](.github/workflows/go-tests.yaml))

- **Pull requests** run the full module test suite — including `tests/` and `tests/e2e` — against **fake enclaves** on GitHub-hosted runners. The three heavy CRE images (chainlink, job-distributor, chip-router/ingress/config) are built once and cached in GHCR, keyed on their pinned refs.
- **Nightly** (scheduled) and **release-branch pushes** re-run `tests/` and `tests/e2e` against **real Nitro enclaves** on self-hosted runners, catching hardware/attestation regressions the fake environment can't.
- The **`e2e-real-enclaves`** label adds a real Nitro e2e + integration run on top of the usual fake-enclave suite. Re-applying the label triggers a fresh run.
- A **backwards-compatibility** variant runs the suite with prior-release capability binaries, and a **legacy-enclaves** variant runs the e2e against deployed staging enclaves over Tailscale.

## Verifying Enclave Images

The enclave build process is publicly verifiable so users can trust what runs inside the enclave. Cutting a release branch produces a GitHub Actions-generated Docker image ([example](https://github.com/smartcontractkit/chainlink-confidential-compute/releases/tag/v1.3.0)). Because the image is built by GitHub from transparent source, it can be used to create reproducible [Enclave Image Files](https://docs.aws.amazon.com/enclaves/latest/user/building-eif.html).

```bash
# Create measurements — produces [ENCLAVE_NAME].eif.measurements.json
./enclave/nitro/build-or-verify-enclave.sh --docker-uri [DOCKER_IMAGE] --output-file [EIF_NAME]

# Verify measurements
./enclave/nitro/build-or-verify-enclave.sh --docker-uri [DOCKER_IMAGE] --output-file [EIF_NAME] --measurements-file [MEASUREMENTS_FILE]
```

## Using the Enclave E2E Test Helpers From Another Repository

This repository provides reusable components for spinning up local enclaves in E2E tests, designed to be consumed from **any** Go repository.

### 1. GitHub Action: `setup-nitro-enclave`

A composite action at [.github/actions/setup-nitro-enclave](.github/actions/setup-nitro-enclave) prepares a self-hosted Nitro runner with all prerequisites (nitro-cli, allocator, hugepages, wireguard-tools, lsof, socat). Reference it from your workflow:

```yaml
steps:
  - uses: actions/checkout@v4
    with:
      repository: smartcontractkit/chainlink-confidential-compute
      path: chainlink-confidential-compute
      # pin to a release tag or commit SHA
      ref: main

  - name: Setup Nitro Enclave Environment
    uses: ./chainlink-confidential-compute/.github/actions/setup-nitro-enclave
    with:
      total-cpu-count: "4"      # optional, default "4"
      total-memory-mib: "2048"  # optional, default "2048"
      hugepages: "1024"         # optional, default "1024"
```

After this step, `nitro-cli`, `wg`, `lsof`, and `socat` are available and the allocator is running. The action targets Amazon Linux (`dnf`), matching the self-hosted Nitro runners.

### 2. Go Test Library: `tests/testhelpers`

Import [tests/testhelpers](tests/testhelpers) to programmatically launch local enclaves. It is a standalone module whose dependency set is just the root module plus testify — no go-ethereum, no chainlink:

```go
import (
    "github.com/smartcontractkit/chainlink-confidential-compute/tests/testhelpers"
)

func TestMyFeature(t *testing.T) {
    // repoRoot is the absolute path to where you checked out this repository.
    repoRoot := os.Getenv("CONFIDENTIAL_COMPUTE_ROOT")

    cfg := testhelpers.DefaultLocalEnclaveSetupConfig(repoRoot, "confidential-http")
    // Optionally override:
    // cfg.EnclaveCount = 1
    // cfg.BinaryPath = "/path/to/prebuilt/binary"
    // cfg.Region = "us-west-2"

    result := testhelpers.SetupLocalEnclaves(t, cfg)
    defer result.CleanupAll()

    // result.Enclaves   – []types.Enclave ready for the enclave client pool
    // result.ConfigURLs – config-plane URLs for pushing EnclaveConfig
}
```

In your `go.mod`, add replace directives pointing at your local checkout:

```
require github.com/smartcontractkit/chainlink-confidential-compute/tests/testhelpers v0.0.0

replace github.com/smartcontractkit/chainlink-confidential-compute/tests/testhelpers => ./path/to/chainlink-confidential-compute/tests/testhelpers
replace github.com/smartcontractkit/chainlink-confidential-compute => ./path/to/chainlink-confidential-compute
```

#### Key exported symbols (package `testhelpers`)

| Symbol | Description |
|--------|-------------|
| `LocalEnclaveSetupConfig` | Configuration struct (repo root, app name, ports, CIDs, enclave type, region, extra env) |
| `DefaultLocalEnclaveSetupConfig(repoRoot, appName)` | Config with sensible defaults (2 enclaves, CID 16+, ports 8080+/8082+) |
| `SetupLocalEnclaves(t, config)` | Provisions local enclaves, returns `*LocalEnclaveResult` |
| `ParseRemoteEnclaves(config)` | Parses pre-deployed enclave URLs + PCR JSON into `[]types.Enclave` |
| `MustSetupEnclave(t, rootDir, cid, httpPort, configPort, app, name, isFirst)` | Low-level: starts a single enclave |
| `MustSetupEnclaveWithEnv(...)` | `MustSetupEnclave` with extra environment entries for the build script |
| `EnsureEnclaveAndGetMeasurements(cid)` | Retrieves PCR measurements from a running enclave |
| `UseFakeEnclave()` | Reports whether fake enclaves are selected (via `ENCLAVE_TYPE`, or no `nitro-cli`) |
| `KillProcessOnPort(t, port)` | Utility: kills any process listening on a port |
| `DetectHostIP()` | Returns the host IP reachable from Docker containers |

#### Prerequisites for the runner

- **Nitro instance**: For real enclaves, the host must be an EC2 instance with Nitro Enclaves enabled. Without `nitro-cli` on `PATH`, the helpers fall back to fake enclaves (see `UseFakeEnclave`).
- **Allocator configured**: Use the `setup-nitro-enclave` action above, or configure manually.
- **Capability binary**: Either build the binary into `tests/e2e/binaries/<app>` before calling `SetupLocalEnclaves`, or set `config.BinaryPath` to a pre-built binary.
- **Repository checkout**: This repo must be checked out — the build script, Dockerfile, and host binary are resolved relative to `config.RepoRoot`.

### 3. Full CI Example (External Repo)

```yaml
name: E2E Tests
on: [pull_request]
jobs:
  e2e:
    runs-on: [self-hosted, Linux, X64]  # must be a Nitro-capable instance
    steps:
      - uses: actions/checkout@v4

      - uses: actions/checkout@v4
        with:
          repository: smartcontractkit/chainlink-confidential-compute
          path: chainlink-confidential-compute
          ref: main  # or pin to a release tag

      - name: Setup Nitro Enclave Environment
        uses: ./chainlink-confidential-compute/.github/actions/setup-nitro-enclave

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Run E2E tests
        env:
          CONFIDENTIAL_COMPUTE_ROOT: ${{ github.workspace }}/chainlink-confidential-compute
        run: go test -v ./e2e/... -timeout 90m
```
