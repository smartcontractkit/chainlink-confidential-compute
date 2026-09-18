# Enclave Architecture

<!-- diagram:BEGIN id=enclave-architecture digest=f0b1dc7ca2c3d9cd -->
<!-- Generated from the sources listed in .github/diagrams.yaml. Do not edit by hand; edit the manifest instructions instead. -->

```mermaid
flowchart LR
    subgraph ENCLAVE["Nitro enclave - trusted execution"]
        direction TB
        START["StartNitroEnclave - VerifyEntropySource, kvm-clock, chrony PHC checks"]
        ENT["kernel entropy pool - rng_current nsm-hwrng"]
        NSM["NSM - Nitro Security Module"]
        SRV["enclaveServer - HTTP over vsock"]
        ROUTES["mux routes - GET /publicKeys, POST and PATCH /config, POST /settings, POST /requests, GET /memory"]
        ATT["Attestor - nitroAttestor over NSM session"]
        KC["Keychain - boxKeychain NaCl box keypairs"]
        COMB["Combiner - tdh2EasyCombiner TDH2 shares"]
        VER["SignatureVerifier - ed25519SignatureVerifier"]
        EMIT["Emitter - ResponseEmitter metrics in response payload"]
        DIAL["proxyclient.Dialer - SOCKS5 over AF_VSOCK, enclave side validateAuthority"]
        subgraph APPS["types.EnclaveApp - interchangeable payloads"]
            APP["types.EnclaveApp"]
            ECHO["echoEnclaveApp - no network access"]
            HTTPAPP["httpEnclaveApp - outbound HTTP with injected secrets"]
            WF["confidentialWorkflowsApp - fetches and runs workflow binaries"]
        end
    end

    subgraph HOST["Parent instance host - untrusted"]
        direction TB
        MAIN["hostServer main listener :8080 - terminates inbound HTTP, quorum batching"]
        CFG["hostServer config listener 127.0.0.1:8081 - localhost only"]
        PROXY["proxyserver - SOCKS5 listener on vsock CIDAny types.ProxyPort"]
        RULES["ruleSet.Allow - policy check, profiles public, configured, test"]
        TRACKER["configTracker - watches DON membership"]
    end

    CHAIN["CapabilitiesRegistry contract - on chain"]
    NET["Internet"]

    START -->|"VerifyEntropySource"| ENT
    NSM -->|"registers nsm-hwrng"| ENT
    START -->|"NewEnclaveServer injects app and services, vsock.Listen"| SRV
    SRV -->|"Handler mux"| ROUTES
    SRV --> ATT
    SRV --> KC
    SRV --> COMB
    SRV --> VER
    SRV --> EMIT
    ATT -->|"CreateAttestation"| NSM
    SRV -->|"app.Execute, InjectSettings, OnConfigUpdate"| APP
    APP --> ECHO
    APP --> HTTPAPP
    APP --> WF
    HTTPAPP -->|"outbound HTTP"| DIAL
    WF -->|"httpfetch, storage fetcher, remote dispatcher"| DIAL
    DIAL -->|"AF_VSOCK dial parent CID types.ProxyPort - enclave initiates"| PROXY
    PROXY -->|"Allow"| RULES
    RULES -->|"net.Dialer dials allowed destination"| NET
    MAIN -->|"AF_VSOCK CID 16 port 5000 - host initiates - /publicKeys, /requests, PATCH /config"| SRV
    CFG -->|"AF_VSOCK CID 16 port 5000 - host initiates - POST /config, POST /settings"| SRV
    TRACKER -->|"GetDON"| CHAIN
    TRACKER -->|"POST /config over localhost"| CFG
```

<!-- diagram:END id=enclave-architecture -->

## Sources

Generated from [`enclave/nitro/starter.go`](../../enclave/nitro/starter.go), [`enclave/nitro/types.go`](../../enclave/nitro/types.go), [`enclave/nitro/entropy.go`](../../enclave/nitro/entropy.go), [`enclave/server/server.go`](../../enclave/server/server.go), [`enclave/server/memory.go`](../../enclave/server/memory.go), [`enclave/server/response_emitter.go`](../../enclave/server/response_emitter.go), [`enclave/nitro/host/host.go`](../../enclave/nitro/host/host.go), [`enclave/nitro/host/public_data.go`](../../enclave/nitro/host/public_data.go), [`enclave/nitro/host/proxy-server/server.go`](../../enclave/nitro/host/proxy-server/server.go), [`enclave/nitro/host/proxy-server/policy.go`](../../enclave/nitro/host/proxy-server/policy.go), [`enclave/nitro/proxy-client/client.go`](../../enclave/nitro/proxy-client/client.go), [`enclave/nitro/proxy-client/policy.go`](../../enclave/nitro/proxy-client/policy.go), [`enclave/services/attestor/attestor.go`](../../enclave/services/attestor/attestor.go), [`enclave/services/attestor/nitro_attestor.go`](../../enclave/services/attestor/nitro_attestor.go), [`enclave/services/combiner/combiner.go`](../../enclave/services/combiner/combiner.go), [`enclave/services/combiner/tdh2easycombiner.go`](../../enclave/services/combiner/tdh2easycombiner.go), [`enclave/services/emitter/noopemitter.go`](../../enclave/services/emitter/noopemitter.go), [`enclave/services/keychain/box_keychain.go`](../../enclave/services/keychain/box_keychain.go), [`enclave/services/keychain/keychain.go`](../../enclave/services/keychain/keychain.go), [`enclave/services/signature-verifier/ed25519_signature_verifier.go`](../../enclave/services/signature-verifier/ed25519_signature_verifier.go), [`enclave/services/signature-verifier/verifier.go`](../../enclave/services/signature-verifier/verifier.go), [`enclave/config-tracker/config_tracker.go`](../../enclave/config-tracker/config_tracker.go), [`enclave/config-tracker/main.go`](../../enclave/config-tracker/main.go), [`enclave/apps/confidential-echo/app/app.go`](../../enclave/apps/confidential-echo/app/app.go), [`enclave/apps/confidential-http/app/app.go`](../../enclave/apps/confidential-http/app/app.go), [`enclave/apps/confidential-workflows/app/app.go`](../../enclave/apps/confidential-workflows/app/app.go).
