# Enclave Architecture

<!-- diagram:BEGIN id=enclave-architecture digest=74c96c1194555362 -->
<!-- Generated from the sources listed in .github/diagrams.yaml. Do not edit by hand; edit the manifest instructions instead. -->

```mermaid
flowchart TB

    EXT["External callers"]

    subgraph HOST["UNTRUSTED HOST - parent instance"]
        MAIN["hostServer main HTTP :8080"]
        CFG["hostServer config HTTP 127.0.0.1:8081"]
        TRACKER["configTracker"]
        PROXY["proxyserver SOCKS5 - vsock.ListenAt CIDAny types.ProxyPort"]
        RULES["ruleSet.Allow and publicProfileAllowsAddress"]
        CRASHH["serveCrashReports listener - types.CrashReportPort"]
    end

    subgraph ENCLAVE["NITRO ENCLAVE - trust boundary"]
        START["StartNitroEnclave"]
        NSM["Nitro Security Module session"]
        ENT["nsm-hwrng feeding kernel entropy pool"]
        SRV["enclaveServer - http.Serve on AF_VSOCK 5000"]
        ROUTES["routes /publicKeys /requests /config /settings /memory"]
        ATT["attestor.Attestor - nitroAttestor"]
        KC["keychain.Keychain - boxKeychain"]
        COMB["combiner.Combiner - tdh2EasyCombiner"]
        VER["SignatureVerifier - ed25519SignatureVerifier"]
        EMIT["types.Emitter - ResponseEmitter or noOpEmitter"]
        APP["types.EnclaveApp"]
        DIALER["proxyclient.Dialer - SOCKS5 profile credentials"]
        POLICY["policy.validateAuthority - ports 80 443 or configured endpoints"]
        CRASHE["enclave supervisor post-mortems"]

        subgraph APPS["EnclaveApp payloads - one per EIF"]
            ECHO["confidential-echo"]
            HTTPA["confidential-http"]
            WF["confidential-workflows"]
        end
    end

    CHAIN["CapabilitiesRegistry contract"]
    INET["Internet destinations"]

    EXT -->|"SignedComputeRequest batches - quorum f+1 or 2f+1"| MAIN
    TRACKER -->|"GetDON DON membership"| CHAIN
    TRACKER -->|"postConfig on membership change"| CFG

    MAIN -->|"proxy /publicKeys /requests PATCH /config - AF_VSOCK 5000 - host dials enclave CID 16"| SRV
    CFG -->|"POST /config and POST /settings - AF_VSOCK 5000 - host dials enclave CID 16"| SRV
    CRASHE -->|"post-mortem - AF_VSOCK types.CrashReportPort - enclave dials host"| CRASHH

    START -->|"OpenNitroAttestor - nsm.OpenDefaultSession"| NSM
    START -->|"VerifyEntropySource"| ENT
    NSM -->|"NSM driver registers hwrng"| ENT
    START -->|"NewEnclaveServer - vsock.Listen - Start"| SRV
    SRV -->|"Handler"| ROUTES

    ROUTES -->|"CreateAttestation"| ATT
    ATT -->|"session.Send Attestation"| NSM
    ROUTES -->|"GetKeyPairs and GetKeyPairForRequest"| KC
    ENT -->|"crypto/rand key material"| KC
    ROUTES -->|"AggregateShares threshold T"| COMB
    ROUTES -->|"VerifySignature against config.Signers"| VER
    ROUTES -->|"NewResponseEmitter per request"| EMIT
    ROUTES -->|"app.Execute with plaintext secrets"| APP
    APP -->|"Emit metric events"| EMIT

    APP -.->|"one payload per EIF"| ECHO
    APP -.->|"one payload per EIF"| HTTPA
    APP -.->|"one payload per EIF"| WF

    HTTPA -->|"httpClient egress"| DIALER
    WF -->|"httpfetch storage fetcher remote dispatcher"| DIALER
    DIALER -->|"validateAuthority before connect"| POLICY
    DIALER -->|"SOCKS5 - AF_VSOCK types.ProxyPort - enclave dials parent"| PROXY
    PROXY -->|"ruleSet.Allow per connection"| RULES
    RULES -->|"dial destination"| INET
```

<!-- diagram:END id=enclave-architecture -->

## Sources

Generated from [`enclave/nitro/starter.go`](../../enclave/nitro/starter.go), [`enclave/nitro/types.go`](../../enclave/nitro/types.go), [`enclave/nitro/entropy.go`](../../enclave/nitro/entropy.go), [`enclave/server/server.go`](../../enclave/server/server.go), [`enclave/server/memory.go`](../../enclave/server/memory.go), [`enclave/server/response_emitter.go`](../../enclave/server/response_emitter.go), [`enclave/nitro/host/host.go`](../../enclave/nitro/host/host.go), [`enclave/nitro/host/public_data.go`](../../enclave/nitro/host/public_data.go), [`enclave/nitro/host/proxy-server/server.go`](../../enclave/nitro/host/proxy-server/server.go), [`enclave/nitro/host/proxy-server/policy.go`](../../enclave/nitro/host/proxy-server/policy.go), [`enclave/nitro/proxy-client/client.go`](../../enclave/nitro/proxy-client/client.go), [`enclave/nitro/proxy-client/policy.go`](../../enclave/nitro/proxy-client/policy.go), [`enclave/services/attestor/attestor.go`](../../enclave/services/attestor/attestor.go), [`enclave/services/attestor/nitro_attestor.go`](../../enclave/services/attestor/nitro_attestor.go), [`enclave/services/combiner/combiner.go`](../../enclave/services/combiner/combiner.go), [`enclave/services/combiner/tdh2easycombiner.go`](../../enclave/services/combiner/tdh2easycombiner.go), [`enclave/services/emitter/noopemitter.go`](../../enclave/services/emitter/noopemitter.go), [`enclave/services/keychain/box_keychain.go`](../../enclave/services/keychain/box_keychain.go), [`enclave/services/keychain/keychain.go`](../../enclave/services/keychain/keychain.go), [`enclave/services/signature-verifier/ed25519_signature_verifier.go`](../../enclave/services/signature-verifier/ed25519_signature_verifier.go), [`enclave/services/signature-verifier/verifier.go`](../../enclave/services/signature-verifier/verifier.go), [`enclave/config-tracker/config_tracker.go`](../../enclave/config-tracker/config_tracker.go), [`enclave/config-tracker/main.go`](../../enclave/config-tracker/main.go), [`enclave/apps/confidential-echo/app/app.go`](../../enclave/apps/confidential-echo/app/app.go), [`enclave/apps/confidential-fault/app/app.go`](../../enclave/apps/confidential-fault/app/app.go), [`enclave/apps/confidential-http/app/app.go`](../../enclave/apps/confidential-http/app/app.go), [`enclave/apps/confidential-workflows/app/app.go`](../../enclave/apps/confidential-workflows/app/app.go).
