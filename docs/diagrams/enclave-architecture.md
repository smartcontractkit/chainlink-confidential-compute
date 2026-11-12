# Enclave Architecture

<!-- diagram:BEGIN id=enclave-architecture digest=f0b1dc7ca2c3d9cd -->
<!-- Generated from the sources listed in .github/diagrams.yaml. Do not edit by hand; edit the manifest instructions instead. -->

```mermaid
flowchart TB
  EXT["External callers - DON signer nodes"]
  CHAIN["CapabilitiesRegistry - on-chain DON membership"]
  NET["Internet"]

  subgraph HOST["HOST - untrusted - parent instance"]
    MAIN["hostServer - terminates inbound HTTP - port 8080"]
    CFG["config server - 127.0.0.1 port 8081 - localhost only"]
    TRACKER["configTracker - on-chain config tracker"]
    PROXY["proxyserver - SOCKS5 server - AF_VSOCK CIDAny types.ProxyPort"]
    RULES["ruleSet.Allow - blocks local and loopback - public profile safeURL blocklist"]
  end

  subgraph ENCLAVE["NITRO ENCLAVE - trusted - EIF image"]
    START["StartNitroEnclave - VerifyEntropySource, kvm-clock, chrony PHC"]
    NSM["NSM - Nitro Security Module"]
    ENT["nsm-hwrng - kernel entropy pool"]
    SRV["enclaveServer - HTTP on AF_VSOCK port 5000"]

    subgraph ROUTES["enclaveServer routes"]
      R1["GET /publicKeys"]
      R2["POST and PATCH /config - PATCH quorum of F+1 signer votes"]
      R4["POST /settings"]
      R5["POST /requests"]
      R6["GET /memory"]
    end

    ATT["attestor.Attestor - nitroAttestor via NSM session"]
    KC["keychain.Keychain - boxKeychain NaCl box keypairs"]
    COMB["combiner.Combiner - tdh2EasyCombiner"]
    VER["SignatureVerifier - ed25519SignatureVerifier"]
    EMIT["types.Emitter - ResponseEmitter per request"]

    subgraph APPS["types.EnclaveApp - interchangeable payloads"]
      APP["types.EnclaveApp interface"]
      ECHO["echoEnclaveApp - confidential-echo - no network access"]
      HTTPAPP["httpEnclaveApp - confidential-http"]
      WFAPP["confidentialWorkflowsApp - confidential-workflows"]
    end

    DIAL["proxyclient.Dialer - SOCKS5 dialer"]
    EPOL["policy.validateAuthority - ports 80 or 443, or configured endpoints only"]
  end

  EXT -->|"signed compute requests - verified and batched to f+1 or 2f+1 quorum"| MAIN
  EXT -->|"PATCH /config signed votes"| MAIN
  TRACKER -->|"polls GetDON"| CHAIN
  TRACKER -->|"POST /config"| CFG
  MAIN ==>|"HTTP over AF_VSOCK - vsock.Dial to CID 16 port 5000 - host initiates"| SRV
  CFG ==>|"POST /config and /settings - AF_VSOCK port 5000 - host initiates"| SRV

  START -->|"NewEnclaveServer and vsock.Listen"| SRV
  START -->|"VerifyEntropySource"| ENT
  NSM -->|"registers nsm-hwrng"| ENT
  ATT -->|"CreateAttestation"| NSM
  SRV -->|"serves"| ROUTES
  SRV -->|"attests responses"| ATT
  SRV -->|"ephemeral keypairs"| KC
  SRV -->|"combines TDH2 shares"| COMB
  SRV -->|"verifies signer signatures"| VER
  SRV -->|"collects metric events"| EMIT
  R5 -->|"app.Execute with secrets"| APP
  R4 -->|"InjectSettings - opaque JSON"| APP
  APP --> ECHO
  APP --> HTTPAPP
  APP --> WFAPP
  HTTPAPP -->|"outbound HTTP"| DIAL
  WFAPP -->|"binary fetch and gateway dispatch"| DIAL
  DIAL -->|"validateAuthority"| EPOL
  DIAL ==>|"SOCKS5 over AF_VSOCK types.ProxyPort - enclave initiates"| PROXY
  PROXY --> RULES
  RULES -->|"dials destination"| NET
```

<!-- diagram:END id=enclave-architecture -->

## Sources

Generated from [`enclave/nitro/starter.go`](../../enclave/nitro/starter.go), [`enclave/nitro/types.go`](../../enclave/nitro/types.go), [`enclave/nitro/entropy.go`](../../enclave/nitro/entropy.go), [`enclave/server/server.go`](../../enclave/server/server.go), [`enclave/server/memory.go`](../../enclave/server/memory.go), [`enclave/server/response_emitter.go`](../../enclave/server/response_emitter.go), [`enclave/nitro/host/host.go`](../../enclave/nitro/host/host.go), [`enclave/nitro/host/public_data.go`](../../enclave/nitro/host/public_data.go), [`enclave/nitro/host/proxy-server/server.go`](../../enclave/nitro/host/proxy-server/server.go), [`enclave/nitro/host/proxy-server/policy.go`](../../enclave/nitro/host/proxy-server/policy.go), [`enclave/nitro/proxy-client/client.go`](../../enclave/nitro/proxy-client/client.go), [`enclave/nitro/proxy-client/policy.go`](../../enclave/nitro/proxy-client/policy.go), [`enclave/services/attestor/attestor.go`](../../enclave/services/attestor/attestor.go), [`enclave/services/attestor/nitro_attestor.go`](../../enclave/services/attestor/nitro_attestor.go), [`enclave/services/combiner/combiner.go`](../../enclave/services/combiner/combiner.go), [`enclave/services/combiner/tdh2easycombiner.go`](../../enclave/services/combiner/tdh2easycombiner.go), [`enclave/services/emitter/noopemitter.go`](../../enclave/services/emitter/noopemitter.go), [`enclave/services/keychain/box_keychain.go`](../../enclave/services/keychain/box_keychain.go), [`enclave/services/keychain/keychain.go`](../../enclave/services/keychain/keychain.go), [`enclave/services/signature-verifier/ed25519_signature_verifier.go`](../../enclave/services/signature-verifier/ed25519_signature_verifier.go), [`enclave/services/signature-verifier/verifier.go`](../../enclave/services/signature-verifier/verifier.go), [`enclave/config-tracker/config_tracker.go`](../../enclave/config-tracker/config_tracker.go), [`enclave/config-tracker/main.go`](../../enclave/config-tracker/main.go), [`enclave/apps/confidential-echo/app/app.go`](../../enclave/apps/confidential-echo/app/app.go), [`enclave/apps/confidential-http/app/app.go`](../../enclave/apps/confidential-http/app/app.go), [`enclave/apps/confidential-workflows/app/app.go`](../../enclave/apps/confidential-workflows/app/app.go).
