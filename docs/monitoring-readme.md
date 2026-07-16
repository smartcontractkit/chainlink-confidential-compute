### High-Level Data Flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           REQUEST FLOW                                       │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Workflow Request                                                            │
│       │                                                                      │
│       ▼                                                                      │
│  ┌─────────────────────────────────────────────────────────┐                 │
│  │  CAPABILITY SIDE (Chainlink Node)                       │                 │
│  │  ┌─────────────────┐    ┌─────────────────┐             │                 │
│  │  │  executor.go    │───▶│  enclave-client │             │                 │ 
│  │  │  (orchestrator) │    │  (pool/client)  │             │                 │
│  │  └────────┬────────┘    └────────┬────────┘             │                 │
│  │           │                      │                      │                 │
│  │           ▼                      │                      │                 │
│  │  ┌─────────────────┐            │                       │                 │
│  │  │  metrics.go     │            │                       │                 │
│  │  │  (OTel export)  │            │                       │                 │
│  │  └─────────────────┘            │                       │                 │
│  └─────────────────────────────────┼───────────────────────┘                 │
│                                    │                                         │
│                                    ▼                                         │ 
│  ┌─────────────────────────────────────────────────────────┐                 │
│  │  ENCLAVE SIDE (TEE)                                     │                 │
│  │  ┌─────────────────┐    ┌──────────────────┐            │                 │
│  │  │  server.go      │───▶│  app.go          │            │                 │
│  │  │  (HTTP handler) │    │  (business logic)│            │                 │
│  │  └────────┬────────┘    └────────┬─────────┘            │                 │
│  │           │                      │                      │                 │
│  │           ▼                      ▼                      │                 │
│  │  ┌─────────────────────────────────────────┐            │                 │
│  │  │  response_emitter.go (metrics collector)│            │                 │
│  │  └─────────────────────────────────────────┘            │                 │
│  └─────────────────────────────────────────────────────────┘                 │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```
---
## Repository Architecture

```
confidential-compute/
├── capabilities/                    # Capability side (runs on Chainlink nodes)
│   └── framework/
│       ├── executor.go              # Request orchestration + metrics emission
│       ├── metrics.go               # OTel metrics interface (via beholder)
│       └── capability.go            # Capability registration
│
├── enclave/                         # Enclave side (runs inside TEE)
│   ├── server/
│   │   ├── server.go                # HTTP server, signature verification
│   │   └── response_emitter.go      # Collects metrics in response payload
│   ├── apps/
│   │   ├── confidential-http/       # HTTP request execution app
│   │   │   └── app/app.go
│   └── services/
│       ├── attestor/                # TEE attestation generation
│       ├── keychain/                # Ephemeral key management
│       ├── combiner/                # Secret share aggregation
│       └── signature-verifier/      # Request signature validation
│
├── enclave-client/                  # Client/pool for enclave communication
├── types/                           # Shared type definitions and protobuf
├── util/                            # Utility functions
├── tests/                           # End-to-end tests
├── scripts/                         # Build and utility scripts
└── runbooks/                        # Operational documentation
```
---

## Component Overview

### Capability Side

| Component | File | Purpose |
|-----------|------|---------|
| **Executor** | `capabilities/framework/executor.go` | Orchestrates enclave requests: rate limiting, VaultDON integration, retry logic, metrics emission |
| **Metrics** | `capabilities/framework/metrics.go` | OTel-based metrics interface using `beholder.GetMeter()` from chainlink-common |
| **Capability** | `capabilities/framework/capability.go` | Registers capability with Chainlink node |
| **Enclave Client** | `enclave-client/` | Connection pool and client for communicating with enclaves |

### Enclave Side

| Component | File | Purpose |
|-----------|------|---------|
| **Server** | `enclave/server/server.go` | HTTP server handling `/publicKeys`, `/config`, `/requests` endpoints |
| **Response Emitter** | `enclave/server/response_emitter.go` | Collects metrics for inclusion in response payload (cannot emit directly from TEE) |
| **Attestor** | `enclave/services/attestor/` | Creates TEE attestations (AWS Nitro Enclave support) |
| **Keychain** | `enclave/services/keychain/` | Manages ephemeral encryption keypairs |
| **Combiner** | `enclave/services/combiner/` | Aggregates decryption shares to recover secrets |
| **Signature Verifier** | `enclave/services/signature-verifier/` | Validates request signatures against allowed signers |

### Enclave Applications

| App | File | Purpose |
|-----|------|---------|
| **Confidential HTTP** | `enclave/apps/confidential-http/app/app.go` | Executes HTTP requests with injected secrets |

---

## Current Metrics Implementation

### Three-Tier Metrics Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  TIER 1: Capability Side (OTel → Prometheus)                            │
│  Location: capabilities/framework/executor.go + metrics.go              │
│  Export: beholder.GetMeter() → Prometheus endpoint                      │
├─────────────────────────────────────────────────────────────────────────┤
│  TIER 2: Enclave Server (Response-embedded)                             │
│  Location: enclave/server/server.go + response_emitter.go               │
│  Export: Embedded in ExecuteResponse.Metrics → forwarded by Tier 1      │
├─────────────────────────────────────────────────────────────────────────┤
│  TIER 3: Application Level (Custom emitters/Response Embedded)          │
│  Location: enclave/apps/*/app/app.go                                    │
│  Export: Via types.Emitter interface → Tier 2 → Tier 1                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Tier 1: Capability Side Metrics

**File:** `capabilities/framework/executor.go`

| Metric Name | Type | Line | Description |
|-------------|------|------|-------------|
| `requests_received_total` | Counter | 226 | Incremented on every incoming request |
| `requests_completed_total` | Counter | 366-367 | Incremented on successful completion (with workflow.owner, enclave.id attributes) |
| `enclave_params_error` | Counter | 243 | Error fetching enclave parameters |
| `vault_don_error` | Counter | 257 | VaultDON capability execution failed |
| `compute_request_signature_error` | Counter | 283 | Failed to sign compute request |
| `execute_error` | Counter | 290 | Enclave execution failed |
| `vault_don_cache_hit` | Counter | 652 | Secrets retrieved from cache |
| `vault_don_cache_miss` | Counter | 655 | Secrets fetched from VaultDON |
| `request_started`, `request_completed`, `signature_verification_completed`, `shares_combining_completed`, `app_execution_completed`, `attestation_creation_failed`, `user_metric` | Counter/Histogram | 340, 344 | Forwarded enclave events with `component=enclave` and `enclave.id` attributes |
| `rate_limit_exceeded` | Counter | 229 | Request rejected due to rate limiting (with workflow.owner attribute) |
| `attestation_validation_failed` | Counter | pool.go | Enclave attestation validation failed (with enclave.id, endpoint, error attributes) |

**Attributes applied:**
- `workflow.owner` - Owner of the workflow
- `component` - Source component for forwarded enclave metrics, currently `enclave`
- `enclave.id` - ID of the enclave that processed the request
- `workflow.id` - Workflow identifier

### Tier 2: Enclave Server Metrics

**File:** `enclave/server/server.go`

| Event Name | Line | Details Captured |
|------------|------|------------------|
| `request_started` | 187-189 | `endpoint` |
| `signature_verification_completed` | 235-238 | `duration_seconds`, `num_signatures` |
| `request_id` | 251-253 | `request_id` |
| `shares_combining_completed` | 302-305 | `duration_seconds`, `num_ciphertexts` |
| `app_execution_completed` | 310-312 | `duration_seconds` |
| `request_completed` | 348-352 | `endpoint`, `request_id`, `duration_seconds` |
| `attestation_creation_failed` | 363-366 | `endpoint`, `error` |

### Tier 3: Application Metrics

**File:** `enclave/apps/confidential-http/app/app.go`

| Event Name | Line | Details Captured |
|------------|------|------------------|
| `http_batch_started` | 79-81 | `num_requests` |
| `http_batch_completed` | 163-166 | `num_requests`, `duration_seconds` |

---

## Grafana Dashboard Status

| Dashboard | Data Source | Status | Notes |
|-----------|-------------|--------|-------|
| **K8S Infrastructure Metrics** | `confidential-compute-infra` repo | ✅ **Live** | Kubernetes-level metrics (pods, nodes, resources) |
| **Application Metrics** | `confidential-compute` repo | ❌ **Not Connected** | OTel metrics from executor.go not reaching Grafana |

Dashboard #2 will go live when we cut our new release and CRE integrates it.

### Required Future 

#### Critical Severity

| Required Metric | Status | Current Implementation | Gap / Action Needed |
|-----------------|--------|------------------------|---------------------|
| TEE private key leakage | ❌ | None | Add key access auditing in `enclave/services/keychain/` |
| Capability node approves invalid attestation | ✅ | `attestation_validation_failed` counter in `enclave-client/pool.go` | Implemented |
| User's private key leak | ❌ | None | Add secret access logging with anomaly detection |

#### Sev1

| Required Metric | Status | Current Implementation | Gap / Action Needed |
|-----------------|--------|------------------------|---------------------|
| Amazon attestation fails | ✅ | `attestation_creation_failed` counter in `enclave/server/server.go` | Implemented |
| All enclaves not receiving requests | ❌ | None | Implement heartbeat/health check system |
| All enclaves not processing requests correctly | ❌ | None | Add success rate tracking per enclave |
| Capability not processing requests | ⚠️ Partial | `execute_error` counter exists | Add granular error type breakdown |

#### Sev2

| Required Metric | Status | Current Implementation | Gap / Action Needed |
|-----------------|--------|------------------------|---------------------|
| Any enclave is down | ❌ | None | Add `/health` endpoint + periodic health checks |
| Abnormal request load | ✅ | `rate_limit_exceeded` counter in `executor.go` | Implemented (anomaly detection still needed) |

## Key Code Locations

### Quick Reference for Common Tasks

| Task | File | Lines | Notes |
|------|------|-------|-------|
| Add a new capability-side metric | `capabilities/framework/executor.go` | 226, 366 | Use `e.metrics.Emit()` |
| Add a new enclave-side metric | `enclave/server/server.go` | 185-352 | Use `responseEmitter.Emit()` |
| Add a new app-level metric | `enclave/apps/*/app/app.go` | varies | Use `emitter.Emit()` in Execute() |
| Modify metrics interface | `types/emitter.go` | all | All metrics use `types.Emitter` interface |
| Add histogram metric | `capabilities/framework/metrics.go` | 40-80 | Include `duration_seconds` in details map |
| Configure rate limiting | `capabilities/framework/executor.go` | 62-72, 454-459 | Modify `Config` struct and `parseConfig()` |

### Metrics Implementation Pattern

All metrics now use the unified `types.Emitter` interface with `Emit(event string, details map[string]any)`.

```go
// Capability side (executor.go) - uses MetricsEmitter which converts to OTel
e.metrics.Emit("metric_name", nil)  // Simple counter increment
e.metrics.Emit("metric_name", map[string]any{
    "workflow.owner": metadata.WorkflowOwner,
    "enclave.id":     enclaveID,
})
e.metrics.Emit("metric_name", map[string]any{
    "duration_seconds": elapsed.Seconds(),  // Automatically creates histogram
})

// Enclave side (server.go) - uses ResponseEmitter which embeds in response
responseEmitter.Emit("event_name", map[string]any{
    "duration_seconds": elapsed.Seconds(),
    "count": count,
})

// App side (app.go) - uses passed emitter
emitter.Emit("event_name", map[string]any{
    "num_requests": len(requests),
})
```

### Key External Dependencies

| Package | Usage |
|---------|-------|
| `github.com/smartcontractkit/chainlink-common/pkg/beholder` | Metrics provider (OTel meter) |
| `github.com/smartcontractkit/chainlink-common/pkg/capabilities` | Capability framework |
| `github.com/smartcontractkit/chainlink-common/pkg/ratelimit` | Rate limiting |
| `github.com/smartcontractkit/tdh2/go/tdh2/tdh2easy` | Threshold decryption |
| `go.opentelemetry.io/otel` | OpenTelemetry interfaces |

### Related Repositories

| Repository | Relationship |
|------------|--------------|
| `confidential-compute-infra` | Kubernetes infrastructure, K8S Grafana dashboard |
| `chainlink-common` | Shared capabilities framework, beholder metrics |

---
