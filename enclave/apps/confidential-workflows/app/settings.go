package app

import (
	"encoding/json"
	"fmt"
	"time"
)

// WorkflowSettings is the runtime config + secrets contract of this app. The
// host injects it as JSON over vsock (POST /settings). Storage settings are
// owned by the host; this app reads the remaining fields. A Nitro EIF is measured
// (PCR), so environment-specific endpoints and tunables cannot be baked in
// without changing the attestation; they are supplied at runtime instead,
// keeping one EIF usable across environments.
//
// Every injection carries the complete configuration: GatewayURL is required
// and a payload missing it is rejected whole, rather than leaving the app
// half-configured. The remaining fields are tunables that fall back to their
// built-in defaults when omitted. Unknown fields are ignored, so a payload
// written for a newer app can still be injected into an older one -- including
// the storage fields, which the host (not the enclave) reads to fetch workflow
// binaries itself.
//
//   - GatewayURL: the Gateway endpoint(s) for remote dispatch (dynamic secrets +
//     capability calls). Accepts a comma-separated list; the enclave round-robins
//     across them and fails over to the next on a transport/proxy error.
//   - RequestTimeout: global request timeout inside the enclave, used as the
//     default deadline for outbound HTTP a workflow makes while being served.
//     Should track the caller's enclave request timeout, since work outliving
//     that deadline is work nobody is waiting for. Zero falls back to the
//     enclave's built-in default.
//   - GatewayRequestTimeout: HTTP client timeout for enclave->gateway requests
//     (dynamic secrets + capability calls). Should not exceed RequestTimeout:
//     the gateway call is nested inside the enclave's own request lifecycle.
//     Zero falls back to the enclave's built-in default.
//   - ExecutionTimeout: wall-clock bound on a single workflow execution (the
//     WASM module run). Caps how long a hung or runaway workflow holds one of
//     the enclave's bounded execution slots. Zero falls back to the WASM host's
//     built-in default, which is 10 minutes.
//   - WorkflowGracePeriod: how long each validated execution waits before it
//     starts running. Zero falls back to types.DefaultWorkflowGracePeriod; a
//     negative value disables the wait.
//   - MaxConcurrentCompilations: how many executions may hold a WASM module
//     under compilation simultaneously. Capping this bounds peak compilation
//     memory; raising it bounds queue wait when many workflows compile at
//     once. Zero falls back to defaultMaxConcurrentCompilations; negative
//     values are rejected so a typo can't fully stall execution.
type WorkflowSettings struct {
	GatewayURL            string   `json:"gatewayUrl"`
	RequestTimeout        Duration `json:"requestTimeout,omitempty"`
	GatewayRequestTimeout Duration `json:"gatewayRequestTimeout,omitempty"`
	// GatewayRetryBackoff paces successive gateway round-trips when the enclave
	// retries a capability call or secret fetch after a transient transport
	// failure (gateway rotation, proxy 5xx). Zero falls back to the enclave's
	// built-in default.
	GatewayRetryBackoff Duration `json:"gatewayRetryBackoff,omitempty"`
	// GatewayRetryTimeout bounds the full gateway retry window for one capability
	// call or secret fetch (all attempts, including backoffs), independent of the
	// per-attempt GatewayRequestTimeout. Zero falls back to the enclave's
	// built-in default.
	GatewayRetryTimeout Duration `json:"gatewayRetryTimeout,omitempty"`
	ExecutionTimeout    Duration `json:"executionTimeout,omitempty"`
	WorkflowGracePeriod Duration `json:"workflowGracePeriod,omitempty"`
	// MaxConcurrentCompilations caps simultaneous WASM compilations; zero means
	// defaultMaxConcurrentCompilations.
	MaxConcurrentCompilations int64 `json:"maxConcurrentCompilations,omitempty"`
}

// defaultMaxConcurrentCompilations is the compile-slot count applied when the
// injected settings omit MaxConcurrentCompilations.
const defaultMaxConcurrentCompilations = 4

// validate rejects missing gateway settings and invalid compilation limits.
func (s *WorkflowSettings) validate() error {
	if s.MaxConcurrentCompilations < 0 {
		return fmt.Errorf("maxConcurrentCompilations must be non-negative; 0 means the default of %d (got %d)", defaultMaxConcurrentCompilations, s.MaxConcurrentCompilations)
	}
	if s.GatewayURL == "" {
		return fmt.Errorf("missing required settings: gatewayUrl")
	}
	return nil
}

// Duration is a time.Duration that unmarshals from either a Go duration string
// ("80s") or a plain number of nanoseconds, so hand-written deployment config
// can use the readable form.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("parsing duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var ns int64
	if err := json.Unmarshal(b, &ns); err != nil {
		return fmt.Errorf("parsing duration: %w", err)
	}
	*d = Duration(ns)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}
