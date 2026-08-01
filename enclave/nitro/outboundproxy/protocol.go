// Package outboundproxy implements the enclave side of the HTTP CONNECT over
// AF_VSOCK egress protocol shared with the Nitro host.
package outboundproxy

import "fmt"

const (
	// ParentCID is the CID Nitro enclaves use to reach their parent instance.
	ParentCID uint32 = 3
	// Port is reserved for enclave outbound egress.
	Port uint32 = 5001

	ResolvePath   = "/v1/resolve"
	VersionHeader = "X-CC-Proxy-Version"
	Version       = "1"

	// MaxResolvedAddresses bounds a resolve response. The broker caps what it
	// sends; the enclave enforces the same ceiling on receipt, because the
	// parent is untrusted and an oversized answer costs the enclave one VSOCK
	// handshake per address inside the caller deadline.
	MaxResolvedAddresses = 16
)

type ErrorCode string

const (
	CodeProtocol       ErrorCode = "protocol_error"
	CodeUnauthorized   ErrorCode = "unauthorized_cid"
	CodePolicyDenied   ErrorCode = "policy_denied"
	CodeCapacity       ErrorCode = "capacity"
	CodeDraining       ErrorCode = "draining"
	CodeDNSNotFound    ErrorCode = "dns_not_found"
	CodeDNSTimeout     ErrorCode = "dns_timeout"
	CodeDNSFailure     ErrorCode = "dns_failure"
	CodeConnectTimeout ErrorCode = "connect_timeout"
	CodeConnectRefused ErrorCode = "connect_refused"
	CodeConnectReset   ErrorCode = "connect_reset"
	CodeConnectFailure ErrorCode = "connect_failure"
)

type ErrorResponse struct {
	Code ErrorCode `json:"code"`
}

type ResolveResponse struct {
	Addresses []string `json:"addresses"`
}

// ProxyError is returned when the broker rejects a request in a way that does
// not map to an existing Go DNS, timeout, connection, or policy error.
type ProxyError struct {
	Code ErrorCode
	Op   string
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("outbound proxy %s failed: %s", e.Op, e.Code)
}

// OutboundUnavailable reports a transient broker failure so callers map it to
// 503 without importing this package's error codes. An unregistered CID is
// lifecycle state owned by the host supervisor, so it is transient too.
func (e *ProxyError) OutboundUnavailable() bool {
	return e.Code == CodeCapacity || e.Code == CodeDraining || e.Code == CodeUnauthorized
}
