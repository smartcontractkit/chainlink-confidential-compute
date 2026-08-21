package util

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
)

// OutboundHTTPError is a synthetic HTTP response returned for an outbound
// request failure that should surface to the caller as an HTTP status rather
// than an enclave/capability error: a client-side or transient-upstream fault.
type OutboundHTTPError struct {
	StatusCode int
	Body       string
}

// ClassifyOutboundHTTPError maps an error from an HTTP client's Do call to a
// synthetic response for the conditions the outbound HTTP capabilities treat as
// caller-facing rather than enclave failures:
//   - timeout (deadline or net timeout)     -> 504 Gateway Timeout
//   - DNS NXDOMAIN / host unreachable        -> 502 Bad Gateway
//   - SSRF policy block                      -> 400 Bad Request
//   - connection refused                     -> 502 Bad Gateway
//   - connection reset / closed (EOF)        -> 502 Bad Gateway
//   - upstream-rejected TLS handshake        -> 502 Bad Gateway
//
// The 502 cases are faults at the upstream endpoint, not the enclave, so they
// surface as a gateway error rather than a capability failure. It returns nil
// for a nil error or any other error, signalling the caller to treat it as a
// genuine transport failure. Certificate verification failures are deliberately
// excluded: an untrusted or mismatched chain may indicate interception, so it
// stays a hard failure rather than a status the caller can ignore.
func ClassifyOutboundHTTPError(err error) *OutboundHTTPError {
	if err == nil {
		return nil
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &OutboundHTTPError{StatusCode: http.StatusGatewayTimeout, Body: "upstream request timed out"}
	}
	var dnsErr *net.DNSError
	if (errors.As(err, &dnsErr) && dnsErr.IsNotFound) || errors.Is(err, syscall.EHOSTUNREACH) {
		return &OutboundHTTPError{StatusCode: http.StatusBadGateway, Body: "upstream host unreachable"}
	}
	if IsRequestBlockedError(err) {
		return &OutboundHTTPError{StatusCode: http.StatusBadRequest, Body: "upstream request blocked by enclave network policy"}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return &OutboundHTTPError{StatusCode: http.StatusBadGateway, Body: "upstream connection refused"}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return &OutboundHTTPError{StatusCode: http.StatusBadGateway, Body: "upstream closed the connection before responding"}
	}
	if detail := upstreamTLSFailure(err); detail != "" {
		return &OutboundHTTPError{StatusCode: http.StatusBadGateway, Body: detail}
	}
	return nil
}

// upstreamTLSFailure describes err when the upstream endpoint failed the TLS
// handshake, and returns an empty string otherwise. It covers a handshake the
// upstream rejected with a fatal alert and an endpoint that is not speaking TLS
// at all; both are faults at the upstream rather than in the enclave. It
// deliberately does not cover certificate verification failures.
func upstreamTLSFailure(err error) string {
	// A fatal alert received from the peer (e.g. "remote error: tls: handshake
	// failure") surfaces as a *net.OpError wrapping crypto/tls's unexported
	// alert type, so Op is the only usable discriminator. Guarding on Op also
	// keeps dial-stage OpErrors out of this branch.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" {
		return fmt.Sprintf("upstream rejected the TLS handshake: %v", opErr.Err)
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) || errors.Is(err, http.ErrSchemeMismatch) {
		return "upstream did not speak TLS on the requested port"
	}
	return ""
}
