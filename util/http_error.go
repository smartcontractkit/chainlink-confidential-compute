package util

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
)

// outboundUnavailableError is implemented by transport errors reporting that the
// enclave's egress broker is out of capacity or draining. Declaring the
// behaviour here keeps util importable by modules that do not link the Nitro
// VSOCK transport (e.g. enclave/config-tracker).
type outboundUnavailableError interface{ OutboundUnavailable() bool }

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
//   - DNS NXDOMAIN                           -> 400 Bad Request
//   - SSRF policy block                      -> 400 Bad Request
//   - connection refused                     -> 502 Bad Gateway
//   - connection reset / closed (EOF)        -> 502 Bad Gateway
//
// The 502 cases are faults at the upstream endpoint, not the enclave, so they
// surface as a gateway error rather than a capability failure. It returns nil
// for a nil error or any other error (e.g. TLS verification), signalling the
// caller to treat it as a genuine transport failure.
func ClassifyOutboundHTTPError(err error) *OutboundHTTPError {
	if err == nil {
		return nil
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return &OutboundHTTPError{StatusCode: http.StatusGatewayTimeout, Body: "upstream request timed out"}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return &OutboundHTTPError{StatusCode: http.StatusBadRequest, Body: fmt.Sprintf("upstream DNS resolution failed for %s: %v", dnsErr.Name, err)}
	}
	if IsRequestBlockedError(err) {
		return &OutboundHTTPError{StatusCode: http.StatusBadRequest, Body: "upstream request blocked by enclave network policy"}
	}
	var unavailable outboundUnavailableError
	if errors.As(err, &unavailable) && unavailable.OutboundUnavailable() {
		return &OutboundHTTPError{StatusCode: http.StatusServiceUnavailable, Body: "enclave outbound proxy is temporarily unavailable"}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return &OutboundHTTPError{StatusCode: http.StatusBadGateway, Body: "upstream connection refused"}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) {
		return &OutboundHTTPError{StatusCode: http.StatusBadGateway, Body: "upstream closed the connection before responding"}
	}
	return nil
}
