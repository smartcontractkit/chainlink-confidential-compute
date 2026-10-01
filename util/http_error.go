package util

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

// SanitizeOutboundHTTPError returns a fixed diagnostic for a hard HTTP failure.
// Neither the message nor the error chain retains the original error: URLs,
// certificate names, headers and response data may contain confidential values.
// ClassifyOutboundHTTPError is applied first by callers; sanitizing a hard
// failure does not turn it into a synthetic HTTP response.
func SanitizeOutboundHTTPError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, errHTTPRedirectNotAllowed) {
		return errors.New(types.ErrHTTPRedirectNotAllowed)
	}
	var (
		verificationErr *tls.CertificateVerificationError
		authorityErr    x509.UnknownAuthorityError
		hostnameErr     x509.HostnameError
		certificateErr  x509.CertificateInvalidError
	)
	if errors.As(err, &hostnameErr) {
		return errors.New("TLS certificate hostname mismatch")
	}
	if errors.As(err, &authorityErr) {
		return errors.New("TLS certificate authority not trusted")
	}
	if errors.As(err, &certificateErr) {
		if certificateErr.Reason == x509.Expired {
			return errors.New("TLS certificate expired or not yet valid")
		}
		return errors.New("TLS certificate verification failed")
	}
	if errors.As(err, &verificationErr) {
		return errors.New("TLS certificate verification failed")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		if detail, ok := tlsAlertDiagnostics[opErr.Err.Error()]; ok {
			switch opErr.Op {
			case "remote error":
				return errors.New("TLS peer reported " + detail)
			case "local error":
				return errors.New("TLS local error: " + detail)
			}
		}
	}
	return errors.New("transport failure")
}

// Like handshakeRejectionAlerts, this allowlist matches crypto/tls's unexported
// alert type by exact text. Only these fixed diagnostics are returned; unknown
// alerts and arbitrary error text remain redacted. These alerts stay hard errors.
var tlsAlertDiagnostics = map[string]string{
	tls.AlertError(10).Error(): "unexpected message",
	tls.AlertError(20).Error(): "bad record MAC",
	tls.AlertError(22).Error(): "record overflow",
	tls.AlertError(42).Error(): "bad certificate",
	tls.AlertError(43).Error(): "unsupported certificate",
	tls.AlertError(44).Error(): "revoked certificate",
	tls.AlertError(45).Error(): "expired certificate",
	tls.AlertError(46).Error(): "unknown certificate",
	tls.AlertError(47).Error(): "illegal parameter",
	tls.AlertError(48).Error(): "unknown certificate authority",
	tls.AlertError(49).Error(): "access denied",
	tls.AlertError(50).Error(): "decode error",
	tls.AlertError(51).Error(): "decrypt error",
	tls.AlertError(80).Error(): "internal error",
}

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

// handshakeRejectionAlerts holds the rendered text of the fatal TLS alerts that
// mean the upstream refused to negotiate: no shared parameters, or it will not
// serve the requested name. Only these are softened to a gateway status.
//
// Integrity alerts (bad record MAC, record overflow, decrypt error) are
// deliberately absent. crypto/tls reports a peer alert identically whenever it
// arrives, including after the handshake, so treating every fatal alert as a
// rejection would downgrade a tampering signal to a benign 502. Ambiguous
// alerts (illegal parameter, decode error, internal error) and the certificate
// family are absent for the same reason as the certificate-verification
// carve-out: they are not unambiguously an upstream negotiation refusal.
//
// Alert codes are IANA-assigned and fixed by RFC 8446 section 6.2. The alert
// value crypto/tls stores in *net.OpError is unexported, but renders identically
// to the exported tls.AlertError of the same code, so deriving the set from
// tls.AlertError tracks crypto/tls instead of hardcoding its wording.
var handshakeRejectionAlerts = map[string]struct{}{
	tls.AlertError(40).Error():  {}, // handshake_failure: no shared cipher suite or parameters
	tls.AlertError(70).Error():  {}, // protocol_version: no shared TLS version
	tls.AlertError(71).Error():  {}, // insufficient_security: our ciphers are below the upstream's floor
	tls.AlertError(112).Error(): {}, // unrecognized_name: the upstream does not serve the requested SNI
	tls.AlertError(116).Error(): {}, // certificate_required: the upstream demands a client certificate
	tls.AlertError(120).Error(): {}, // no_application_protocol: no shared ALPN protocol
}

// upstreamTLSFailure describes err when the upstream endpoint refused to
// negotiate TLS, and returns an empty string otherwise. It covers a handshake
// the upstream rejected with a negotiation-refusal alert and an endpoint that is
// not speaking TLS at all; both are faults at the upstream rather than in the
// enclave. It deliberately does not cover certificate verification failures, nor
// alerts and record-layer faults that can indicate tampering or a fault on
// either side ("local error: ..."), which stay hard failures.
//
// A version or cipher-suite mismatch does not need a separate branch: the client
// offers its parameters and the upstream refuses, so those arrive here as
// alert 70 or alert 40 rather than as a client-side abort.
func upstreamTLSFailure(err error) string {
	// A fatal alert from the peer (e.g. "remote error: tls: handshake failure")
	// surfaces as a *net.OpError wrapping crypto/tls's unexported alert type, so
	// Op identifies the peer as the sender and the rendered alert identifies
	// which fault it reported. Guarding on Op also keeps dial-stage OpErrors out
	// of this branch.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "remote error" && opErr.Err != nil {
		if _, ok := handshakeRejectionAlerts[opErr.Err.Error()]; ok {
			return fmt.Sprintf("upstream rejected the TLS handshake: %v", opErr.Err)
		}
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) || errors.Is(err, http.ErrSchemeMismatch) {
		return "upstream did not speak TLS on the requested port"
	}
	return ""
}
