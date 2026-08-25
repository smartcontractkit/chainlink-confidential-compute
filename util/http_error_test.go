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
	"net/http/httptest"
	"net/url"
	"os"
	"syscall"
	"testing"

	"github.com/doyensec/safeurl"
	proxyclient "github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrap reproduces the layering net/http puts around a transport error: the
// classifier always sees the failure through a *url.Error.
func wrap(err error) error {
	return &url.Error{Op: "Get", URL: "https://upstream.example.com/v1", Err: err}
}

// peerAlert builds the error crypto/tls produces on receiving a fatal alert from
// the peer. crypto/tls uses an unexported alert type, but it renders identically
// to tls.AlertError of the same code, which is what the classifier matches on.
func peerAlert(code uint8) error {
	return &net.OpError{Op: "remote error", Err: tls.AlertError(code)}
}

func TestClassifyOutboundHTTPError(t *testing.T) {
	tests := map[string]struct {
		err            error
		wantStatus     int
		wantBodySubstr string
	}{
		"nil error": {
			err: nil,
		},
		"unrecognized transport failure": {
			err: wrap(errors.New("some other transport failure")),
		},
		"deadline exceeded": {
			err:            wrap(context.DeadlineExceeded),
			wantStatus:     http.StatusGatewayTimeout,
			wantBodySubstr: "timed out",
		},
		"net timeout": {
			err:            wrap(&net.DNSError{Name: "upstream.example.com", IsTimeout: true}),
			wantStatus:     http.StatusGatewayTimeout,
			wantBodySubstr: "timed out",
		},
		"dns nxdomain": {
			err:            wrap(&net.DNSError{Name: "upstream.example.com", IsNotFound: true}),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream host unreachable",
		},
		"host unreachable via outbound proxy": {
			err:            wrap(syscall.EHOSTUNREACH),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream host unreachable",
		},
		"outbound proxy policy block": {
			err:            wrap(&proxyclient.PolicyError{Reason: "private address"}),
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "blocked by enclave network policy",
		},
		"ssrf policy block": {
			err:            wrap(&net.OpError{Op: "dial", Err: &safeurl.AllowedSchemeError{}}),
			wantStatus:     http.StatusBadRequest,
			wantBodySubstr: "blocked by enclave network policy",
		},
		"connection refused": {
			err:            wrap(&net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED}}),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "connection refused",
		},
		"connection reset": {
			err:            wrap(&net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}}),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "closed the connection",
		},
		"unexpected eof": {
			err:            wrap(io.ErrUnexpectedEOF),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "closed the connection",
		},
		// crypto/tls reports a fatal alert from the peer as a *net.OpError with
		// Op "remote error"; the wrapped alert type is unexported but renders
		// identically to the exported tls.AlertError of the same code.
		"peer rejected handshake": {
			err:            wrap(peerAlert(40)), // handshake_failure
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream rejected the TLS handshake: tls: handshake failure",
		},
		"peer refused the TLS version": {
			err:            wrap(peerAlert(70)), // protocol_version
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream rejected the TLS handshake: tls: protocol version not supported",
		},
		"peer ciphers below its security floor": {
			err:            wrap(peerAlert(71)), // insufficient_security
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream rejected the TLS handshake: tls: insufficient security level",
		},
		"peer does not serve the requested SNI": {
			err:            wrap(peerAlert(112)), // unrecognized_name
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream rejected the TLS handshake: tls: unrecognized name",
		},
		"peer demands a client certificate": {
			err:            wrap(peerAlert(116)), // certificate_required
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream rejected the TLS handshake: tls: certificate required",
		},
		"peer found no shared ALPN protocol": {
			err:            wrap(peerAlert(120)), // no_application_protocol
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "upstream rejected the TLS handshake: tls: no application protocol",
		},
		// Integrity alerts can arrive after the handshake and can indicate
		// tampering, so they must not be softened into a gateway status.
		"bad record MAC stays a hard error": {
			err: wrap(peerAlert(20)), // bad_record_mac
		},
		"record overflow stays a hard error": {
			err: wrap(peerAlert(22)), // record_overflow
		},
		"decrypt error stays a hard error": {
			err: wrap(peerAlert(51)), // decrypt_error
		},
		// Ambiguous alerts do not pin the fault on the upstream.
		"illegal parameter stays a hard error": {
			err: wrap(peerAlert(47)), // illegal_parameter
		},
		"peer internal error stays a hard error": {
			err: wrap(peerAlert(80)), // internal_error
		},
		"peer certificate alert stays a hard error": {
			err: wrap(peerAlert(48)), // unknown_ca
		},
		// A local record-layer fault is corruption in the stream, not an upstream
		// negotiation refusal.
		"local decode error stays a hard error": {
			err: wrap(&net.OpError{Op: "local error", Err: tls.AlertError(50)}),
		},
		// Certificate failures stay hard errors: an untrusted or mismatched
		// chain may indicate interception, so it is not softened to a status.
		"untrusted certificate chain stays a hard error": {
			err: wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}),
		},
		"certificate hostname mismatch stays a hard error": {
			err: wrap(&tls.CertificateVerificationError{Err: x509.HostnameError{Host: "upstream.example.com", Certificate: &x509.Certificate{}}}),
		},
		"upstream not speaking tls": {
			err:            wrap(tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "did not speak TLS",
		},
		"upstream served plaintext http": {
			err:            wrap(http.ErrSchemeMismatch),
			wantStatus:     http.StatusBadGateway,
			wantBodySubstr: "did not speak TLS",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := ClassifyOutboundHTTPError(tt.err)
			if tt.wantStatus == 0 {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.wantStatus, got.StatusCode)
			assert.Contains(t, got.Body, tt.wantBodySubstr)
		})
	}
}

// TestClassifyOutboundHTTPErrorBodyOmitsRequestURL asserts the TLS branches
// describe the failure without echoing the request URL back, since the URL can
// carry caller secrets in its query string.
func TestClassifyOutboundHTTPErrorBodyOmitsRequestURL(t *testing.T) {
	secretURL := "https://upstream.example.com/v1?api_key=super-secret"
	errs := []error{
		&url.Error{Op: "Get", URL: secretURL, Err: &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}},
		&url.Error{Op: "Get", URL: secretURL, Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}},
	}
	for i, err := range errs {
		t.Run(fmt.Sprintf("case %d", i), func(t *testing.T) {
			got := ClassifyOutboundHTTPError(err)
			require.NotNil(t, got)
			assert.NotContains(t, got.Body, "super-secret")
		})
	}
}

// TestClassifyOutboundHTTPErrorRealTLSFailures drives the classifier with errors
// produced by crypto/tls itself rather than hand-built ones. The peer-alert
// branch keys off *net.OpError's unexported alert payload, so this pins the
// shape crypto/tls actually returns.
func TestClassifyOutboundHTTPErrorRealTLSFailures(t *testing.T) {
	tests := map[string]struct {
		serve          func(net.Conn)
		wantBodySubstr string
	}{
		"peer sends fatal handshake_failure alert": {
			// TLS record: alert(21), version 3.3, length 2, level fatal(2),
			// description handshake_failure(40).
			serve:          writeThenClose([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40}),
			wantBodySubstr: "upstream rejected the TLS handshake: tls: handshake failure",
		},
		"peer sends fatal protocol_version alert": {
			serve:          writeThenClose([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 70}),
			wantBodySubstr: "upstream rejected the TLS handshake: tls: protocol version not supported",
		},
		"peer is not speaking TLS": {
			serve:          writeThenClose([]byte("definitely not a TLS record\r\n\r\n")),
			wantBodySubstr: "did not speak TLS",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addr := serveRaw(t, tt.serve)
			_, err := NewUnrestrictedClient().Get("https://" + addr)
			require.Error(t, err)

			got := ClassifyOutboundHTTPError(err)
			require.NotNil(t, got, "unclassified TLS error: %v", err)
			assert.Equal(t, http.StatusBadGateway, got.StatusCode)
			assert.Contains(t, got.Body, tt.wantBodySubstr)
		})
	}
}

// TestClassifyOutboundHTTPErrorRealCertificateFailure pins the carve-out: a
// chain the enclave will not trust remains a transport failure for the caller
// to report, not a synthetic gateway response.
func TestClassifyOutboundHTTPErrorRealCertificateFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	// The default roots do not include httptest's ad-hoc CA.
	_, err := NewUnrestrictedClient().Get(server.URL)
	require.Error(t, err)
	assert.Nil(t, ClassifyOutboundHTTPError(err))
}

// serveRaw starts a TCP listener that hands each connection to serve after
// reading the client's first flight, and returns its address.
func serveRaw(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			serve(conn)
		}
	}()
	return listener.Addr().String()
}

func writeThenClose(payload []byte) func(net.Conn) {
	return func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 1024))
		_, _ = conn.Write(payload)
	}
}

// TestClassifyOutboundHTTPErrorRealNonRejectionAlerts pins the narrowing: fatal
// alerts that are not a negotiation refusal stay hard failures even though
// crypto/tls reports them through the same *net.OpError as a rejection. An
// integrity alert can signal tampering, and crypto/tls surfaces it the same way
// whether it arrives during or after the handshake, so it must not become a 502.
func TestClassifyOutboundHTTPErrorRealNonRejectionAlerts(t *testing.T) {
	alerts := map[string]byte{
		"bad_record_mac":    20,
		"record_overflow":   22,
		"illegal_parameter": 47,
		"unknown_ca":        48,
		"decrypt_error":     51,
		"internal_error":    80,
	}
	for name, code := range alerts {
		t.Run(name, func(t *testing.T) {
			addr := serveRaw(t, writeThenClose([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, code}))
			_, err := NewUnrestrictedClient().Get("https://" + addr)
			require.Error(t, err)
			assert.Nil(t, ClassifyOutboundHTTPError(err), "alert %d must stay a hard failure", code)
		})
	}
}

// TestClassifyOutboundHTTPErrorRealLocalRecordFault pins that a corrupt record
// from the upstream ("local error: tls: error decoding message") stays a hard
// failure rather than being reported as a handshake rejection.
func TestClassifyOutboundHTTPErrorRealLocalRecordFault(t *testing.T) {
	// A handshake record announcing a ServerHello with an invalid body.
	addr := serveRaw(t, writeThenClose([]byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}))
	_, err := NewUnrestrictedClient().Get("https://" + addr)
	require.Error(t, err)

	var opErr *net.OpError
	require.True(t, errors.As(err, &opErr), "expected a *net.OpError, got %v", err)
	require.Equal(t, "local error", opErr.Op)
	assert.Nil(t, ClassifyOutboundHTTPError(err))
}

func TestClassifyOutboundProxyPolicyError(t *testing.T) {
	classified := ClassifyOutboundHTTPError(&proxyclient.PolicyError{Reason: "private address"})
	require.NotNil(t, classified)
	require.Equal(t, http.StatusBadRequest, classified.StatusCode)
}

func TestClassifyOutboundHostUnreachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "direct DNS failure", err: &net.DNSError{Name: "example.invalid", IsNotFound: true}},
		{name: "SOCKS host unreachable", err: syscall.EHOSTUNREACH},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			classified := ClassifyOutboundHTTPError(test.err)
			require.NotNil(t, classified)
			require.Equal(t, http.StatusBadGateway, classified.StatusCode)
			require.Equal(t, "upstream host unreachable", classified.Body)
		})
	}
}
