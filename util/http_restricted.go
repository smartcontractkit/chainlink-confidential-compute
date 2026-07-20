// Package util provides HTTP client constructors with SSRF protection via
// doyensec/safeurl. Private-network blocking, scheme/port enforcement, and
// redirect prevention are all delegated to safeurl's built-in mechanisms.
package util

import (
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/doyensec/safeurl"
)

// disableRedirects prevents the HTTP client from following any redirects.
func disableRedirects(*http.Request, []*http.Request) error {
	return errors.New("redirects are not allowed")
}

// newSafeurlClient builds a safeurl-based HTTP client that enforces:
// - HTTPS only (any port)
// - No redirects
// - Private-network blocking (loopback, RFC 1918, CGNAT, link-local, etc.)
// An optional tls.Config can be supplied for custom CA certificates.
func newSafeurlClient(tlsConfig *tls.Config) *safeurl.WrappedClient {
	builder := safeurl.GetConfigBuilder().
		SetAllowedSchemes("https").
		SetCheckRedirect(disableRedirects)
	if tlsConfig != nil {
		builder = builder.SetTlsConfig(tlsConfig)
	}
	client := safeurl.Client(builder.Build())
	transport, ok := client.Client.Transport.(*http.Transport)
	if !ok {
		panic("safeurl client uses an unsupported HTTP transport")
	}
	// The client is shared across workflows, so connection reuse would carry
	// TCP/TLS and server-side connection state across workflow boundaries.
	transport.DisableKeepAlives = true
	return client
}

// NewRestrictedHTTPClient returns an HTTP client that blocks connections to
// private/local IP addresses, allows only HTTPS (any port), and disables
// redirects. SSRF protection is provided by doyensec/safeurl.
func NewRestrictedHTTPClient() *safeurl.WrappedClient {
	return newSafeurlClient(nil)
}

// NewRestrictedHTTPClientWithTLS returns a restricted HTTP client configured
// with a custom TLS configuration (e.g. a custom root CA). It enforces the
// same SSRF protections as NewRestrictedHTTPClient.
func NewRestrictedHTTPClientWithTLS(tlsConfig *tls.Config) *safeurl.WrappedClient {
	return newSafeurlClient(tlsConfig)
}

// NewUnrestrictedClient returns a plain HTTP client with no transport
// restrictions. This is intended for use in tests that need to reach local
// test servers.
func NewUnrestrictedClient() *http.Client {
	return &http.Client{}
}

// IsRequestBlockedError reports whether err was produced by the restricted
// HTTP client's SSRF policy: a disallowed scheme, port, host, or IP (including
// private-network targets), an IPv6 connection, or blocked credentials. These
// are client errors (the caller asked for a destination the enclave is not
// permitted to reach), not transport failures. safeurl surfaces them from the
// dialer wrapped in *net.OpError / *url.Error, so errors.As is used to unwrap.
func IsRequestBlockedError(err error) bool {
	var (
		schemeErr *safeurl.AllowedSchemeError
		portErr   *safeurl.AllowedPortError
		hostErr   *safeurl.AllowedHostError
		invHost   *safeurl.InvalidHostError
		ipErr     *safeurl.AllowedIPError
		ipv6Err   *safeurl.IPv6BlockedError
		credErr   *safeurl.SendingCredentialsBlockedError
	)
	return errors.As(err, &schemeErr) ||
		errors.As(err, &portErr) ||
		errors.As(err, &hostErr) ||
		errors.As(err, &invHost) ||
		errors.As(err, &ipErr) ||
		errors.As(err, &ipv6Err) ||
		errors.As(err, &credErr)
}
