package httpfetch

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
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/doyensec/safeurl"
	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

// doerFunc adapts a function to the httpDoer interface.
type doerFunc func(*http.Request) (*http.Response, error)

func (d doerFunc) Do(req *http.Request) (*http.Response, error) { return d(req) }

func TestSetDefaultTimeout(t *testing.T) {
	// The host injects the enclave's global request timeout at runtime, so a
	// Fetcher already serving executions has to pick up the new deadline.
	var remaining time.Duration
	stub := doerFunc(func(req *http.Request) (*http.Response, error) {
		deadline, ok := req.Context().Deadline()
		require.True(t, ok)
		remaining = time.Until(deadline)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
	})
	policy := DefaultPolicy()
	policy.DefaultTimeout = 5 * time.Second
	f := NewFetcherWithClient(policy, stub)

	get := func(timeout *durationpb.Duration) {
		_, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com/", Method: "GET", Timeout: timeout})
		require.NoError(t, err)
	}

	get(nil)
	assert.InDelta(t, 5, remaining.Seconds(), 1, "policy default applies before injection")

	f.SetDefaultTimeout(80 * time.Second)
	get(nil)
	assert.InDelta(t, 80, remaining.Seconds(), 1, "injected timeout applies")

	f.SetDefaultTimeout(0)
	get(nil)
	assert.InDelta(t, 80, remaining.Seconds(), 1, "non-positive injection is ignored")

	get(durationpb.New(2 * time.Second))
	assert.InDelta(t, 2, remaining.Seconds(), 1, "caller-supplied timeout still wins")
}

func TestDefaultPolicy_RejectsHTTPLoopback(t *testing.T) {
	// Sanity check the shipping defaults: http scheme and loopback are both
	// rejected by the shared restricted client and surface as a 400 response
	// (SSRF-policy blocks are caller-facing, not capability failures).
	f := NewFetcher(DefaultPolicy())

	// http scheme is not in the restricted client's allowlist.
	resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: "http://127.0.0.1:80/", Method: "GET"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint32(http.StatusBadRequest), resp.StatusCode)
	assert.Equal(t, "upstream request blocked by enclave network policy", string(resp.Body))

	// Https to a loopback literal is rejected by safeurl's baked-in privateNetworks.
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(443))}
	resp, err = f.Fetch(context.Background(), &httpcap.Request{Url: u.String(), Method: "GET"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint32(http.StatusBadRequest), resp.StatusCode)
}

func TestFetch_UpstreamRejectsTLSHandshakeReturns502(t *testing.T) {
	// A fatal alert from the peer is an upstream fault, so it surfaces as a 502
	// response rather than a capability failure. The unrestricted client is
	// needed because the shipping one refuses loopback.
	addr := serveFatalTLSAlert(t)
	f := NewFetcherWithClient(DefaultPolicy(), util.NewUnrestrictedClient())

	resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://" + addr, Method: "GET"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint32(http.StatusBadGateway), resp.StatusCode)
	assert.Contains(t, string(resp.Body), "upstream rejected the TLS handshake")
}

// serveFatalTLSAlert starts a listener that answers every ClientHello with a
// fatal handshake_failure alert, and returns its address.
func serveFatalTLSAlert(t *testing.T) string {
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
			_, _ = conn.Read(make([]byte, 1024))
			// TLS record: alert(21), version 3.3, length 2, level fatal(2),
			// description handshake_failure(40).
			_, _ = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40})
			_ = conn.Close()
		}
	}()
	return listener.Addr().String()
}

func TestFetch_RedactsErrors(t *testing.T) {
	const secret = "confidential-canary"
	const rawURL = "https://" + secret + ".example/" + secret + "?token=" + secret
	tests := []struct {
		name   string
		method string
		url    string
		err    error
		body   io.ReadCloser
		want   string
	}{
		{name: "method", method: secret, url: rawURL, want: "method not allowed"},
		{name: "URL parsing", method: "GET", url: "https://example.com/%zz?token=" + secret, want: "building request failed"},
		{name: "certificate", method: "GET", url: rawURL,
			err:  &tls.CertificateVerificationError{Err: x509.HostnameError{Host: secret, Certificate: &x509.Certificate{}}},
			want: "http request failed: TLS certificate verification failed"},
		{name: "TLS integrity alert", method: "GET", url: rawURL,
			err: &net.OpError{Op: "remote error", Err: tls.AlertError(20)}, want: "http request failed: transport failure"},
		{name: "TLS internal alert", method: "GET", url: rawURL,
			err: &net.OpError{Op: "remote error", Err: tls.AlertError(80)}, want: "http request failed: transport failure"},
		{name: "unknown transport", method: "GET", url: rawURL, err: errors.New(secret), want: "http request failed: transport failure"},
		{name: "body read", method: "GET", url: rawURL, body: &privateErrorBody{secret: secret}, want: "reading response failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, rawURL, req.URL.String())
				assert.Equal(t, secret, req.Header.Get("Authorization"))
				if tt.err != nil {
					return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: tt.err}
				}
				require.NotNil(t, tt.body, "invalid requests must be rejected before transport")
				return &http.Response{StatusCode: http.StatusOK, Body: tt.body}, nil
			}))
			resp, err := f.Fetch(context.Background(), &httpcap.Request{
				Url: tt.url, Method: tt.method,
				MultiHeaders: map[string]*httpcap.HeaderValues{"Authorization": {Values: []string{secret}}},
			})
			require.EqualError(t, err, tt.want)
			assert.Nil(t, resp)
			assert.NotContains(t, fmt.Sprintf("%+v", err), secret)
			var urlErr *url.Error
			assert.False(t, errors.As(err, &urlErr), "raw error must not be recoverable by unwrapping")
		})
	}
}

type privateErrorBody struct{ secret string }

func (b *privateErrorBody) Read(p []byte) (int, error) {
	return copy(p, b.secret), errors.New(b.secret)
}

func (b *privateErrorBody) Close() error { return nil }

func TestFetch_SyntheticResponsesRemainRedacted(t *testing.T) {
	const secret = "confidential-canary"
	tests := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{"timeout", context.DeadlineExceeded, 504, "upstream request timed out"},
		{"DNS", &net.DNSError{Name: secret, Err: secret, IsNotFound: true}, 502, "upstream host unreachable"},
		{"policy", &safeurl.AllowedHostError{}, 400, "upstream request blocked by enclave network policy"},
		{"refused", syscall.ECONNREFUSED, 502, "upstream connection refused"},
		{"reset", syscall.ECONNRESET, 502, "upstream closed the connection before responding"},
		{"TLS negotiation", &net.OpError{Op: "remote error", Err: tls.AlertError(40)}, 502, "upstream rejected the TLS handshake: tls: handshake failure"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(req *http.Request) (*http.Response, error) {
				return nil, &url.Error{Op: req.Method, URL: req.URL.String(), Err: tt.err}
			}))
			resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com/" + secret + "?token=" + secret, Method: "GET"})
			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.EqualValues(t, tt.status, resp.StatusCode)
			assert.Equal(t, tt.body, string(resp.Body))
			assert.NotContains(t, resp.String(), secret)
		})
	}
}

func TestFetch_RealHTTPFailuresAreRedacted(t *testing.T) {
	const secret = "confidential-canary"
	for _, status := range []int{301, 302, 303, 307, 308, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				http.Redirect(w, r, "/"+secret+"?token="+secret, status)
			}))
			t.Cleanup(server.Close)
			dialer := &net.Dialer{}
			tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			want := "http request failed: redirects are not allowed"
			if status == 200 {
				tlsConfig.RootCAs = x509.NewCertPool()
				want = "http request failed: TLS certificate verification failed"
			}
			client := util.NewRestrictedHTTPClientWithTLSAndDialer(tlsConfig, func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
			})
			f := NewFetcherWithClient(DefaultPolicy(), client)
			resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: server.URL + "/" + secret + "?token=" + secret, Method: "GET"})
			require.EqualError(t, err, want)
			assert.Nil(t, resp)
			if status == 200 {
				assert.Zero(t, requests.Load(), "untrusted TLS must not send the request")
			} else {
				assert.Equal(t, int32(1), requests.Load(), "redirect targets must not be requested")
			}
		})
	}
}
