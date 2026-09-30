package httpfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/doyensec/safeurl"
	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func (b *privateErrorBody) Close() error { return errors.New(b.secret) }

func TestFetch_DoesNotLogCloseError(t *testing.T) {
	const secret = "confidential-close-canary"
	var logs strings.Builder
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &privateErrorBody{secret: secret}}, nil
	}))
	_, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com", Method: "GET"})
	require.Error(t, err)
	assert.NotContains(t, logs.String(), secret)
}

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
