package httpfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/doyensec/safeurl"
	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

// doerFunc adapts a function to the httpDoer interface.
type doerFunc func(*http.Request) (*http.Response, error)

func (d doerFunc) Do(req *http.Request) (*http.Response, error) { return d(req) }

func defaultLimits() Limits {
	cfg := cresettings.Default.PerWorkflow.HTTPAction
	return Limits{
		ConnectionTimeout: cfg.ConnectionTimeout.DefaultValue,
		RequestSizeLimit:  cfg.RequestSizeLimit.DefaultValue,
		ResponseSizeLimit: cfg.ResponseSizeLimit.DefaultValue,
	}
}

func TestFetch_MethodNotAllowed(t *testing.T) {
	f := NewFetcher(DefaultPolicy())
	_, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com/", Method: "TRACE"}, defaultLimits())
	require.Error(t, err)
	assert.EqualError(t, err, "method not allowed")
}

func TestFetch_RequestSizeLimit(t *testing.T) {
	for _, field := range []string{"body", "headers", "multi headers", "url", "mtls key", "mtls certificate"} {
		t.Run(field, func(t *testing.T) {
			in := &httpcap.Request{Url: "https://example.com/", Method: "POST"}
			large := strings.Repeat("x", 10_000)
			switch field {
			case "body":
				// Base64 alone exceeds 10 KB while the raw body fits.
				in.Body = []byte(large[:7_503])
			case "headers":
				in.Headers = map[string]string{"X-Test": large} //nolint:staticcheck // deprecated headers remain size-limited
			case "multi headers":
				in.MultiHeaders = map[string]*httpcap.HeaderValues{"X-Test": {Values: []string{large}}}
			case "url":
				in.Url += large
			case "mtls key":
				in.Mtls = &httpcap.MtlsAuth{PrivateKey: []byte(large)}
			case "mtls certificate":
				in.Mtls = &httpcap.MtlsAuth{Certificate: []byte(large)}
			}
			original := proto.Clone(in)
			limits := defaultLimits()
			assert.Greater(t, requestSizeLowerBound(in), limits.RequestSizeLimit)
			calls := 0
			f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			}))
			_, err := f.Fetch(t.Context(), in, limits)
			require.ErrorContains(t, err, "RequestSizeLimit")
			assert.Zero(t, calls)

			normalized := proto.Clone(in).(*httpcap.Request)
			normalized.Timeout = durationpb.New(limits.ConnectionTimeout)
			encoded, err := json.Marshal(normalized)
			require.NoError(t, err)
			limits.RequestSizeLimit = config.Size(len(encoded))
			_, err = f.Fetch(t.Context(), in, limits)
			require.NoError(t, err, "exact JSON boundary is allowed")
			assert.Equal(t, 1, calls)
			limits.RequestSizeLimit--
			_, err = f.Fetch(t.Context(), in, limits)
			require.ErrorContains(t, err, "RequestSizeLimit")
			assert.Equal(t, 1, calls)
			assert.True(t, proto.Equal(original, in), "the caller's request is not mutated")
		})
	}
}

func BenchmarkFetch_OversizedRequest(b *testing.B) {
	in := &httpcap.Request{Url: "https://example.com/", Method: "POST", Body: make([]byte, 32<<20)}
	f := NewFetcher(DefaultPolicy())
	limits := defaultLimits()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := f.Fetch(b.Context(), in, limits); err == nil {
			b.Fatal("expected request size rejection")
		}
	}
}

func TestFetch_ZeroConnectionTimeout(t *testing.T) {
	f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("zero timeout limit must reject before dispatch")
		return nil, nil
	}))
	limits := defaultLimits()
	limits.ConnectionTimeout = 0
	for _, timeout := range []*durationpb.Duration{nil, durationpb.New(0), durationpb.New(time.Second)} {
		_, err := f.Fetch(t.Context(), &httpcap.Request{Url: "https://example.com/", Method: "GET", Timeout: timeout}, limits)
		require.ErrorContains(t, err, "ConnectionTimeout")
	}
}

func TestFetch_ConnectionTimeout(t *testing.T) {
	for _, tt := range []struct {
		name    string
		timeout *durationpb.Duration
		want    time.Duration
		wantErr string
	}{
		{"omitted", nil, 2 * time.Second, ""},
		{"zero", durationpb.New(0), 2 * time.Second, ""},
		{"shorter", durationpb.New(time.Second), time.Second, ""},
		{"boundary", durationpb.New(2 * time.Second), 2 * time.Second, ""},
		{"exceeded", durationpb.New(2*time.Second + time.Nanosecond), 0, "ConnectionTimeout"},
		{"negative", durationpb.New(-time.Second), 0, "negative"},
		{"invalid", &durationpb.Duration{Nanos: 1_000_000_000}, 0, "invalid timeout"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := req.Context().Deadline()
				require.True(t, ok)
				assert.InDelta(t, tt.want.Seconds(), time.Until(deadline).Seconds(), 0.5)
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			}))
			limits := defaultLimits()
			limits.ConnectionTimeout = 2 * time.Second
			_, err := f.Fetch(t.Context(), &httpcap.Request{Url: "https://example.com/", Method: "GET", Timeout: tt.timeout}, limits)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Zero(t, calls)
			} else {
				require.NoError(t, err)
				assert.Equal(t, 1, calls)
			}
		})
	}
}

type trackedBody struct {
	io.Reader
	read   int
	closed bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestFetch_ResponseSizeLimit(t *testing.T) {
	for _, tt := range []struct {
		name     string
		limit    config.Size
		bodySize int
		wantRead int
		wantErr  bool
	}{
		{"default boundary", 100_000, 100_000, 100_000, false},
		{"default exceeded", 100_000, 200_000, 100_001, true},
		{"lower override", 3, 10, 4, true},
		{"higher override", 200_000, 200_000, 200_000, false},
		{"policy cap remains", 2_000_000, 2_000_000, int(DefaultPolicy().MaxResponseBodyBytes) + 1, true},
		{"zero allows empty", 0, 0, 0, false},
		{"zero rejects body", 0, 1, 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &trackedBody{Reader: strings.NewReader(strings.Repeat("x", tt.bodySize))}
			f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
			}))
			limits := defaultLimits()
			limits.ResponseSizeLimit = tt.limit
			resp, err := f.Fetch(t.Context(), &httpcap.Request{Url: "https://example.com/", Method: "GET"}, limits)
			if tt.wantErr {
				require.ErrorContains(t, err, "response body exceeds limit")
				assert.Nil(t, resp)
			} else {
				require.NoError(t, err)
				assert.Len(t, resp.Body, tt.bodySize)
			}
			assert.Equal(t, tt.wantRead, body.read)
			assert.True(t, body.closed)
		})
	}
}

func TestFetch_ParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	want, _ := ctx.Deadline()
	f := NewFetcherWithClient(DefaultPolicy(), doerFunc(func(req *http.Request) (*http.Response, error) {
		got, ok := req.Context().Deadline()
		require.True(t, ok)
		assert.Equal(t, want, got)
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}))
	_, err := f.Fetch(ctx, &httpcap.Request{Url: "https://example.com/", Method: "GET"}, defaultLimits())
	require.NoError(t, err)
}

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
		_, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com/", Method: "GET", Timeout: timeout}, defaultLimits())
		require.NoError(t, err)
	}

	get(nil)
	assert.InDelta(t, 5, remaining.Seconds(), 1, "policy default applies before injection")

	f.SetDefaultTimeout(80 * time.Second)
	get(nil)
	assert.InDelta(t, 10, remaining.Seconds(), 1, "CRE ceiling bounds the injected timeout")

	f.SetDefaultTimeout(0)
	get(nil)
	assert.InDelta(t, 10, remaining.Seconds(), 1, "non-positive injection is ignored")

	get(durationpb.New(2 * time.Second))
	assert.InDelta(t, 2, remaining.Seconds(), 1, "caller-supplied timeout still wins")
}

func TestDefaultPolicy_RejectsHTTPLoopback(t *testing.T) {
	// Sanity check the shipping defaults: http scheme and loopback are both
	// rejected by the shared restricted client and surface as a 400 response
	// (SSRF-policy blocks are caller-facing, not capability failures).
	f := NewFetcher(DefaultPolicy())

	// http scheme is not in the restricted client's allowlist.
	resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: "http://127.0.0.1:80/", Method: "GET"}, defaultLimits())
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, uint32(http.StatusBadRequest), resp.StatusCode)
	assert.Equal(t, "upstream request blocked by enclave network policy", string(resp.Body))

	// Https to a loopback literal is rejected by safeurl's baked-in privateNetworks.
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(443))}
	resp, err = f.Fetch(context.Background(), &httpcap.Request{Url: u.String(), Method: "GET"}, defaultLimits())
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

	resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://" + addr, Method: "GET"}, defaultLimits())
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
			}, defaultLimits())
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
			resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com/" + secret + "?token=" + secret, Method: "GET"}, defaultLimits())
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
			resp, err := f.Fetch(context.Background(), &httpcap.Request{Url: server.URL + "/" + secret + "?token=" + secret, Method: "GET"}, defaultLimits())
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
