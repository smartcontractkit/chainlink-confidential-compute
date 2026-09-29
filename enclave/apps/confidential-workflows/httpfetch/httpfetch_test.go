package httpfetch

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

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
	assert.Contains(t, err.Error(), `method "TRACE" not allowed`)
}

func TestFetch_RequestSizeLimit(t *testing.T) {
	for _, field := range []string{"body", "headers", "multi headers", "url"} {
		t.Run(field, func(t *testing.T) {
			in := &httpcap.Request{Url: "https://example.com/", Method: "POST"}
			large := strings.Repeat("x", 10_000)
			switch field {
			case "body":
				in.Body = []byte(large)
			case "headers":
				in.Headers = map[string]string{"X-Test": large} //nolint:staticcheck // deprecated headers remain size-limited
			case "multi headers":
				in.MultiHeaders = map[string]*httpcap.HeaderValues{"X-Test": {Values: []string{large}}}
			case "url":
				in.Url += large
			}
			original := proto.Clone(in)
			limits := defaultLimits()
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
