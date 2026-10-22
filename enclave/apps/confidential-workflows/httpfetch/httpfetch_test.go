package httpfetch

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

// doerFunc adapts a function to the httpDoer interface.
type doerFunc func(*http.Request) (*http.Response, error)

func (d doerFunc) Do(req *http.Request) (*http.Response, error) { return d(req) }

func TestFetch_MethodNotAllowed(t *testing.T) {
	f := NewFetcher(DefaultPolicy())
	_, err := f.Fetch(context.Background(), &httpcap.Request{Url: "https://example.com/", Method: "TRACE"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `method "TRACE" not allowed`)
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
