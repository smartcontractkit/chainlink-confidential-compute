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
