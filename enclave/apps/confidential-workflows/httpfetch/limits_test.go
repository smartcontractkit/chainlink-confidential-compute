package httpfetch

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	timeoutKey  = "PerWorkflow.HTTPAction.ConnectionTimeout"
	requestKey  = "PerWorkflow.HTTPAction.RequestSizeLimit"
	responseKey = "PerWorkflow.HTTPAction.ResponseSizeLimit"
)

// limitsFetcher returns a Fetcher whose upstream answers with a body of
// bodySize bytes, and records the deadline each request carried.
func limitsFetcher(t *testing.T, bodySize int, remaining *time.Duration) *Fetcher {
	t.Helper()
	stub := doerFunc(func(req *http.Request) (*http.Response, error) {
		if deadline, ok := req.Context().Deadline(); ok && remaining != nil {
			*remaining = time.Until(deadline)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), bodySize))),
			Header:     http.Header{},
		}, nil
	})
	policy := DefaultPolicy()
	policy.DefaultTimeout = 60 * time.Second
	policy.MaxResponseBodyBytes = 1000
	return NewFetcherWithClient(policy, stub)
}

// recorder collects the keys reported through Limits callbacks.
type recorder struct{ exceeded, clamped []string }

func (r *recorder) limits() *Limits {
	return &Limits{
		Exceeded: func(key string) { r.exceeded = append(r.exceeded, key) },
		Clamped:  func(key string) { r.clamped = append(r.clamped, key) },
	}
}

func ptr[T any](v T) *T { return &v }

func get(timeout *durationpb.Duration) *httpcap.Request {
	return &httpcap.Request{Url: "https://example.com/", Method: "GET", Timeout: timeout}
}

func TestFetchLimits(t *testing.T) {
	t.Run("caller timeout above the limit fails", func(t *testing.T) {
		var r recorder
		l := r.limits()
		l.ConnectionTimeout = ptr(10 * time.Second)
		_, err := limitsFetcher(t, 1, nil).Fetch(context.Background(), get(durationpb.New(11*time.Second)), l)
		require.ErrorContains(t, err, "timeout exceeds "+timeoutKey+" limit 10s")
		assert.Equal(t, []string{timeoutKey}, r.exceeded)
	})

	t.Run("default timeout is capped at the limit", func(t *testing.T) {
		var r recorder
		var remaining time.Duration
		l := r.limits()
		l.ConnectionTimeout = ptr(10 * time.Second)
		_, err := limitsFetcher(t, 1, &remaining).Fetch(context.Background(), get(nil), l)
		require.NoError(t, err)
		assert.InDelta(t, 10, remaining.Seconds(), 1)
		assert.Empty(t, r.exceeded, "capping the default is not a violation")
	})

	t.Run("zero timeout limit fails every request", func(t *testing.T) {
		var r recorder
		l := r.limits()
		l.ConnectionTimeout = ptr(time.Duration(0))
		_, err := limitsFetcher(t, 1, nil).Fetch(context.Background(), get(nil), l)
		require.ErrorContains(t, err, timeoutKey)
	})

	t.Run("request over the size limit fails", func(t *testing.T) {
		var r recorder
		l := r.limits()
		l.RequestSizeLimit = ptr(int64(10_000))
		req := &httpcap.Request{Url: "https://example.com/", Method: "POST", Body: []byte(strings.Repeat("x", 8_000))}
		_, err := limitsFetcher(t, 1, nil).Fetch(context.Background(), req, l)
		require.ErrorContains(t, err, "request exceeds "+requestKey+" limit 10000 bytes")
		assert.Equal(t, []string{requestKey}, r.exceeded)
	})

	t.Run("request under the size limit passes", func(t *testing.T) {
		var r recorder
		l := r.limits()
		l.RequestSizeLimit = ptr(int64(10_000))
		req := &httpcap.Request{Url: "https://example.com/", Method: "POST", Body: []byte(strings.Repeat("x", 5_000))}
		_, err := limitsFetcher(t, 1, nil).Fetch(context.Background(), req, l)
		require.NoError(t, err)
		assert.Empty(t, r.exceeded)
	})

	t.Run("response over the CRE limit fails naming the setting", func(t *testing.T) {
		var r recorder
		l := r.limits()
		l.ResponseSizeLimit = ptr(int64(500))
		_, err := limitsFetcher(t, 501, nil).Fetch(context.Background(), get(nil), l)
		require.ErrorContains(t, err, "response exceeds "+responseKey+" limit 500 bytes")
		assert.Equal(t, []string{responseKey}, r.exceeded)
		assert.Empty(t, r.clamped)
	})

	t.Run("response the fixed cap rejects although the CRE limit allows it is clamped", func(t *testing.T) {
		var r recorder
		l := r.limits()
		l.ResponseSizeLimit = ptr(int64(2000))
		_, err := limitsFetcher(t, 1500, nil).Fetch(context.Background(), get(nil), l)
		require.ErrorContains(t, err, "response body exceeds limit 1000 bytes")
		assert.Empty(t, r.exceeded)
		assert.Equal(t, []string{responseKey}, r.clamped)
	})
}
