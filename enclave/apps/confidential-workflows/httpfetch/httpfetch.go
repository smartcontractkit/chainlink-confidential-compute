// Package httpfetch performs outbound HTTP requests from inside a TEE enclave
// with a fixed safety policy. Transport-level SSRF protection (HTTPS only,
// private-network blocking, no redirects) is delegated to the shared restricted
// client in util; this package layers on a method allowlist, bounded timeout,
// and bounded request and response bodies. It operates on chainlink-common's
// http capability proto types so callers can route `http-actions@1.0.0-alpha`
// traffic through it without additional translation.
package httpfetch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/smartcontractkit/confidential-compute/types"
	"github.com/smartcontractkit/confidential-compute/util"
)

// Policy holds the knobs owned by this package: the method allowlist, the
// default request timeout, and the response body cap. Scheme/IP/redirect
// enforcement is handled by the shared restricted client in util; request-body
// and timeout ceilings are enforced upstream by the capability validator.
type Policy struct {
	AllowedMethods       []string // uppercase
	DefaultTimeout       time.Duration
	MaxResponseBodyBytes int64
}

// DefaultPolicy returns the production policy, mirroring the standalone
// confidential-http capability: the CRE SDK method set, a 30s default timeout
// honouring any caller-supplied request timeout, and a ~1 MB response cap.
// Transport restrictions (HTTPS only, private-network blocking) come from the
// shared restricted client in util.
func DefaultPolicy() Policy {
	return Policy{
		AllowedMethods:       []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		DefaultTimeout:       types.DefaultEnclaveRequestTimeout,
		MaxResponseBodyBytes: types.MaxHTTPResponseBodyBytes,
	}
}

// httpDoer is the subset of *http.Client that Fetcher depends on. It lets tests
// inject an unrestricted client that can reach endpoints (loopback test servers)
// the restricted client blocks.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Fetcher executes outbound HTTP requests according to a fixed Policy.
type Fetcher struct {
	client httpDoer
	policy Policy
}

// NewFetcher builds a Fetcher on top of the shared restricted HTTP client
// (HTTPS only, private-network blocking, no redirects). Method, timeout, and
// response body caps are applied per-request in Fetch.
func NewFetcher(policy Policy) *Fetcher {
	return NewFetcherWithClient(policy, util.NewRestrictedHTTPClient())
}

// NewFetcherWithClient builds a Fetcher backed by a caller-supplied HTTP client.
// Production code should use NewFetcher; this exists for tests that need to
// reach endpoints the restricted client blocks (e.g. loopback test servers).
func NewFetcherWithClient(policy Policy, client httpDoer) *Fetcher {
	return &Fetcher{
		client: client,
		policy: policy,
	}
}

// Fetch executes a single HTTP request. On success the returned Response has
// StatusCode, Headers, and Body populated. Errors are policy violations
// (method/scheme/IP/port), transport failures, or body-size overruns.
func (f *Fetcher) Fetch(ctx context.Context, in *httpcap.Request) (*httpcap.Response, error) {
	if in == nil {
		return nil, errors.New("request is nil")
	}

	method := strings.ToUpper(strings.TrimSpace(in.GetMethod()))
	if !slices.Contains(f.policy.AllowedMethods, method) {
		return nil, fmt.Errorf("method %q not allowed", method)
	}

	if strings.TrimSpace(in.GetUrl()) == "" {
		return nil, errors.New("url is empty")
	}

	timeout := resolveTimeout(in.GetTimeout(), f.policy.DefaultTimeout)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, method, strings.TrimSpace(in.GetUrl()), bytesReaderOrNil(in.GetBody()))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	applyHeaders(httpReq, in)

	resp, err := f.client.Do(httpReq)
	if err != nil {
		// Timeout (504), DNS NXDOMAIN (400), and SSRF-policy blocks (400) are
		// caller-facing conditions returned as HTTP status responses rather than
		// capability failures, matching the standalone confidential-http path.
		if he := util.ClassifyOutboundHTTPError(err); he != nil {
			return &httpcap.Response{
				StatusCode: uint32(he.StatusCode), //nolint:gosec // status codes are always in-range
				Body:       []byte(he.Body),
			}, nil
		}
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer util.SafeClose(resp)

	limited := io.LimitReader(resp.Body, f.policy.MaxResponseBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if int64(len(body)) > f.policy.MaxResponseBodyBytes {
		return nil, fmt.Errorf("response body exceeds limit %d bytes", f.policy.MaxResponseBodyBytes)
	}

	return &httpcap.Response{
		StatusCode:   uint32(resp.StatusCode), //nolint:gosec // status codes are always in-range
		Headers:      flattenHeaders(resp.Header),
		MultiHeaders: multiHeaders(resp.Header),
		Body:         body,
	}, nil
}

// resolveTimeout honours a positive caller-supplied timeout, falling back to
// the policy default otherwise. Any upper bound is enforced upstream by the
// capability validator, matching the standalone confidential-http capability.
func resolveTimeout(in *durationpb.Duration, def time.Duration) time.Duration {
	if in == nil || in.AsDuration() <= 0 {
		return def
	}
	return in.AsDuration()
}

func applyHeaders(req *http.Request, in *httpcap.Request) {
	if mh := in.GetMultiHeaders(); len(mh) > 0 {
		for k, vs := range mh {
			for _, v := range vs.GetValues() {
				req.Header.Add(k, v)
			}
		}
		return
	}
	for k, v := range in.GetHeaders() { //nolint:staticcheck // deprecated but still supported
		req.Header.Set(k, v)
	}
}

func flattenHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

func multiHeaders(h http.Header) map[string]*httpcap.HeaderValues {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]*httpcap.HeaderValues, len(h))
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		out[k] = &httpcap.HeaderValues{Values: slices.Clone(vs)}
	}
	return out
}

func bytesReaderOrNil(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return bytes.NewReader(b)
}
