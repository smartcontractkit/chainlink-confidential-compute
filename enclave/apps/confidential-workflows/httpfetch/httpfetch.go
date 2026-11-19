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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	httpcap "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/http"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

// Policy holds the knobs owned by this package: the method allowlist, the
// default request timeout, and the response body cap. Scheme/IP/redirect
// enforcement is handled by the shared restricted client in util; request-body
// and timeout ceilings come from the Limits the workflow DON sends.
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

// Fetcher executes outbound HTTP requests according to a fixed Policy. The
// default timeout is held separately as an atomic because it is the one knob the
// host can move at runtime (injected over vsock), while a Fetcher is shared
// across concurrent executions.
type Fetcher struct {
	client         httpDoer
	policy         Policy
	defaultTimeout atomic.Int64 // nanoseconds
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
	f := &Fetcher{
		client: client,
		policy: policy,
	}
	f.defaultTimeout.Store(int64(policy.DefaultTimeout))
	return f
}

// SetDefaultTimeout updates the deadline applied to requests that carry no
// caller-supplied timeout. A non-positive value is ignored, leaving the policy
// default in place.
func (f *Fetcher) SetDefaultTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	f.defaultTimeout.Store(int64(d))
}

// Limits holds the PerWorkflow.HTTPAction limits the workflow DON sent for one
// execution. A nil field is not applied.
type Limits struct {
	ConnectionTimeout *time.Duration
	RequestSizeLimit  *int64
	ResponseSizeLimit *int64
	// Exceeded receives the setting key of each limit a request exceeds.
	Exceeded func(key string)
	// Clamped receives the ResponseSizeLimit key when the fixed response cap
	// rejects a response that ResponseSizeLimit would have allowed.
	Clamped func(key string)
}

// Fetch executes a single HTTP request. On success the returned Response has
// StatusCode, Headers, and Body populated. Errors are policy violations
// (method/scheme/IP/port), transport failures, body-size overruns, or exceeded
// CRE limits. Nil limits apply the fixed policy alone.
func (f *Fetcher) Fetch(ctx context.Context, in *httpcap.Request, limits *Limits) (*httpcap.Response, error) {
	if in == nil {
		return nil, errors.New("request is nil")
	}

	method := strings.ToUpper(strings.TrimSpace(in.GetMethod()))
	if !slices.Contains(f.policy.AllowedMethods, method) {
		return nil, errors.New("method not allowed")
	}

	if strings.TrimSpace(in.GetUrl()) == "" {
		return nil, errors.New("url is empty")
	}

	timeout := resolveTimeout(in.GetTimeout(), time.Duration(f.defaultTimeout.Load()))
	if limits != nil {
		var err error
		if timeout, err = limits.checkRequest(in, timeout); err != nil {
			return nil, err
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, method, strings.TrimSpace(in.GetUrl()), bytesReaderOrNil(in.GetBody()))
	if err != nil {
		return nil, errors.New("building request failed")
	}
	applyHeaders(httpReq, in)

	resp, err := f.client.Do(httpReq)
	if err != nil {
		// Caller-facing conditions (timeouts, unreachable hosts, SSRF-policy
		// blocks) and faults at the upstream endpoint (refused/reset connections,
		// TLS handshake failures) are returned as HTTP status responses rather
		// than capability failures, matching the standalone confidential-http path.
		if he := util.ClassifyOutboundHTTPError(err); he != nil {
			return &httpcap.Response{
				StatusCode: uint32(he.StatusCode), //nolint:gosec // status codes are always in-range
				Body:       []byte(he.Body),
			}, nil
		}
		return nil, fmt.Errorf("http request failed: %w", util.SanitizeOutboundHTTPError(err))
	}
	defer util.SafeClose(resp)

	maxBody := limits.maxResponseBody(f.policy.MaxResponseBodyBytes)
	limited := io.LimitReader(resp.Body, maxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", util.SanitizeOutboundHTTPError(err))
	}
	if err := limits.checkResponse(int64(len(body)), maxBody, f.policy.MaxResponseBodyBytes); err != nil {
		return nil, err
	}

	return &httpcap.Response{
		StatusCode: uint32(resp.StatusCode), //nolint:gosec // status codes are always in-range
		// Headers is deprecated in favor of MultiHeaders; kept as a dual-write for
		// backward compatibility with older consumers during the migration window.
		Headers:      flattenHeaders(resp.Header), //nolint:staticcheck // SA1019: intentional backward-compat dual-write; MultiHeaders is the replacement
		MultiHeaders: multiHeaders(resp.Header),
		Body:         body,
	}, nil
}

// resolveTimeout honours a positive caller-supplied timeout, falling back to
// the policy default otherwise. The only upper bound is the workflow DON's
// PerWorkflow.HTTPAction.ConnectionTimeout, applied by Limits.
func resolveTimeout(in *durationpb.Duration, def time.Duration) time.Duration {
	if in == nil || in.AsDuration() <= 0 {
		return def
	}
	return in.AsDuration()
}

// exceeded reports a violation and returns err.
func (l *Limits) exceeded(key string, err error) error {
	if l.Exceeded != nil {
		l.Exceeded(key)
	}
	return err
}

// checkRequest applies ConnectionTimeout and RequestSizeLimit, mirroring the
// http-action capability's validator, and returns the timeout to use: a
// request without its own timeout gets the default capped at the limit.
func (l *Limits) checkRequest(in *httpcap.Request, timeout time.Duration) (time.Duration, error) {
	if limit := l.ConnectionTimeout; limit != nil {
		key := cresettings.Default.PerWorkflow.HTTPAction.ConnectionTimeout.Key
		requested := in.GetTimeout().AsDuration()
		if requested <= 0 {
			timeout = min(timeout, *limit)
		}
		if *limit <= 0 || requested > *limit {
			return 0, l.exceeded(key, fmt.Errorf("timeout exceeds %s limit %s", key, *limit))
		}
	}
	if limit := l.RequestSizeLimit; limit != nil {
		key := cresettings.Default.PerWorkflow.HTTPAction.RequestSizeLimit.Key
		// The lower bound skips encoding a request that is already over the limit,
		// so an oversized body is not copied again inside the enclave.
		over := requestSizeLowerBound(in) > *limit
		if !over {
			size, err := requestSize(in, timeout)
			if err != nil {
				return 0, err
			}
			over = size > *limit
		}
		if over {
			return 0, l.exceeded(key, fmt.Errorf("request exceeds %s limit %d bytes", key, *limit))
		}
	}
	return timeout, nil
}

// maxResponseBody is the response cap to read up to: the fixed policy cap, or
// ResponseSizeLimit when lower. Nil-safe.
func (l *Limits) maxResponseBody(policyMax int64) int64 {
	if l != nil && l.ResponseSizeLimit != nil {
		return min(policyMax, *l.ResponseSizeLimit)
	}
	return policyMax
}

// checkResponse applies ResponseSizeLimit to a body read up to maxBody+1 bytes,
// and reports when the fixed policy cap, not the CRE limit, rejected it.
// Nil-safe.
func (l *Limits) checkResponse(size, maxBody, policyMax int64) error {
	policyErr := fmt.Errorf("response body exceeds limit %d bytes", policyMax)
	if l == nil || l.ResponseSizeLimit == nil {
		if size > maxBody {
			return policyErr
		}
		return nil
	}
	key := cresettings.Default.PerWorkflow.HTTPAction.ResponseSizeLimit.Key
	limit := *l.ResponseSizeLimit
	if size > limit {
		return l.exceeded(key, fmt.Errorf("response exceeds %s limit %d bytes", key, limit))
	}
	if size > maxBody {
		if limit > policyMax && l.Clamped != nil {
			l.Clamped(key)
		}
		return policyErr
	}
	return nil
}

// requestSizeLowerBound excludes JSON syntax and escaping, which only add bytes.
func requestSizeLowerBound(in *httpcap.Request) int64 {
	size := len(in.GetUrl()) + len(in.GetMethod())
	size += base64.StdEncoding.EncodedLen(len(in.GetBody()))
	size += base64.StdEncoding.EncodedLen(len(in.GetMtls().GetPrivateKey()))
	size += base64.StdEncoding.EncodedLen(len(in.GetMtls().GetCertificate()))
	for key, value := range in.GetHeaders() { //nolint:staticcheck // deprecated headers remain size-limited
		size += len(key) + len(value)
	}
	for key, values := range in.GetMultiHeaders() {
		size += len(key)
		for _, value := range values.GetValues() {
			size += len(value)
		}
	}
	return int64(size)
}

// requestSize measures a request the way the http-action capability's
// validator does: encoding/json of the request after defaulting the timeout,
// which counts the URL, headers and base64-encoded body, not just body bytes.
// The resolved timeout may encode a few bytes differently from the validator's
// defaulted one, which only matters at the exact boundary.
func requestSize(in *httpcap.Request, timeout time.Duration) (int64, error) {
	in = proto.Clone(in).(*httpcap.Request)
	in.Timeout = durationpb.New(timeout)
	encoded, err := json.Marshal(in)
	if err != nil {
		return 0, fmt.Errorf("encoding request: %w", err)
	}
	return int64(len(encoded)), nil
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
