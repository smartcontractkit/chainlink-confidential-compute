package outboundproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"

	ccvsock "github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
)

const (
	handshakeTimeout = 10 * time.Second
	maxResponseBytes = 8 << 10
	// net.partialDeadline's saneMinimum: below this a per-candidate share is
	// too short to be worth attempting, so later candidates are given up on
	// rather than every candidate being given a share that cannot succeed.
	candidateMinimumTimeout = 2 * time.Second
)

// Dialer resolves and tunnels TCP destinations through the parent broker under
// one fixed policy selected at construction time.
type Dialer struct {
	parentCID uint32
	port      uint32
	policy    policy
}

func NewWorkflowDialer(parentCID, port uint32) *Dialer {
	return &Dialer{parentCID: parentCID, port: port, policy: workflowPolicy()}
}

func NewArtifactDialer(parentCID, port uint32) *Dialer {
	return &Dialer{parentCID: parentCID, port: port, policy: artifactPolicy()}
}

// NewInsecureArtifactDialerForTests permits private IPv4 destinations for
// local HTTP fixtures. Production entrypoints must use NewArtifactDialer.
func NewInsecureArtifactDialerForTests(parentCID, port uint32) *Dialer {
	return &Dialer{parentCID: parentCID, port: port, policy: policy{kind: policyInsecureArtifactTest}}
}

func NewOperatorDialer(parentCID, port uint32, endpoints ...string) (*Dialer, error) {
	p, err := operatorPolicy(endpoints...)
	if err != nil {
		return nil, err
	}
	return &Dialer{parentCID: parentCID, port: port, policy: p}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("outbound proxy supports only TCP, got %q", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, &PolicyError{Reason: "invalid destination authority"}
	}
	if err := d.policy.validateAuthority(host, port); err != nil {
		return nil, err
	}

	addresses, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	// Keep the first failure, as net.Dialer.dialSerial does: "The error from the
	// first address is most relevant". Returning the last one instead would flip
	// the caller-facing status when attempts fail differently, e.g. a timeout
	// then a refusal classifying as 502 where the pre-migration path gave 504.
	var firstErr error
	for i, addr := range addresses {
		if !d.policy.allowAddress(addr) {
			// safeurl rejects a blocked address inside the dial, so it becomes
			// dialSerial's first error. Record it for the same reason the first
			// error is kept at all: a policy denial reported as a later
			// address's refusal classifies 502 where the baseline gave 400.
			if firstErr == nil {
				firstErr = &PolicyError{Reason: "destination address is not allowed"}
			}
			continue
		}
		attemptCtx, cancel := candidateContext(ctx, len(addresses)-i)
		conn, err := d.connect(attemptCtx, net.JoinHostPort(addr.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, &PolicyError{Reason: "destination has no allowed IPv4 address"}
}

// candidateContext gives one attempt an equal share of the remaining caller
// deadline, mirroring net.partialDeadline (net/dial.go) including its two-second
// floor, which trades reaching every address for giving each a usable one.
// Without it a blackholed first address consumes the whole deadline and the
// remaining addresses are never tried at all.
func candidateContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ctx, func() {}
	}
	timeRemaining := time.Until(deadline)
	if timeRemaining <= 0 {
		return ctx, func() {}
	}
	timeout := timeRemaining / time.Duration(remaining)
	if timeout < candidateMinimumTimeout {
		timeout = min(timeRemaining, candidateMinimumTimeout)
	}
	return context.WithTimeout(ctx, timeout)
}

func (d *Dialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr.Unmap()}, nil
	}

	conn, stop, err := d.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close() //nolint:errcheck // request result is already determined
	defer stop()

	u := &url.URL{Scheme: "http", Host: "proxy", Path: ResolvePath}
	q := u.Query()
	q.Set("host", host)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build resolve request: %w", err)
	}
	req.Header.Set(VersionHeader, Version)
	req.Close = true
	if err := req.Write(conn); err != nil {
		return nil, contextError(ctx, fmt.Errorf("write resolve request: %w", err))
	}

	// Bound the header block. http.ReadResponse parses the status line and
	// headers with unlimited textproto reads, so an untrusted parent could
	// otherwise make the enclave allocate without limit inside the handshake
	// deadline. maxResponseBytes covers only the body, below.
	headers := &headerLimitReader{r: conn, remaining: maxResponseBytes}
	reader := bufio.NewReader(headers)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, contextError(ctx, fmt.Errorf("read resolve response: %w", err))
	}
	defer resp.Body.Close() //nolint:errcheck // connection is also closed
	if resp.StatusCode != http.StatusOK {
		return nil, decodeError(resp, "resolve", host)
	}
	var payload ResolveResponse
	if err := decodeJSON(resp.Body, &payload); err != nil {
		return nil, fmt.Errorf("decode resolve response: %w", err)
	}
	// The wire contract is at most MaxResolvedAddresses unique addresses in
	// resolver order. An honest broker already caps and deduplicates, but the
	// threat model distrusts the parent: without enforcing it here a parent can
	// make one call attempt an unbounded number of VSOCK handshakes.
	addresses := make([]netip.Addr, 0, min(len(payload.Addresses), MaxResolvedAddresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, raw := range payload.Addresses {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("proxy returned invalid address: %w", err)
		}
		addr = addr.Unmap()
		if _, duplicate := seen[addr]; duplicate {
			continue
		}
		if len(addresses) == MaxResolvedAddresses {
			return nil, &ProxyError{Code: CodeProtocol, Op: "resolve"}
		}
		seen[addr] = struct{}{}
		addresses = append(addresses, addr)
	}
	if len(addresses) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return addresses, nil
}

func (d *Dialer) connect(ctx context.Context, authority string) (net.Conn, error) {
	conn, stop, err := d.open(ctx)
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: authority},
		Host:   authority,
		Header: make(http.Header),
	}
	req.Header.Set(VersionHeader, Version)
	if err := req.Write(conn); err != nil {
		stop()
		_ = conn.Close()
		return nil, contextError(ctx, fmt.Errorf("write CONNECT request: %w", err))
	}

	// Same bound as resolve: the parent is untrusted, and this runs before any
	// tunnel exists. The limit is lifted once the response is parsed, since the
	// same reader then carries relayed bytes.
	headers := &headerLimitReader{r: conn, remaining: maxResponseBytes}
	reader := bufio.NewReader(headers)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		stop()
		_ = conn.Close()
		return nil, contextError(ctx, fmt.Errorf("read CONNECT response: %w", err))
	}
	if resp.StatusCode != http.StatusOK {
		proxyErr := decodeError(resp, "connect", authority)
		_ = resp.Body.Close()
		stop()
		_ = conn.Close()
		return nil, proxyErr
	}
	stop()
	if err := contextError(ctx, nil); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear tunnel deadline: %w", err)
	}
	headers.unlimited = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func (d *Dialer) open(ctx context.Context) (net.Conn, func(), error) {
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 1)
	go func() {
		conn, err := ccvsock.Dial(d.parentCID, d.port, nil)
		results <- result{conn: conn, err: err}
	}()

	var conn net.Conn
	select {
	case <-ctx.Done():
		go func() {
			result := <-results
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, func() {}, ctx.Err()
	case result := <-results:
		if result.err != nil {
			return nil, func() {}, contextError(ctx, result.err)
		}
		conn = result.conn
	}

	deadline := time.Now().Add(handshakeTimeout)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, func() {}, fmt.Errorf("set proxy handshake deadline: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	return conn, func() { stop() }, nil
}

func decodeError(resp *http.Response, operation, name string) error {
	var payload ErrorResponse
	if err := decodeJSON(resp.Body, &payload); err != nil {
		return &ProxyError{Code: CodeProtocol, Op: operation}
	}
	switch payload.Code {
	case CodeDNSNotFound:
		return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	case CodeDNSTimeout:
		return &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
	case CodeConnectTimeout:
		return &timeoutError{operation: operation}
	case CodeConnectRefused:
		return syscall.ECONNREFUSED
	case CodeConnectReset:
		return syscall.ECONNRESET
	case CodePolicyDenied:
		return &PolicyError{Reason: "parent-local destination denied"}
	default:
		return &ProxyError{Code: payload.Code, Op: operation}
	}
}

func decodeJSON(r io.Reader, target any) error {
	limited := io.LimitReader(r, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("proxy response is too large")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func contextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

type timeoutError struct {
	operation string
}

func (e *timeoutError) Error() string   { return e.operation + " timed out" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// headerLimitReader caps how much a peer may send before its response headers
// are parsed. Go parses those with unbounded textproto reads, so without this an
// untrusted parent could exhaust enclave memory during the handshake. Reads are
// uncapped again once a tunnel is established and the same reader starts
// carrying relayed bytes.
type headerLimitReader struct {
	r         io.Reader
	remaining int64
	unlimited bool
}

func (h *headerLimitReader) Read(p []byte) (int, error) {
	if h.unlimited {
		return h.r.Read(p)
	}
	if h.remaining <= 0 {
		return 0, errors.New("proxy response header is too large")
	}
	if int64(len(p)) > h.remaining {
		p = p[:h.remaining]
	}
	n, err := h.r.Read(p)
	h.remaining -= int64(n)
	return n, err
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (c *bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}
