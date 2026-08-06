package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	mdvsock "github.com/mdlayher/vsock"
	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outboundproxy"
)

// Defaults sized against the host container's 500m CPU / 512Mi memory budget.
// The derivation, so these are auditable rather than assumed:
//
//	descriptors  sessions(256) + rejection headroom(64) + tunnels(256) + 128 for
//	             the rest of the host = 704, checked against RLIMIT_NOFILE at
//	             startup by validateOutboundFileDescriptorLimit. A tunnel adds
//	             only its upstream socket, since its enclave side is the session.
//	memory       io.Copy takes a 32KiB buffer per direction, so 64KiB per tunnel:
//	             256 tunnels is ~16MiB of relay buffers against 512Mi, before
//	             socket buffers.
//	CPU          relays are I/O-bound and spend nearly all their time blocked, so
//	             500m is not the binding constraint at this fan-out.
//
// What is still missing is measured connection fanout under real workflow load,
// which the plan wants these derived from; until that exists these are bounds
// that fit the budget rather than numbers proven against demand. The six max
// limits, the rejection headroom and the half-close linger all have flags, so an
// operator can retune those without a release; the timeouts and header cap below
// do not.
const (
	defaultOutboundMaxSessions       = 256
	defaultOutboundMaxSessionsPerCID = 256
	defaultOutboundMaxDNS            = 64
	defaultOutboundMaxDNSPerCID      = 64
	defaultOutboundMaxTunnels        = 256
	defaultOutboundMaxTunnelsPerCID  = 256
	defaultOutboundReadHeaderTimeout = 5 * time.Second
	defaultOutboundDialTimeout       = 10 * time.Second
	defaultOutboundMaxHeaderBytes    = 8 << 10
	// Both sides enforce this now: the enclave refuses a longer answer as a
	// protocol error, so raising it here alone would break every resolve.
	maxResolvedAddresses = outboundproxy.MaxResolvedAddresses
	// maxWriteStallBounds caps how long one write may keep earning fresh bounds
	// on partial progress, so a peer draining a trickle cannot hold a tunnel
	// indefinitely without ever being idle for a whole interval.
	maxWriteStallBounds = 3
	// defaultOutboundRejectionHeadroom is how many connections beyond MaxSessions
	// may be held open purely to answer with a typed rejection. Answering costs a
	// connection, so the capacity to answer must itself be bounded.
	defaultOutboundRejectionHeadroom = 64
	// defaultOutboundHalfCloseLinger is how long a tunnel may make no progress.
	// Three distinct triggers derive from it:
	//
	//   - as a linger it bounds a half-closed tunnel, releasing it after an
	//     interval in which neither direction moved anything;
	//   - as stallGuardConn's per-attempt bound it fires on a live tunnel when a
	//     write moves nothing and neither direction has moved anything;
	//   - multiplied by maxWriteStallBounds it caps one write's total time, and
	//     that one fires even while bytes are still moving -- a peer draining
	//     under roughly 182 B/s can have a live transfer cut. That is the
	//     deliberate price of bounding a trickle that never sits idle.
	//
	// Reads are never bounded, which is what keeps this from being the
	// proxy-level total tunnel timeout the migration plan rules out: a tunnel
	// that is simply idle is left alone however long the caller wants.
	//
	// One value serves both, so lowering it to reclaim capacity faster also
	// tightens how long a peer may stop reading. Split it if those ever need to
	// differ.
	defaultOutboundHalfCloseLinger = 60 * time.Second
)

type outboundResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type outboundDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type outboundProxyConfig struct {
	Resolver                       outboundResolver
	Dialer                         outboundDialer
	Logger                         cllogger.SugaredLogger
	Metrics                        outboundProxyMetrics
	FallbackCID                    uint32
	LocalAddresses                 map[netip.Addr]struct{}
	AllowLocalDestinationsForTests bool
	MaxSessions                    int
	MaxSessionsPerCID              int
	RejectionHeadroom              int
	HalfCloseLinger                time.Duration
	MaxDNS                         int
	MaxDNSPerCID                   int
	MaxTunnels                     int
	MaxTunnelsPerCID               int
	ReadHeaderTimeout              time.Duration
	DialTimeout                    time.Duration
	MaxHeaderBytes                 int
}

func defaultOutboundProxyConfig(logger cllogger.SugaredLogger, metrics outboundProxyMetrics) (outboundProxyConfig, error) {
	local, err := localInterfaceAddresses()
	if err != nil {
		return outboundProxyConfig{}, err
	}
	return outboundProxyConfig{
		Resolver:          net.DefaultResolver,
		Dialer:            &net.Dialer{},
		Logger:            logger,
		Metrics:           metrics,
		LocalAddresses:    local,
		MaxSessions:       defaultOutboundMaxSessions,
		MaxSessionsPerCID: defaultOutboundMaxSessionsPerCID,
		RejectionHeadroom: defaultOutboundRejectionHeadroom,
		HalfCloseLinger:   defaultOutboundHalfCloseLinger,
		MaxDNS:            defaultOutboundMaxDNS,
		MaxDNSPerCID:      defaultOutboundMaxDNSPerCID,
		MaxTunnels:        defaultOutboundMaxTunnels,
		MaxTunnelsPerCID:  defaultOutboundMaxTunnelsPerCID,
		ReadHeaderTimeout: defaultOutboundReadHeaderTimeout,
		DialTimeout:       defaultOutboundDialTimeout,
		MaxHeaderBytes:    defaultOutboundMaxHeaderBytes,
	}, nil
}

type outboundProxy struct {
	config outboundProxyConfig

	mu       sync.Mutex
	children map[uint32]*outboundProxyChild
	sessions map[*outboundSessionConn]struct{}
	pairs    map[*outboundTunnelPair]struct{}
	changed  chan struct{}
	draining bool
	listener net.Listener
	server   *http.Server

	acceptLimit   *scopedProxyLimit
	admissionDone chan struct{}
	stopOnce      sync.Once
	dnsLimit      *scopedProxyLimit
	tunnelLimit   *scopedProxyLimit
}

type outboundProxyChild struct {
	draining bool
	sessions map[*outboundSessionConn]struct{}
}

func newOutboundProxy(config outboundProxyConfig) (*outboundProxy, error) {
	if config.Resolver == nil || config.Dialer == nil || config.Logger == nil || config.Metrics == nil {
		return nil, errors.New("outbound proxy resolver, dialer, logger, and metrics are required")
	}
	if config.MaxSessions <= 0 || config.MaxSessionsPerCID <= 0 || config.MaxDNS <= 0 || config.MaxDNSPerCID <= 0 || config.MaxTunnels <= 0 || config.MaxTunnelsPerCID <= 0 {
		return nil, errors.New("outbound proxy limits must be positive")
	}
	if config.RejectionHeadroom <= 0 {
		return nil, errors.New("outbound proxy rejection headroom must be positive")
	}
	if config.HalfCloseLinger <= 0 {
		return nil, errors.New("outbound proxy half-close linger must be positive")
	}
	if config.ReadHeaderTimeout <= 0 || config.DialTimeout <= 0 || config.MaxHeaderBytes <= 0 {
		return nil, errors.New("outbound proxy timeouts and header limit must be positive")
	}
	return &outboundProxy{
		config:        config,
		children:      make(map[uint32]*outboundProxyChild),
		sessions:      make(map[*outboundSessionConn]struct{}),
		pairs:         make(map[*outboundTunnelPair]struct{}),
		changed:       make(chan struct{}),
		acceptLimit:   newScopedProxyLimit(config.MaxSessions+config.RejectionHeadroom, config.MaxSessionsPerCID+config.RejectionHeadroom),
		admissionDone: make(chan struct{}),
		dnsLimit:      newScopedProxyLimit(config.MaxDNS, config.MaxDNSPerCID),
		tunnelLimit:   newScopedProxyLimit(config.MaxTunnels, config.MaxTunnelsPerCID),
	}, nil
}

func (p *outboundProxy) RegisterChild(cid uint32) error {
	if cid == 0 {
		return errors.New("cannot register CID 0")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.draining {
		return errors.New("outbound proxy is draining")
	}
	if _, exists := p.children[cid]; exists {
		return fmt.Errorf("CID %d is already registered", cid)
	}
	p.children[cid] = &outboundProxyChild{sessions: make(map[*outboundSessionConn]struct{})}
	p.notifyLocked()
	return nil
}

func (p *outboundProxy) DrainChild(ctx context.Context, cid uint32) error {
	p.mu.Lock()
	child, exists := p.children[cid]
	if !exists {
		p.mu.Unlock()
		return fmt.Errorf("CID %d is not registered", cid)
	}
	child.draining = true
	p.notifyLocked()
	for len(child.sessions) != 0 {
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
		p.mu.Lock()
		child, exists = p.children[cid]
		if !exists {
			p.mu.Unlock()
			return nil
		}
	}
	p.mu.Unlock()
	return nil
}

func (p *outboundProxy) UnregisterChild(cid uint32) {
	p.mu.Lock()
	child, exists := p.children[cid]
	if !exists {
		p.mu.Unlock()
		return
	}
	connections := make([]*outboundSessionConn, 0, len(child.sessions))
	for conn := range child.sessions {
		connections = append(connections, conn)
	}
	pairs := make([]*outboundTunnelPair, 0)
	for pair := range p.pairs {
		if pair.cid == cid {
			pairs = append(pairs, pair)
		}
	}
	delete(p.children, cid)
	p.notifyLocked()
	p.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	for _, pair := range pairs {
		p.finishPair(pair)
	}
}

// Start serves the broker on listener. The returned channel receives exactly
// one terminal Serve result.
func (p *outboundProxy) Start(listener net.Listener) (<-chan error, error) {
	p.mu.Lock()
	if p.server != nil {
		p.mu.Unlock()
		return nil, errors.New("outbound proxy already started")
	}
	p.listener = listener
	server := &http.Server{
		Handler:           p,
		ReadHeaderTimeout: p.config.ReadHeaderTimeout,
		MaxHeaderBytes:    p.config.MaxHeaderBytes,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			session, ok := conn.(*outboundSessionConn)
			if !ok {
				return ctx
			}
			ctx = context.WithValue(ctx, outboundCIDContextKey{}, session.cid)
			if session.reject != "" {
				ctx = context.WithValue(ctx, outboundRejectContextKey{}, session.reject)
			}
			return ctx
		},
	}
	p.server = server
	p.mu.Unlock()

	results := make(chan error, 1)
	go func() {
		err := server.Serve(&outboundAdmissionListener{Listener: listener, proxy: p})
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		results <- err
		close(results)
	}()
	return results, nil
}

// Drain follows the plan's shutdown order: mark draining and reject new
// sessions, let current work finish within the deadline, and only then close
// the listener. The listener stays open through the wait so a session opened
// mid-drain receives the typed draining rejection; closing it first would give
// the enclave a connection refusal, which classifies as an upstream 502 rather
// than the transient 503 the failure table promises.
func (p *outboundProxy) Drain(ctx context.Context) error {
	p.mu.Lock()
	p.draining = true
	p.notifyLocked()
	p.mu.Unlock()

	waitErr := p.waitForSessions(ctx)

	p.mu.Lock()
	p.stopAdmissionsLocked()
	listener, server := p.listener, p.server
	p.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	// Shutdown covers the rejected sessions, which are served and closed but
	// never entered the session maps. Its error matters: it reports that some
	// connection outlived the deadline, which must force a close rather than be
	// reported as a clean drain.
	var shutdownErr error
	if server != nil {
		shutdownErr = server.Shutdown(ctx)
	}
	if waitErr == nil {
		waitErr = shutdownErr
	}
	if waitErr != nil {
		p.config.Metrics.forcedDrain()
		p.Close()
		return waitErr
	}
	return nil
}

// waitForSessions blocks until no admitted session remains or ctx expires.
// Sessions that never send a request are reaped by ReadHeaderTimeout, so this
// cannot wait on a silent peer indefinitely.
func (p *outboundProxy) waitForSessions(ctx context.Context) error {
	for {
		p.mu.Lock()
		if len(p.sessions) == 0 {
			p.mu.Unlock()
			return nil
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (p *outboundProxy) Close() {
	p.mu.Lock()
	p.draining = true
	p.stopAdmissionsLocked()
	listener, server := p.listener, p.server
	connections := make([]*outboundSessionConn, 0, len(p.sessions))
	for conn := range p.sessions {
		connections = append(connections, conn)
	}
	pairs := make([]*outboundTunnelPair, 0, len(p.pairs))
	for pair := range p.pairs {
		pairs = append(pairs, pair)
	}
	p.notifyLocked()
	p.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if server != nil {
		_ = server.Close()
	}
	for _, conn := range connections {
		_ = conn.Close()
	}
	for _, pair := range pairs {
		p.finishPair(pair)
	}
}

func (p *outboundProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Answer a rejected session before any DNS or dial work so the enclave can
	// recreate a typed transient error rather than infer one from a closed
	// connection.
	if reject, rejected := r.Context().Value(outboundRejectContextKey{}).(outboundproxy.ErrorCode); rejected {
		writeOutboundError(w, outboundRejectStatus(reject), reject)
		return
	}
	cid, ok := r.Context().Value(outboundCIDContextKey{}).(uint32)
	if !ok {
		writeOutboundError(w, http.StatusForbidden, outboundproxy.CodeUnauthorized)
		return
	}
	// The plan's grammar rejects an unsupported protocol version alongside the
	// method, path, body and authority rules. The enclave dialer only ever
	// speaks HTTP/1.1, so anything else is not a client of this protocol.
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}
	if r.Header.Get(outboundproxy.VersionHeader) != outboundproxy.Version {
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}
	if r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == outboundproxy.ResolvePath:
		p.handleResolve(w, r, cid)
	case r.Method == http.MethodConnect:
		p.handleConnect(w, r, cid)
	default:
		writeOutboundError(w, http.StatusMethodNotAllowed, outboundproxy.CodeProtocol)
	}
}

func (p *outboundProxy) handleResolve(w http.ResponseWriter, r *http.Request, cid uint32) {
	release, ok := p.dnsLimit.tryAcquire(cid)
	if !ok {
		p.config.Metrics.capacityRejected()
		writeOutboundError(w, http.StatusServiceUnavailable, outboundproxy.CodeCapacity)
		return
	}
	defer release()

	started := time.Now()
	outcome := "success"
	defer func() { p.config.Metrics.dnsRequest(outcome, time.Since(started)) }()

	query := r.URL.Query()
	if len(query) != 1 || len(query["host"]) != 1 || r.Host != "proxy" {
		outcome = "protocol_error"
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}
	host := strings.TrimSuffix(query.Get("host"), ".")
	if !validDNSName(host) {
		outcome = "protocol_error"
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}

	if literal, err := netip.ParseAddr(host); err == nil {
		if !literal.Is4() {
			outcome = "protocol_error"
			writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
			return
		}
		if err := writeResolveResponse(w, outboundproxy.ResolveResponse{Addresses: []string{literal.String()}}); err != nil {
			p.config.Logger.Errorw("outbound DNS response failed", "event", "OUTBOUND_DNS_ERROR", "enclaveCID", cid, "errorClass", "write")
		}
		return
	}
	addresses, err := p.config.Resolver.LookupNetIP(r.Context(), "ip4", host+".")
	if err != nil {
		var dnsErr *net.DNSError
		switch {
		case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
			outcome = "not_found"
			writeOutboundError(w, http.StatusBadGateway, outboundproxy.CodeDNSNotFound)
		case errors.As(err, &dnsErr) && dnsErr.Timeout():
			outcome = "timeout"
			writeOutboundError(w, http.StatusGatewayTimeout, outboundproxy.CodeDNSTimeout)
		default:
			outcome = "error"
			writeOutboundError(w, http.StatusBadGateway, outboundproxy.CodeDNSFailure)
		}
		return
	}

	seen := make(map[netip.Addr]struct{})
	response := outboundproxy.ResolveResponse{Addresses: make([]string, 0, min(len(addresses), maxResolvedAddresses))}
	for _, address := range addresses {
		address = address.Unmap()
		if !address.Is4() {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		response.Addresses = append(response.Addresses, address.String())
		if len(response.Addresses) == maxResolvedAddresses {
			break
		}
	}
	if len(response.Addresses) == 0 {
		outcome = "not_found"
		writeOutboundError(w, http.StatusBadGateway, outboundproxy.CodeDNSNotFound)
		return
	}
	if err := writeResolveResponse(w, response); err != nil {
		p.config.Logger.Errorw("outbound DNS response failed", "event", "OUTBOUND_DNS_ERROR", "enclaveCID", cid, "errorClass", "write")
	}
}

func writeResolveResponse(w http.ResponseWriter, response outboundproxy.ResolveResponse) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	return json.NewEncoder(w).Encode(response)
}

func (p *outboundProxy) handleConnect(w http.ResponseWriter, r *http.Request, cid uint32) {
	authority := r.RequestURI
	if authority == "" || r.Host != authority || (r.URL.Host != "" && r.URL.Host != authority) {
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	address, addressErr := netip.ParseAddr(host)
	if err != nil || portNumber == 0 || addressErr != nil || !address.Is4() || address.String() != host {
		writeOutboundError(w, http.StatusBadRequest, outboundproxy.CodeProtocol)
		return
	}
	if p.destinationDenied(address) {
		writeOutboundError(w, http.StatusForbidden, outboundproxy.CodePolicyDenied)
		return
	}

	release, ok := p.tunnelLimit.tryAcquire(cid)
	if !ok {
		p.config.Metrics.capacityRejected()
		writeOutboundError(w, http.StatusServiceUnavailable, outboundproxy.CodeCapacity)
		return
	}
	started := time.Now()
	dialCtx, cancel := context.WithTimeout(r.Context(), p.config.DialTimeout)
	upstream, err := p.config.Dialer.DialContext(dialCtx, "tcp4", authority)
	cancel()
	if err != nil {
		release()
		code, status, outcome := classifyOutboundDialError(err)
		p.config.Metrics.connect(outcome, time.Since(started))
		writeOutboundError(w, status, code)
		return
	}
	p.config.Metrics.connect("success", time.Since(started))

	client, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		release()
		_ = upstream.Close()
		return
	}
	if rw.Reader.Buffered() != 0 {
		release()
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	// Both directions share one activity counter, so a write is only judged
	// stalled when the whole tunnel has stopped moving.
	activity := &tunnelActivity{}
	activity.touch()
	pair := &outboundTunnelPair{
		cid:      cid,
		activity: activity,
		client:   &stallGuardConn{Conn: client, bound: p.config.HalfCloseLinger, activity: activity},
		upstream: &stallGuardConn{Conn: upstream, bound: p.config.HalfCloseLinger, activity: activity},
		release:  release,
	}
	p.trackPair(pair)
	p.config.Metrics.tunnelDelta(cid, 1)
	if _, err := fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.finishPair(pair)
		return
	}
	if err := rw.Flush(); err != nil {
		p.finishPair(pair)
		return
	}
	p.relay(pair)
}

func (p *outboundProxy) relay(pair *outboundTunnelPair) {
	type result struct {
		direction string
		bytes     int64
		err       error
	}
	results := make(chan result, 2)
	go func() {
		n, err := io.Copy(pair.upstream, pair.client)
		closeWrite(pair.upstream)
		closeRead(pair.client)
		results <- result{direction: "egress", bytes: n, err: err}
	}()
	go func() {
		n, err := io.Copy(pair.client, pair.upstream)
		closeWrite(pair.client)
		closeRead(pair.upstream)
		results <- result{direction: "ingress", bytes: n, err: err}
	}()
	// Waiting for both directions is only safe while the peer reciprocates a
	// half-close. An upstream that neither sends nor closes leaves the other
	// io.Copy blocked, stranding this tunnel's permits and descriptors; enough
	// of those and every enclave on the parent is refused egress.
	//
	// A copy that ended in error says the tunnel is already broken -- a write
	// stall hit its bound, the peer reset, or the pair was closed underneath it
	// -- so release at once. Only a clean end waits out the linger, which keeps
	// the two bounds from stacking into twice the configured no-progress budget.
	// finishPair closes both connections, unblocking the other copy, and its
	// closeOnce makes the later calls harmless. The loop still drains both
	// results so neither direction's bytes go unrecorded.
	lingering := false
	stopLinger := make(chan struct{})
	for range 2 {
		result := <-results
		p.config.Metrics.bytes(result.direction, result.bytes)
		switch {
		case result.err != nil:
			p.finishPair(pair)
		case !lingering:
			lingering = true
			// Watch for inactivity rather than counting wall time from the
			// half-close: a peer that keeps streaming its response after the
			// other direction ended cleanly is still making progress, and
			// truncating it at a fixed interval would break a standards
			// compliant half-closed transfer.
			go p.lingerUntilIdle(pair, stopLinger)
		}
	}
	if lingering {
		close(stopLinger)
	}
	p.finishPair(pair)
}

// lingerUntilIdle releases a half-closed pair one interval after its last
// transfer, and exits when the relay finishes on its own. It waits on the time
// since that transfer rather than on a fixed tick: a tick that merely observes
// movement since the previous one would restart the whole interval, allowing
// almost two of them against a bound documented as one.
func (p *outboundProxy) lingerUntilIdle(pair *outboundTunnelPair, stop <-chan struct{}) {
	timer := time.NewTimer(p.config.HalfCloseLinger)
	defer timer.Stop()
	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			idle := pair.activity.idleFor()
			if idle >= p.config.HalfCloseLinger {
				p.finishPair(pair)
				return
			}
			timer.Reset(p.config.HalfCloseLinger - idle)
		}
	}
}

func (p *outboundProxy) trackPair(pair *outboundTunnelPair) {
	p.mu.Lock()
	p.pairs[pair] = struct{}{}
	p.mu.Unlock()
}

func (p *outboundProxy) finishPair(pair *outboundTunnelPair) {
	pair.closeOnce.Do(func() {
		_ = pair.client.Close()
		_ = pair.upstream.Close()
		pair.release()
		p.config.Metrics.tunnelDelta(pair.cid, -1)
		p.mu.Lock()
		delete(p.pairs, pair)
		p.notifyLocked()
		p.mu.Unlock()
	})
}

func (p *outboundProxy) destinationDenied(address netip.Addr) bool {
	if !address.Is4() || address.IsUnspecified() || address.IsLinkLocalUnicast() || address.IsMulticast() {
		return true
	}
	if !p.config.AllowLocalDestinationsForTests && address.IsLoopback() {
		return true
	}
	if _, local := p.config.LocalAddresses[address]; local && !p.config.AllowLocalDestinationsForTests {
		return true
	}
	return netip.MustParsePrefix("0.0.0.0/8").Contains(address) || netip.MustParsePrefix("240.0.0.0/4").Contains(address)
}

// admit always returns a usable connection so the HTTP server can answer a
// rejected session with a typed error instead of a bare close, which the enclave
// would otherwise see as an upstream EOF. Rejected sessions are excluded from
// the session maps but still hold the accept slot the caller acquired, so they
// remain bounded both globally and per CID.
func (p *outboundProxy) admit(conn net.Conn, cid uint32, haveCID bool, releaseAccept func()) *outboundSessionConn {
	reject := func(code outboundproxy.ErrorCode) *outboundSessionConn {
		return &outboundSessionConn{Conn: conn, cid: cid, proxy: p, reject: code, releaseAccept: releaseAccept}
	}
	if !haveCID {
		return reject(outboundproxy.CodeUnauthorized)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	child, registered := p.children[cid]
	switch {
	case p.draining:
		return reject(outboundproxy.CodeDraining)
	case !registered:
		return reject(outboundproxy.CodeUnauthorized)
	case child.draining:
		return reject(outboundproxy.CodeDraining)
	case len(p.sessions) >= p.config.MaxSessions || len(child.sessions) >= p.config.MaxSessionsPerCID:
		p.config.Metrics.capacityRejected()
		return reject(outboundproxy.CodeCapacity)
	}
	session := &outboundSessionConn{Conn: conn, cid: cid, proxy: p, releaseAccept: releaseAccept}
	child.sessions[session] = struct{}{}
	p.sessions[session] = struct{}{}
	p.config.Metrics.sessionDelta(cid, 1)
	p.notifyLocked()
	return session
}

func (p *outboundProxy) releaseSession(conn *outboundSessionConn) {
	p.mu.Lock()
	delete(p.sessions, conn)
	if child := p.children[conn.cid]; child != nil {
		delete(child.sessions, conn)
	}
	p.notifyLocked()
	p.mu.Unlock()
	p.config.Metrics.sessionDelta(conn.cid, -1)
}

func (p *outboundProxy) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *outboundProxy) stopAdmissionsLocked() {
	p.stopOnce.Do(func() { close(p.admissionDone) })
}

type outboundAdmissionListener struct {
	net.Listener
	proxy *outboundProxy
}

func (l *outboundAdmissionListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.proxy.admissionDone:
			return nil, net.ErrClosed
		default:
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// Every accepted connection holds a slot until it closes, admitted or
		// rejected, so a peer cannot exhaust host descriptors by opening
		// connections it never uses. The slot is charged to the CID, so one child
		// cannot consume the whole budget and starve its siblings. Past the
		// ceiling there is no room left to answer, so drop without a response
		// rather than accept unboundedly.
		cid, haveCID := remoteCID(conn.RemoteAddr())
		if !haveCID && l.proxy.config.FallbackCID != 0 {
			cid, haveCID = l.proxy.config.FallbackCID, true
		}
		release, ok := l.proxy.acceptLimit.tryAcquire(cid)
		if !ok {
			l.proxy.config.Metrics.capacityRejected()
			_ = conn.Close()
			continue
		}
		return l.proxy.admit(conn, cid, haveCID, release), nil
	}
}

type outboundSessionConn struct {
	net.Conn
	cid uint32
	// reject is empty for an admitted session; otherwise it is the typed code
	// the handler returns before doing any DNS or dial work.
	reject        outboundproxy.ErrorCode
	proxy         *outboundProxy
	releaseAccept func()
	closeOnce     sync.Once
}

func (c *outboundSessionConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.Conn.Close()
		if c.reject == "" {
			c.proxy.releaseSession(c)
		}
		c.releaseAccept()
	})
	return err
}

func (c *outboundSessionConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (c *outboundSessionConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

// tunnelActivity counts bytes moved by either direction of one tunnel, so a
// stalled write can tell "this pair is dead" from "this peer is not reading
// right now while the other direction still flows".
type tunnelActivity struct {
	bytes atomic.Uint64
	// at is when the last transfer happened, so a waiter can close exactly one
	// interval after it rather than at the next tick of a fixed ticker. It is
	// held as an offset from processStart rather than as a wall-clock instant,
	// because this is an interval: reading time.Now().UnixNano() at each end
	// would let an NTP step close a live tunnel early or hold a dead one open.
	at atomic.Int64
}

// processStart carries a monotonic reading, so time.Since(processStart) is
// immune to wall-clock steps.
var processStart = time.Now()

func (a *tunnelActivity) touch() { a.at.Store(int64(time.Since(processStart))) }

func (a *tunnelActivity) add(n int) {
	if n > 0 {
		a.bytes.Add(uint64(n)) //nolint:gosec // n is positive
		a.touch()
	}
}

func (a *tunnelActivity) count() uint64 { return a.bytes.Load() }

func (a *tunnelActivity) idleFor() time.Duration {
	return time.Since(processStart) - time.Duration(a.at.Load())
}

// stallGuardConn fails a write only when the whole tunnel has stopped moving.
//
// The half-close linger only arms once a relay direction reports. A peer that
// accepts and then stops reading fills its receive window, so the egress copy
// blocks in Write while the ingress copy blocks reading that same silent peer:
// neither reports, the linger never arms, and the tunnel strands permanently.
// TCP does not break it either -- a zero window is probed indefinitely rather
// than timed out.
//
// The bound is on lack of progress, not on completing a write. A write that
// moves some bytes, or that is slow while the opposite direction is still
// delivering, gets a fresh bound: otherwise a slow-but-draining peer, or an
// upstream streaming a response while it stops reading the request, would have
// its live traffic truncated. Only reads are never bounded, which is what keeps
// this from being the proxy-level total tunnel timeout the plan rules out.
//
// It must not grow a ReadFrom: io.Copy would take that fast path and bypass
// Write entirely, silently reopening the stall this closes. Embedding the
// net.Conn interface rather than a concrete type is what prevents promotion.
type stallGuardConn struct {
	net.Conn
	bound    time.Duration
	activity *tunnelActivity
}

// Read records progress so the opposite direction's write is not judged stalled
// while this one is mid-transfer. io.Copy cannot start another read while its
// own write is blocked, so this cannot manufacture unlimited liveness.
func (c *stallGuardConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.activity.add(n)
	return n, err
}

func (c *stallGuardConn) Write(p []byte) (int, error) {
	written := 0
	// Retrying on progress alone would let a peer that drains a trickle hold the
	// tunnel forever. Whether a slow drain yields partial progress or none at all
	// depends on kernel socket-buffer sizing on the TCP side, and on credit
	// accounting on the VSOCK side, so it is not something to rely on: cap the
	// total instead. At the default bound this still tolerates a peer draining
	// one buffer at well under a kilobyte per second.
	deadline := time.Now().Add(c.bound * maxWriteStallBounds)
	for {
		before := c.activity.count()
		if err := c.SetWriteDeadline(time.Now().Add(c.bound)); err != nil {
			return written, err
		}
		n, err := c.Conn.Write(p[written:])
		written += n
		c.activity.add(n)
		if err == nil {
			break
		}
		var netErr net.Error
		// Anything but a deadline is a real failure; so is a deadline that found
		// the whole tunnel idle for the bound, or one write outliving its total
		// allowance however much it dribbled.
		if !errors.As(err, &netErr) || !netErr.Timeout() ||
			(n == 0 && c.activity.count() == before) ||
			!time.Now().Before(deadline) {
			_ = c.SetWriteDeadline(time.Time{})
			return written, err
		}
	}
	// Clear it so a later write is judged on its own progress, not this one's.
	_ = c.SetWriteDeadline(time.Time{})
	return written, nil
}

// CloseRead and CloseWrite must be forwarded: the relay type-asserts for them
// to half-close, and would otherwise fall back to closing the whole connection.
func (c *stallGuardConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (c *stallGuardConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	// Mirror closeWrite's fallback exactly. Wrapping makes the type assertion in
	// that helper always succeed, so without this a transport that cannot
	// half-close would silently no-op here instead of being closed, and the
	// opposite relay direction would never unblock.
	return c.Close()
}

type outboundTunnelPair struct {
	cid uint32
	// activity is shared with both guarded connections, so the relay and the
	// linger judge liveness from the same counter.
	activity  *tunnelActivity
	client    net.Conn
	upstream  net.Conn
	release   func()
	closeOnce sync.Once
}

type outboundCIDContextKey struct{}

type outboundRejectContextKey struct{}

func outboundRejectStatus(code outboundproxy.ErrorCode) int {
	if code == outboundproxy.CodeUnauthorized {
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
}

type scopedProxyLimit struct {
	mu        sync.Mutex
	global    int
	perCID    map[uint32]int
	maxGlobal int
	maxPerCID int
}

func newScopedProxyLimit(maxGlobal, maxPerCID int) *scopedProxyLimit {
	return &scopedProxyLimit{perCID: make(map[uint32]int), maxGlobal: maxGlobal, maxPerCID: maxPerCID}
}

func (l *scopedProxyLimit) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.global
}

func (l *scopedProxyLimit) tryAcquire(cid uint32) (func(), bool) {
	l.mu.Lock()
	if l.global >= l.maxGlobal || l.perCID[cid] >= l.maxPerCID {
		l.mu.Unlock()
		return nil, false
	}
	l.global++
	l.perCID[cid]++
	l.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			l.global--
			l.perCID[cid]--
			if l.perCID[cid] == 0 {
				delete(l.perCID, cid)
			}
			l.mu.Unlock()
		})
	}, true
}

func classifyOutboundDialError(err error) (outboundproxy.ErrorCode, int, string) {
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return outboundproxy.CodeConnectTimeout, http.StatusGatewayTimeout, "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return outboundproxy.CodeConnectRefused, http.StatusBadGateway, "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return outboundproxy.CodeConnectReset, http.StatusBadGateway, "reset"
	default:
		return outboundproxy.CodeConnectFailure, http.StatusBadGateway, "error"
	}
}

func writeOutboundError(w http.ResponseWriter, status int, code outboundproxy.ErrorCode) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(outboundproxy.ErrorResponse{Code: code})
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "/:@[]") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			// '_' is permitted because Go's resolver accepts it, so rejecting it
			// here would break hostnames the pre-broker enclave could resolve.
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return false
			}
		}
	}
	return true
}

func remoteCID(address net.Addr) (uint32, bool) {
	vsockAddress, ok := address.(*mdvsock.Addr)
	if !ok {
		return 0, false
	}
	return vsockAddress.ContextID, true
}

func closeRead(conn net.Conn) {
	if conn, ok := conn.(interface{ CloseRead() error }); ok {
		_ = conn.CloseRead()
	}
}

func closeWrite(conn net.Conn) {
	if conn, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = conn.CloseWrite()
		return
	}
	// A full close is the only portable way to unblock the opposite relay when
	// a test or alternate transport cannot half-close.
	_ = conn.Close()
}

// localInterfaceAddresses reports the parent's own addresses, which the broker
// refuses as destinations. Enumeration failure is returned rather than
// swallowed: an empty set silently disables that deny, and a compromised
// enclave could then reach pod-local services by numeric CONNECT.
func localInterfaceAddresses() (map[netip.Addr]struct{}, error) {
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("enumerate local interface addresses: %w", err)
	}
	addresses := make(map[netip.Addr]struct{})
	for _, raw := range interfaceAddresses {
		prefix, err := netip.ParsePrefix(raw.String())
		if err != nil {
			return nil, fmt.Errorf("parse local interface address %q: %w", raw.String(), err)
		}
		addresses[prefix.Addr().Unmap()] = struct{}{}
	}
	return addresses, nil
}
