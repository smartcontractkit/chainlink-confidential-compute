package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	cllogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/outboundproxy"
	ccvsock "github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundProxyResolveConnectAndRelay(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5191, 16, resolver, dialerFunc(echoPipeDialer))

	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5191)
	conn, err := dialer.DialContext(context.Background(), "tcp", "service.example:443")
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	got := make([]byte, 5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
	require.NoError(t, conn.Close())

	require.Eventually(t, func() bool { return proxy.sessionCount() == 0 }, time.Second, 10*time.Millisecond)
	require.Equal(t, "service.example.", resolver.lastName())
}

func TestOutboundProxyRejectsUnregisteredCIDBeforeDNS(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5192, 17, resolver, dialerFunc(echoPipeDialer))

	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5192)
	_, err := dialer.DialContext(context.Background(), "tcp", "service.example:443")
	require.Error(t, err)
	require.Empty(t, resolver.lastName())
	require.Equal(t, 0, proxy.sessionCount())

	// The caller must see a typed transient error, not the EOF a bare close
	// would produce.
	var proxyErr *outboundproxy.ProxyError
	require.ErrorAs(t, err, &proxyErr)
	require.Equal(t, outboundproxy.CodeUnauthorized, proxyErr.Code)
	require.True(t, proxyErr.OutboundUnavailable())
}

func TestOutboundProxyReturnsTypedCapacityError(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	startOutboundProxyTestServer(t, 5196, 16, resolver, dialerFunc(echoPipeDialer),
		func(config *outboundProxyConfig) { config.MaxSessions = 1 })

	// An IP literal is validated in the enclave, so each dial is exactly one
	// session and the cap is reached deterministically.
	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5196)
	tunnel, err := dialer.DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.NoError(t, err)
	defer tunnel.Close() //nolint:errcheck // closed again by the test server cleanup

	_, err = dialer.DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.Error(t, err)
	require.Empty(t, resolver.lastName(), "capacity must be refused before any DNS work")

	var proxyErr *outboundproxy.ProxyError
	require.ErrorAs(t, err, &proxyErr)
	require.Equal(t, outboundproxy.CodeCapacity, proxyErr.Code)
	require.True(t, proxyErr.OutboundUnavailable())
}

func TestOutboundProxyDeniesMetadataForOperatorPolicy(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("169.254.169.254")}}
	startOutboundProxyTestServer(t, 5193, 16, resolver, dialerFunc(echoPipeDialer))

	dialer, err := outboundproxy.NewOperatorDialer(outboundproxy.ParentCID, 5193, "metadata.example:443")
	require.NoError(t, err)
	_, err = dialer.DialContext(context.Background(), "tcp", "metadata.example:443")
	require.Error(t, err)
	require.True(t, outboundproxy.IsPolicyError(err))
}

func TestOutboundProxyMapsConnectRefused(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	startOutboundProxyTestServer(t, 5194, 16, resolver, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNREFUSED
	}))

	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5194)
	_, err := dialer.DialContext(context.Background(), "tcp", "service.example:443")
	require.ErrorIs(t, err, syscall.ECONNREFUSED)
}

// An upstream that neither sends nor closes after receiving the tunnel's
// half-close leaves the ingress io.Copy blocked forever. Nothing sets a
// deadline on either hijacked connection, so without a bound on the half-closed
// state the tunnel, session and accept permits are never returned and a
// workflow-chosen destination can exhaust the broker.
func TestOutboundProxyBoundsHalfClosedTunnel(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)

	// A real TCP peer, so the broker's CloseWrite is a genuine FIN rather than
	// the full close that net.Pipe would fall back to. It never replies.
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, acceptErr := upstream.Accept()
			if acceptErr != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})

	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5201, 16, resolver,
		dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
		}),
		func(config *outboundProxyConfig) { config.HalfCloseLinger = 250 * time.Millisecond })

	conn, err := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5201).
		DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.NoError(t, err)
	// The enclave abandons the request, as a timeout or cancellation would.
	require.NoError(t, conn.Close())

	require.Eventually(t, func() bool {
		return proxy.sessionCount() == 0 &&
			proxy.tunnelLimit.count() == 0 &&
			proxy.acceptLimit.count() == 0
	}, 10*time.Second, 25*time.Millisecond, "a half-closed tunnel never returned its permits")
}

// The half-close linger arms when the first relay direction reports. An
// upstream that accepts and then stops reading fills its receive window, so the
// egress copy blocks in Write while the ingress copy blocks reading the same
// silent peer: neither direction reports, the linger never arms, and the tunnel
// strands. TCP will not break the deadlock either -- a zero window is probed
// indefinitely rather than timed out.
func TestOutboundProxyBoundsWriteStalledTunnel(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)

	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, acceptErr := upstream.Accept()
			if acceptErr != nil {
				return
			}
			// Accept and never read, so the window fills.
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})

	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5202, 16, resolver,
		dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Addr().String())
		}),
		// Large enough that one bound is clearly distinguishable from two: the
		// write deadline and the linger must not stack.
		func(config *outboundProxyConfig) { config.HalfCloseLinger = 2 * time.Second })

	conn, err := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5202).
		DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.NoError(t, err)

	// Enough to fill the upstream's receive window and the relay's send buffer,
	// so the egress copy is blocked writing rather than reading.
	go func() {
		payload := make([]byte, 1<<20)
		for range 32 {
			if _, writeErr := conn.Write(payload); writeErr != nil {
				return
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, conn.Close())

	// Generous, because the number of bounds is not fixed: the peer accepts bytes
	// until its window fills, so a write straddling the boundary makes partial
	// progress and earns a fresh bound by design. What matters here is that the
	// permits come back at all. TestOutboundProxyErrorReleasesWithoutLinger
	// pins the no-stacking property without depending on socket timing.
	require.Eventually(t, func() bool {
		return proxy.sessionCount() == 0 &&
			proxy.tunnelLimit.count() == 0 &&
			proxy.acceptLimit.count() == 0
	}, 20*time.Second, 25*time.Millisecond, "a write-stalled tunnel never returned its permits")
}

// A copy that ends in error means the tunnel is already broken, so the pair is
// released at once rather than waiting out the linger as well. Without that the
// two bounds stack into twice the configured no-progress budget. Asserted
// against a linger far longer than the deadline, so it cannot pass by timing.
func TestOutboundProxyErrorReleasesWithoutLinger(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5203, 16, resolver,
		dialerFunc(func(context.Context, string, string) (net.Conn, error) {
			// Reads fail immediately, so the ingress copy reports an error
			// rather than a clean end. Closing a net.Pipe would give EOF, which
			// is a clean end and correctly waits out the linger.
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			return readErrorConn{Conn: client}, nil
		}),
		func(config *outboundProxyConfig) { config.HalfCloseLinger = 30 * time.Second })

	conn, err := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5203).
		DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck // released by the broker

	require.Eventually(t, func() bool {
		return proxy.tunnelLimit.count() == 0
	}, 3*time.Second, 25*time.Millisecond,
		"an errored copy waited out the linger instead of releasing at once")
}

func TestOutboundProxyMapsConnectReset(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	startOutboundProxyTestServer(t, 5199, 16, resolver, dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		return nil, syscall.ECONNRESET
	}))

	// The baseline mapped a reset to 502; losing the syscall on the wire would
	// downgrade it to an opaque enclave failure.
	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5199)
	_, err := dialer.DialContext(context.Background(), "tcp", "service.example:443")
	require.ErrorIs(t, err, syscall.ECONNRESET)
}

// The accept ceiling is charged per CID, so one child cannot occupy the whole
// budget and leave its siblings with bare closes.
func TestOutboundProxyBoundsAcceptedSessionsPerCID(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5200, 16, resolver, dialerFunc(echoPipeDialer),
		func(config *outboundProxyConfig) {
			config.MaxSessions = 8
			config.MaxSessionsPerCID = 1
			config.RejectionHeadroom = 1
		})

	// Two connections exhaust this CID's share even though the global ceiling
	// is 9.
	for range 2 {
		conn, err := ccvsock.Dial(outboundproxy.ParentCID, 5200, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
	}
	require.Eventually(t, func() bool { return proxy.acceptLimit.count() == 2 },
		2*time.Second, 5*time.Millisecond)

	extra, err := ccvsock.Dial(outboundproxy.ParentCID, 5200, nil)
	require.NoError(t, err)
	defer extra.Close() //nolint:errcheck // already closed by the broker
	require.NoError(t, extra.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = extra.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 2, proxy.acceptLimit.count())
}

// CONNECT must carry the exact numeric address the enclave validated, which is
// what leaves no window for a rebind between validation and dial. The earlier
// version of this test sent no proxy-version header, so it was refused by the
// version check and never reached that rule -- deleting the rule would have
// left it green.
func TestOutboundProxyRejectsMalformedProtocol(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	var dialed atomic.Int64
	startOutboundProxyTestServer(t, 5195, 16, &recordingResolver{},
		dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed.Add(1)
			return echoPipeDialer(ctx, network, address)
		}))

	connect := func(t *testing.T, target string, withVersion bool) *http.Response {
		t.Helper()
		conn, err := ccvsock.Dial(outboundproxy.ParentCID, 5195, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
		if withVersion {
			request += outboundproxy.VersionHeader + ": " + outboundproxy.Version + "\r\n"
		}
		_, err = io.WriteString(conn, request+"\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufioReader(conn), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	// Refused on its own merits, with the version header present.
	require.Equal(t, http.StatusBadRequest, connect(t, "example.com:443", true).StatusCode)
	require.Zero(t, dialed.Load(), "a hostname CONNECT must be refused before any dial")

	// The companion case, so the rejection above is known to be about the
	// hostname rather than about refusing every CONNECT.
	require.Equal(t, http.StatusOK, connect(t, "8.8.8.8:443", true).StatusCode)
	require.Equal(t, int64(1), dialed.Load())

	// And the version check itself still rejects.
	require.Equal(t, http.StatusBadRequest, connect(t, "8.8.8.8:443", false).StatusCode)
	require.Equal(t, int64(1), dialed.Load())

	// The remaining grammar rules, sent raw so the violation survives to the
	// handler. Before this only the version and hostname rules were under test.
	// Mutation shows these cases pin the body/transfer-encoding rule, the
	// zero-port rule and the IPv4-only rule.
	//
	// Three further guards in handleConnect cannot be pinned, and this test does
	// not claim to: every input that reaches them is already refused by a later
	// rule. The authority/Host match and the address.String() != host check are
	// both subsumed by the numeric IPv4 rule, because netip.ParseAddr rejects
	// leading zeros and accepts only canonical dotted quads, and the
	// SplitHostPort error is subsumed by the port parse. They are cheap
	// belt-and-braces should that parser ever grow lenient. The two odd
	// request-target forms below exercise the path those guards sit on without
	// isolating them.
	raw := func(t *testing.T, request string) *http.Response {
		t.Helper()
		conn, err := ccvsock.Dial(outboundproxy.ParentCID, 5195, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = io.WriteString(conn, request)
		require.NoError(t, err)
		response, err := http.ReadResponse(bufioReader(conn), nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	version := outboundproxy.VersionHeader + ": " + outboundproxy.Version + "\r\n"
	for _, testCase := range []struct{ name, request string }{
		{"unsupported protocol version",
			"CONNECT 8.8.8.8:443 HTTP/1.0\r\nHost: 8.8.8.8:443\r\n" + version + "\r\n"},
		// A mismatched Host *header* is deliberately not a case here: for
		// authority-form CONNECT, http.ReadRequest sets r.Host from the
		// request-target and never consults the header, and the dial target is
		// that same request-target, so the two cannot diverge. The rule is
		// reachable through the other two request-target forms.
		{"origin-form request target",
			"CONNECT /evil HTTP/1.1\r\nHost: 8.8.8.8:443\r\n" + version + "\r\n"},
		{"absolute-form request target",
			"CONNECT http://8.8.8.8:443/x HTTP/1.1\r\nHost: 8.8.8.8:443\r\n" + version + "\r\n"},
		{"body present",
			"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nContent-Length: 3\r\n" + version + "\r\nabc"},
		{"chunked transfer encoding",
			"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\nTransfer-Encoding: chunked\r\n" + version + "\r\n0\r\n\r\n"},
		{"zero port",
			"CONNECT 8.8.8.8:0 HTTP/1.1\r\nHost: 8.8.8.8:0\r\n" + version + "\r\n"},
		{"port out of range",
			"CONNECT 8.8.8.8:65536 HTTP/1.1\r\nHost: 8.8.8.8:65536\r\n" + version + "\r\n"},
		{"missing port",
			"CONNECT 8.8.8.8 HTTP/1.1\r\nHost: 8.8.8.8\r\n" + version + "\r\n"},
		// Non-canonical and non-IPv4 forms: the rule is that the address dialled
		// is byte-for-byte the address the enclave validated.
		{"non-canonical IPv4",
			"CONNECT 8.8.8.08:443 HTTP/1.1\r\nHost: 8.8.8.08:443\r\n" + version + "\r\n"},
		{"IPv6 literal",
			"CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n" + version + "\r\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, http.StatusBadRequest, raw(t, testCase.request).StatusCode)
		})
	}
	require.Equal(t, int64(1), dialed.Load(), "no malformed request may reach a dial")
}

func TestOutboundProxyDrainChildWaitsForSession(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5196, 16, resolver, dialerFunc(echoPipeDialer))
	dialer := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5196)
	conn, err := dialer.DialContext(context.Background(), "tcp", "service.example:443")
	require.NoError(t, err)

	drained := make(chan error, 1)
	go func() { drained <- proxy.DrainChild(context.Background(), 16) }()
	select {
	case err := <-drained:
		t.Fatalf("DrainChild returned before the tunnel closed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	require.NoError(t, conn.Close())
	require.NoError(t, <-drained)
}

func TestScopedProxyLimitIsGlobalAndPerCID(t *testing.T) {
	limit := newScopedProxyLimit(2, 1)
	release1, ok := limit.tryAcquire(16)
	require.True(t, ok)
	_, ok = limit.tryAcquire(16)
	require.False(t, ok)
	release2, ok := limit.tryAcquire(17)
	require.True(t, ok)
	_, ok = limit.tryAcquire(18)
	require.False(t, ok)
	release1()
	release2()
	_, ok = limit.tryAcquire(18)
	require.True(t, ok)
}

func TestOutboundDestinationDenied(t *testing.T) {
	p := &outboundProxy{config: outboundProxyConfig{LocalAddresses: map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.7"): {}}}}
	for _, raw := range []string{"0.0.0.1", "127.0.0.1", "169.254.169.254", "224.0.0.1", "240.0.0.1", "10.0.0.7"} {
		assert.True(t, p.destinationDenied(netip.MustParseAddr(raw)), raw)
	}
	assert.False(t, p.destinationDenied(netip.MustParseAddr("10.0.0.8")))
	assert.False(t, p.destinationDenied(netip.MustParseAddr("8.8.8.8")))
}

func TestOutboundDestinationAllowsLocalOnlyForTests(t *testing.T) {
	p := &outboundProxy{config: outboundProxyConfig{
		LocalAddresses:                 map[netip.Addr]struct{}{netip.MustParseAddr("10.0.0.7"): {}},
		AllowLocalDestinationsForTests: true,
	}}
	assert.False(t, p.destinationDenied(netip.MustParseAddr("127.0.0.1")))
	assert.False(t, p.destinationDenied(netip.MustParseAddr("10.0.0.7")))
	assert.True(t, p.destinationDenied(netip.MustParseAddr("169.254.169.254")))
}

// tune, when set, adjusts the config before Start. The accept goroutine reads
// config, so tests must not mutate it afterwards.
// A session opened while the broker drains must get the typed draining
// rejection, not a connection refusal the enclave would classify as a 502.
func TestOutboundProxyDrainRejectsNewSessionsTyped(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5198, 16, resolver, dialerFunc(echoPipeDialer))

	// Hold a tunnel so the drain cannot complete before the probe below.
	tunnel, err := outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5198).
		DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.NoError(t, err)

	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	drained := make(chan error, 1)
	go func() { drained <- proxy.Drain(drainCtx) }()

	require.Eventually(t, func() bool {
		proxy.mu.Lock()
		defer proxy.mu.Unlock()
		return proxy.draining
	}, 2*time.Second, 5*time.Millisecond)

	_, err = outboundproxy.NewWorkflowDialer(outboundproxy.ParentCID, 5198).
		DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.Error(t, err)
	var proxyErr *outboundproxy.ProxyError
	require.ErrorAs(t, err, &proxyErr)
	require.Equal(t, outboundproxy.CodeDraining, proxyErr.Code)
	require.True(t, proxyErr.OutboundUnavailable())

	require.NoError(t, tunnel.Close())
	require.NoError(t, <-drained)
}

// Answering a rejection costs a connection, so the number of connections held
// open for that purpose must itself be bounded: a peer that opens connections
// and never sends must not be able to exhaust host descriptors.
func TestOutboundProxyBoundsAcceptedSessions(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	resolver := &recordingResolver{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	proxy := startOutboundProxyTestServer(t, 5197, 16, resolver, dialerFunc(echoPipeDialer),
		func(config *outboundProxyConfig) { config.MaxSessions = 1; config.RejectionHeadroom = 1 })

	// Fill the ceiling with connections that never send a request.
	for range 2 {
		conn, err := ccvsock.Dial(outboundproxy.ParentCID, 5197, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
	}
	require.Eventually(t, func() bool { return proxy.acceptLimit.count() == 2 },
		2*time.Second, 5*time.Millisecond, "broker did not accept both connections")

	// The next one is dropped immediately rather than accumulating.
	extra, err := ccvsock.Dial(outboundproxy.ParentCID, 5197, nil)
	require.NoError(t, err)
	defer extra.Close() //nolint:errcheck // already closed by the broker
	require.NoError(t, extra.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = extra.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, 2, proxy.acceptLimit.count())
}

func startOutboundProxyTestServer(t *testing.T, port uint32, registeredCID uint32, resolver outboundResolver, dialer outboundDialer, tune ...func(*outboundProxyConfig)) *outboundProxy {
	t.Helper()
	config, err := defaultOutboundProxyConfig(cllogger.Sugared(cllogger.Nop()), noopOutboundProxyMetrics{})
	require.NoError(t, err)
	config.Resolver = resolver
	config.Dialer = dialer
	config.FallbackCID = 16
	config.LocalAddresses = nil
	for _, apply := range tune {
		apply(&config)
	}
	proxy, err := newOutboundProxy(config)
	require.NoError(t, err)
	require.NoError(t, proxy.RegisterChild(registeredCID))
	listener, err := ccvsock.ListenAt(outboundproxy.ParentCID, port, nil)
	require.NoError(t, err)
	results, err := proxy.Start(listener)
	require.NoError(t, err)
	t.Cleanup(func() {
		proxy.Close()
		select {
		case <-results:
		case <-time.After(time.Second):
			t.Error("outbound proxy did not stop")
		}
	})
	return proxy
}

func (p *outboundProxy) sessionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sessions)
}

type recordingResolver struct {
	mu        sync.Mutex
	addresses []netip.Addr
	err       error
	name      string
}

func (r *recordingResolver) LookupNetIP(_ context.Context, _, name string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.name = name
	return r.addresses, r.err
}

func (r *recordingResolver) lastName() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.name
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func echoPipeDialer(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close() //nolint:errcheck
		_, _ = io.Copy(server, server)
	}()
	return client, nil
}

func bufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

func TestParseOutboundCIDs(t *testing.T) {
	cids, err := parseOutboundCIDs("", 16)
	require.NoError(t, err)
	require.Equal(t, []uint32{16}, cids)

	cids, err = parseOutboundCIDs(" 16 , 17 ", 16)
	require.NoError(t, err)
	require.Equal(t, []uint32{16, 17}, cids)

	_, err = parseOutboundCIDs("16,0", 16)
	require.Error(t, err)

	_, err = parseOutboundCIDs("16,abc", 16)
	require.Error(t, err)
}

// readErrorConn fails reads outright, unlike a closed net.Pipe whose reads
// return a clean io.EOF.
type readErrorConn struct{ net.Conn }

func (readErrorConn) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
