package outboundproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	ccvsock "github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/stretchr/testify/require"
)

// The broker may pack the CONNECT response and the first upstream bytes into a
// single segment, leaving those bytes in the client's bufio.Reader. The
// returned connection must serve them before it reads the socket again, or the
// first bytes of a TLS ServerHello are silently dropped.
func TestDialerPreservesBytesBufferedWithConnectResponse(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	const port = 5312
	listener, err := ccvsock.ListenAt(ParentCID, port, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		if _, readErr := http.ReadRequest(bufio.NewReader(conn)); readErr != nil {
			return
		}
		// One write, so the payload cannot arrive after the response is parsed.
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nHELLO")
		time.Sleep(time.Second)
	}()

	// An IP literal is validated in the enclave, so no resolve round trip runs.
	conn, err := NewWorkflowDialer(ParentCID, port).DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	payload := make([]byte, 5)
	_, err = io.ReadFull(conn, payload)
	require.NoError(t, err)
	require.Equal(t, "HELLO", string(payload))
}

func TestDialerResolveConnectAndCandidateFallback(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)

	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, upstream.Close()) })
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_, _ = io.Copy(conn, conn)
	}()

	proxyPort := uint32(5091)
	startTestBroker(t, proxyPort, []string{"127.0.0.2", "127.0.0.1"})
	dialer, err := NewOperatorDialer(ParentCID, proxyPort, "service.test:"+portOf(t, upstream.Addr().String()))
	require.NoError(t, err)

	conn, err := dialer.DialContext(context.Background(), "tcp", "service.test:"+portOf(t, upstream.Addr().String()))
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck

	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	got := make([]byte, 5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

func TestDialerRejectsBlockedAddressBeforeConnect(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	proxyPort := uint32(5092)
	broker := startTestBroker(t, proxyPort, []string{"127.0.0.1"})

	dialer := NewWorkflowDialer(ParentCID, proxyPort)
	_, err := dialer.DialContext(context.Background(), "tcp", "service.test:443")
	require.Error(t, err)
	require.True(t, IsPolicyError(err))
	require.Equal(t, 0, broker.connects())
}

func TestDialerRejectsIPv6AndNonDefaultWorkflowPort(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	dialer := NewWorkflowDialer(ParentCID, 5093)

	_, err := dialer.DialContext(context.Background(), "tcp", "[2001:db8::1]:443")
	require.Error(t, err)
	require.True(t, IsPolicyError(err))

	_, err = dialer.DialContext(context.Background(), "tcp", "example.com:444")
	require.Error(t, err)
	require.True(t, IsPolicyError(err))
}

func TestDialerMapsTypedDNSError(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	proxyPort := uint32(5094)
	listener, err := ccvsock.ListenAt(ParentCID, proxyPort, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		require.NoError(t, json.NewEncoder(w).Encode(ErrorResponse{Code: CodeDNSNotFound}))
	})}
	go server.Serve(listener) //nolint:errcheck
	t.Cleanup(func() { _ = server.Close() })

	dialer := NewWorkflowDialer(ParentCID, proxyPort)
	_, err = dialer.DialContext(context.Background(), "tcp", "missing.test:443")
	var dnsErr *net.DNSError
	require.ErrorAs(t, err, &dnsErr)
	require.True(t, dnsErr.IsNotFound)
}

// The plan requires candidates be tried "in resolver order within one caller
// deadline". net.Dialer.dialSerial does that by dividing the deadline among the
// remaining addresses (partialDeadline, net/dial.go:270), so a blackholed first
// address still leaves time for the second. Handing every candidate the whole
// remaining deadline instead lets the first one consume it, and the fallback
// never runs: a caller that the WireGuard path served turns into a timeout.
func TestDialerDividesCallerDeadlineAcrossCandidates(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)

	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		conn, acceptErr := upstream.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		_, _ = io.Copy(conn, conn)
	}()
	port := portOf(t, upstream.Addr().String())

	const proxyPort = uint32(5096)
	listener, err := ccvsock.ListenAt(ParentCID, proxyPort, nil)
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// 127.0.0.2 first, so the healthy address is only reached by fallback.
			require.NoError(t, json.NewEncoder(w).Encode(ResolveResponse{
				Addresses: []string{"127.0.0.2", "127.0.0.1"},
			}))
			return
		}
		if strings.HasPrefix(r.RequestURI, "127.0.0.2:") {
			<-r.Context().Done() // a blackholed address: no response, ever.
			return
		}
		upstreamConn, dialErr := net.Dial("tcp4", r.RequestURI)
		require.NoError(t, dialErr)
		client, rw, hijackErr := http.NewResponseController(w).Hijack()
		require.NoError(t, hijackErr)
		_, _ = fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		require.NoError(t, rw.Flush())
		go func() {
			defer client.Close()             //nolint:errcheck
			defer upstreamConn.Close()       //nolint:errcheck
			go io.Copy(upstreamConn, client) //nolint:errcheck
			_, _ = io.Copy(client, upstreamConn)
		}()
	})}
	go server.Serve(listener) //nolint:errcheck
	t.Cleanup(func() { _ = server.Close() })

	dialer, err := NewOperatorDialer(ParentCID, proxyPort, "service.test:"+port)
	require.NoError(t, err)

	// Shorter than handshakeTimeout, so the caller deadline is what bounds each
	// attempt. Two candidates must both get a share of it.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", "service.test:"+port)
	require.NoError(t, err, "the blackholed first address must not consume the whole deadline")
	defer conn.Close() //nolint:errcheck

	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	got := make([]byte, 5)
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))
}

// The gateway authority pin is a deliberate narrowing away from origin/main,
// which cloned the default transport and followed redirects anywhere. The
// narrowing is documented at environments/nitro/main.go, where the comment
// claims "a gateway redirect to a host outside that set fails at dial".
// TestOperatorPolicyRestrictsAuthority proves validateAuthority rejects the
// authority, which is not the same claim: it does not show the redirect reaches
// the dialer at all. Both halves are pinned here, because the narrowing is only
// acceptable if a redirect to a *configured* authority still works.
func TestOperatorDialerAdmitsRedirectOnlyToConfiguredAuthority(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)

	serve := func(handler http.HandlerFunc) string {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		server := &http.Server{Handler: handler}
		go server.Serve(listener) //nolint:errcheck
		t.Cleanup(func() { _ = server.Close() })
		return portOf(t, listener.Addr().String())
	}

	redirectTarget := serve(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "arrived")
	})
	// The broker resolves every name to 127.0.0.1, so the two endpoints are
	// distinguished by port, and the redirect authority is a name the operator
	// policy compares literally.
	entry := serve(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://redirect-target.test:"+redirectTarget+"/", http.StatusFound)
	})

	proxyPort := uint32(5095)
	startTestBroker(t, proxyPort, []string{"127.0.0.1"})

	get := func(t *testing.T, endpoints ...string) (*http.Response, error) {
		t.Helper()
		dialer, err := NewOperatorDialer(ParentCID, proxyPort, endpoints...)
		require.NoError(t, err)
		client := &http.Client{
			Timeout:   5 * time.Second,
			Transport: &http.Transport{Proxy: nil, DialContext: dialer.DialContext},
		}
		t.Cleanup(client.CloseIdleConnections)
		return client.Get("http://entry.test:" + entry + "/")
	}

	t.Run("configured redirect target is followed", func(t *testing.T) {
		response, err := get(t, "entry.test:"+entry, "redirect-target.test:"+redirectTarget)
		require.NoError(t, err)
		defer response.Body.Close() //nolint:errcheck
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, response.StatusCode)
		require.Equal(t, "arrived", string(body),
			"a redirect within the configured authorities must still be followed")
	})

	t.Run("unconfigured redirect target fails at dial", func(t *testing.T) {
		_, err := get(t, "entry.test:"+entry)
		require.Error(t, err)
		require.True(t, IsPolicyError(err),
			"the redirect must be refused by policy at dial, not by a transport or timeout: %v", err)
	})
}

// startRefusingBroker answers resolve with addresses and refuses every CONNECT,
// counting the attempts. Nothing leaves the machine, so blocked and allowed
// public addresses can both appear in one answer.
func startRefusingBroker(t *testing.T, port uint32, addresses []string) *testBroker {
	t.Helper()
	listener, err := ccvsock.ListenAt(ParentCID, port, nil)
	require.NoError(t, err)
	b := &testBroker{}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			b.mu.Lock()
			b.connectCount++
			b.mu.Unlock()
			w.WriteHeader(http.StatusBadGateway)
			require.NoError(t, json.NewEncoder(w).Encode(ErrorResponse{Code: CodeConnectRefused}))
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(ResolveResponse{Addresses: addresses}))
	})}
	go server.Serve(listener) //nolint:errcheck
	t.Cleanup(func() { _ = server.Close() })
	return b
}

// safeurl rejected a blocked address inside the dial, so it became the first
// error net.Dialer reported and the call site mapped it to 400. Skipping the
// blocked address silently surfaces the next address's refusal instead, which
// maps to 502: the same DNS answer changes the caller-visible status.
func TestDialerReportsBlockedAddressAheadOfLaterFailure(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	proxyPort := uint32(5097)
	broker := startRefusingBroker(t, proxyPort, []string{"10.0.0.1", "8.8.8.8"})

	_, err := NewWorkflowDialer(ParentCID, proxyPort).
		DialContext(context.Background(), "tcp", "service.test:443")
	require.Error(t, err)
	require.True(t, IsPolicyError(err),
		"the blocked first address must outrank the later refusal, got %v", err)
	require.Equal(t, 1, broker.connects(), "the allowed address must still be attempted")
}

// The broker caps its answer, but the parent is untrusted: an oversized answer
// would otherwise cost one VSOCK handshake per address inside the deadline.
func TestDialerRejectsOversizedResolveResponse(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	addresses := make([]string, 0, MaxResolvedAddresses+1)
	for i := range MaxResolvedAddresses + 1 {
		addresses = append(addresses, netip.AddrFrom4([4]byte{8, 8, 8, byte(i)}).String())
	}
	proxyPort := uint32(5098)
	broker := startRefusingBroker(t, proxyPort, addresses)

	_, err := NewWorkflowDialer(ParentCID, proxyPort).
		DialContext(context.Background(), "tcp", "service.test:443")
	var proxyErr *ProxyError
	require.ErrorAs(t, err, &proxyErr)
	require.Equal(t, CodeProtocol, proxyErr.Code)
	require.Equal(t, 0, broker.connects(), "an over-long answer must be refused before any CONNECT")
}

// Duplicates are the cheaper form of the same amplification: sixteen entries
// that are one address repeated must cost one attempt, not sixteen.
func TestDialerDeduplicatesResolveResponse(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	addresses := make([]string, MaxResolvedAddresses)
	for i := range addresses {
		addresses[i] = "8.8.8.8"
	}
	proxyPort := uint32(5099)
	broker := startRefusingBroker(t, proxyPort, addresses)

	_, err := NewWorkflowDialer(ParentCID, proxyPort).
		DialContext(context.Background(), "tcp", "service.test:443")
	require.Error(t, err)
	require.Equal(t, 1, broker.connects(), "a repeated address must be attempted once")
}

type testBroker struct {
	mu           sync.Mutex
	connectCount int
}

func (b *testBroker) connects() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.connectCount
}

func startTestBroker(t *testing.T, port uint32, addresses []string) *testBroker {
	t.Helper()
	listener, err := ccvsock.ListenAt(ParentCID, port, nil)
	require.NoError(t, err)
	b := &testBroker{}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			require.NoError(t, json.NewEncoder(w).Encode(ResolveResponse{Addresses: addresses}))
		case http.MethodConnect:
			b.mu.Lock()
			b.connectCount++
			b.mu.Unlock()
			upstream, dialErr := net.Dial("tcp4", r.RequestURI)
			if dialErr != nil {
				w.WriteHeader(http.StatusBadGateway)
				require.NoError(t, json.NewEncoder(w).Encode(ErrorResponse{Code: CodeConnectRefused}))
				return
			}
			client, rw, hijackErr := http.NewResponseController(w).Hijack()
			require.NoError(t, hijackErr)
			_, writeErr := fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
			require.NoError(t, writeErr)
			require.NoError(t, rw.Flush())
			go func() {
				defer client.Close()   //nolint:errcheck
				defer upstream.Close() //nolint:errcheck
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
				go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
				<-done
			}()
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})}
	go server.Serve(listener) //nolint:errcheck
	t.Cleanup(func() { _ = server.Close() })
	return b
}

func portOf(t *testing.T, address string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	return port
}

// The parent is untrusted. http.ReadResponse parses the status line and header
// block with unlimited textproto reads, so without a bound a parent could make
// the enclave allocate without limit inside the handshake deadline -- before any
// tunnel exists and with no body involved.
func TestDialerBoundsResponseHeaderFromParent(t *testing.T) {
	t.Setenv(types.EnvVSOCKBackend, types.VSOCKBackendTCP)
	const port = 5313
	listener, err := ccvsock.ListenAt(ParentCID, port, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close() //nolint:errcheck
		if _, readErr := http.ReadRequest(bufio.NewReader(conn)); readErr != nil {
			return
		}
		// A status line followed by header lines that never end.
		if _, writeErr := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n"); writeErr != nil {
			return
		}
		filler := "X-Filler: " + strings.Repeat("a", 4096) + "\r\n"
		for {
			if _, writeErr := io.WriteString(conn, filler); writeErr != nil {
				return
			}
		}
	}()

	// An IP literal, so this is the CONNECT path with no resolve round trip.
	_, err = NewWorkflowDialer(ParentCID, port).
		DialContext(context.Background(), "tcp", "8.8.8.8:443")
	require.Error(t, err)
	require.Contains(t, err.Error(), "too large",
		"the header block must be refused on size, not left to the handshake deadline")
}
