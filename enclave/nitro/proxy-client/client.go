// Package proxyclient implements enclave egress through SOCKS5 over AF_VSOCK.
package proxyclient

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	ccvsock "github.com/smartcontractkit/chainlink-confidential-compute/enclave/vsock"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"golang.org/x/net/proxy"
)

// handshakeTimeout does not apply after SOCKS negotiation completes.
const handshakeTimeout = 10 * time.Second

// Dialer tunnels TCP destinations through the parent SOCKS5 server under one
// fixed policy selected at construction time.
type Dialer struct {
	policy policy
	socks  proxy.ContextDialer
}

// NewWorkflowControlledDialer allows public destinations on ports 80 and 443.
func NewWorkflowControlledDialer(parentCID, port uint32) *Dialer {
	return newDialer(parentCID, port, workflowControlledPolicy())
}

// NewPreSignedURLDialer allows public artifact destinations on port 443.
func NewPreSignedURLDialer(parentCID, port uint32) *Dialer {
	return newDialer(parentCID, port, preSignedURLPolicy())
}

// NewInsecureFixtureDialerForTests still requires the host's local-address opt-in.
func NewInsecureFixtureDialerForTests(parentCID, port uint32) *Dialer {
	return newDialer(parentCID, port, policy{kind: policyInsecureFixture, profile: types.ProxyProfileTest})
}

// NewConfiguredEndpointDialer allows only the configured endpoint authorities.
func NewConfiguredEndpointDialer(parentCID, port uint32, endpoints ...string) (*Dialer, error) {
	p, err := configuredEndpointPolicy(endpoints...)
	if err != nil {
		return nil, err
	}
	return newDialer(parentCID, port, p), nil
}

func newDialer(parentCID, port uint32, destinationPolicy policy) *Dialer {
	profile := string(destinationPolicy.profile)
	dialer, err := proxy.SOCKS5(
		"tcp",
		net.JoinHostPort("vsock", strconv.FormatUint(uint64(port), 10)),
		&proxy.Auth{User: profile, Password: profile},
		vsockDialer{parentCID: parentCID, port: port},
	)
	if err != nil {
		panic(fmt.Sprintf("construct SOCKS5 dialer: %v", err))
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		panic("SOCKS5 dialer does not support contexts")
	}
	return &Dialer{policy: destinationPolicy, socks: contextDialer}
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

	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	conn, err := d.socks.DialContext(handshakeCtx, network, address)
	if err != nil {
		return nil, mapSOCKSError(err)
	}
	return conn, nil
}

// x/net/proxy exposes SOCKS reply codes only in error strings.
func mapSOCKSError(err error) error {
	switch {
	case strings.HasSuffix(err.Error(), "unknown error host unreachable"):
		// SOCKS5 uses the same reply for NXDOMAIN and an unreachable resolved host.
		return syscall.EHOSTUNREACH
	case strings.HasSuffix(err.Error(), "unknown error connection refused"):
		return syscall.ECONNREFUSED
	case strings.HasSuffix(err.Error(), "unknown error connection not allowed by ruleset"):
		return &PolicyError{Reason: "destination address is not allowed"}
	default:
		return err
	}
}

type vsockDialer struct {
	parentCID uint32
	port      uint32
}

func (d vsockDialer) Dial(_, _ string) (net.Conn, error) {
	return ccvsock.Dial(d.parentCID, d.port, nil)
}

func (d vsockDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, err := d.Dial("", "")
		resultCh <- dialResult{conn: conn, err: err}
	}()

	select {
	case result := <-resultCh:
		return result.conn, result.err
	case <-ctx.Done():
		go func() {
			result := <-resultCh
			if result.conn != nil {
				_ = result.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}
