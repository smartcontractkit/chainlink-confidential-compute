// Package proxyserver relays enclave TCP connections over SOCKS5 on
// AF_VSOCK.
package proxyserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

const outboundDialTimeout = 10 * time.Second

type warningLogger interface {
	Warnw(msg string, keysAndValues ...any)
}

type socksLogger struct {
	logger warningLogger
}

func (l socksLogger) Errorf(format string, args ...interface{}) {
	l.logger.Warnw(
		"outbound proxy request failed",
		"event", "OUTBOUND_PROXY_REQUEST_ERR",
		"error", fmt.Errorf(format, args...),
	)
}

type ruleSet struct {
	localAddresses                 map[netip.Addr]struct{}
	allowLocalDestinationsForTests bool
}

func New(allowLocalDestinationsForTests bool, logger warningLogger) (*socks5.Server, error) {
	localAddresses, err := localInterfaceAddresses()
	if err != nil {
		return nil, err
	}
	rules := ruleSet{
		localAddresses:                 localAddresses,
		allowLocalDestinationsForTests: allowLocalDestinationsForTests,
	}
	dialer := &net.Dialer{Timeout: outboundDialTimeout}
	return socks5.NewServer(
		socks5.WithCredential(socks5.StaticCredentials{
			string(types.ProxyProfilePublic):     string(types.ProxyProfilePublic),
			string(types.ProxyProfileConfigured): string(types.ProxyProfileConfigured),
			string(types.ProxyProfileTest):       string(types.ProxyProfileTest),
		}),
		socks5.WithRule(rules),
		socks5.WithDial(dialer.DialContext),
		socks5.WithLogger(socksLogger{logger: logger}),
	), nil
}

func (r ruleSet) Allow(ctx context.Context, request *socks5.Request) (context.Context, bool) {
	if request.Command != statute.CommandConnect || request.AuthContext == nil || request.DestAddr == nil {
		return ctx, false
	}
	address, ok := netip.AddrFromSlice(request.DestAddr.IP)
	if !ok {
		return ctx, false
	}
	address = address.Unmap()
	if r.destinationDenied(address) {
		return ctx, false
	}

	switch types.ProxyProfile(request.AuthContext.Payload["username"]) {
	case types.ProxyProfilePublic:
		return ctx, publicProfileAllowsAddress(address)
	case types.ProxyProfileConfigured, types.ProxyProfileTest:
		return ctx, true
	default:
		return ctx, false
	}
}

func (r ruleSet) destinationDenied(address netip.Addr) bool {
	if !address.Is4() || address.IsUnspecified() || address.IsLinkLocalUnicast() || address.IsMulticast() {
		return true
	}
	if !r.allowLocalDestinationsForTests {
		if address.IsLoopback() {
			return true
		}
		if _, local := r.localAddresses[address]; local {
			return true
		}
	}
	return netip.MustParsePrefix("0.0.0.0/8").Contains(address) || netip.MustParsePrefix("240.0.0.0/4").Contains(address)
}

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
