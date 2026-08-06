package outboundproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var safeURLBlockedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

type policyKind uint8

const (
	policyWorkflow policyKind = iota
	policyOperator
	policyArtifact
	policyInsecureArtifactTest
)

type policy struct {
	kind        policyKind
	authorities map[string]struct{}
}

// PolicyError reports a destination rejected by enclave network policy.
type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string {
	return "outbound request blocked by enclave network policy: " + e.Reason
}

// NetworkPolicyBlocked lets util.IsRequestBlockedError classify this error
// without util importing this package.
func (e *PolicyError) NetworkPolicyBlocked() bool { return true }

func IsPolicyError(err error) bool {
	var target *PolicyError
	return errors.As(err, &target)
}

func workflowPolicy() policy { return policy{kind: policyWorkflow} }
func artifactPolicy() policy { return policy{kind: policyArtifact} }

func operatorPolicy(endpoints ...string) (policy, error) {
	authorities := make(map[string]struct{})
	for _, raw := range endpoints {
		for _, endpoint := range strings.Split(raw, ",") {
			authority, err := endpointAuthority(strings.TrimSpace(endpoint))
			if err != nil {
				return policy{}, err
			}
			authorities[authority] = struct{}{}
		}
	}
	if len(authorities) == 0 {
		return policy{}, fmt.Errorf("at least one operator endpoint is required")
	}
	return policy{kind: policyOperator, authorities: authorities}, nil
}

func endpointAuthority(endpoint string) (string, error) {
	if endpoint == "" {
		return "", fmt.Errorf("operator endpoint is empty")
	}
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil || u.Hostname() == "" {
			return "", fmt.Errorf("invalid operator endpoint %q", endpoint)
		}
		port := u.Port()
		if port == "" {
			switch strings.ToLower(u.Scheme) {
			case "https":
				port = "443"
			case "http":
				port = "80"
			default:
				return "", fmt.Errorf("operator endpoint %q has unsupported scheme", endpoint)
			}
		}
		authority, _, err := canonicalAuthority(u.Hostname(), port)
		return authority, err
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("operator endpoint %q must include a port: %w", endpoint, err)
	}
	authority, _, err := canonicalAuthority(host, port)
	return authority, err
}

func canonicalAuthority(host, port string) (string, uint64, error) {
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", 0, fmt.Errorf("invalid destination port %q", port)
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", 0, fmt.Errorf("destination host is empty")
	}
	// Configure operator endpoints in ASCII. http.Transport converts a Unicode
	// hostname to IDNA ASCII before it reaches DialContext, so an endpoint
	// configured in Unicode would not match the authority actually dialled and
	// every request to it would be refused by its own allowlist. Normalising
	// here would mean taking golang.org/x/text as a new dependency of this
	// module, which is not worth it for an operator-configured hostname that can
	// simply be written in punycode.
	return net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), portNumber, nil
}

func (p policy) validateAuthority(host, port string) error {
	authority, portNumber, err := canonicalAuthority(host, port)
	if err != nil {
		return &PolicyError{Reason: err.Error()}
	}
	switch p.kind {
	case policyWorkflow:
		// Compare the parsed port, not the raw string: safeurl checks a port
		// already normalised by TCPAddr.String(), so it accepts "080" and so
		// must this.
		if portNumber != 80 && portNumber != 443 {
			return &PolicyError{Reason: "port is not 80 or 443"}
		}
	case policyArtifact:
		// Deliberate deviation from the plan's artifact profile: HTTPS,
		// credentials and the public-IPv4 blocklist are enforced, but the port
		// set is not narrowed to {80,443} and there is no operator allowlist.
		// Narrowing either without the other would break pre-signed URLs on
		// private or non-standard endpoints, which the baseline allowed. Settle
		// this with the real-Nitro preflight.
		//
		// For that preflight: a deployed CRE gateway is configured https-only on
		// port 443 (chainlink deployment/cre/jobs/pkg/gateway_job.go), so
		// requiring HTTPS here matches the platform's own posture. That is not
		// evidence for the port set, though -- the enclave fetches artifacts on
		// its own path rather than through that gateway, so what decides it is
		// which ports the storage service's pre-signed URLs actually use.
	case policyInsecureArtifactTest:
		// Test-only HTTP fixtures may use an explicitly selected port.
	case policyOperator:
		if _, ok := p.authorities[authority]; !ok {
			return &PolicyError{Reason: "destination is not the configured operator endpoint"}
		}
	default:
		return &PolicyError{Reason: "unknown network policy"}
	}
	return nil
}

func (p policy) allowAddress(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if p.kind == policyOperator || p.kind == policyInsecureArtifactTest {
		return true
	}
	for _, blocked := range safeURLBlockedIPv4 {
		if blocked.Contains(addr) {
			return false
		}
	}
	return true
}
