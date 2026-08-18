package proxyclient

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

type policyKind uint8

const (
	policyWorkflowControlled policyKind = iota
	policyConfiguredEndpoint
	policyPreSignedURL
	policyInsecureFixture
)

type policy struct {
	kind        policyKind
	profile     types.ProxyProfile
	authorities map[string]struct{}
}

type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string {
	return "outbound request blocked by enclave network policy: " + e.Reason
}

// NetworkPolicyBlocked avoids coupling util to this package.
func (e *PolicyError) NetworkPolicyBlocked() bool { return true }

func IsPolicyError(err error) bool {
	var target *PolicyError
	return errors.As(err, &target)
}

func workflowControlledPolicy() policy {
	return policy{kind: policyWorkflowControlled, profile: types.ProxyProfilePublic}
}

func preSignedURLPolicy() policy {
	return policy{kind: policyPreSignedURL, profile: types.ProxyProfilePublic}
}

func configuredEndpointPolicy(endpoints ...string) (policy, error) {
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
	return policy{kind: policyConfiguredEndpoint, profile: types.ProxyProfileConfigured, authorities: authorities}, nil
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
	// http.Transport converts Unicode hostnames to IDNA before DialContext, so
	// configured endpoints must use ASCII or punycode.
	return net.JoinHostPort(host, strconv.FormatUint(portNumber, 10)), portNumber, nil
}

func (p policy) validateAuthority(host, port string) error {
	authority, portNumber, err := canonicalAuthority(host, port)
	if err != nil {
		return &PolicyError{Reason: err.Error()}
	}
	switch p.kind {
	case policyWorkflowControlled:
		// Match safeurl's parsed-port behavior for zero-padded ports.
		if portNumber != 80 && portNumber != 443 {
			return &PolicyError{Reason: "port is not 80 or 443"}
		}
	case policyPreSignedURL:
		// Match the gateway's safeurl policy; custom dialing bypasses its port check:
		// https://github.com/smartcontractkit/chainlink/blob/25990b2724f8b8398f846adeb77f615112330a16/core/services/gateway/network/httpclient.go#L284-L293
		if portNumber != 443 {
			return &PolicyError{Reason: "artifact port is not 443"}
		}
	case policyInsecureFixture:
		return nil
	case policyConfiguredEndpoint:
		if _, ok := p.authorities[authority]; !ok {
			return &PolicyError{Reason: "destination is not the configured operator endpoint"}
		}
	default:
		return &PolicyError{Reason: "unknown network policy"}
	}
	return nil
}
