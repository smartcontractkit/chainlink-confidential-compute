// Package nitrotransport constructs the same restricted clients in coordinators
// and execution workers. Workflow-controlled traffic never uses the operator dialer.
package nitrotransport

import (
	"net/http"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/app"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/gateway"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
	proxyclient "github.com/smartcontractkit/chainlink-confidential-compute/enclave/nitro/proxy-client"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/attestor"
	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/combiner"
	signatureverifier "github.com/smartcontractkit/chainlink-confidential-compute/enclave/services/signature-verifier"
	"github.com/smartcontractkit/chainlink-confidential-compute/types"
	"github.com/smartcontractkit/chainlink-confidential-compute/util"
)

func HTTPFetcher(timeout time.Duration) *httpfetch.Fetcher {
	f := httpfetch.NewFetcherWithClient(httpfetch.DefaultPolicy(), util.NewRestrictedHTTPClientWithDialer(
		proxyclient.NewWorkflowControlledDialer(types.ProxyParentCID, types.ProxyPort).DialContext))
	f.SetDefaultTimeout(timeout)
	return f
}

func Dispatcher(gw app.GatewayConfig, config types.EnclaveConfig, att attestor.Attestor, keys app.RequestKeyProvider, lggr logger.Logger, startOffset uint64) (app.RemoteDispatcher, error) {
	dialer, err := proxyclient.NewConfiguredEndpointDialer(types.ProxyParentCID, types.ProxyPort, gw.URL)
	if err != nil {
		return nil, err
	}
	// The coordinator already resolved the timeout, including a disabled deadline.
	client := gateway.NewGatewayClient(gw.URL, att, gateway.WithStartOffset(startOffset), gateway.WithHTTPClient(&http.Client{
		Timeout:   gw.RequestTimeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true, ForceAttemptHTTP2: true},
	}))
	return app.NewRemoteDispatcher(client, att, config, lggr, keys, combiner.NewTDH2EasyCombiner(),
		signatureverifier.NewEd25519SignatureVerifier(), gw.RetryBackoff, gw.RetryTimeout), nil
}
