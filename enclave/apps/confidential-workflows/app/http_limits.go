package app

import (
	"math"
	"sync"

	confworkflowtypes "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/actions/confidentialworkflow"
	"github.com/smartcontractkit/chainlink-common/pkg/settings/cresettings"

	"github.com/smartcontractkit/chainlink-confidential-compute/enclave/apps/confidential-workflows/httpfetch"
)

// httpActionLimits holds the PerWorkflow.HTTPAction limits the workflow DON
// signed into one execution's request, plus that execution's call count. The
// enclave never resolves CRE settings itself: limits it was not sent are not
// applied (INCIDENT-2784).
type httpActionLimits struct {
	callLimit *uint32
	fetch     httpfetch.Limits

	mu    sync.Mutex
	calls uint64
}

// newHTTPActionLimits returns nil when the DON sent no HTTP action limits,
// which leaves http-actions on the fixed policy alone. Sent limits are applied
// as they are, matching CRE for regular workflows.
func newHTTPActionLimits(l *confworkflowtypes.ExecutionLimits) *httpActionLimits {
	h := l.GetHttpAction()
	if h == nil {
		return nil
	}
	out := &httpActionLimits{}
	if h.CallLimit != nil {
		v := h.GetCallLimit()
		out.callLimit = &v
	}
	if h.RequestSizeLimitBytes != nil {
		v := clampToInt64(h.GetRequestSizeLimitBytes())
		out.fetch.RequestSizeLimit = &v
	}
	if h.ResponseSizeLimitBytes != nil {
		v := clampToInt64(h.GetResponseSizeLimitBytes())
		out.fetch.ResponseSizeLimit = &v
	}
	// A negative timeout is never sent by the DON; treating it as unset keeps a
	// malformed request from failing every call.
	if d := h.GetConnectionTimeout(); d != nil && d.CheckValid() == nil && d.AsDuration() >= 0 {
		v := d.AsDuration()
		out.fetch.ConnectionTimeout = &v
	}
	return out
}

func clampToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// countCall records one http-actions call and reports whether it exceeds
// CallLimit. The WASM host may issue calls concurrently.
func (l *httpActionLimits) countCall() bool {
	if l.callLimit == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	return l.calls > uint64(*l.callLimit)
}

var httpCallLimitKey = cresettings.Default.PerWorkflow.HTTPAction.CallLimit.Key
