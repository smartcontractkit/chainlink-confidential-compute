// Package wasmlimits carries resolved per-execution limits without linking Wasmtime.
package wasmlimits

import "github.com/smartcontractkit/chainlink-common/pkg/config"

type Config struct {
	Memory                     config.Size
	MaxCompressedBinary        config.Size
	MaxDecompressedBinary      config.Size
	MaxResponseSize            config.Size
	PendingCalls               int
	EnableUserMetrics          bool
	MaxUserMetricPayload       config.Size
	MaxUserMetricNameLength    int
	MaxUserMetricLabels        int
	MaxUserMetricLabelValueLen int
	MaxSubscriptions           int
	MaxLogLenBytes             uint32
}
