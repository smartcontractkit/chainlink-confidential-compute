package framework

import (
	"github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/confidential-compute/types"
)

func MapEnclaveType(et types.EnclaveType) sdk.TeeType {
	switch et {
	case types.EnclaveTypeNitro:
		return sdk.TeeType_TEE_TYPE_AWS_NITRO
	default:
		return sdk.TeeType_TEE_TYPE_UNSPECIFIED
	}
}
