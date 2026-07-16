package emitter

import "github.com/smartcontractkit/confidential-compute/types"

type noOpEmitter struct{}

var _ types.Emitter = &noOpEmitter{}

func NewNoOpEmitter() types.Emitter {
	return &noOpEmitter{}
}

func (e *noOpEmitter) Emit(event string, details map[string]any) {
	// no-op
}
