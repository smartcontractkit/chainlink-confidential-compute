package wasmruntime

import "context"

// Queue permits one compilation at a time, without serializing guest execution.
type Queue struct {
	slot chan struct{}
}

func NewQueue() *Queue {
	return &Queue{slot: make(chan struct{}, 1)}
}

func (q *Queue) Run(ctx context.Context, compile func() error) error {
	select {
	case q.slot <- struct{}{}:
		defer func() { <-q.slot }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return compile()
}
