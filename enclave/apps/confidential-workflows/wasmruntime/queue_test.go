package wasmruntime

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueueSerializesCompilation(t *testing.T) {
	q := NewQueue()
	var active atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			err := q.Run(t.Context(), func() error {
				assert.Equal(t, int32(1), active.Add(1))
				runtime.Gosched()
				assert.Zero(t, active.Add(-1))
				return nil
			})
			assert.NoError(t, err)
		})
	}
	wg.Wait()
}

func TestQueueCancellationAndFailure(t *testing.T) {
	q := NewQueue()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- q.Run(t.Context(), func() error {
			close(entered)
			<-ctx.Done()
			return nil
		})
	}()
	<-entered
	waiter, cancelWaiter := context.WithCancel(t.Context())
	cancelWaiter()
	require.ErrorIs(t, q.Run(waiter, func() error {
		t.Fatal("canceled waiter must not compile")
		return nil
	}), context.Canceled)
	require.Len(t, q.slot, 1)
	cancel()
	require.NoError(t, <-done)
	want := errors.New("compile failed")
	require.ErrorIs(t, q.Run(t.Context(), func() error { return want }), want)
	require.NoError(t, q.Run(t.Context(), func() error { return nil }))
	require.ErrorIs(t, q.Run(waiter, func() error {
		t.Fatal("an idle queue must also reject canceled work")
		return nil
	}), context.Canceled)
	require.Empty(t, q.slot)
}
