package main

import (
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/smartcontractkit/chainlink-confidential-compute/types"
)

const (
	liveQueueSize = 8192
	// liveMaxLines and liveMaxBytes bound one message so the host can log it
	// as a single line.
	liveMaxLines     = 60
	liveMaxBytes     = 6000
	liveWriteTimeout = 5 * time.Second
	liveRedialEvery  = time.Second
	// liveGiveUpAfter is how long one message waits for the host to appear.
	liveGiveUpAfter = 30 * time.Second
)

// liveStream sends observations to the host as they happen, so the host holds
// everything up to the last second even if the VM vanishes without a
// post-mortem. Sending never blocks the caller: a full queue drops and counts.
type liveStream struct {
	cfg     config
	header  types.CrashStreamHeader
	queue   chan types.CrashLiveMessage
	dropped atomic.Uint64
	done    chan struct{}
	closed  chan struct{}
	once    sync.Once
}

func newLiveStream(cfg config, header types.CrashStreamHeader) *liveStream {
	return &liveStream{
		cfg:    cfg,
		header: header,
		queue:  make(chan types.CrashLiveMessage, liveQueueSize),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
}

// send queues lines on the named stream, split into host-loggable messages.
func (l *liveStream) send(stream string, lines ...string) {
	now := time.Now().UnixNano()
	for len(lines) > 0 {
		n, size := 0, 0
		for n < len(lines) && n < liveMaxLines && (n == 0 || size+len(lines[n]) <= liveMaxBytes) {
			size += len(lines[n])
			n++
		}
		msg := types.CrashLiveMessage{Stream: stream, UnixNano: now, Lines: lines[:n]}
		select {
		case l.queue <- msg:
		default:
			l.dropped.Add(1)
		}
		lines = lines[n:]
	}
}

// close flushes what is queued, within timeout, and ends the stream.
func (l *liveStream) close(timeout time.Duration) {
	l.once.Do(func() { close(l.done) })
	select {
	case <-l.closed:
	case <-time.After(timeout):
	}
}

func (l *liveStream) run() {
	defer close(l.closed)
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	write := func(msg types.CrashLiveMessage, patient bool) {
		deadline := time.Now().Add(liveGiveUpAfter)
		for {
			if conn == nil {
				c, err := dialHostTimeout(l.cfg.dialTimeout)
				if err == nil {
					header := l.header
					header.UnixNano = time.Now().UnixNano()
					_ = c.SetWriteDeadline(time.Now().Add(liveWriteTimeout))
					if err = json.NewEncoder(c).Encode(header); err != nil {
						_ = c.Close()
					} else {
						conn = c
					}
				}
				if conn == nil {
					if !patient || time.Now().After(deadline) {
						l.dropped.Add(1)
						return
					}
					select {
					case <-time.After(liveRedialEvery):
					case <-l.done:
						patient = false
					}
					continue
				}
			}
			_ = conn.SetWriteDeadline(time.Now().Add(liveWriteTimeout))
			if err := json.NewEncoder(conn).Encode(msg); err != nil {
				_ = conn.Close()
				conn = nil
				if !patient || time.Now().After(deadline) {
					l.dropped.Add(1)
					return
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return
		}
	}

	for {
		select {
		case msg := <-l.queue:
			write(msg, true)
		case <-l.done:
			for {
				select {
				case msg := <-l.queue:
					write(msg, false)
				default:
					return
				}
			}
		}
	}
}
