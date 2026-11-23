package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const kmsgKeepLines = 6000

// lineRing keeps the most recent lines.
type lineRing struct {
	mu    sync.Mutex
	lines []string
	next  int
	full  bool
}

func newLineRing(size int) *lineRing {
	return &lineRing{lines: make([]string, size)}
}

func (r *lineRing) add(line string) {
	r.mu.Lock()
	r.lines[r.next] = line
	r.next++
	if r.next == len(r.lines) {
		r.next, r.full = 0, true
	}
	r.mu.Unlock()
}

// snapshot returns the kept lines, oldest first.
func (r *lineRing) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]string(nil), r.lines[:r.next]...)
	}
	out := make([]string, 0, len(r.lines))
	out = append(out, r.lines[r.next:]...)
	return append(out, r.lines[:r.next]...)
}

// kmsgReader follows the kernel log from its oldest retained record. An OOM
// kill, a fatal signal's register dump or an oops is only ever reported there.
type kmsgReader struct {
	live  *liveStream
	notes *notes
	ring  *lineRing

	mu      sync.Mutex
	pending []string
}

func newKmsgReader(live *liveStream, n *notes) *kmsgReader {
	return &kmsgReader{live: live, notes: n, ring: newLineRing(kmsgKeepLines)}
}

// flush forwards the lines read since the last flush as one batch.
func (k *kmsgReader) flush() {
	k.mu.Lock()
	lines := k.pending
	k.pending = nil
	k.mu.Unlock()
	k.live.send("kmsg", lines...)
}

func (k *kmsgReader) run() {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		k.notes.addf("kernel log unavailable: %v", err)
		return
	}
	defer f.Close() //nolint:errcheck // read-only
	k.notes.addf("following /dev/kmsg")

	go func() {
		for range time.Tick(250 * time.Millisecond) {
			k.flush()
		}
	}()

	// Each read returns exactly one record.
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if err != nil {
			// EPIPE: records were overwritten before we read them; the next
			// read resumes at the oldest one still held.
			if errors.Is(err, syscall.EPIPE) {
				k.emit("[kmsg] records lost to ring overrun")
				continue
			}
			k.notes.addf("kernel log reader stopped: %v", err)
			return
		}
		if line, ok := formatKmsg(string(buf[:n])); ok {
			k.emit(line)
		}
	}
}

func (k *kmsgReader) emit(line string) {
	k.ring.add(line)
	k.mu.Lock()
	k.pending = append(k.pending, line)
	k.mu.Unlock()
}

// formatKmsg turns one /dev/kmsg record ("prio,seq,usec,flags;text" plus
// optional " KEY=value" lines) into "[seconds] <level> text".
func formatKmsg(record string) (string, bool) {
	head, rest, ok := strings.Cut(record, ";")
	if !ok {
		return "", false
	}
	fields := strings.Split(head, ",")
	if len(fields) < 3 {
		return "", false
	}
	prio, _ := strconv.Atoi(fields[0])
	usec, _ := strconv.ParseInt(fields[2], 10, 64)
	text, _, _ := strings.Cut(rest, "\n")
	return fmt.Sprintf("[%5d.%06d] <%d> %s", usec/1e6, usec%1e6, prio&7, text), true
}
