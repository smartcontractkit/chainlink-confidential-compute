// Package crashdebug is the debug-build flight recorder for enclave apps.
//
// The app writes short trace records into a file-backed shared mapping. The
// records live in the page cache, so they outlive the process however it dies,
// and the enclave supervisor reads them back for the crash report. Nothing here
// performs I/O on the hot path.
//
// DEBUG BUILDS ONLY: records carry request, workflow and payload details in the
// clear and are shipped to the untrusted host.
package crashdebug

import (
	"encoding/binary"
	"errors"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
)

const (
	ringMagic      = "CCTRACE1"
	ringHeaderSize = 64
	slotHeaderSize = 18

	// DefaultSlotSize and DefaultSlots size the trace ring at 8 MiB.
	DefaultSlotSize = 512
	DefaultSlots    = 16384

	offSlotSize  = 8
	offSlots     = 12
	offBeatNanos = 16
	offBeatCount = 24
)

// RingSize is the byte length of a ring with the given geometry.
func RingSize(slotSize, slots int) int {
	return ringHeaderSize + slotSize*slots
}

// Ring is a fixed-size overwrite-oldest record buffer laid out in buf.
type Ring struct {
	buf      []byte
	slotSize int
	slots    uint64
	seq      atomic.Uint64
}

// NewRing formats buf as an empty ring.
func NewRing(buf []byte, slotSize, slots int) (*Ring, error) {
	if slotSize <= slotHeaderSize || slots <= 0 || len(buf) < RingSize(slotSize, slots) {
		return nil, errors.New("crashdebug: ring buffer too small")
	}
	copy(buf[:8], ringMagic)
	binary.LittleEndian.PutUint32(buf[offSlotSize:], uint32(slotSize))
	binary.LittleEndian.PutUint32(buf[offSlots:], uint32(slots))
	return &Ring{buf: buf, slotSize: slotSize, slots: uint64(slots)}, nil
}

// Write stores one record, truncating msg to the slot payload.
func (r *Ring) Write(unixNano int64, msg string) {
	seq := r.seq.Add(1)
	off := ringHeaderSize + int((seq-1)%r.slots)*r.slotSize
	slot := r.buf[off : off+r.slotSize]
	// Sequence zero marks the slot as being rewritten.
	binary.LittleEndian.PutUint64(slot[0:8], 0)
	n := copy(slot[slotHeaderSize:], msg)
	binary.LittleEndian.PutUint64(slot[8:16], uint64(unixNano))
	binary.LittleEndian.PutUint16(slot[16:18], uint16(n))
	binary.LittleEndian.PutUint64(slot[0:8], seq)
}

// Beat records a liveness heartbeat in the ring header.
func (r *Ring) Beat(unixNano int64, count uint64) {
	binary.LittleEndian.PutUint64(r.buf[offBeatNanos:], uint64(unixNano))
	binary.LittleEndian.PutUint64(r.buf[offBeatCount:], count)
}

// Record is one decoded trace record.
type Record struct {
	Seq      uint64
	UnixNano int64
	Msg      string
}

// ReadRing decodes every record with a sequence above afterSeq, oldest first.
func ReadRing(buf []byte, afterSeq uint64) ([]Record, error) {
	if len(buf) < ringHeaderSize || string(buf[:8]) != ringMagic {
		return nil, errors.New("crashdebug: not a trace ring")
	}
	slotSize := int(binary.LittleEndian.Uint32(buf[offSlotSize:]))
	slots := int(binary.LittleEndian.Uint32(buf[offSlots:]))
	if slotSize <= slotHeaderSize || slots <= 0 || len(buf) < RingSize(slotSize, slots) {
		return nil, errors.New("crashdebug: corrupt trace ring header")
	}
	var out []Record
	for i := 0; i < slots; i++ {
		slot := buf[ringHeaderSize+i*slotSize : ringHeaderSize+(i+1)*slotSize]
		seq := binary.LittleEndian.Uint64(slot[0:8])
		if seq == 0 || seq <= afterSeq {
			continue
		}
		n := int(binary.LittleEndian.Uint16(slot[16:18]))
		if n > slotSize-slotHeaderSize {
			n = slotSize - slotHeaderSize
		}
		out = append(out, Record{
			Seq:      seq,
			UnixNano: int64(binary.LittleEndian.Uint64(slot[8:16])),
			Msg:      string(slot[slotHeaderSize : slotHeaderSize+n]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// ReadBeat returns the last heartbeat time and count stored in the ring header.
func ReadBeat(buf []byte) (unixNano int64, count uint64, ok bool) {
	if len(buf) < ringHeaderSize || string(buf[:8]) != ringMagic {
		return 0, 0, false
	}
	return int64(binary.LittleEndian.Uint64(buf[offBeatNanos:])), binary.LittleEndian.Uint64(buf[offBeatCount:]), true
}

// Format renders a record as "15:04:05.000000 #seq message" in UTC.
func (r Record) Format() string {
	return time.Unix(0, r.UnixNano).UTC().Format("15:04:05.000000") + " #" + strconv.FormatUint(r.Seq, 10) + " " + r.Msg
}
