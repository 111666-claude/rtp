// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package jitterbuffer provides an optional, bounded reordering buffer for
// RTP packets. Packets are grouped by SSRC and released in sequence-number
// order; gaps are waited on for a bounded time and then reported as lost.
package jitterbuffer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pion/rtp"
)

// ErrClosed is returned by Write and Read after the Buffer was closed.
var ErrClosed = errors.New("jitterbuffer: buffer closed")

// ErrNilPacket is returned by Write when passed a nil packet.
var ErrNilPacket = errors.New("jitterbuffer: nil packet")

const (
	defaultMaxWait  = 50 * time.Millisecond
	defaultCapacity = 128

	// historyBits is the number of already-passed sequence numbers per stream
	// for which delivered/lost status is remembered, so that a recurring copy
	// of a delivered packet is counted as a duplicate and a packet that was
	// declared lost is counted as late.
	historyBits = 64
)

// Stats counts packets for one SSRC. All counters are monotonically
// increasing.
type Stats struct {
	// Received is the number of unique, in-window packets accepted by the
	// buffer (delivered immediately or stored).
	Received uint64
	// Delivered is the number of packets handed out via Read.
	Delivered uint64
	// Lost is the number of sequence numbers declared lost after waiting
	// MaxWait without the packet arriving.
	Lost uint64
	// Duplicates is the number of copies of packets already buffered or
	// already delivered.
	Duplicates uint64
	// Late is the number of packets that arrived after their sequence number
	// was declared lost (or before the stream started).
	Late uint64
	// DroppedOverflow is the number of packets discarded because the
	// per-SSRC buffer was full.
	DroppedOverflow uint64
}

// Option configures a Buffer.
type Option func(*Buffer)

// WithMaxWait sets how long the buffer waits for a missing sequence number
// before declaring it lost and moving on. Values <= 0 disable waiting: gaps
// are skipped immediately.
func WithMaxWait(d time.Duration) Option {
	return func(b *Buffer) { b.maxWait = d }
}

// WithCapacity sets the maximum number of packets buffered per SSRC.
// Values < 1 are clamped to 1. When a stream is full, the packet with the
// highest (furthest in the future) sequence number is dropped; if the
// incoming packet is that packet, the incoming packet is dropped.
func WithCapacity(n int) Option {
	return func(b *Buffer) { b.capacity = n }
}

// WithClock sets the clock used for wait timers. Defaults to RealClock.
func WithClock(c Clock) Option {
	return func(b *Buffer) { b.clock = c }
}

// Buffer reorders RTP packets per SSRC. It is safe for concurrent use.
//
// The Buffer spawns no goroutines; wait timers are driven by the Clock.
// Memory is bounded by Capacity packets per observed SSRC plus one timer per
// SSRC with a pending gap.
type Buffer struct {
	maxWait  time.Duration
	capacity int
	clock    Clock

	mu      sync.Mutex
	streams map[uint32]*stream
	out     []*rtp.Packet // ready for delivery, FIFO
	changed chan struct{} // closed and replaced on every state change
	closed  bool
}

// New returns a Buffer with the given options.
func New(opts ...Option) *Buffer {
	b := &Buffer{
		maxWait:  defaultMaxWait,
		capacity: defaultCapacity,
		clock:    RealClock{},
		streams:  map[uint32]*stream{},
		changed:  make(chan struct{}),
	}
	for _, o := range opts {
		o(b)
	}
	if b.capacity < 1 {
		b.capacity = 1
	}
	if b.clock == nil {
		b.clock = RealClock{}
	}

	return b
}

// stream holds the reordering state for one SSRC.
type stream struct {
	expected uint64                 // extended sequence number of the next packet to deliver
	packets  map[uint64]*rtp.Packet // buffered packets, keyed by extended sequence number
	hist     uint64                 // bit i: status of expected-1-i, 1 = delivered, 0 = lost
	timer    Timer                  // non-nil while waiting on a gap
	timerGen uint64                 // invalidates stale timer callbacks
	stats    Stats
}

// extSeq maps a 16-bit sequence number onto the extended sequence space
// anchored at s.expected, resolving wraparound by picking the representative
// within +/- 2^15 of expected.
func (s *stream) extSeq(seq uint16) int64 {
	return int64(s.expected) + int64(int16(seq-uint16(s.expected))) //nolint:gosec // G115 intentional wrap
}

// Write adds a packet to the buffer. The packet must not be mutated after
// this call. Duplicate, late and overflow-dropped packets are accepted
// silently and counted in Stats.
func (b *Buffer) Write(pkt *rtp.Packet) error {
	if pkt == nil {
		return ErrNilPacket
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrClosed
	}

	s, ok := b.streams[pkt.SSRC]
	if !ok {
		s = &stream{
			expected: uint64(pkt.SequenceNumber),
			packets:  map[uint64]*rtp.Packet{},
		}
		b.streams[pkt.SSRC] = s
	}

	ext := s.extSeq(pkt.SequenceNumber)

	switch {
	case ext < 0:
		// Before the first sequence number of the stream.
		s.stats.Late++
	case ext < int64(s.expected): //nolint:gosec // G115 expected fits int64
		// Already delivered or declared lost.
		shift := int64(s.expected) - ext //nolint:gosec // G115 expected fits int64
		if shift <= historyBits && s.hist&(1<<(shift-1)) != 0 {
			s.stats.Duplicates++
		} else {
			s.stats.Late++
		}
	case ext == int64(s.expected): //nolint:gosec // G115 expected fits int64
		s.stats.Received++
		b.deliverLocked(s, pkt)
	default:
		if _, dup := s.packets[uint64(ext)]; dup {
			s.stats.Duplicates++

			break
		}
		if len(s.packets) >= b.capacity && !b.makeRoomLocked(s, uint64(ext)) {
			// The incoming packet itself was the eviction candidate.
			s.stats.DroppedOverflow++

			break
		}
		s.stats.Received++
		s.packets[uint64(ext)] = pkt
	}

	b.reconcileTimerLocked(pkt.SSRC, s)

	return nil
}

// makeRoomLocked evicts the buffered packet with the highest extended
// sequence number if the incoming packet is older. It reports whether the
// incoming packet may be stored.
func (b *Buffer) makeRoomLocked(s *stream, incoming uint64) bool {
	var highest uint64
	first := true
	for ext := range s.packets {
		if first || ext > highest {
			highest = ext
			first = false
		}
	}
	if incoming >= highest {
		return false
	}
	delete(s.packets, highest)
	s.stats.DroppedOverflow++

	return true
}

// deliverLocked hands pkt and any contiguous buffered followers to the out
// queue.
func (b *Buffer) deliverLocked(s *stream, pkt *rtp.Packet) {
	b.out = append(b.out, pkt)
	s.stats.Delivered++
	s.advanceLocked(true)

	for {
		next, ok := s.packets[s.expected]
		if !ok {
			break
		}
		delete(s.packets, s.expected)
		b.out = append(b.out, next)
		s.stats.Delivered++
		s.advanceLocked(true)
	}
	b.signalLocked()
}

// advanceLocked moves expected past one sequence number, recording in the
// history bitmap whether it was delivered.
func (s *stream) advanceLocked(delivered bool) {
	s.hist <<= 1
	if delivered {
		s.hist |= 1
	}
	s.expected++
}

// reconcileTimerLocked maintains the invariant that a wait timer runs exactly
// when the stream holds packets but the head-of-line sequence number is
// missing. With maxWait <= 0 gaps are skipped synchronously.
func (b *Buffer) reconcileTimerLocked(ssrc uint32, s *stream) {
	for len(s.packets) > 0 && b.maxWait <= 0 {
		if _, ok := s.packets[s.expected]; ok {
			break
		}
		s.stats.Lost++
		s.advanceLocked(false)
		b.drainContiguousLocked(s)
	}

	if len(s.packets) == 0 {
		b.stopTimerLocked(s)

		return
	}
	if _, ok := s.packets[s.expected]; ok {
		// Head-of-line present; it is drained synchronously by deliverLocked,
		// so this only happens right after a timeout with maxWait <= 0.
		b.stopTimerLocked(s)

		return
	}
	if s.timer == nil {
		s.timerGen++
		gen := s.timerGen
		s.timer = b.clock.AfterFunc(b.maxWait, func() { b.onTimeout(ssrc, gen) })
	}
}

// drainContiguousLocked moves any buffered packets that are now contiguous
// with expected to the out queue.
func (b *Buffer) drainContiguousLocked(s *stream) {
	for {
		next, ok := s.packets[s.expected]
		if !ok {
			return
		}
		delete(s.packets, s.expected)
		b.out = append(b.out, next)
		s.stats.Delivered++
		s.advanceLocked(true)
	}
}

func (b *Buffer) stopTimerLocked(s *stream) {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
		s.timerGen++
	}
}

// onTimeout declares the head-of-line sequence number lost and continues
// delivery.
func (b *Buffer) onTimeout(ssrc uint32, gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	s, ok := b.streams[ssrc]
	if !ok || s.timerGen != gen {
		return // stale timer
	}
	s.timer = nil

	if _, ok := s.packets[s.expected]; !ok && len(s.packets) > 0 {
		s.stats.Lost++
		s.advanceLocked(false)
		b.drainContiguousLocked(s)
		b.signalLocked()
	}
	b.reconcileTimerLocked(ssrc, s)
}

// Read returns the next packet in per-SSRC sequence order. It blocks until a
// packet is ready, ctx is cancelled, or the Buffer is closed. Packets already
// queued for delivery are still returned after Close; once they are drained
// Read returns ErrClosed.
func (b *Buffer) Read(ctx context.Context) (*rtp.Packet, error) {
	for {
		b.mu.Lock()
		if len(b.out) > 0 {
			pkt := b.out[0]
			b.out[0] = nil // allow GC
			b.out = b.out[1:]
			b.mu.Unlock()

			return pkt, nil
		}
		if b.closed {
			b.mu.Unlock()

			return nil, ErrClosed
		}
		changed := b.changed
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

// Close stops all wait timers and releases buffered packets. Packets already
// queued for delivery remain readable.
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrClosed
	}
	b.closed = true
	for _, s := range b.streams {
		b.stopTimerLocked(s)
		s.packets = map[uint64]*rtp.Packet{}
	}
	b.signalLocked()

	return nil
}

// Stats returns the counters for one SSRC, and whether the stream is known.
func (b *Buffer) Stats(ssrc uint32) (Stats, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	s, ok := b.streams[ssrc]
	if !ok {
		return Stats{}, false
	}

	return s.stats, true
}

// StatsAll returns a snapshot of the counters of all known SSRCs.
func (b *Buffer) StatsAll() map[uint32]Stats {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make(map[uint32]Stats, len(b.streams))
	for ssrc, s := range b.streams {
		out[ssrc] = s.stats
	}

	return out
}

// signalLocked wakes all blocked Readers.
func (b *Buffer) signalLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
}
