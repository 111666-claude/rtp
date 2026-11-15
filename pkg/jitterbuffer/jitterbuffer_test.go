// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package jitterbuffer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manualClock is a Clock whose time only advances when Advance is called.
type manualClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*manualTimer
}

type manualTimer struct {
	clock    *manualClock
	deadline time.Time
	f        func()
	fired    bool
	stopped  bool
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *manualClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()

	t := &manualTimer{clock: c, deadline: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)

	return t
}

func (t *manualTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()

	if t.fired || t.stopped {
		return false
	}
	t.stopped = true

	return true
}

// Advance moves the clock forward by d, firing timers in deadline order as
// their deadlines pass.
func (c *manualClock) Advance(d time.Duration) {
	end := c.Now().Add(d)
	for {
		c.mu.Lock()
		var next *manualTimer
		for _, t := range c.timers {
			if t.fired || t.stopped || t.deadline.After(end) {
				continue
			}
			if next == nil || t.deadline.Before(next.deadline) {
				next = t
			}
		}
		if next == nil {
			c.now = end
			c.mu.Unlock()

			return
		}
		next.fired = true
		c.now = next.deadline
		f := next.f
		c.mu.Unlock()
		f()
	}
}

// pendingTimers reports how many timers are still armed.
func (c *manualClock) pendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := 0
	for _, t := range c.timers {
		if !t.fired && !t.stopped {
			n++
		}
	}

	return n
}

func pkt(ssrc uint32, seq uint16) *rtp.Packet {
	return &rtp.Packet{
		Header:  rtp.Header{SSRC: ssrc, SequenceNumber: seq},
		Payload: []byte{byte(seq >> 8), byte(seq)},
	}
}

// readSeqs reads until no more packets are immediately available and returns
// the received sequence numbers.
func readSeqs(t *testing.T, b *Buffer) []uint16 {
	t.Helper()

	var seqs []uint16
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		p, err := b.Read(ctx)
		cancel()
		if err != nil {
			return seqs
		}
		seqs = append(seqs, p.SequenceNumber)
	}
}

func mustStats(t *testing.T, b *Buffer, ssrc uint32) Stats {
	t.Helper()
	s, ok := b.Stats(ssrc)
	require.True(t, ok)

	return s
}

func TestReorderOutOfOrder(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(time.Second))
	defer func() { require.NoError(t, b.Close()) }()

	// Voice packets arriving as 10, 12, 11.
	require.NoError(t, b.Write(pkt(1, 10)))
	require.NoError(t, b.Write(pkt(1, 12)))
	require.NoError(t, b.Write(pkt(1, 11)))

	assert.Equal(t, []uint16{10, 11, 12}, readSeqs(t, b))

	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(3), s.Received)
	assert.Equal(t, uint64(3), s.Delivered)
	assert.Equal(t, uint64(0), s.Lost)
	assert.Equal(t, 0, clock.pendingTimers(), "gap was filled, timer must be stopped")
}

func TestGapTimeoutThenLate(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(50*time.Millisecond))
	defer func() { require.NoError(t, b.Close()) }()

	require.NoError(t, b.Write(pkt(1, 1)))
	require.NoError(t, b.Write(pkt(1, 2)))
	require.NoError(t, b.Write(pkt(1, 4))) // gap at 3

	assert.Equal(t, []uint16{1, 2}, readSeqs(t, b), "4 is held behind the gap")
	assert.Equal(t, 1, clock.pendingTimers())

	clock.Advance(50 * time.Millisecond)

	assert.Equal(t, []uint16{4}, readSeqs(t, b), "timeout delivers past the gap")
	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(1), s.Lost)
	assert.Equal(t, uint64(3), s.Delivered)

	// 3 arrives after being declared lost: dropped, counted late, not delivered.
	require.NoError(t, b.Write(pkt(1, 3)))
	assert.Empty(t, readSeqs(t, b))
	s = mustStats(t, b, 1)
	assert.Equal(t, uint64(1), s.Late)
	assert.Equal(t, uint64(3), s.Delivered)
}

func TestWraparound(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(time.Second))
	defer func() { require.NoError(t, b.Close()) }()

	require.NoError(t, b.Write(pkt(1, 65534)))
	require.NoError(t, b.Write(pkt(1, 65535)))
	require.NoError(t, b.Write(pkt(1, 1))) // gap at 0, across the wrap
	require.NoError(t, b.Write(pkt(1, 0)))

	assert.Equal(t, []uint16{65534, 65535, 0, 1}, readSeqs(t, b))

	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(4), s.Received)
	assert.Equal(t, uint64(4), s.Delivered)
	assert.Equal(t, uint64(0), s.Lost)
}

func TestWraparoundTimeoutAndLateAcrossWrap(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(50*time.Millisecond))
	defer func() { require.NoError(t, b.Close()) }()

	require.NoError(t, b.Write(pkt(1, 65534)))
	require.NoError(t, b.Write(pkt(1, 0))) // gap at 65535

	clock.Advance(50 * time.Millisecond)
	assert.Equal(t, []uint16{65534, 0}, readSeqs(t, b))

	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(1), s.Lost, "65535 declared lost")

	// Late arrival of 65535 must not be delivered or confused with a future seq.
	require.NoError(t, b.Write(pkt(1, 65535)))
	assert.Empty(t, readSeqs(t, b))
	s = mustStats(t, b, 1)
	assert.Equal(t, uint64(1), s.Late)
	assert.Equal(t, uint64(2), s.Delivered)
}

func TestDuplicates(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(time.Second))
	defer func() { require.NoError(t, b.Close()) }()

	// Duplicate of an immediately delivered packet.
	require.NoError(t, b.Write(pkt(1, 5)))
	require.NoError(t, b.Write(pkt(1, 5)))
	// Duplicate of a buffered packet.
	require.NoError(t, b.Write(pkt(1, 8)))
	require.NoError(t, b.Write(pkt(1, 8)))
	// Fill the gap; 6,7,8 delivered. Then a stray copy of 7.
	require.NoError(t, b.Write(pkt(1, 6)))
	require.NoError(t, b.Write(pkt(1, 7)))
	require.NoError(t, b.Write(pkt(1, 7)))

	assert.Equal(t, []uint16{5, 6, 7, 8}, readSeqs(t, b))

	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(3), s.Duplicates)
	assert.Equal(t, uint64(4), s.Received)
	assert.Equal(t, uint64(4), s.Delivered)
}

func TestBurstLoss(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(10*time.Millisecond))
	defer func() { require.NoError(t, b.Close()) }()

	require.NoError(t, b.Write(pkt(1, 1)))
	for seq := uint16(10); seq <= 20; seq++ { // 2..9 lost in a burst
		require.NoError(t, b.Write(pkt(1, seq)))
	}

	assert.Equal(t, []uint16{1}, readSeqs(t, b))

	// Each timer fire declares one missing sequence number lost and rearms.
	clock.Advance(80 * time.Millisecond)

	var want []uint16
	for seq := uint16(10); seq <= 20; seq++ {
		want = append(want, seq)
	}
	assert.Equal(t, want, readSeqs(t, b))

	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(8), s.Lost)
	assert.Equal(t, uint64(12), s.Delivered)
	assert.Equal(t, 0, clock.pendingTimers())
}

func TestCapacityOverflowDeterministic(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(time.Second), WithCapacity(3))
	defer func() { require.NoError(t, b.Close()) }()

	require.NoError(t, b.Write(pkt(1, 1))) // delivered, expected = 2
	require.NoError(t, b.Write(pkt(1, 3)))
	require.NoError(t, b.Write(pkt(1, 4)))
	require.NoError(t, b.Write(pkt(1, 5))) // buffer full: 3,4,5

	// Incoming 6 is the furthest in the future: dropped itself.
	require.NoError(t, b.Write(pkt(1, 6)))
	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(1), s.DroppedOverflow)

	// Incoming 2 fills the gap and drains 3,4,5.
	require.NoError(t, b.Write(pkt(1, 2)))
	assert.Equal(t, []uint16{1, 2, 3, 4, 5}, readSeqs(t, b))

	// Refill behind a new gap at 6; an older packet evicts the newest one.
	require.NoError(t, b.Write(pkt(1, 8)))
	require.NoError(t, b.Write(pkt(1, 9)))
	require.NoError(t, b.Write(pkt(1, 10))) // buffer full: 8,9,10
	require.NoError(t, b.Write(pkt(1, 7)))  // evicts 10
	s = mustStats(t, b, 1)
	assert.Equal(t, uint64(2), s.DroppedOverflow)

	clock.Advance(time.Second) // 6 declared lost
	assert.Equal(t, []uint16{7, 8, 9}, readSeqs(t, b))

	s = mustStats(t, b, 1)
	assert.Equal(t, uint64(1), s.Lost)
	assert.Equal(t, uint64(8), s.Delivered)
}

func TestSSRCIsolation(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(50*time.Millisecond))
	defer func() { require.NoError(t, b.Close()) }()

	// Interleave two streams; each must be reordered independently.
	require.NoError(t, b.Write(pkt(100, 10)))
	require.NoError(t, b.Write(pkt(200, 1000)))
	require.NoError(t, b.Write(pkt(100, 12)))
	require.NoError(t, b.Write(pkt(200, 1002)))
	require.NoError(t, b.Write(pkt(100, 11)))
	require.NoError(t, b.Write(pkt(200, 1001)))

	got := make(map[uint32][]uint16)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		p, err := b.Read(ctx)
		cancel()
		if err != nil {
			break
		}
		got[p.SSRC] = append(got[p.SSRC], p.SequenceNumber)
	}
	assert.Equal(t, []uint16{10, 11, 12}, got[100])
	assert.Equal(t, []uint16{1000, 1001, 1002}, got[200])

	all := b.StatsAll()
	require.Len(t, all, 2)
	assert.Equal(t, uint64(3), all[100].Delivered)
	assert.Equal(t, uint64(3), all[200].Delivered)
	assert.Equal(t, uint64(0), all[100].Lost)
	assert.Equal(t, uint64(0), all[200].Lost)
}

func TestReadCancel(t *testing.T) {
	b := New()
	defer func() { require.NoError(t, b.Close()) }()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := b.Read(ctx)
		done <- err
	}()

	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestCloseDrainsAndEnds(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(time.Second))

	require.NoError(t, b.Write(pkt(1, 1)))
	require.NoError(t, b.Write(pkt(1, 3))) // buffered behind gap, dropped on close

	require.NoError(t, b.Close())
	require.ErrorIs(t, b.Close(), ErrClosed, "double close")

	// Queued packet still readable, then ErrClosed.
	p, err := b.Read(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint16(1), p.SequenceNumber)

	_, err = b.Read(context.Background())
	require.ErrorIs(t, err, ErrClosed)

	require.ErrorIs(t, b.Write(pkt(1, 2)), ErrClosed)
	assert.Equal(t, 0, clock.pendingTimers(), "close stops all timers")
}

func TestNoRedeliveryAfterDelivery(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(50*time.Millisecond))
	defer func() { require.NoError(t, b.Close()) }()

	for seq := uint16(1); seq <= 5; seq++ {
		require.NoError(t, b.Write(pkt(1, seq)))
	}
	assert.Equal(t, []uint16{1, 2, 3, 4, 5}, readSeqs(t, b))

	// Replay the whole window: all duplicates, nothing delivered again.
	for seq := uint16(1); seq <= 5; seq++ {
		require.NoError(t, b.Write(pkt(1, seq)))
	}
	assert.Empty(t, readSeqs(t, b))

	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(5), s.Duplicates)
	assert.Equal(t, uint64(5), s.Delivered)
}

func TestZeroMaxWaitSkipsGapsImmediately(t *testing.T) {
	b := New(WithMaxWait(0))
	defer func() { require.NoError(t, b.Close()) }()

	require.NoError(t, b.Write(pkt(1, 1)))
	require.NoError(t, b.Write(pkt(1, 4))) // 2,3 skipped without waiting

	assert.Equal(t, []uint16{1, 4}, readSeqs(t, b))
	s := mustStats(t, b, 1)
	assert.Equal(t, uint64(2), s.Lost)
}

func TestConcurrentWriteReadClose(t *testing.T) {
	clock := &manualClock{}
	b := New(WithClock(clock), WithMaxWait(time.Millisecond), WithCapacity(64))

	const writers = 4
	const perWriter = 200

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type deliveredPkt struct {
		ssrc uint32
		seq  uint16
	}
	delivered := make(chan deliveredPkt, writers*perWriter)

	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		for {
			p, err := b.Read(ctx)
			if err != nil {
				return
			}
			delivered <- deliveredPkt{p.SSRC, p.SequenceNumber}
		}
	}()

	var writerWg sync.WaitGroup
	for w := 0; w < writers; w++ {
		writerWg.Add(1)
		go func(ssrc uint32) {
			defer writerWg.Done()
			// Write 0 first to anchor the stream, then swap each pair
			// (2,1), (4,3), ... to create reordering while writing every
			// sequence number exactly once.
			_ = b.Write(pkt(ssrc, 0))
			for i := 1; i+1 < perWriter; i += 2 {
				_ = b.Write(pkt(ssrc, uint16(i+1))) //nolint:gosec // test helper
				_ = b.Write(pkt(ssrc, uint16(i)))   //nolint:gosec // test helper
			}
			_ = b.Write(pkt(ssrc, uint16(perWriter-1))) //nolint:gosec // test helper
		}(uint32(w + 1)) //nolint:gosec // test helper
	}
	writerWg.Wait()

	clock.Advance(10 * time.Millisecond) // flush any pending gaps
	require.NoError(t, b.Close())
	cancel()
	readerWg.Wait()
	close(delivered)

	perStream := make(map[uint32][]uint16)
	for d := range delivered {
		perStream[d.ssrc] = append(perStream[d.ssrc], d.seq)
	}

	require.Len(t, perStream, writers)
	for ssrc, seqs := range perStream {
		// Per SSRC the output must be strictly increasing with no repeats:
		// no delivered packet is re-delivered because of a late duplicate.
		for i := 1; i < len(seqs); i++ {
			require.Less(t, seqs[i-1], seqs[i], "ssrc %d out of order at %d", ssrc, i)
		}
		s := mustStats(t, b, ssrc)
		assert.Equal(t, uint64(len(seqs)), s.Delivered, "ssrc %d", ssrc)
		assert.Equal(t, uint64(perWriter), s.Received, "ssrc %d", ssrc)
	}
}
