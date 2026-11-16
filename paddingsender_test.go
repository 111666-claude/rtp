// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSSRC        uint32 = 0xDEADBEEF
	testMTU         uint16 = 1200
	testPayloadType uint8  = 96
	testInitSeq     uint16 = 100
	testTimestamp   uint32 = 5000
)

// fixedClock returns a controllable time source.
type fixedClock struct {
	now time.Time
}

func newFixedClock() *fixedClock {
	return &fixedClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *fixedClock) timeFunc() func() time.Time {
	return func() time.Time {
		return c.now
	}
}

func newTestPaddingSender(t *testing.T) *PaddingSender {
	t.Helper()

	return NewPaddingSender(
		testSSRC, testInitSeq, testMTU,
		PaddingSenderWithPayloadType(testPayloadType),
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
}

// marshalPackets serializes every packet and returns the raw packets alongside
// their total on-wire size.
func marshalPackets(t *testing.T, packets []*Packet) ([][]byte, int) {
	t.Helper()

	rawPackets := make([][]byte, len(packets))
	total := 0

	for i, packet := range packets {
		raw, err := packet.Marshal()
		require.NoError(t, err)
		rawPackets[i] = raw
		total += len(raw)
	}

	return rawPackets, total
}

func TestPaddingSenderBasicBudget(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	// MTU 1200 with a 12-byte header means full packets carry 1188 padding
	// bytes, which is capped at 255, so each packet is 267 bytes.
	target := 267*3 + 100 // three full packets plus a 100-byte remainder
	packets, err := sender.GeneratePadding(context.Background(), target)
	require.NoError(t, err)
	require.Len(t, packets, 4)

	rawPackets, total := marshalPackets(t, packets)

	// The last packet consumes the remainder exactly.
	require.Len(t, rawPackets[3], 100)
	assert.Equal(t, target, total, "probe must fill the budget exactly")

	for i, packet := range packets {
		// No media payload anywhere.
		assert.Empty(t, packet.Payload)
		assert.True(t, packet.Padding)
		assert.GreaterOrEqual(t, int(packet.Header.PaddingSize), 1)
		assert.LessOrEqual(t, int(packet.Header.PaddingSize), 255)
		assert.Equal(t, testSSRC, packet.SSRC)
		assert.Equal(t, testPayloadType, packet.PayloadType)
		assert.Equal(t, testTimestamp, packet.Timestamp, "fixed timestamp must be preserved")
		assert.Equal(t, testInitSeq+uint16(i), packet.SequenceNumber)
		assert.LessOrEqual(t, len(rawPackets[i]), int(testMTU))

		// Every serialized packet must decode through the public Packet API.
		decoded := &Packet{}
		require.NoError(t, decoded.Unmarshal(rawPackets[i]))
		assert.True(t, decoded.Padding)
		assert.Empty(t, decoded.Payload)
		assert.Equal(t, packet.SequenceNumber, decoded.SequenceNumber)
		assert.Equal(t, packet.Header.PaddingSize, decoded.Header.PaddingSize)
	}

	// First packet byte layout: V=2, P=1, X=0, CC=0; marker=0, PT=96.
	assert.Equal(t, byte(0xA0), rawPackets[0][0])
	assert.Equal(t, testPayloadType, rawPackets[0][1])
	// Last byte of each packet carries the padding length.
	assert.Equal(t, byte(255), rawPackets[0][len(rawPackets[0])-1])
	assert.Equal(t, byte(100-12), rawPackets[3][len(rawPackets[3])-1])

	assert.Equal(t, int64(target), sender.MediaBytes())

	// A second call in the same window must not exceed the budget.
	more, err := sender.GeneratePadding(context.Background(), target)
	require.NoError(t, err)
	assert.Empty(t, more)
}

func TestPaddingSenderExactBudgetAndSmallRemainder(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	// Exact budget: three 267-byte packets, nothing left over.
	packets, err := sender.GeneratePadding(context.Background(), 267*3)
	require.NoError(t, err)
	require.Len(t, packets, 3)

	_, total := marshalPackets(t, packets)
	assert.Equal(t, 267*3, total)

	// Remainder smaller than a minimum packet (header 12 + 1 padding byte):
	// no packet may be emitted, the budget must not be exceeded.
	sender.Reset()
	packets, err = sender.GeneratePadding(context.Background(), 267+12)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	_, total = marshalPackets(t, packets)
	assert.Equal(t, 267, total, "12 leftover bytes cannot fit a minimum packet")
}

func TestPaddingSenderTargetSmallerThanMinimumPacket(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	for _, target := range []int{0, -1, -100, 12, 1} {
		packets, err := sender.GeneratePadding(context.Background(), target)
		if target <= 0 {
			assert.ErrorIs(t, err, ErrInvalidTargetBytes)
		} else {
			assert.NoError(t, err)
			assert.Empty(t, packets, "budget smaller than minimum packet sends nothing")
		}
	}
}

func TestPaddingSenderInvalidMTU(t *testing.T) {
	t.Parallel()

	// A plain header is 12 bytes, so an MTU of 12 leaves no room for padding.
	sender := NewPaddingSender(
		testSSRC, testInitSeq, 12,
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
	packets, err := sender.GeneratePadding(context.Background(), 1000)
	assert.ErrorIs(t, err, ErrInvalidMTU)
	assert.Nil(t, packets)

	// MTU of 13 fits exactly one minimum padding byte.
	sender = NewPaddingSender(
		testSSRC, testInitSeq, 13,
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
	packets, err = sender.GeneratePadding(context.Background(), 13)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	raw, total := marshalPackets(t, packets)
	assert.Equal(t, 13, total)
	assert.Equal(t, byte(1), raw[0][len(raw[0])-1])
}

func TestPaddingSenderMTULimitsPacketSize(t *testing.T) {
	t.Parallel()

	mtu := uint16(100)
	sender := NewPaddingSender(
		testSSRC, testInitSeq, mtu,
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
	packets, err := sender.GeneratePadding(context.Background(), int(mtu)*5) //nolint:mnd // five MTUs of budget
	require.NoError(t, err)
	require.NotEmpty(t, packets)

	rawPackets, _ := marshalPackets(t, packets)
	for _, raw := range rawPackets {
		assert.LessOrEqual(t, len(raw), int(mtu))
	}
}

func TestPaddingSenderPaddingCappedAt255(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	packets, err := sender.GeneratePadding(context.Background(), int(testMTU))
	require.NoError(t, err)
	require.NotEmpty(t, packets)

	for _, packet := range packets {
		assert.LessOrEqual(t, int(packet.Header.PaddingSize), 255)
	}

	// Even with a large MTU the padding field never exceeds 255.
	largeMTUSender := NewPaddingSender(
		testSSRC, testInitSeq, 9000, //nolint:mnd // jumbo frame MTU for the test
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
	packets, err = largeMTUSender.GeneratePadding(context.Background(), 9000) //nolint:mnd
	require.NoError(t, err)
	// 33 full 267-byte packets (8811 bytes) plus one 189-byte remainder.
	require.Len(t, packets, 34) //nolint:mnd // derived from the 9000-byte budget
	assert.Equal(t, byte(255), packets[0].Header.PaddingSize)
	assert.Equal(t, 177, int(packets[33].Header.PaddingSize)) //nolint:mnd // 189 - 12 byte header
}

func TestPaddingSenderMediaBytesDeductBudget(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	// One full probe packet worth of media already on the wire. Each probe
	// packet is 267 bytes (12-byte header + 255 padding).
	sender.AddMediaBytes(267)
	packets, err := sender.GeneratePadding(context.Background(), 267*2)
	require.NoError(t, err)
	require.Len(t, packets, 1, "only one 267-byte packet fits after media deduction")

	_, total := marshalPackets(t, packets)
	assert.Equal(t, 267, total)
	assert.Equal(t, int64(267+267), sender.MediaBytes())

	// Reset opens a fresh window while keeping the sequence number.
	sender.Reset()
	assert.Equal(t, int64(0), sender.MediaBytes())
	packets, err = sender.GeneratePadding(context.Background(), 267)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, testInitSeq+1, packets[0].SequenceNumber)
}

func TestPaddingSenderSequenceRollover(t *testing.T) {
	t.Parallel()

	sender := NewPaddingSender(
		testSSRC, 0xFFFF, testMTU,
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
	packets, err := sender.GeneratePadding(context.Background(), 267*3)
	require.NoError(t, err)
	require.Len(t, packets, 3)

	assert.Equal(t, uint16(0xFFFF), packets[0].SequenceNumber)
	assert.Equal(t, uint16(0x0000), packets[1].SequenceNumber)
	assert.Equal(t, uint16(0x0001), packets[2].SequenceNumber)

	// Rollover must also survive serialization.
	rawPackets, _ := marshalPackets(t, packets)
	for i, raw := range rawPackets {
		decoded := &Packet{}
		require.NoError(t, decoded.Unmarshal(raw))
		assert.Equal(t, packets[i].SequenceNumber, decoded.SequenceNumber)
	}
}

func TestPaddingSenderPreservesHeaderExtensions(t *testing.T) {
	t.Parallel()

	template := Header{
		Version:          2,
		Marker:           true,
		PayloadType:      testPayloadType,
		Extension:        true,
		ExtensionProfile: ExtensionProfileOneByte,
	}
	require.NoError(t, template.SetExtension(3, []byte{0xAB, 0xCD})) //nolint:mnd // extension id
	require.NoError(t, template.SetExtension(7, []byte{0x01}))       //nolint:mnd // extension id

	sender := NewPaddingSender(
		testSSRC, testInitSeq, testMTU,
		PaddingSenderWithHeaderTemplate(template),
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(newFixedClock().timeFunc()),
	)
	packets, err := sender.GeneratePadding(context.Background(), 1000)
	require.NoError(t, err)
	require.NotEmpty(t, packets)

	rawPackets, _ := marshalPackets(t, packets)
	for i, raw := range rawPackets {
		assert.True(t, len(raw) > 12)
		decoded := &Packet{}
		require.NoError(t, decoded.Unmarshal(raw))
		assert.True(t, decoded.Extension)
		assert.Equal(t, uint16(ExtensionProfileOneByte), decoded.ExtensionProfile)
		assert.Equal(t, []byte{0xAB, 0xCD}, decoded.GetExtension(3))
		assert.Equal(t, []byte{0x01}, decoded.GetExtension(7))
		assert.True(t, decoded.Marker)
		assert.Empty(t, decoded.Payload)
		assert.LessOrEqual(t, len(raw), int(testMTU))
		assert.Equal(t, testInitSeq+uint16(i), decoded.SequenceNumber)
	}
}

func TestPaddingSenderFixedAndClockDrivenTimestamps(t *testing.T) {
	t.Parallel()

	// Fixed timestamp: every packet shares the configured value.
	clock := newFixedClock()
	sender := NewPaddingSender(
		testSSRC, testInitSeq, testMTU,
		PaddingSenderWithInitialTimestamp(testTimestamp),
		paddingSenderWithTimeGenerator(clock.timeFunc()),
	)
	clock.now = clock.now.Add(time.Second)
	packets, err := sender.GeneratePadding(context.Background(), 267*2)
	require.NoError(t, err)
	require.Len(t, packets, 2)
	for _, packet := range packets {
		assert.Equal(t, testTimestamp, packet.Timestamp)
	}

	// Clock-driven timestamp: advances by elapsed time at the clock rate.
	clock = newFixedClock()
	const clockRate = 90000 //nolint:mnd // standard video RTP clock rate
	sender = NewPaddingSender(
		testSSRC, testInitSeq, testMTU,
		PaddingSenderWithInitialTimestamp(testTimestamp),
		PaddingSenderWithClockRate(clockRate),
		paddingSenderWithTimeGenerator(clock.timeFunc()),
	)
	clock.now = clock.now.Add(2 * time.Second) //nolint:mnd // two seconds of media time
	packets, err = sender.GeneratePadding(context.Background(), 267)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, testTimestamp+2*clockRate, packets[0].Timestamp)

	// SetTimestamp overrides the base even with a clock rate configured.
	sender.Reset()
	sender.SetTimestamp(42)
	packets, err = sender.GeneratePadding(context.Background(), 267)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint32(42+2*clockRate), packets[0].Timestamp)
}

func TestPaddingSenderCancellation(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Pre-canceled context produces no packets and the context error.
	packets, err := sender.GeneratePadding(ctx, 1000)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, packets)
	assert.Equal(t, int64(0), sender.MediaBytes(), "canceled call must not count bytes")

	// Cancellation observed mid-generation: stop cleanly and report the
	// packets built so far together with the context error. The time
	// generator hook cancels the context after a few packets.
	clock := newFixedClock()
	ctx, cancel = context.WithCancel(context.Background())
	emitted := 0
	sender = NewPaddingSender(
		testSSRC, testInitSeq, testMTU,
		PaddingSenderWithClockRate(90000), //nolint:mnd // standard video RTP clock rate
		paddingSenderWithTimeGenerator(func() time.Time {
			emitted++
			if emitted == 3 { //nolint:mnd // cancel after the first two packets are built
				cancel()
			}

			return clock.now
		}),
	)
	packets, err = sender.GeneratePadding(ctx, 1_000_000)
	assert.ErrorIs(t, err, context.Canceled)
	require.Len(t, packets, 2, "generation must stop promptly after cancellation")
	rawPackets, total := marshalPackets(t, packets)
	assert.Equal(t, 267*2, total)
	assert.Equal(t, int64(267*2), sender.MediaBytes(), "emitted bytes remain accounted for")
	for _, raw := range rawPackets {
		decoded := &Packet{}
		require.NoError(t, decoded.Unmarshal(raw))
		assert.True(t, decoded.Padding)
	}
}

func TestPaddingSenderNoStaleBufferLeak(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	packets, err := sender.GeneratePadding(context.Background(), 267*2)
	require.NoError(t, err)
	require.Len(t, packets, 2)

	for _, packet := range packets {
		raw, err := packet.Marshal()
		require.NoError(t, err)

		headerSize := packet.Header.MarshalSize()
		padding := raw[headerSize:]
		// All padding bytes except the final length byte must be zero, no
		// stale buffer contents may survive.
		for i := 0; i < len(padding)-1; i++ {
			assert.Equal(t, byte(0), padding[i])
		}
		assert.Equal(t, packet.Header.PaddingSize, padding[len(padding)-1])
	}
}

func TestPaddingSenderConcurrentMediaAccounting(t *testing.T) {
	t.Parallel()

	sender := newTestPaddingSender(t)

	const goroutines = 16   //nolint:mnd // concurrent media writers
	const increments = 1000 //nolint:mnd // bytes added per writer
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			for range increments {
				sender.AddMediaBytes(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(goroutines*increments), sender.MediaBytes())

	// Probe generation concurrent with media accounting must never exceed the
	// target budget and must always produce legal, decodable packets.
	sender.Reset()
	const target = 267 * 10
	var generated []*Packet
	wg.Add(2) //nolint:mnd // one generator, one media writer

	go func() {
		defer wg.Done()
		packets, genErr := sender.GeneratePadding(context.Background(), target)
		assert.NoError(t, genErr)
		generated = packets
	}()

	go func() {
		defer wg.Done()
		for range increments {
			sender.AddMediaBytes(1)
		}
	}()
	wg.Wait()

	// Decode outside the goroutine so testify failures stay on the test goroutine.
	rawPackets, _ := marshalPackets(t, generated)
	for _, raw := range rawPackets {
		decoded := &Packet{}
		assert.NoError(t, decoded.Unmarshal(raw))
		assert.True(t, decoded.Padding)
	}

	assert.LessOrEqual(t, sender.MediaBytes(), int64(target+increments))
}

func TestPaddingSenderErrorSentinels(t *testing.T) {
	t.Parallel()

	assert.NotNil(t, ErrInvalidMTU)
	assert.NotNil(t, ErrInvalidTargetBytes)
	assert.True(t, errors.Is(ErrInvalidMTU, ErrInvalidMTU))
}
