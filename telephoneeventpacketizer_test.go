// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"testing"
	"time"

	"github.com/pion/rtp/codecs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTelephoneEventPayloadType uint8 = 101

func newTestTelephoneEventPacketizer(t *testing.T) *TelephoneEventPacketizer {
	t.Helper()

	packetizer, err := NewTelephoneEventPacketizer(
		testTelephoneEventPayloadType, 0x1234ABCD, NewFixedSequencer(1), 8000,
	)
	require.NoError(t, err)
	packetizer.EndRepeat = DefaultTelephoneEventEndRepeat

	return packetizer
}

// TestTelephoneEventTwoKeyTiming checks a two-key sequence against RFC 4733
// section 5, Table 5 ("911", using the first two digits): the "9" pressed for
// 200 ms and the "1" pressed for 250 ms starting 880 ms later, both reported
// at a 50 ms frame duration. Payload bytes and headers are checked exactly.
func TestTelephoneEventTwoKeyTiming(t *testing.T) {
	packetizer := newTestTelephoneEventPacketizer(t)

	var generated []*Packet

	// First key: "9" starts at timestamp 0, reported every 50 ms (400 units)
	// for 200 ms (1600 units). The end is reported with the same timestamp.
	packets, err := packetizer.Start(0, codecs.TelephoneEventDTMF9, 0, 400)
	require.NoError(t, err)
	generated = append(generated, packets...)

	for _, duration := range []uint32{800, 1200, 1600} {
		packets, err = packetizer.Update(duration)
		require.NoError(t, err)
		generated = append(generated, packets...)
	}

	packets, err = packetizer.End(1600)
	require.NoError(t, err)
	generated = append(generated, packets...)

	// Second key: "1" starts 880 ms (7040 units) after the first one and lasts
	// 250 ms (2000 units).
	packets, err = packetizer.Start(7040, codecs.TelephoneEventDTMF1, 0, 400)
	require.NoError(t, err)
	generated = append(generated, packets...)

	packets, err = packetizer.Update(2000)
	require.NoError(t, err)
	generated = append(generated, packets...)

	packets, err = packetizer.End(2000)
	require.NoError(t, err)
	generated = append(generated, packets...)

	// Expected payload bytes: event | E|R|volume | duration.
	type want struct {
		timestamp uint32
		marker    bool
		payload   []byte
	}
	expected := []want{
		// "9": 400, 800, 1200 and 1600 units, then the final report three
		// times (initial transmission of the final packet plus two
		// retransmissions).
		{0, true, []byte{0x09, 0x00, 0x01, 0x90}},
		{0, false, []byte{0x09, 0x00, 0x03, 0x20}},
		{0, false, []byte{0x09, 0x00, 0x04, 0xB0}},
		{0, false, []byte{0x09, 0x00, 0x06, 0x40}},
		{0, false, []byte{0x09, 0x80, 0x06, 0x40}},
		{0, false, []byte{0x09, 0x80, 0x06, 0x40}},
		{0, false, []byte{0x09, 0x80, 0x06, 0x40}},
		// "1": 400 and 2000 units, then the final report three times.
		{7040, true, []byte{0x01, 0x00, 0x01, 0x90}},
		{7040, false, []byte{0x01, 0x00, 0x07, 0xD0}},
		{7040, false, []byte{0x01, 0x80, 0x07, 0xD0}},
		{7040, false, []byte{0x01, 0x80, 0x07, 0xD0}},
		{7040, false, []byte{0x01, 0x80, 0x07, 0xD0}},
	}

	require.Len(t, generated, len(expected))

	for i, packet := range generated {
		assert.Equal(t, uint8(2), packet.Version)
		assert.Equal(t, testTelephoneEventPayloadType, packet.PayloadType)
		assert.Equal(t, uint32(0x1234ABCD), packet.SSRC)
		assert.Equal(t, uint16(i+1), packet.SequenceNumber, "sequence number must increase by one")
		assert.Equal(t, expected[i].timestamp, packet.Timestamp)
		assert.Equal(t, expected[i].marker, packet.Marker)
		assert.Equal(t, expected[i].payload, packet.Payload)

		// The generated packets must survive a marshal/unmarshal round trip.
		raw, marshalErr := packet.Marshal()
		require.NoError(t, marshalErr)

		var parsed Packet
		require.NoError(t, parsed.Unmarshal(raw))
		assert.Equal(t, packet.Payload, parsed.Payload)
		assert.Equal(t, packet.SequenceNumber, parsed.SequenceNumber)
		assert.Equal(t, packet.Timestamp, parsed.Timestamp)
		assert.Equal(t, packet.Marker, parsed.Marker)
	}

	// The depacketizer exposes the event semantics of every final packet.
	depacketizer := codecs.TelephoneEventPacket{}
	media, err := depacketizer.Unmarshal(generated[len(generated)-1].Payload)
	require.NoError(t, err)
	assert.Equal(t, generated[len(generated)-1].Payload, media)
	assert.Equal(t, codecs.TelephoneEventDTMF1, depacketizer.Event)
	assert.True(t, depacketizer.End)
	assert.Equal(t, uint16(2000), depacketizer.Duration)
	digit, err := depacketizer.DTMF()
	require.NoError(t, err)
	assert.Equal(t, '1', digit)

	// Exactly one end bit per final packet, and only after the event ends.
	for _, packet := range generated[:4] {
		assert.Equal(t, byte(0), packet.Payload[1]&0x80)
	}
	for _, packet := range generated[4:7] {
		assert.Equal(t, byte(0x80), packet.Payload[1]&0x80)
	}
}

func TestTelephoneEventPacketizeOneShot(t *testing.T) {
	const timestamp = 90000

	oneShot := newTestTelephoneEventPacketizer(t)
	incremental := newTestTelephoneEventPacketizer(t)

	durations := []uint32{400, 800, 1200}

	fromPacketize, err := oneShot.Packetize(timestamp, codecs.TelephoneEventStar, 8, durations)
	require.NoError(t, err)

	var stepped []*Packet
	packets, err := incremental.Start(timestamp, codecs.TelephoneEventStar, 8, durations[0])
	require.NoError(t, err)
	stepped = append(stepped, packets...)
	packets, err = incremental.Update(durations[1])
	require.NoError(t, err)
	stepped = append(stepped, packets...)
	packets, err = incremental.End(durations[2])
	require.NoError(t, err)
	stepped = append(stepped, packets...)

	require.Len(t, fromPacketize, len(stepped))
	for i := range fromPacketize {
		assert.Equal(t, stepped[i], fromPacketize[i])
		assert.Equal(t, uint32(timestamp), fromPacketize[i].Timestamp, "timestamp must not advance")
		assert.Equal(t, byte(8), fromPacketize[i].Payload[1]&0x3F)
	}

	// A single duration reports first and final packet in one payload.
	oneShot = newTestTelephoneEventPacketizer(t)
	fromPacketize, err = oneShot.Packetize(timestamp, codecs.TelephoneEventPound, 0, []uint32{800})
	require.NoError(t, err)
	require.Len(t, fromPacketize, 1+DefaultTelephoneEventEndRepeat)
	assert.True(t, fromPacketize[0].Marker)
	assert.Equal(t, []byte{0x0B, 0x80, 0x03, 0x20}, fromPacketize[0].Payload)

	started, ended := oneShot.State()
	assert.True(t, started)
	assert.True(t, ended)
}

func TestTelephoneEventPayloadsOnly(t *testing.T) {
	packetizer := newTestTelephoneEventPacketizer(t)

	payloads, err := packetizer.Payloads(0, codecs.TelephoneEventDTMF3, 0, []uint32{400, 800})
	require.NoError(t, err)

	expected := [][]byte{
		{0x03, 0x00, 0x01, 0x90},
		{0x03, 0x80, 0x03, 0x20},
		{0x03, 0x80, 0x03, 0x20},
		{0x03, 0x80, 0x03, 0x20},
	}
	assert.Equal(t, expected, payloads)
}

func TestTelephoneEventEndRepeatConfigurable(t *testing.T) {
	for _, repeats := range []int{0, 1, 2, 5} {
		packetizer := newTestTelephoneEventPacketizer(t)
		packetizer.EndRepeat = repeats

		packets, err := packetizer.Start(0, codecs.TelephoneEventDTMF5, 0, 160)
		require.NoError(t, err)
		require.Len(t, packets, 1)

		final, err := packetizer.End(320)
		require.NoError(t, err)
		require.Len(t, final, 1+repeats)

		for i, packet := range final {
			assert.Equal(t, []byte{0x05, 0x80, 0x01, 0x40}, packet.Payload)
			assert.Equal(t, uint16(2+i), packet.SequenceNumber)
			assert.Equal(t, uint32(0), packet.Timestamp)
			assert.False(t, packet.Marker)
		}
	}

	// A negative repeat count is treated as zero rather than panicking.
	packetizer := newTestTelephoneEventPacketizer(t)
	packetizer.EndRepeat = -3

	_, err := packetizer.Start(0, codecs.TelephoneEventDTMF5, 0, 160)
	require.NoError(t, err)
	final, err := packetizer.End(320)
	require.NoError(t, err)
	assert.Len(t, final, 1)
}

func TestTelephoneEventLongDurationSegments(t *testing.T) {
	packetizer := newTestTelephoneEventPacketizer(t)

	// 70000 units exceeds the 16-bit duration field and must be reported as
	// segments: 0xFFFF units without the end bit, then 4465 units starting at
	// the timestamp where the previous segment ended.
	packets, err := packetizer.Start(1000, codecs.TelephoneEventDTMF7, 0, 20000)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, []byte{0x07, 0x00, 0x4E, 0x20}, packets[0].Payload)

	packets, err = packetizer.Update(0xFFFF)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, []byte{0x07, 0x00, 0xFF, 0xFF}, packets[0].Payload)
	assert.Equal(t, uint32(1000), packets[0].Timestamp)

	packets, err = packetizer.Update(70000)
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, []byte{0x07, 0x00, 0x11, 0x71}, packets[0].Payload, "4465 units")
	assert.Equal(t, uint32(1000+0xFFFF), packets[0].Timestamp)
	assert.False(t, packets[0].Marker, "only the first segment sets the marker bit")

	packets, err = packetizer.End(70000)
	require.NoError(t, err)
	require.Len(t, packets, 1+DefaultTelephoneEventEndRepeat)
	for _, packet := range packets {
		assert.Equal(t, uint32(1000+0xFFFF), packet.Timestamp)
		assert.Equal(t, byte(0x07), packet.Payload[0])
		assert.Equal(t, byte(0x80), packet.Payload[1]&0x80)
		assert.Equal(t, byte(0x11), packet.Payload[2])
		assert.Equal(t, byte(0x71), packet.Payload[3])
	}
}

func TestTelephoneEventSegmentsOnlyAtFirstUpdate(t *testing.T) {
	packetizer := newTestTelephoneEventPacketizer(t)

	// A single update that jumps straight past several segments must close the
	// current segment once and then report the remainder of the last segment.
	packets, err := packetizer.Start(0, codecs.TelephoneEventDTMF6, 0, 400)
	require.NoError(t, err)
	require.Len(t, packets, 1)

	packets, err = packetizer.Update(0xFFFF + 5000)
	require.NoError(t, err)
	require.Len(t, packets, 2)
	assert.Equal(t, []byte{0x06, 0x00, 0xFF, 0xFF}, packets[0].Payload)
	assert.Equal(t, []byte{0x06, 0x00, 0x13, 0x88}, packets[1].Payload, "5000 units")
	assert.Equal(t, uint32(0), packets[0].Timestamp)
	assert.Equal(t, uint32(0xFFFF), packets[1].Timestamp)

	// Ending within the same segment reports the end on the running segment.
	packets, err = packetizer.End(0xFFFF + 6000)
	require.NoError(t, err)
	require.Len(t, packets, 1+DefaultTelephoneEventEndRepeat)
	for _, packet := range packets {
		assert.Equal(t, []byte{0x06, 0x80, 0x17, 0x70}, packet.Payload)
		assert.Equal(t, uint32(0xFFFF), packet.Timestamp)
	}
}

func TestTelephoneEventDeterministicErrors(t *testing.T) {
	t.Run("InvalidClockRate", func(t *testing.T) {
		_, err := NewTelephoneEventPacketizer(101, 0, NewFixedSequencer(1), 0)
		assert.ErrorIs(t, err, ErrTelephoneEventInvalidClockRate)

		// A zero-valued packetizer cannot run either.
		packetizer := &TelephoneEventPacketizer{Sequencer: NewFixedSequencer(1)}
		_, err = packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 400)
		assert.ErrorIs(t, err, ErrTelephoneEventInvalidClockRate)

		_, err = packetizer.Samples(time.Second)
		assert.ErrorIs(t, err, ErrTelephoneEventInvalidClockRate)
		_, err = packetizer.Duration(8000)
		assert.ErrorIs(t, err, ErrTelephoneEventInvalidClockRate)
	})

	t.Run("NilSequencer", func(t *testing.T) {
		_, err := NewTelephoneEventPacketizer(101, 0, nil, 8000)
		assert.ErrorIs(t, err, ErrTelephoneEventNilSequencer)

		packetizer := &TelephoneEventPacketizer{ClockRate: 8000}
		_, err = packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 400)
		assert.ErrorIs(t, err, ErrTelephoneEventNilSequencer)
	})

	t.Run("VolumeOutOfRange", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Start(0, codecs.TelephoneEventDTMF1, codecs.TelephoneEventMaxVolume+1, 400)
		assert.ErrorIs(t, err, ErrTelephoneEventVolumeOutOfRange)

		// The rejected start must not leave the packetizer in progress.
		_, err = packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 400)
		assert.NoError(t, err)
	})

	t.Run("NoUpdates", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Packetize(0, codecs.TelephoneEventDTMF1, 0, nil)
		assert.ErrorIs(t, err, ErrTelephoneEventNoUpdates)

		started, _ := packetizer.State()
		assert.False(t, started)
	})

	t.Run("PacketizeRejectsRollbackBeforeEmitting", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Packetize(0, codecs.TelephoneEventDTMF1, 0, []uint32{400, 800, 600})
		assert.ErrorIs(t, err, ErrTelephoneEventDurationRollback)

		// Validation happens before any packet is generated, so the sequencer
		// and event state are untouched.
		started, ended := packetizer.State()
		assert.False(t, started)
		assert.False(t, ended)

		packets, err := packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 400)
		require.NoError(t, err)
		require.Len(t, packets, 1)
		assert.Equal(t, uint16(1), packets[0].SequenceNumber)
	})

	t.Run("PacketizeAcceptsRepeatedDuration", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)

		// A repeated duration is legal in the batch form; the duplicate report
		// is simply not emitted.
		packets, err := packetizer.Packetize(0, codecs.TelephoneEventDTMF1, 0, []uint32{400, 400, 800})
		require.NoError(t, err)
		require.Len(t, packets, 2+DefaultTelephoneEventEndRepeat)
		assert.Equal(t, []byte{0x01, 0x00, 0x01, 0x90}, packets[0].Payload)
		assert.Equal(t, []byte{0x01, 0x80, 0x03, 0x20}, packets[1].Payload)
	})

	t.Run("UpdateBeforeStart", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Update(400)
		assert.ErrorIs(t, err, ErrTelephoneEventNotStarted)
		_, err = packetizer.End(400)
		assert.ErrorIs(t, err, ErrTelephoneEventNotStarted)
	})

	t.Run("StartWhileInProgress", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 400)
		require.NoError(t, err)

		_, err = packetizer.Start(8000, codecs.TelephoneEventDTMF2, 0, 400)
		assert.ErrorIs(t, err, ErrTelephoneEventInProgress)

		// A new event is accepted once the previous one ended.
		_, err = packetizer.End(800)
		require.NoError(t, err)
		packets, err := packetizer.Start(8000, codecs.TelephoneEventDTMF2, 0, 400)
		require.NoError(t, err)
		require.Len(t, packets, 1)
		assert.Equal(t, uint32(8000), packets[0].Timestamp)
		assert.True(t, packets[0].Marker)
		assert.Equal(t, []byte{0x02, 0x00, 0x01, 0x90}, packets[0].Payload)
	})

	t.Run("UpdateAfterEnd", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 400)
		require.NoError(t, err)
		_, err = packetizer.End(800)
		require.NoError(t, err)

		_, err = packetizer.Update(1200)
		assert.ErrorIs(t, err, ErrTelephoneEventEnded)
		_, err = packetizer.End(1200)
		assert.ErrorIs(t, err, ErrTelephoneEventEnded)
	})

	t.Run("DurationRollback", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)
		_, err := packetizer.Start(0, codecs.TelephoneEventDTMF1, 0, 800)
		require.NoError(t, err)

		_, err = packetizer.Update(400)
		assert.ErrorIs(t, err, ErrTelephoneEventDurationRollback)

		// Nothing was emitted and the state is unchanged: a repeated duration
		// is a no-op and growing from the last accepted duration works.
		packets, err := packetizer.Update(800)
		require.NoError(t, err)
		assert.Empty(t, packets)

		packets, err = packetizer.Update(1200)
		require.NoError(t, err)
		require.Len(t, packets, 1)
		assert.Equal(t, []byte{0x01, 0x00, 0x04, 0xB0}, packets[0].Payload)

		// An end that rolls back is rejected and does not end the event.
		_, err = packetizer.End(1000)
		assert.ErrorIs(t, err, ErrTelephoneEventDurationRollback)
		started, ended := packetizer.State()
		assert.True(t, started)
		assert.False(t, ended)
	})

	t.Run("DurationOverflow", func(t *testing.T) {
		packetizer := newTestTelephoneEventPacketizer(t)

		// 200 hours at 8 kHz does not fit in a uint32 timestamp.
		_, err := packetizer.Samples(200 * time.Hour)
		assert.ErrorIs(t, err, ErrTelephoneEventDurationOverflow)

		_, err = packetizer.Samples(-time.Second)
		assert.ErrorIs(t, err, ErrTelephoneEventDurationOverflow)

		// One second at 8 kHz is not an overflow.
		samples, err := packetizer.Samples(time.Second)
		require.NoError(t, err)
		assert.Equal(t, uint32(8000), samples)
	})
}

func TestTelephoneEventSamplesDuration(t *testing.T) {
	packetizer := newTestTelephoneEventPacketizer(t)

	tests := []struct {
		duration time.Duration
		samples  uint32
	}{
		{0, 0},
		{time.Millisecond, 8},
		{20 * time.Millisecond, 160},
		{50 * time.Millisecond, 400},
		{time.Second, 8000},
		{time.Minute, 480000},
	}
	for _, test := range tests {
		samples, err := packetizer.Samples(test.duration)
		require.NoError(t, err)
		assert.Equal(t, test.samples, samples)

		duration, err := packetizer.Duration(test.samples)
		require.NoError(t, err)
		assert.Equal(t, test.duration, duration)
	}

	// A redefined clock rate is honored, as RFC 4733 allows.
	packetizer.ClockRate = 48000
	samples, err := packetizer.Samples(20 * time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, uint32(960), samples)
}

func TestTelephoneEventUnknownEventPassesThrough(t *testing.T) {
	packetizer := newTestTelephoneEventPacketizer(t)

	// 32 is not a DTMF digit but is a valid RFC 4733 event code, so the
	// packetizer must report it without modification.
	packets, err := packetizer.Packetize(0, 32, 4, []uint32{400, 800})
	require.NoError(t, err)
	require.NotEmpty(t, packets)
	for _, packet := range packets {
		assert.Equal(t, byte(32), packet.Payload[0])
		assert.Equal(t, byte(4), packet.Payload[1]&0x3F)
	}

	event := codecs.TelephoneEventPacket{}
	_, err = event.Unmarshal(packets[len(packets)-1].Payload)
	require.NoError(t, err)
	assert.Equal(t, uint8(32), event.Event)
	_, err = event.DTMF()
	assert.ErrorIs(t, err, codecs.ErrUnknownTelephoneEvent)
}

func TestTelephoneEventDoesNotAffectOrdinaryPacketizer(t *testing.T) {
	// Regression guard: the regular packetizer path keeps advancing samples
	// and producing ordinary RTP packets.
	packetizer := NewPacketizerWithOptions(
		1500,
		&codecs.OpusPayloader{},
		NewFixedSequencer(1),
		48000,
		WithTimestamp(90000),
	)

	packets := packetizer.Packetize([]byte{0x01, 0x02, 0x03}, 960)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(1), packets[0].SequenceNumber)
	assert.Equal(t, uint32(90000), packets[0].Timestamp)

	packets = packetizer.Packetize([]byte{0x04, 0x05, 0x06}, 960)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(2), packets[0].SequenceNumber)
	assert.Equal(t, uint32(90960), packets[0].Timestamp)
}
