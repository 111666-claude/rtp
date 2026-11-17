// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTelephoneEventMarshal(t *testing.T) {
	tests := []struct {
		name    string
		event   TelephoneEvent
		payload []byte
	}{
		{
			// RFC 4733 Table 5, first report of DTMF "9" after 50 ms: 400
			// timestamp units, no end bit.
			name:    "RFC4733Table5First9",
			event:   TelephoneEvent{Event: TelephoneEventDTMF9, Volume: 0, Duration: 400},
			payload: []byte{0x09, 0x00, 0x01, 0x90},
		},
		{
			// RFC 4733 Table 5, final report of the first "9": end bit set.
			name:    "RFC4733Table5Final9",
			event:   TelephoneEvent{Event: TelephoneEventDTMF9, End: true, Volume: 0, Duration: 1600},
			payload: []byte{0x09, 0x80, 0x06, 0x40},
		},
		{
			// RFC 4733 Table 5, first report of "1": 400 timestamp units.
			name:    "RFC4733Table5First1",
			event:   TelephoneEvent{Event: TelephoneEventDTMF1, Volume: 0, Duration: 400},
			payload: []byte{0x01, 0x00, 0x01, 0x90},
		},
		{
			// RFC 4733 Table 5, final report of "1": 2000 timestamp units.
			name:    "RFC4733Table5Final1",
			event:   TelephoneEvent{Event: TelephoneEventDTMF1, End: true, Volume: 0, Duration: 2000},
			payload: []byte{0x01, 0x80, 0x07, 0xD0},
		},
		{
			// RFC 4733 Table 5, final report of the second "1": 1760 units.
			name:    "RFC4733Table5FinalSecond1",
			event:   TelephoneEvent{Event: TelephoneEventDTMF1, End: true, Volume: 0, Duration: 1760},
			payload: []byte{0x01, 0x80, 0x06, 0xE0},
		},
		{
			name:    "VolumeAndMaximumValues",
			event:   TelephoneEvent{Event: TelephoneEventPound, End: true, Volume: 63, Duration: 0xFFFF},
			payload: []byte{0x0B, 0xBF, 0xFF, 0xFF},
		},
		{
			name:    "ZeroDurationState",
			event:   TelephoneEvent{Event: TelephoneEventStar, Volume: 10, Duration: 0},
			payload: []byte{0x0A, 0x0A, 0x00, 0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := test.event.Marshal()
			require.NoError(t, err)
			assert.Equal(t, test.payload, payload)
			assert.Equal(t, len(test.payload), test.event.MarshalSize())

			parsed, err := ParseTelephoneEvent(payload)
			require.NoError(t, err)
			assert.Equal(t, test.event, parsed)

			// MarshalTo writes into a caller-provided buffer.
			buf := make([]byte, TelephoneEventPayloadSize)
			n, err := test.event.MarshalTo(buf)
			require.NoError(t, err)
			assert.Equal(t, TelephoneEventPayloadSize, n)
			assert.Equal(t, test.payload, buf)

			// The depacketizer exposes the same fields.
			depacketizer := TelephoneEventPacket{}
			media, err := depacketizer.Unmarshal(payload)
			require.NoError(t, err)
			assert.Equal(t, payload, media)
			assert.Equal(t, test.event.Event, depacketizer.Event)
			assert.Equal(t, test.event.End, depacketizer.End)
			assert.Equal(t, test.event.Volume, depacketizer.Volume)
			assert.Equal(t, test.event.Duration, depacketizer.Duration)
		})
	}
}

func TestTelephoneEventReservedBit(t *testing.T) {
	// The R bit is ignored when parsing and cleared when marshaling.
	event, err := ParseTelephoneEvent([]byte{0x05, 0x40 | 0x80, 0x00, 0x64})
	require.NoError(t, err)
	assert.Equal(t, TelephoneEventDTMF5, event.Event)
	assert.True(t, event.End)
	assert.Equal(t, uint8(0), event.Volume)
	assert.Equal(t, uint16(100), event.Duration)

	payload, err := event.Marshal()
	require.NoError(t, err)
	assert.Equal(t, []byte{0x05, 0x80, 0x00, 0x64}, payload, "reserved bit must be cleared")
}

func TestTelephoneEventErrors(t *testing.T) {
	t.Run("NilPayload", func(t *testing.T) {
		packet := TelephoneEventPacket{}
		_, err := packet.Unmarshal(nil)
		assert.ErrorIs(t, err, errNilPacket)
	})

	for _, payload := range [][]byte{{}, {0x09}, {0x09, 0x80}, {0x09, 0x80, 0x06}} {
		t.Run("TruncatedPayload", func(t *testing.T) {
			event, err := ParseTelephoneEvent(payload)
			assert.ErrorIs(t, err, ErrTelephoneEventPayloadTooShort)
			assert.Equal(t, TelephoneEvent{}, event)

			packet := TelephoneEventPacket{}
			_, err = packet.Unmarshal(payload)
			assert.ErrorIs(t, err, ErrTelephoneEventPayloadTooShort)

			assert.False(t, packet.IsPartitionHead(payload))
			assert.False(t, packet.IsPartitionTail(true, payload))
		})
	}

	t.Run("PartitionChecks", func(t *testing.T) {
		packet := TelephoneEventPacket{}

		// Both the ongoing and the final payloads are complete partitions.
		assert.True(t, packet.IsPartitionHead([]byte{0x09, 0x00, 0x01, 0x90}))
		assert.True(t, packet.IsPartitionTail(false, []byte{0x09, 0x00, 0x01, 0x90}))
		assert.True(t, packet.IsPartitionHead([]byte{0x09, 0x80, 0x06, 0x40}))
		assert.True(t, packet.IsPartitionTail(true, []byte{0x09, 0x80, 0x06, 0x40}))
	})

	t.Run("TrailingOctetsIgnored", func(t *testing.T) {
		event, err := ParseTelephoneEvent([]byte{0x09, 0x80, 0x06, 0x40, 0xAA, 0xBB})
		require.NoError(t, err)
		assert.Equal(t, TelephoneEvent{Event: 9, End: true, Duration: 1600}, event)
	})

	t.Run("VolumeOutOfRange", func(t *testing.T) {
		event := TelephoneEvent{Event: TelephoneEventDTMF1, Volume: TelephoneEventMaxVolume + 1}
		_, err := event.Marshal()
		assert.ErrorIs(t, err, ErrTelephoneEventVolumeOutOfRange)

		buf := make([]byte, TelephoneEventPayloadSize)
		_, err = event.MarshalTo(buf)
		assert.ErrorIs(t, err, ErrTelephoneEventVolumeOutOfRange)
	})

	t.Run("ShortMarshalBuffer", func(t *testing.T) {
		event := TelephoneEvent{Event: TelephoneEventDTMF1}
		_, err := event.MarshalTo(make([]byte, TelephoneEventPayloadSize-1))
		assert.ErrorIs(t, err, ErrTelephoneEventPayloadTooShort)
	})
}

func TestTelephoneEventDTMFMapping(t *testing.T) {
	digits := []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'A', 'B', 'C', 'D'}
	for index, digit := range digits {
		event, err := TelephoneEventFromRune(digit)
		require.NoError(t, err)
		assert.Equal(t, uint8(index), event) // nolint: gosec // G115, index is 0..15
		assert.True(t, IsDTMFEvent(event))

		actual, err := TelephoneEventToRune(event)
		require.NoError(t, err)
		assert.Equal(t, digit, actual)

		decoded, err := (TelephoneEvent{Event: event}).DTMF()
		require.NoError(t, err)
		assert.Equal(t, digit, decoded)
		assert.True(t, (TelephoneEvent{Event: event}).IsDTMF())

		packet := TelephoneEventPacket{}
		_, err = packet.Unmarshal([]byte{event, 0x00, 0x00, 0x00})
		require.NoError(t, err)
		decoded, err = packet.DTMF()
		require.NoError(t, err)
		assert.Equal(t, digit, decoded)
	}

	// Event codes above the DTMF range are valid RFC 4733 events but are not
	// DTMF digits. They must be reported as unknown rather than mapped to an
	// arbitrary character, and they must still marshal and parse verbatim.
	for _, event := range []uint8{16, 32, 63, 64, 100, 255} {
		digit, err := TelephoneEventToRune(event)
		assert.ErrorIs(t, err, ErrUnknownTelephoneEvent)
		assert.Equal(t, rune(0), digit)

		isDTMF := IsDTMFEvent(event)
		assert.False(t, isDTMF)

		payload, err := (TelephoneEvent{Event: event, End: true, Duration: 800}).Marshal()
		require.NoError(t, err)
		assert.Equal(t, event, payload[0])

		parsed, err := ParseTelephoneEvent(payload)
		require.NoError(t, err)
		assert.Equal(t, event, parsed.Event)
	}

	for _, digit := range []rune{'a', 'e', '/', ' ', 0, 'F'} {
		event, err := TelephoneEventFromRune(digit)
		assert.ErrorIs(t, err, ErrUnknownTelephoneEvent)
		assert.Equal(t, uint8(0), event)
	}
}

func TestTelephoneEventPayloads(t *testing.T) {
	// A complete DTMF "5" reported at 20 ms intervals: 160, 320, 480, 640 and
	// a final 800 with the end bit, retransmitted twice.
	payloads, err := TelephoneEventPayloads(TelephoneEventDTMF5, 12, []uint32{160, 320, 480, 640, 800}, 2)
	require.NoError(t, err)

	expected := [][]byte{
		{0x05, 0x0C, 0x00, 0xA0},
		{0x05, 0x0C, 0x01, 0x40},
		{0x05, 0x0C, 0x01, 0xE0},
		{0x05, 0x0C, 0x02, 0x80},
		{0x05, 0x8C, 0x03, 0x20},
		{0x05, 0x8C, 0x03, 0x20},
		{0x05, 0x8C, 0x03, 0x20},
	}
	assert.Equal(t, expected, payloads)

	// End repeats must be independent copies: mutating one must not affect the
	// others.
	payloads[5][3] = 0xFF
	assert.Equal(t, byte(0x20), payloads[6][3])
	assert.Equal(t, byte(0x20), payloads[4][3])

	t.Run("Errors", func(t *testing.T) {
		_, err := TelephoneEventPayloads(TelephoneEventDTMF5, 0, nil, 0)
		assert.ErrorIs(t, err, ErrTelephoneEventNoUpdates)

		_, err = TelephoneEventPayloads(TelephoneEventDTMF5, TelephoneEventMaxVolume+1, []uint32{160}, 0)
		assert.ErrorIs(t, err, ErrTelephoneEventVolumeOutOfRange)

		_, err = TelephoneEventPayloads(TelephoneEventDTMF5, 0, []uint32{320, 160}, 0)
		assert.ErrorIs(t, err, ErrTelephoneEventDurationRollback)

		_, err = TelephoneEventPayloads(TelephoneEventDTMF5, 0, []uint32{TelephoneEventMaxDuration + 1}, 0)
		assert.ErrorIs(t, err, ErrTelephoneEventDurationOverflow)
	})

	t.Run("NegativeEndRepeats", func(t *testing.T) {
		payloads, err := TelephoneEventPayloads(TelephoneEventDTMF5, 0, []uint32{160}, -1)
		require.NoError(t, err)
		assert.Len(t, payloads, 1)
		assert.Equal(t, byte(0x80), payloads[0][1])
	})

	t.Run("VeryNegativeEndRepeats", func(t *testing.T) {
		// A large negative repeat count must not panic on slice allocation.
		payloads, err := TelephoneEventPayloads(TelephoneEventDTMF5, 0, []uint32{160}, -1000)
		require.NoError(t, err)
		assert.Len(t, payloads, 1)
	})
}

func TestTelephoneEventPayloader(t *testing.T) {
	payloader := &TelephoneEventPayloader{}

	payload := []byte{0x09, 0x80, 0x06, 0x40}
	payloads := payloader.Payload(100, payload)
	require.Len(t, payloads, 1)
	assert.Equal(t, payload, payloads[0])

	// The payloader copies its input.
	payloads[0][0] = 0xFF
	assert.Equal(t, byte(0x09), payload[0])

	assert.Empty(t, payloader.Payload(100, nil))
}
