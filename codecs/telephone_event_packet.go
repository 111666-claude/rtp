// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"fmt"
)

const (
	// TelephoneEventPayloadSize is the size in bytes of an RFC 4733
	// telephone-event payload.
	TelephoneEventPayloadSize = 4

	// TelephoneEventMaxVolume is the maximum volume value expressible in the
	// 6-bit volume field. Larger values denote lower volume.
	TelephoneEventMaxVolume = 0x3F

	// TelephoneEventMaxDuration is the largest duration expressible in the
	// 16-bit duration field.
	TelephoneEventMaxDuration = 0xFFFF

	// TelephoneEventDTMF0 is the event code for the DTMF digit 0.
	TelephoneEventDTMF0 uint8 = 0
	// TelephoneEventDTMF1 is the event code for the DTMF digit 1.
	TelephoneEventDTMF1 uint8 = 1
	// TelephoneEventDTMF2 is the event code for the DTMF digit 2.
	TelephoneEventDTMF2 uint8 = 2
	// TelephoneEventDTMF3 is the event code for the DTMF digit 3.
	TelephoneEventDTMF3 uint8 = 3
	// TelephoneEventDTMF4 is the event code for the DTMF digit 4.
	TelephoneEventDTMF4 uint8 = 4
	// TelephoneEventDTMF5 is the event code for the DTMF digit 5.
	TelephoneEventDTMF5 uint8 = 5
	// TelephoneEventDTMF6 is the event code for the DTMF digit 6.
	TelephoneEventDTMF6 uint8 = 6
	// TelephoneEventDTMF7 is the event code for the DTMF digit 7.
	TelephoneEventDTMF7 uint8 = 7
	// TelephoneEventDTMF8 is the event code for the DTMF digit 8.
	TelephoneEventDTMF8 uint8 = 8
	// TelephoneEventDTMF9 is the event code for the DTMF digit 9.
	TelephoneEventDTMF9 uint8 = 9
	// TelephoneEventStar is the event code for the DTMF digit *.
	TelephoneEventStar uint8 = 10
	// TelephoneEventPound is the event code for the DTMF digit #.
	TelephoneEventPound uint8 = 11
	// TelephoneEventDTMFA is the event code for the DTMF digit A.
	TelephoneEventDTMFA uint8 = 12
	// TelephoneEventDTMFB is the event code for the DTMF digit B.
	TelephoneEventDTMFB uint8 = 13
	// TelephoneEventDTMFC is the event code for the DTMF digit C.
	TelephoneEventDTMFC uint8 = 14
	// TelephoneEventDTMFD is the event code for the DTMF digit D.
	TelephoneEventDTMFD uint8 = 15

	// TelephoneEventMaxDTMF is the largest DTMF event code (D). RFC 4733
	// reserves event codes above this value for other telephony events.
	TelephoneEventMaxDTMF = TelephoneEventDTMFD

	telephoneEventEndMask    = 0x80
	telephoneEventVolumeMask = 0x3F
)

// TelephoneEvent is an RFC 4733 telephony event payload.
//
// The payload is four octets:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|     event     |E|R| volume    |          duration             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The R (reserved) bit is ignored when parsing and is always cleared when
// marshaling, as required by RFC 4733.
type TelephoneEvent struct {
	// Event is the telephony event code. Values 0-15 are the DTMF digits.
	Event uint8
	// End indicates that this payload contains the end of the event.
	End bool
	// Volume is the power level in -dBm0 after dropping the sign (0-63).
	Volume uint8
	// Duration is the duration of the event in RTP timestamp units.
	Duration uint16
}

// IsDTMF reports whether the event code is one of the DTMF digits defined by
// RFC 4733 (0-9, *, #, A-D).
func (e TelephoneEvent) IsDTMF() bool {
	return IsDTMFEvent(e.Event)
}

// IsDTMFEvent reports whether event is one of the DTMF digits defined by
// RFC 4733 (0-9, *, #, A-D).
func IsDTMFEvent(event uint8) bool {
	return event <= TelephoneEventMaxDTMF
}

// DTMF returns the DTMF digit represented by the event. An event code that is
// not a DTMF digit results in ErrUnknownTelephoneEvent.
func (e TelephoneEvent) DTMF() (rune, error) {
	return TelephoneEventToRune(e.Event)
}

// TelephoneEventToRune maps an RFC 4733 DTMF event code to its character.
// Event codes that are not DTMF digits result in ErrUnknownTelephoneEvent.
func TelephoneEventToRune(event uint8) (rune, error) {
	switch {
	case event <= TelephoneEventDTMF9:
		return rune('0') + rune(event), nil // nolint: gosec // G115, event is <= 9
	case event == TelephoneEventStar:
		return '*', nil
	case event == TelephoneEventPound:
		return '#', nil
	case event <= TelephoneEventMaxDTMF:
		return rune('A') + rune(event-TelephoneEventDTMFA), nil
	default:
		return 0, fmt.Errorf("%w: event %d", ErrUnknownTelephoneEvent, event)
	}
}

// TelephoneEventFromRune maps a DTMF character to its RFC 4733 event code.
// Characters that are not DTMF digits result in ErrUnknownTelephoneEvent.
func TelephoneEventFromRune(digit rune) (uint8, error) {
	switch {
	case digit >= '0' && digit <= '9':
		return uint8(digit - '0'), nil // nolint: gosec // G115, digit is in '0'..'9'
	case digit == '*':
		return TelephoneEventStar, nil
	case digit == '#':
		return TelephoneEventPound, nil
	case digit >= 'A' && digit <= 'D':
		return uint8(digit-'A') + TelephoneEventDTMFA, nil // nolint: gosec // G115, digit is in 'A'..'D'
	default:
		return 0, fmt.Errorf("%w: digit %q", ErrUnknownTelephoneEvent, digit)
	}
}

// Verify checks the field values that cannot be represented on the wire.
//
// Event codes above TelephoneEventMaxDTMF are accepted because RFC 4733
// defines telephony events other than DTMF; use IsDTMF to distinguish them.
func (e TelephoneEvent) Verify() error {
	if e.Volume > TelephoneEventMaxVolume {
		return fmt.Errorf("%w: %d", ErrTelephoneEventVolumeOutOfRange, e.Volume)
	}

	return nil
}

// MarshalSize returns the size of the marshaled event payload in bytes.
func (e TelephoneEvent) MarshalSize() int {
	return TelephoneEventPayloadSize
}

// Marshal returns the RFC 4733 encoding of the event.
func (e TelephoneEvent) Marshal() ([]byte, error) {
	buf := make([]byte, TelephoneEventPayloadSize)
	if _, err := e.MarshalTo(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

// MarshalTo writes the RFC 4733 encoding of the event into buf and returns the
// number of bytes written. The reserved bit is cleared and the end bit is set
// according to End.
func (e TelephoneEvent) MarshalTo(buf []byte) (int, error) {
	if err := e.Verify(); err != nil {
		return 0, err
	}
	if len(buf) < TelephoneEventPayloadSize {
		return 0, ErrTelephoneEventPayloadTooShort
	}

	buf[0] = e.Event
	buf[1] = e.Volume & telephoneEventVolumeMask
	if e.End {
		buf[1] |= telephoneEventEndMask
	}
	binary.BigEndian.PutUint16(buf[2:4], e.Duration)

	return TelephoneEventPayloadSize, nil
}

// Unmarshal parses an RFC 4733 event payload. The payload must contain at
// least four octets; any trailing octets are ignored. The reserved bit is
// ignored.
func (e *TelephoneEvent) Unmarshal(payload []byte) error {
	if len(payload) < TelephoneEventPayloadSize {
		return ErrTelephoneEventPayloadTooShort
	}

	e.Event = payload[0]
	e.End = payload[1]&telephoneEventEndMask != 0
	e.Volume = payload[1] & telephoneEventVolumeMask
	e.Duration = binary.BigEndian.Uint16(payload[2:4])

	return nil
}

// ParseTelephoneEvent parses an RFC 4733 event payload.
func ParseTelephoneEvent(payload []byte) (TelephoneEvent, error) {
	event := TelephoneEvent{}
	err := event.Unmarshal(payload)

	return event, err
}

// TelephoneEventPayloader payloads RFC 4733 telephone-event payloads.
//
// Telephone-event payloads are always four octets, so they are never
// fragmented. The MTU is ignored.
type TelephoneEventPayloader struct{}

// Payload copies a telephone-event payload into a single RTP payload.
func (*TelephoneEventPayloader) Payload(_ uint16, payload []byte) [][]byte {
	if payload == nil {
		return [][]byte{}
	}

	out := make([]byte, len(payload))
	copy(out, payload)

	return [][]byte{out}
}

// TelephoneEventPacket represents the telephone-event payload stored in an RTP
// packet. It implements the Depacketizer interface.
type TelephoneEventPacket struct {
	// Payload is the raw RTP payload.
	Payload []byte
	// Event is the telephony event code.
	Event uint8
	// End indicates that the packet contains the end of the event.
	End bool
	// Volume is the power level of the event in -dBm0 (0-63).
	Volume uint8
	// Duration is the event duration in RTP timestamp units.
	Duration uint16
}

// Unmarshal parses the passed RTP payload and stores the result in the
// TelephoneEventPacket. It returns the payload unchanged, since the event
// itself is the media.
func (p *TelephoneEventPacket) Unmarshal(packet []byte) ([]byte, error) {
	if packet == nil {
		return nil, errNilPacket
	}

	event := TelephoneEvent{}
	if err := event.Unmarshal(packet); err != nil {
		return nil, err
	}

	p.Payload = packet
	p.Event = event.Event
	p.End = event.End
	p.Volume = event.Volume
	p.Duration = event.Duration

	return packet, nil
}

// IsPartitionHead reports whether payload starts a new telephony event. Every
// complete telephone-event payload is a partition of its own, so this only
// rejects truncated payloads.
func (*TelephoneEventPacket) IsPartitionHead(payload []byte) bool {
	return len(payload) >= TelephoneEventPayloadSize
}

// DTMF returns the DTMF digit represented by the parsed event. An event code
// that is not a DTMF digit results in ErrUnknownTelephoneEvent.
func (p *TelephoneEventPacket) DTMF() (rune, error) {
	return TelephoneEventToRune(p.Event)
}

// IsPartitionTail reports whether payload is a complete telephone-event
// payload. Each payload is self-contained, so, like other audio codecs, every
// complete payload is a partition tail regardless of the end bit. The end bit
// itself is available as End.
func (*TelephoneEventPacket) IsPartitionTail(_ bool, payload []byte) bool {
	return len(payload) >= TelephoneEventPayloadSize
}

// TelephoneEventPayloads builds the payloads that report a complete telephony
// event. durations are the cumulative durations, in RTP timestamp units,
// reported by successive payloads; they must not decrease and must fit in a
// single payload (at most 0xFFFF). The final payload has the end bit set and is
// repeated endRepeats extra times, as RFC 4733 recommends. A negative
// endRepeats is treated as zero.
//
// The payloads are returned in transmission order. Use TelephoneEventPayloads
// when only the event payloads are needed; use rtp.TelephoneEventPacketizer
// when RTP headers (timestamp, sequence number and marker bit) are needed too.
func TelephoneEventPayloads(
	event uint8,
	volume uint8,
	durations []uint32,
	endRepeats int,
) ([][]byte, error) {
	if len(durations) == 0 {
		return nil, ErrTelephoneEventNoUpdates
	}
	if volume > TelephoneEventMaxVolume {
		return nil, fmt.Errorf("%w: %d", ErrTelephoneEventVolumeOutOfRange, volume)
	}

	if endRepeats < 0 {
		endRepeats = 0
	}

	payloads := make([][]byte, 0, len(durations)+endRepeats)
	last := uint32(0)
	for i, duration := range durations {
		if duration < last {
			return nil, fmt.Errorf("%w: %d < %d", ErrTelephoneEventDurationRollback, duration, last)
		}
		if duration > TelephoneEventMaxDuration {
			return nil, fmt.Errorf("%w: %d", ErrTelephoneEventDurationOverflow, duration)
		}
		last = duration

		payload, err := TelephoneEvent{
			Event:    event,
			End:      i == len(durations)-1,
			Volume:   volume,
			Duration: uint16(duration), // nolint: gosec // G115, checked above
		}.Marshal()
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, payload)
	}

	if endRepeats > 0 {
		final := payloads[len(payloads)-1]
		for range endRepeats {
			repeat := make([]byte, len(final))
			copy(repeat, final)
			payloads = append(payloads, repeat)
		}
	}

	return payloads, nil
}
