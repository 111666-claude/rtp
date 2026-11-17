// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/pion/rtp/codecs"
)

const (
	// DefaultTelephoneEventEndRepeat is the number of extra times the final
	// packet of an event is retransmitted. RFC 4733 recommends that the final
	// packet be sent a total of three times, that is the packet plus two
	// retransmissions.
	DefaultTelephoneEventEndRepeat = 2

	// TelephoneEventMaxDuration is the largest duration expressible in a
	// single RFC 4733 payload. Longer events are reported as multiple segments.
	TelephoneEventMaxDuration = codecs.TelephoneEventMaxDuration
)

var (
	// ErrTelephoneEventInvalidClockRate is returned when a telephone-event
	// packetizer is configured with a clock rate of zero.
	ErrTelephoneEventInvalidClockRate = errors.New("telephone-event clock rate must be greater than zero")
	// ErrTelephoneEventNilSequencer is returned when a telephone-event
	// packetizer is configured without a sequencer.
	ErrTelephoneEventNilSequencer = errors.New("telephone-event sequencer must not be nil")
	// ErrTelephoneEventNotStarted is returned when an event is updated or ended
	// before it has been started.
	ErrTelephoneEventNotStarted = errors.New("telephone event has not been started")
	// ErrTelephoneEventInProgress is returned when an event is started while
	// another event has not been ended.
	ErrTelephoneEventInProgress = errors.New("telephone event already in progress")
	// ErrTelephoneEventEnded is returned when an ended event is updated or
	// ended again.
	ErrTelephoneEventEnded = errors.New("telephone event has already ended")
	// ErrTelephoneEventDurationRollback is returned when the cumulative
	// duration of an event would decrease.
	ErrTelephoneEventDurationRollback = errors.New("telephone-event duration must not decrease")
	// ErrTelephoneEventDurationOverflow is returned when a duration cannot be
	// represented in the packetizer's clock rate.
	ErrTelephoneEventDurationOverflow = errors.New("telephone-event duration overflows the timestamp space")
	// ErrTelephoneEventVolumeOutOfRange is returned when the volume does not
	// fit in the six bits of the payload.
	ErrTelephoneEventVolumeOutOfRange = errors.New("telephone-event volume out of range")
	// ErrTelephoneEventNoUpdates is returned when no duration updates are
	// provided for an event.
	ErrTelephoneEventNoUpdates = errors.New("telephone event requires at least one duration update")
)

// TelephoneEventPacketizer generates the sequence of RTP packets that report a
// single RFC 4733 telephony event, such as a DTMF key press.
//
// All packets generated for one event keep the RTP timestamp of the event
// start. Only the sequence number and the cumulative duration increase. The
// first packet has the marker bit set, the final packet has the end bit set and
// is retransmitted EndRepeat extra times.
//
// Durations are expressed in RTP timestamp units, so the clock rate is only
// used by Samples and Duration. RFC 4733 allows the clock rate to be redefined
// for the payload type, so any non-zero rate is accepted.
type TelephoneEventPacketizer struct {
	// PayloadType is the RTP payload type negotiated for telephone-event.
	PayloadType uint8
	// SSRC is the synchronization source of the RTP stream.
	SSRC uint32
	// Sequencer generates the sequence numbers of the generated packets.
	Sequencer Sequencer
	// EndRepeat is the number of extra times the final packet is sent.
	// A negative value is treated as zero. The constructor sets it to
	// DefaultTelephoneEventEndRepeat, so the final packet is sent three times
	// in total, as RFC 4733 recommends.
	EndRepeat int
	// ClockRate is the clock rate negotiated for the payload type.
	ClockRate uint32

	started        bool
	ended          bool
	event          uint8
	volume         uint8
	startTimestamp uint32
	segmentBase    uint32 // Cumulative duration reported by earlier segments.
	segmentOffset  uint32 // Timestamp offset of the current segment.
	segmentReport  uint32 // Duration reported within the current segment.
	lastDuration   uint32
	packetCount    int
}

// NewTelephoneEventPacketizer returns a packetizer for RFC 4733 events.
//
// A zero clock rate and a nil sequencer are rejected. EndRepeat defaults to
// DefaultTelephoneEventEndRepeat.
func NewTelephoneEventPacketizer(
	payloadType uint8,
	ssrc uint32,
	sequencer Sequencer,
	clockRate uint32,
) (*TelephoneEventPacketizer, error) {
	if clockRate == 0 {
		return nil, ErrTelephoneEventInvalidClockRate
	}
	if sequencer == nil {
		return nil, ErrTelephoneEventNilSequencer
	}

	return &TelephoneEventPacketizer{
		PayloadType: payloadType,
		SSRC:        ssrc,
		Sequencer:   sequencer,
		EndRepeat:   DefaultTelephoneEventEndRepeat,
		ClockRate:   clockRate,
	}, nil
}

// Samples converts duration to RTP timestamp units at the packetizer's clock
// rate. Durations whose conversion does not fit in a uint32 are rejected with
// ErrTelephoneEventDurationOverflow.
func (p *TelephoneEventPacketizer) Samples(duration time.Duration) (uint32, error) {
	if p.ClockRate == 0 {
		return 0, ErrTelephoneEventInvalidClockRate
	}
	if duration < 0 {
		return 0, fmt.Errorf("%w: negative duration %s", ErrTelephoneEventDurationOverflow, duration)
	}

	seconds := uint64(duration / time.Second)
	remainder := uint64(duration % time.Second)
	rate := uint64(p.ClockRate)
	if seconds > math.MaxUint32/rate {
		return 0, fmt.Errorf("%w: %s", ErrTelephoneEventDurationOverflow, duration)
	}

	samples := seconds*rate + remainder*rate/uint64(time.Second)
	if samples > math.MaxUint32 {
		return 0, fmt.Errorf("%w: %s", ErrTelephoneEventDurationOverflow, duration)
	}

	return uint32(samples), nil
}

// Duration converts timestamp units to a time.Duration at the packetizer's
// clock rate.
func (p *TelephoneEventPacketizer) Duration(samples uint32) (time.Duration, error) {
	if p.ClockRate == 0 {
		return 0, ErrTelephoneEventInvalidClockRate
	}

	return time.Duration(samples) * time.Second / time.Duration(p.ClockRate), nil
}

// State reports whether an event has been started and whether it has ended.
func (p *TelephoneEventPacketizer) State() (started, ended bool) {
	return p.started, p.ended
}

// Start begins a new event at timestamp, which is the RTP timestamp shared by
// every packet of the event, and emits its first packet.
//
// duration is the cumulative duration of the event in RTP timestamp units. It
// may be zero for events that model a state, although RFC 4733 requires
// non-zero durations for ordinary events. A duration above
// TelephoneEventMaxDuration is split into segments.
//
// Event codes 0-15 are the DTMF digits; other values are valid RFC 4733 event
// codes and are passed through unchanged. Volume is the power level in -dBm0
// and must be at most 63.
//
// Starting an event while another one is in progress is rejected, so the
// caller must always finish an event with End before starting the next one.
func (p *TelephoneEventPacketizer) Start(
	timestamp uint32,
	event uint8,
	volume uint8,
	duration uint32,
) ([]*Packet, error) {
	if err := p.begin(timestamp, event, volume); err != nil {
		return nil, err
	}

	return p.grow(duration, false)
}

// Update reports the cumulative duration of the running event and emits the
// packets needed to report the growth since the previous call.
//
// A duration equal to the last reported one emits nothing. A smaller duration
// is rejected with ErrTelephoneEventDurationRollback, which makes reordered
// updates deterministic: the packetizer state is left unchanged. Reporting a
// duration above 0xFFFF splits the event into segments as required by RFC 4733:
// a packet carrying the maximum duration without the end bit is followed by a
// segment with a new RTP timestamp.
func (p *TelephoneEventPacketizer) Update(duration uint32) ([]*Packet, error) {
	if !p.started {
		return nil, ErrTelephoneEventNotStarted
	}
	if p.ended {
		return nil, ErrTelephoneEventEnded
	}

	return p.grow(duration, false)
}

// End reports the final cumulative duration of the running event and emits the
// final packet, which has the end bit set, followed by EndRepeat
// retransmissions of that same packet.
//
// Every retransmission carries a new sequence number but keeps the RTP
// timestamp and payload of the final packet.
func (p *TelephoneEventPacketizer) End(duration uint32) ([]*Packet, error) {
	if !p.started {
		return nil, ErrTelephoneEventNotStarted
	}
	if p.ended {
		return nil, ErrTelephoneEventEnded
	}

	packets, err := p.grow(duration, true)
	if err != nil {
		return nil, err
	}

	return p.finish(packets)
}

// Packetize emits a complete event in one call. timestamp, event and volume
// have the same meaning as in Start. durations are the cumulative durations
// reported by successive packets; the last one ends the event. At least one
// duration must be provided and durations must not decrease.
//
// The packetizer must not have an event in progress.
func (p *TelephoneEventPacketizer) Packetize(
	timestamp uint32,
	event uint8,
	volume uint8,
	durations []uint32,
) ([]*Packet, error) {
	if len(durations) == 0 {
		return nil, ErrTelephoneEventNoUpdates
	}

	// Validate the whole sequence first so that an out-of-order update is
	// rejected without emitting a partial event.
	for i := 1; i < len(durations); i++ {
		if durations[i] < durations[i-1] {
			return nil, fmt.Errorf(
				"%w: %d < %d", ErrTelephoneEventDurationRollback, durations[i], durations[i-1],
			)
		}
	}

	if err := p.begin(timestamp, event, volume); err != nil {
		return nil, err
	}

	packets, err := p.grow(durations[0], len(durations) == 1)
	if err != nil {
		return nil, err
	}
	if len(durations) == 1 {
		return p.finish(packets)
	}

	for _, duration := range durations[1 : len(durations)-1] {
		more, updateErr := p.Update(duration)
		if updateErr != nil {
			return nil, updateErr
		}
		packets = append(packets, more...)
	}

	final, err := p.End(durations[len(durations)-1])
	if err != nil {
		return nil, err
	}

	return append(packets, final...), nil
}

// Payloads returns only the RFC 4733 payloads of Packetize, which is
// convenient when the caller builds RTP packets itself.
func (p *TelephoneEventPacketizer) Payloads(
	timestamp uint32,
	event uint8,
	volume uint8,
	durations []uint32,
) ([][]byte, error) {
	packets, err := p.Packetize(timestamp, event, volume, durations)
	if err != nil {
		return nil, err
	}

	payloads := make([][]byte, len(packets))
	for i, packet := range packets {
		payloads[i] = packet.Payload
	}

	return payloads, nil
}

func (p *TelephoneEventPacketizer) endRepeats() int {
	if p.EndRepeat < 0 {
		return 0
	}

	return p.EndRepeat
}

// begin validates the packetizer and event parameters and resets the state for
// a new event.
func (p *TelephoneEventPacketizer) begin(timestamp uint32, event uint8, volume uint8) error {
	if p.ClockRate == 0 {
		return ErrTelephoneEventInvalidClockRate
	}
	if p.Sequencer == nil {
		return ErrTelephoneEventNilSequencer
	}
	if volume > codecs.TelephoneEventMaxVolume {
		return fmt.Errorf("%w: %d", ErrTelephoneEventVolumeOutOfRange, volume)
	}
	if p.started && !p.ended {
		return ErrTelephoneEventInProgress
	}

	p.started = true
	p.ended = false
	p.event = event
	p.volume = volume
	p.startTimestamp = timestamp
	p.segmentBase = 0
	p.segmentOffset = 0
	p.segmentReport = 0
	p.lastDuration = 0
	p.packetCount = 0

	return nil
}

// finish appends the end retransmissions to the packets of a completed event
// and marks the packetizer as ended.
func (p *TelephoneEventPacketizer) finish(packets []*Packet) ([]*Packet, error) {
	final := packets[len(packets)-1]
	for range p.endRepeats() {
		packets = append(packets, p.retransmit(final))
	}
	p.ended = true

	return packets, nil
}

// grow emits the packets that report the growth of the event to total and
// updates the packetizer state. When end is true the final emitted packet has
// the end bit set; a segment-closing packet that carries the maximum duration
// never does, per RFC 4733.
//
// RFC 4733 section 2.5.1.4 recommends sending the final packet of each segment
// three times, so the retransmissions of a segment-closing packet are emitted
// with the rest of the update that follows it. A repeat count of zero disables
// the retransmissions, which keeps the packet count equal to the number of
// duration updates.
func (p *TelephoneEventPacketizer) grow(total uint32, end bool) ([]*Packet, error) {
	if total < p.lastDuration {
		return nil, fmt.Errorf("%w: %d < %d", ErrTelephoneEventDurationRollback, total, p.lastDuration)
	}

	var packets []*Packet

	for total-p.segmentBase > TelephoneEventMaxDuration {
		if p.segmentReport < TelephoneEventMaxDuration {
			packet, err := p.packet(TelephoneEventMaxDuration, false)
			if err != nil {
				return nil, err
			}
			packets = append(packets, packet)
			p.segmentReport = TelephoneEventMaxDuration
		}
		p.segmentBase += TelephoneEventMaxDuration
		p.segmentOffset = p.segmentBase
		p.segmentReport = 0
	}

	remaining := total - p.segmentBase
	if remaining > p.segmentReport || end || p.packetCount == 0 {
		packet, err := p.packet(remaining, end)
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
		p.segmentReport = remaining
	}
	p.lastDuration = total

	return packets, nil
}

// packet builds one RTP packet that reports duration within the current
// segment.
func (p *TelephoneEventPacketizer) packet(duration uint32, end bool) (*Packet, error) {
	event := codecs.TelephoneEvent{
		Event:    p.event,
		End:      end,
		Volume:   p.volume,
		Duration: uint16(duration), // nolint: gosec // G115, duration is at most 0xFFFF
	}
	payload, err := event.Marshal()
	if err != nil {
		return nil, err
	}

	packet := &Packet{
		Header: Header{
			Version:        2,
			Marker:         p.packetCount == 0,
			PayloadType:    p.PayloadType,
			SequenceNumber: p.Sequencer.NextSequenceNumber(),
			Timestamp:      p.startTimestamp + p.segmentOffset,
			SSRC:           p.SSRC,
		},
		Payload: payload,
	}
	p.packetCount++

	return packet, nil
}

// retransmit returns a copy of final with a fresh sequence number.
func (p *TelephoneEventPacketizer) retransmit(final *Packet) *Packet {
	payload := make([]byte, len(final.Payload))
	copy(payload, final.Payload)

	return &Packet{
		Header: Header{
			Version:        2,
			Marker:         false,
			PayloadType:    final.PayloadType,
			SequenceNumber: p.Sequencer.NextSequenceNumber(),
			Timestamp:      final.Timestamp,
			SSRC:           final.SSRC,
		},
		Payload: payload,
	}
}
