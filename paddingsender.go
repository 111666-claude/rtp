// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrInvalidMTU is returned when the MTU is too small to carry the header plus
// the minimum legal RTP padding packet.
var ErrInvalidMTU = errors.New("MTU is too small for an RTP padding packet")

// ErrInvalidTargetBytes is returned when the window target is not positive.
var ErrInvalidTargetBytes = errors.New("target bytes must be greater than zero")

// minPaddingSize is the smallest legal RTP padding length: the last padding
// byte carries the padding count, which must be in the 1-255 range.
const minPaddingSize = 1

// maxProbePacketCapacity bounds the initial allocation for a probe batch. It
// only caps slice capacity; append grows the slice if a window genuinely
// needs more packets.
const maxProbePacketCapacity = 1 << 16

// PaddingSender emits padding-only RTP packets for short-lived bandwidth
// probes. It fills a byte budget for a time window without adding any media
// payload: packets already sent as media are accounted for, and the sender
// emits legal RTP packets whose only content is RFC 3550 padding.
//
// A PaddingSender is safe for concurrent use. Media packets and probe packets
// can be produced from different goroutines; the internal byte counter and
// sequence number are updated atomically.
type PaddingSender struct {
	mu sync.Mutex

	ssrc       uint32
	mtu        uint16
	sequence   uint16
	timestamp  uint32
	clockRate  uint32
	header     Header
	mediaBytes int64
	timegen    func() time.Time
	start      time.Time
}

// PaddingSenderOption configures a PaddingSender.
type PaddingSenderOption func(*PaddingSender)

// PaddingSenderWithPayloadType sets the RTP payload type of the probe packets.
func PaddingSenderWithPayloadType(payloadType uint8) PaddingSenderOption {
	return func(s *PaddingSender) {
		s.header.PayloadType = payloadType
	}
}

// PaddingSenderWithMarker sets the marker bit of the probe packets.
func PaddingSenderWithMarker(marker bool) PaddingSenderOption {
	return func(s *PaddingSender) {
		s.header.Marker = marker
	}
}

// PaddingSenderWithHeaderTemplate copies the given header and uses it as the template for
// every probe packet. Its extension configuration (profile and extensions),
// CSRC list, marker bit and payload type are preserved; version, padding bit,
// sequence number, timestamp and SSRC are overridden per packet.
func PaddingSenderWithHeaderTemplate(header Header) PaddingSenderOption {
	return func(s *PaddingSender) {
		s.header = header.Clone()
	}
}

// PaddingSenderWithInitialTimestamp sets the RTP timestamp used by the first probe packet.
// When set, the clock is fixed and timestamps only advance through
// SetTimestamp; otherwise timestamps are derived from the injected clock and
// clock rate.
func PaddingSenderWithInitialTimestamp(timestamp uint32) PaddingSenderOption {
	return func(s *PaddingSender) {
		s.timestamp = timestamp
		s.clockRate = 0
	}
}

// PaddingSenderWithClockRate enables clock-driven timestamps at the given RTP clock rate.
// The timestamp of each probe packet is the initial timestamp advanced by the
// elapsed time since the sender was created. A zero clockRate keeps the
// timestamp fixed.
func PaddingSenderWithClockRate(clockRate uint32) PaddingSenderOption {
	return func(s *PaddingSender) {
		s.clockRate = clockRate
	}
}

// paddingSenderWithTimeGenerator overrides the wall clock. It is intended for tests that
// need a deterministic clock.
func paddingSenderWithTimeGenerator(timegen func() time.Time) PaddingSenderOption {
	return func(s *PaddingSender) {
		s.timegen = timegen
	}
}

// NewPaddingSender creates a PaddingSender that emits padding-only RTP packets
// for ssrc. initialSequence is the sequence number of the first emitted
// packet; sequence numbers are consecutive and wrap at 16 bits. mtu bounds the
// total serialized size (header plus padding) of every packet.
func NewPaddingSender(
	ssrc uint32,
	initialSequence uint16,
	mtu uint16,
	options ...PaddingSenderOption,
) *PaddingSender {
	sender := &PaddingSender{
		ssrc:      ssrc,
		mtu:       mtu,
		sequence:  initialSequence,
		clockRate: 0,
		header: Header{
			Version: 2,
		},
		timegen: time.Now,
	}

	for _, option := range options {
		option(sender)
	}

	sender.start = sender.timegen()

	return sender
}

// AddMediaBytes accounts for size bytes of media (or other non-probe) RTP
// traffic already sent in the current window. The count is subtracted from the
// probe budget on the next GeneratePadding call.
func (s *PaddingSender) AddMediaBytes(size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mediaBytes += size
}

// Reset starts a new probing window by clearing the media byte counter. The
// sequence number and timestamp configuration are retained so that probe
// packets stay in sequence with the media stream.
func (s *PaddingSender) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mediaBytes = 0
}

// SetTimestamp sets the RTP timestamp stamped on subsequent probe packets. It
// is meant for callers that drive timestamps themselves; with a clock rate
// configured, the next generated packet recomputes the timestamp from the
// clock.
func (s *PaddingSender) SetTimestamp(timestamp uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.timestamp = timestamp
}

// SetSequenceNumber sets the sequence number of the next emitted packet. This
// re-synchronizes the sender with the media packetizer after sequence numbers
// are consumed elsewhere.
func (s *PaddingSender) SetSequenceNumber(sequence uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sequence = sequence
}

// MediaBytes returns the number of bytes already accounted for in the current
// window, including both media bytes and the padding bytes emitted so far.
func (s *PaddingSender) MediaBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.mediaBytes
}

// GeneratePadding emits RTP padding packets until the window budget is
// exhausted. targetBytes is the total number of on-wire bytes the window is
// allowed to contain; bytes reported through AddMediaBytes (and padding from
// earlier calls in the same window) are deducted first.
//
// Every emitted packet carries no media payload and is a legal RTP packet:
// the padding bit is set, the padding length is between 1 and 255 bytes, and
// the serialized packet never exceeds the configured MTU. Packets use
// consecutive sequence numbers (wrapping at 16 bits), the configured SSRC,
// timestamp and header template (including extensions). When the remaining
// budget cannot fit a minimum-size packet, no packet is emitted, so the
// window is never exceeded.
//
// If ctx is canceled, generation stops after the current packet and the
// packets built so far are returned together with the context error.
func (s *PaddingSender) GeneratePadding(ctx context.Context, targetBytes int) ([]*Packet, error) {
	if targetBytes <= 0 {
		return nil, ErrInvalidTargetBytes
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	headerSize := s.header.MarshalSize()

	// A minimum packet is the fixed header plus one padding byte.
	if int(s.mtu) < headerSize+minPaddingSize {
		return nil, ErrInvalidMTU
	}

	remaining := int64(targetBytes) - s.mediaBytes
	if remaining < int64(headerSize+minPaddingSize) {
		// Budget exhausted, or too small for even one minimum packet.
		return nil, nil //nolint:nilnil // no probe packets fit the remaining budget
	}

	// Upper bound on the packet count, used only for slice capacity. Clamp it
	// so an arbitrarily large target cannot trigger a huge allocation.
	capacity := min(int(remaining/int64(headerSize+minPaddingSize)), maxProbePacketCapacity)
	packets := make([]*Packet, 0, capacity) //nolint:makezero // packets are appended below

	for remaining >= int64(headerSize+minPaddingSize) {
		if err := ctx.Err(); err != nil {
			return packets, err
		}

		// At most the MTU, and at most 255 padding bytes per packet.
		padding := int(s.mtu) - headerSize
		if maxByBudget := int(remaining) - headerSize; padding > maxByBudget {
			padding = maxByBudget
		}

		if padding > 255 { //nolint:mnd // RTP padding length is an 8-bit field
			padding = 255
		}

		packet := s.buildPacket(byte(padding)) //nolint:gosec // G115: padding is 1..255
		packets = append(packets, packet)

		packetSize := int64(headerSize + padding)
		remaining -= packetSize
		s.mediaBytes += packetSize
	}

	return packets, nil
}

// buildPacket constructs one padding-only packet with the next sequence number
// and the current timestamp. The caller holds s.mu.
func (s *PaddingSender) buildPacket(paddingSize byte) *Packet {
	header := s.header.Clone()
	header.Version = 2
	header.Padding = true
	header.SSRC = s.ssrc
	header.SequenceNumber = s.sequence
	header.Timestamp = s.currentTimestampLocked()
	header.PaddingSize = paddingSize

	s.sequence++

	return &Packet{
		Header:      header,
		PaddingSize: paddingSize,
	}
}

// currentTimestampLocked returns the timestamp to stamp on a new packet. With
// a clock rate configured it advances the base timestamp by the elapsed time;
// otherwise the fixed timestamp is returned. The caller holds s.mu.
func (s *PaddingSender) currentTimestampLocked() uint32 {
	if s.clockRate == 0 {
		return s.timestamp
	}

	elapsed := s.timegen().Sub(s.start)
	nanos := max(elapsed.Nanoseconds(), 0) // guard against a clock that jumps backwards

	advance := uint64(nanos) * uint64(s.clockRate) / uint64(time.Second)

	return s.timestamp + uint32(advance) //nolint:gosec // G115: timestamp wraps in 32 bits by design
}
