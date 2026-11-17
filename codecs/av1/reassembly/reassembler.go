// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
//
// SPDX-License-Identifier: MIT

// Package reassembly assembles AV1 RTP packets into complete temporal units.
//
// The codecs.AV1Depacketizer consumes single, already ordered RTP payloads.
// AV1Reassembler takes ownership of that ordering problem: it accepts
// *rtp.Packet instances as they arrive, reorders them inside a small sequence
// number window and, at the RTP marker boundary, emits the reassembled AV1 low
// overhead bitstream of one temporal unit together with its RTP timestamp.
package reassembly

import (
	"errors"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
)

const (
	// DefaultReorderWindow is the default maximum distance, in sequence
	// numbers, between the oldest not yet consumed packet and a packet that is
	// still accepted for reordering.
	DefaultReorderWindow = 64

	// DefaultMaxTemporalUnitSize is the default maximum size, in bytes, of a
	// reassembled temporal unit (16 MiB).
	DefaultMaxTemporalUnitSize = 16 << 20

	// halfSequenceSpace is the wraparound boundary of the uint16 sequence
	// number space.
	halfSequenceSpace = 1 << 15
)

// Sentinel errors returned for malformed Push calls.
var (
	// ErrNilPacket is returned when Push is called with a nil packet.
	ErrNilPacket = errors.New("av1 reassembler: nil RTP packet")

	// ErrEmptyPayload is returned when a pushed packet carries no payload.
	ErrEmptyPayload = errors.New("av1 reassembler: empty RTP payload")
)

// Stats reports how the reassembler handled the pushed packet stream.
// All counters are cumulative over the lifetime of the reassembler.
type Stats struct {
	// Outputs is the number of temporal units emitted successfully.
	Outputs uint64
	// Duplicates is the number of buffered packets pushed a second time.
	Duplicates uint64
	// LatePackets is the number of packets dropped because their sequence
	// number was already consumed or had fallen behind the reorder window.
	LatePackets uint64
	// LostPackets is the number of sequence numbers never observed while the
	// window advanced, i.e. packets presumed lost on the network.
	LostPackets uint64
	// DiscardedUnits is the number of temporal units dropped because a
	// fragment was missing, oversized or could not be parsed.
	DiscardedUnits uint64
	// TimestampJumps is the number of times a new RTP timestamp was observed
	// before the previous temporal unit was closed with a marker bit.
	TimestampJumps uint64
	// MissingMarkers is the number of temporal units that were closed by a
	// timestamp change without ever seeing the marker bit.
	MissingMarkers uint64
	// OversizedUnits is the number of temporal units dropped because their
	// reassembled size exceeded MaxTemporalUnitSize.
	OversizedUnits uint64
	// ParseErrors is the number of packets whose payload could not be parsed
	// by codecs.AV1Depacketizer.
	ParseErrors uint64
}

// AV1Reassembler reorders AV1 RTP packets and reassembles temporal units.
//
// ReorderWindow limits how far ahead of the next expected sequence number a
// packet may arrive and still be buffered. Packets beyond the window force the
// window to advance: every skipped sequence number is counted as lost and every
// temporal unit touched by the gap is discarded at its next boundary. Packets
// arriving behind the window base are counted as late and dropped.
//
// The zero value is not usable; create one with NewAV1Reassembler.
type AV1Reassembler struct {
	reorderWindow      uint16
	maxTemporalUnitLen int

	depacketizer codecs.AV1Depacketizer

	// packets buffered for reordering, kept sorted by sequence number.
	buffer []*rtp.Packet
	// base is the sequence number of the next packet to consume.
	base uint16
	// initialized tells whether base has been seeded with the first packet.
	initialized bool

	// ts is the RTP timestamp of the temporal unit currently being assembled.
	ts uint32
	// unit accumulates the low overhead bitstream of the current temporal unit.
	unit []byte
	// corrupt marks the current temporal unit as unrecoverable.
	corrupt bool
	// assembling tells whether a temporal unit is currently in progress.
	assembling bool
	// expectContinuation mirrors the Y flag of the last processed packet: the
	// next packet must carry the Z continuation flag when it is set.
	expectContinuation bool

	stats Stats
}

// TemporalUnit is one reassembled AV1 temporal unit.
type TemporalUnit struct {
	// Payload is the AV1 low overhead bitstream (size-framed OBUs) of the
	// temporal unit.
	Payload []byte
	// Timestamp is the RTP timestamp shared by every packet of the unit.
	Timestamp uint32
}

// NewAV1Reassembler creates an AV1Reassembler.
// reorderWindow is the maximum reorder distance in packets; a zero value is
// replaced by DefaultReorderWindow. maxTemporalUnitSize bounds the reassembled
// size of a single temporal unit; a non-positive value is replaced by
// DefaultMaxTemporalUnitSize.
func NewAV1Reassembler(reorderWindow uint16, maxTemporalUnitSize int) *AV1Reassembler {
	if reorderWindow == 0 {
		reorderWindow = DefaultReorderWindow
	}
	if maxTemporalUnitSize <= 0 {
		maxTemporalUnitSize = DefaultMaxTemporalUnitSize
	}

	return &AV1Reassembler{
		reorderWindow:      reorderWindow,
		maxTemporalUnitLen: maxTemporalUnitSize,
	}
}

// Push consumes one RTP packet. When the packet (together with previously
// buffered packets) completes a temporal unit at a marker boundary, the unit is
// returned. Otherwise nil is returned and more packets are needed.
//
// A non-nil error only signals a malformed call (nil packet or empty payload).
// Packet loss, duplicates, reordering, missing markers, oversized units and
// malformed payloads are handled internally and reported through Stats.
func (r *AV1Reassembler) Push(packet *rtp.Packet) (*TemporalUnit, error) {
	if packet == nil {
		return nil, ErrNilPacket
	}

	if len(packet.Payload) == 0 {
		return nil, ErrEmptyPayload
	}

	if !r.initialized {
		// Seed the window with the first packet and let it follow the normal
		// insertion path below.
		r.base = packet.SequenceNumber
		r.initialized = true
	} else {
		// Signed distance in uint16 sequence space: negative values mean the
		// packet arrived behind the base of the window.
		distance := seqDistance(packet.SequenceNumber, r.base)
		switch {
		case distance < 0:
			// The sequence number has already been consumed, or it is too old
			// to enter the window.
			r.stats.LatePackets++

			return nil, nil //nolint:nilnil // no unit is emitted for a dropped packet.
		case distance >= int(r.reorderWindow):
			r.overflowWindow(packet, distance)
		default:
			if r.isBuffered(packet.SequenceNumber) {
				r.stats.Duplicates++

				return nil, nil //nolint:nilnil // no unit is emitted for a duplicate packet.
			}
		}
	}

	r.insert(packet)

	return r.drain()
}

// Stats returns a snapshot of the reassembler counters.
func (r *AV1Reassembler) Stats() Stats {
	return r.stats
}

// overflowWindow re-bases the window on a packet that arrived beyond it. The
// whole gap is unrecoverable: buffered packets become late, the missing
// sequences are counted as lost and the temporal unit in flight is corrupted.
func (r *AV1Reassembler) overflowWindow(packet *rtp.Packet, distance int) {
	lost := max(distance-1-len(r.buffer), 0)

	r.stats.LatePackets += uint64(len(r.buffer)) //nolint:gosec // G115
	r.stats.LostPackets += uint64(lost)          //nolint:gosec // G115
	r.buffer = nil
	r.base = packet.SequenceNumber

	if r.assembling {
		r.markCorrupt()
	}
}

// drain consumes buffered packets in sequence order. When the head sequence is
// missing, the gap is only skipped once two temporal unit boundaries are
// reachable in the buffer: a single boundary may still be completed by a
// reordered packet, while a second one proves the missing sequences belong to
// a unit that is already in the past. Window overflow remains the hard
// backstop for streams that stop producing packets.
func (r *AV1Reassembler) drain() (*TemporalUnit, error) {
	var output *TemporalUnit

	for len(r.buffer) > 0 {
		head := r.buffer[0]
		if head.SequenceNumber != r.base {
			if r.countBoundaryPackets() < 2 {
				break
			}

			// The missing sequences are not going to arrive. Skip the gap and
			// corrupt the temporal unit they belong to.
			gap := head.SequenceNumber - r.base
			r.stats.LostPackets += uint64(gap) //nolint:gosec // G115 gap is bounded by the window.
			r.base = head.SequenceNumber
			if r.assembling {
				r.markCorrupt()
			}
		}

		r.buffer = r.buffer[1:]
		r.base++

		if unit := r.processPacket(head); unit != nil {
			output = unit
		}
	}

	return output, nil
}

// countBoundaryPackets counts buffered packets that close or leave the
// temporal unit in flight, either through the marker bit or a new timestamp.
func (r *AV1Reassembler) countBoundaryPackets() int {
	boundaries := 0
	for _, packet := range r.buffer {
		if packet.Marker || (r.assembling && packet.Timestamp != r.ts) {
			boundaries++
		}
	}

	return boundaries
}

// processPacket feeds one in-order packet to the depacketizer and handles the
// temporal unit boundaries. It returns a non-nil temporal unit when the packet
// closes a valid unit, or nil when more packets are needed.
func (r *AV1Reassembler) processPacket(packet *rtp.Packet) *TemporalUnit {
	r.handleTimestampChange(packet.Timestamp)

	media, parseErr := r.depacketizer.Unmarshal(packet.Payload)
	if parseErr != nil {
		// The payload itself is malformed. The unit cannot be trusted, and the
		// depacketizer may have retained a fragment, so reset it explicitly.
		// Parse failure is reported through Stats rather than as a Push error.
		r.stats.ParseErrors++
		r.markCorrupt()
		r.depacketizer.Reset()
		r.expectContinuation = false

		return nil
	}

	r.checkContinuation()
	r.appendMedia(media)

	if !packet.Marker {
		return nil
	}

	if r.corrupt {
		r.finalizeCurrentUnit()

		return nil
	}

	return r.emitUnit()
}

// handleTimestampChange closes the temporal unit in flight when a packet with
// a new RTP timestamp arrives before the marker bit was seen.
func (r *AV1Reassembler) handleTimestampChange(timestamp uint32) {
	if !r.assembling {
		r.ts = timestamp
		r.assembling = true

		return
	}

	if timestamp == r.ts {
		return
	}

	// The previous timestamp never saw its marker and is therefore incomplete.
	r.stats.TimestampJumps++
	r.stats.MissingMarkers++
	r.finalizeCurrentUnit()
	r.ts = timestamp
	r.assembling = true
}

// checkContinuation verifies that the Z flag of the current packet matches the
// Y flag of the previous one, as required by the AV1 RTP specification. A
// mismatch means an OBU fragment was lost even when the sequence numbers are
// intact.
func (r *AV1Reassembler) checkContinuation() {
	if r.depacketizer.Z != r.expectContinuation {
		r.markCorrupt()
	}

	r.expectContinuation = r.depacketizer.Y
}

// appendMedia adds the depacketized OBUs to the temporal unit, enforcing the
// configured maximum size.
func (r *AV1Reassembler) appendMedia(media []byte) {
	if r.corrupt || len(media) == 0 {
		return
	}

	if len(r.unit)+len(media) > r.maxTemporalUnitLen {
		r.stats.OversizedUnits++
		r.markCorrupt()

		return
	}

	r.unit = append(r.unit, media...)
}

// emitUnit returns the assembled temporal unit and resets the assembly state.
func (r *AV1Reassembler) emitUnit() *TemporalUnit {
	unit := &TemporalUnit{
		Payload:   r.unit,
		Timestamp: r.ts,
	}
	r.unit = nil
	r.assembling = false
	r.corrupt = false
	r.expectContinuation = false
	r.stats.Outputs++

	return unit
}

// finalizeCurrentUnit discards the unit currently being assembled, accounting
// for it when it was corrupted, and resets the assembly state.
func (r *AV1Reassembler) finalizeCurrentUnit() {
	if r.corrupt {
		r.stats.DiscardedUnits++
	}

	r.unit = nil
	r.assembling = false
	r.corrupt = false
	r.expectContinuation = false
	r.depacketizer.Reset()
}

// markCorrupt flags the current temporal unit as unrecoverable.
func (r *AV1Reassembler) markCorrupt() {
	r.corrupt = true
}

// insert stores the packet in sequence number order. Duplicates must have been
// filtered out by the caller.
func (r *AV1Reassembler) insert(packet *rtp.Packet) {
	pos := len(r.buffer)
	for i, buffered := range r.buffer {
		if seqDistance(packet.SequenceNumber, buffered.SequenceNumber) < 0 {
			pos = i

			break
		}
	}

	r.buffer = append(r.buffer, nil)
	copy(r.buffer[pos+1:], r.buffer[pos:])
	r.buffer[pos] = packet
}

// isBuffered reports whether the sequence number is already queued.
func (r *AV1Reassembler) isBuffered(seq uint16) bool {
	for _, packet := range r.buffer {
		if packet.SequenceNumber == seq {
			return true
		}
	}

	return false
}

// seqDistance returns the signed distance from a to b in 16 bit sequence
// number space. A negative result means a is behind b.
func seqDistance(a, b uint16) int {
	diff := a - b
	if diff >= halfSequenceSpace {
		return -int(^diff + 1) //nolint:gosec // G115 result is within the int range.
	}

	return int(diff) //nolint:gosec // G115 result is within the int range.
}
