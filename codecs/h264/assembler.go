// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package h264

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/pion/rtp"
)

// DefaultMaxBufferedAccessUnits is the number of incomplete access units an
// Assembler buffers when NewAssembler is given a non-positive limit.
const DefaultMaxBufferedAccessUnits = 32

var (
	// ErrNilPacket is returned when Process is called with a nil RTP packet.
	ErrNilPacket = errors.New("h264: nil RTP packet")
	// ErrEmptyPayload is returned when Process is called with an RTP packet
	// that carries no payload.
	ErrEmptyPayload = errors.New("h264: RTP packet has an empty payload")
	// ErrAssemblerClosed is returned when Process is called after Close.
	ErrAssemblerClosed = errors.New("h264: assembler is closed")
)

var (
	errTruncatedStapA = errors.New("h264: STAP-A NALU size is truncated")
	errFuATooShort    = errors.New("h264: FU-A packet is too short")
	errFuAStartAndEnd = errors.New("h264: FU-A fragment has both start and end bits set")
	errFuANoStart     = errors.New("h264: FU-A fragment without a preceding start")
	errFuAInterrupted = errors.New("h264: FU-A sequence interrupted by another NALU")
	errFuANeverEnded  = errors.New("h264: FU-A sequence is never terminated")
	errUnhandledNALU  = errors.New("h264: NALU type is not supported")
)

// AccessUnit is a complete H264 access unit reassembled from one or more RTP
// packets. Data holds the NALUs of the access unit in decode order, packaged
// according to Assembler.IsAVC: each NALU is prefixed either with a 4-byte
// Annex-B start code or with a 4-byte big-endian length.
type AccessUnit struct {
	Timestamp uint32
	Data      []byte
}

// Assembler reassembles complete H264 access units from a stream of RTP
// packets. It combines Single NALU, STAP-A and FU-A packets (rfc6184),
// grouping packets by RTP timestamp and using the marker bit to detect the
// end of an access unit.
//
// An access unit is emitted once it is complete (marker received, sequence
// numbers contiguous) and sealed, meaning a packet of a newer access unit has
// arrived; Flush emits whatever remains at the end of a stream. This gives
// limited packet reordering a chance to resolve: out-of-order and duplicate
// packets are handled as long as they arrive while their access unit is still
// buffered, and the 16-bit sequence number may wrap at any point.
//
// Access units that can never be completed (packet loss, truncated STAP-A,
// broken FU-A chains, unsupported NALU types) are dropped without emitting
// anything and counted by DroppedAccessUnits; a broken unit never leaks
// NALUs into the next one. Note that the loss of the leading Single NALU
// packets of an access unit is not detectable from RTP alone and yields a
// truncated unit.
//
// At most MaxBufferedAccessUnits incomplete access units are kept; when a
// newer unit arrives beyond that limit the oldest incomplete unit is dropped.
// Assembler is not safe for concurrent use.
type Assembler struct {
	// IsAVC selects the packaging of AccessUnit.Data: AVC (length-prefixed)
	// when true, Annex-B (start-code-prefixed) when false.
	IsAVC bool

	maxBuffered int
	units       map[uint32]*accessUnit
	order       []uint32 // timestamps of buffered units, oldest first

	droppedUnits     uint64
	duplicatePackets uint64
	closed           bool
}

type accessUnit struct {
	timestamp uint32
	packets   map[uint16][]byte // sequence number -> payload copy
	startSeq  uint16
	markerSeq uint16
	hasMarker bool
}

// NewAssembler returns an Assembler that buffers at most
// maxBufferedAccessUnits incomplete access units. A non-positive value selects
// DefaultMaxBufferedAccessUnits.
func NewAssembler(maxBufferedAccessUnits int) *Assembler {
	if maxBufferedAccessUnits <= 0 {
		maxBufferedAccessUnits = DefaultMaxBufferedAccessUnits
	}

	return &Assembler{
		maxBuffered: maxBufferedAccessUnits,
		units:       make(map[uint32]*accessUnit),
	}
}

// Process consumes one RTP packet and returns the access units that became
// complete and sealed by it, in stream order. The packet payload is copied,
// so the caller may reuse its buffers. Dropped access units are reported
// through DroppedAccessUnits, not through the returned error: the error is
// reserved for invalid calls (nil packet, empty payload, closed assembler).
func (a *Assembler) Process(pkt *rtp.Packet) ([]AccessUnit, error) {
	if a.closed {
		return nil, ErrAssemblerClosed
	}
	if pkt == nil {
		return nil, ErrNilPacket
	}
	if len(pkt.Payload) == 0 {
		return nil, ErrEmptyPayload
	}

	au, ok := a.units[pkt.Timestamp]
	if !ok {
		au = &accessUnit{
			timestamp: pkt.Timestamp,
			packets:   make(map[uint16][]byte),
		}
		a.units[pkt.Timestamp] = au
		a.order = append(a.order, pkt.Timestamp)
	}
	au.add(pkt, a)

	return a.drain(false), nil
}

// Flush emits every buffered access unit that is complete and drops the
// incomplete ones. It should be called when the stream ends. Flush on a
// closed assembler returns nil.
func (a *Assembler) Flush() []AccessUnit {
	if a.closed {
		return nil
	}

	return a.drain(true)
}

// Reset releases all buffered state. The assembler keeps its configuration
// and counters and may keep being used. Reset on a closed assembler only
// releases state; the assembler stays closed.
func (a *Assembler) Reset() {
	a.units = make(map[uint32]*accessUnit)
	a.order = nil
}

// Close releases all buffered state and closes the assembler: subsequent
// Process calls return ErrAssemblerClosed.
func (a *Assembler) Close() error {
	a.Reset()
	a.units = nil
	a.closed = true

	return nil
}

// DroppedAccessUnits returns how many access units were dropped because they
// could not be completed or assembled.
func (a *Assembler) DroppedAccessUnits() uint64 {
	return a.droppedUnits
}

// DuplicatePackets returns how many packets were ignored because their
// sequence number was already present in their access unit.
func (a *Assembler) DuplicatePackets() uint64 {
	return a.duplicatePackets
}

// BufferedAccessUnits returns how many incomplete access units are currently
// buffered.
func (a *Assembler) BufferedAccessUnits() int {
	return len(a.order)
}

func (u *accessUnit) add(pkt *rtp.Packet, a *Assembler) {
	seq := pkt.SequenceNumber
	if _, ok := u.packets[seq]; ok {
		a.duplicatePackets++

		return
	}
	payload := make([]byte, len(pkt.Payload))
	copy(payload, pkt.Payload)
	u.packets[seq] = payload
	if pkt.Marker {
		// a second marker for the same unit is contradictory; last one wins
		u.hasMarker = true
		u.markerSeq = seq
	}
}

// complete reports whether the marker packet was received and the packets
// form a contiguous chain (mod 2^16) ending at it. The chain start is
// recorded for assemble.
func (u *accessUnit) complete() bool {
	if !u.hasMarker {
		return false
	}
	start := u.markerSeq
	for {
		prev := start - 1
		if _, ok := u.packets[prev]; !ok {
			break
		}
		start = prev
		if start == u.markerSeq { // wrapped all the way around
			break
		}
	}
	u.startSeq = start

	return true
}

// drain emits complete units from the oldest buffered one. A unit is sealed
// once a newer unit exists behind it (or when flushing); sealed incomplete
// units are dropped when flushing or when the buffer limit forces it.
func (a *Assembler) drain(flushing bool) []AccessUnit {
	var out []AccessUnit
	for len(a.order) > 0 {
		au := a.units[a.order[0]]
		sealed := flushing || len(a.order) > 1
		switch {
		case sealed && au.complete():
			data, err := au.assemble(a.IsAVC)
			a.pop()
			if err != nil {
				a.droppedUnits++

				continue
			}
			out = append(out, AccessUnit{Timestamp: au.timestamp, Data: data})
		case sealed && (flushing || len(a.order) > a.maxBuffered):
			a.droppedUnits++
			a.pop()
		default:
			return out
		}
	}

	return out
}

func (a *Assembler) pop() {
	delete(a.units, a.order[0])
	a.order = a.order[1:]
}

// assemble concatenates the NALUs of the unit in sequence order. Any
// inconsistency (truncated STAP-A, broken FU-A chain, unsupported NALU type)
// is an error and the caller drops the whole unit.
func (u *accessUnit) assemble(isAVC bool) ([]byte, error) { //nolint:cyclop
	var out []byte
	var fuBuf []byte
	var fuNALUHeader byte
	fuActive := false

	for seq := u.startSeq; ; seq++ {
		payload := u.packets[seq]
		naluType := payload[nalUnitTypeOffset] & naluTypeBitmask
		switch naluType {
		case stapaNALUType:
			if fuActive {
				return nil, errFuAInterrupted
			}
			var err error
			if out, err = unpackStapA(out, payload, isAVC); err != nil {
				return nil, err
			}
		case fuaNALUType:
			if len(payload) < fuaOverhead {
				return nil, errFuATooShort
			}
			start := payload[1]&fuStartBitmask != 0
			end := payload[1]&fuEndBitmask != 0
			switch {
			case start && end:
				return nil, errFuAStartAndEnd
			case start:
				if fuActive {
					return nil, errFuAInterrupted
				}
				fuActive = true
				fuNALUHeader = (payload[0] &^ naluTypeBitmask) | (payload[1] & naluTypeBitmask)
				fuBuf = append(fuBuf[:0], payload[fuaOverhead:]...)
			case !fuActive:
				return nil, errFuANoStart
			default:
				fuBuf = append(fuBuf, payload[fuaOverhead:]...)
			}
			if end {
				nalu := make([]byte, 0, len(fuBuf)+1)
				nalu = append(nalu, fuNALUHeader)
				nalu = append(nalu, fuBuf...)
				out = appendPackagedNALU(out, nalu, isAVC)
				fuActive = false
				fuBuf = fuBuf[:0]
			}
		default:
			if naluType == 0 || naluType >= stapbNALUType {
				return nil, fmt.Errorf("%w: %d", errUnhandledNALU, naluType)
			}
			if fuActive {
				return nil, errFuAInterrupted
			}
			out = appendPackagedNALU(out, payload, isAVC)
		}
		if seq == u.markerSeq {
			break
		}
	}
	if fuActive {
		return nil, errFuANeverEnded
	}

	return out, nil
}

func unpackStapA(out, payload []byte, isAVC bool) ([]byte, error) {
	offset := stapaHeaderSize
	for offset < len(payload) {
		if len(payload)-offset < stapaNALULengthSize {
			return nil, errTruncatedStapA
		}
		naluSize := int(binary.BigEndian.Uint16(payload[offset:]))
		offset += stapaNALULengthSize
		if naluSize == 0 || len(payload)-offset < naluSize {
			return nil, errTruncatedStapA
		}
		out = appendPackagedNALU(out, payload[offset:offset+naluSize], isAVC)
		offset += naluSize
	}

	return out, nil
}

func appendPackagedNALU(out, nalu []byte, isAVC bool) []byte {
	if isAVC {
		out = binary.BigEndian.AppendUint32(out, uint32(len(nalu))) //nolint:gosec // G115 false positive

		return append(out, nalu...)
	}

	out = append(out, 0x00, 0x00, 0x00, 0x01)

	return append(out, nalu...)
}
