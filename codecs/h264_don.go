// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// NAL unit types carrying Decoding Order Number information, as defined by
// https://datatracker.ietf.org/doc/html/rfc6184#section-5.4
const (
	stapbNALUType = 25
	mtap16NALType = 26
	mtap24NALType = 27
)

// Header sizes of the interleaved packetization mode packet types, in bytes.
const (
	stapbHeaderSize  = 3 // NAL header + 16-bit DON
	fubHeaderSize    = 4 // FU indicator + FU header + 16-bit DON
	halfDonSpace     = 1 << 15
	defaultWindowCap = 64
)

var (
	// errH264ExpectFragmentationStart is returned when a FU-A/FU-B continuation
	// fragment is received without the fragmentation start unit.
	errH264ExpectFragmentationStart = errors.New("expecting a fragmentation start unit")
	// errFragmentationUnitNotStart is returned when a FU-B does not set the
	// start bit. FU-B is only legal as the first fragment of a NAL unit.
	errFragmentationUnitNotStart = errors.New("FU-B must be the first fragmentation unit")
	// errSingleFragmentationUnit is returned when a FU sets both the start and
	// end bits, which the RFC forbids.
	errSingleFragmentationUnit = errors.New("start and end bits must not both be set")
	// errFragmentTimestampMismatch is returned when a continuation fragment
	// carries a different RTP timestamp than the fragmentation start unit.
	errFragmentTimestampMismatch = errors.New("continuation fragment changed RTP timestamp")
)

var (
	// ErrDuplicateDON is returned when two NAL units carry the same DON while
	// the first one is still held in the de-interleaving window.
	ErrDuplicateDON = errors.New("duplicate H264 Decoding Order Number")
	// ErrDeinterleaverFull is returned when a NAL unit is too far ahead of the
	// expected DON to fit inside the configured reorder window.
	ErrDeinterleaverFull = errors.New("H264 de-interleaving buffer is full")
	// ErrNALUOutOfWindow is returned when a NAL unit is older (in circular DON
	// space) than the next NAL unit expected in decoding order.
	ErrNALUOutOfWindow = errors.New("H264 NAL unit arrived outside the reorder window")
)

// H264NALUnit is a complete, reassembled H264 NAL unit together with the
// 16-bit Decoding Order Number (DON) derived from its RTP packet.
//
// NAL references the packet buffer for single NAL units and aggregation
// units, and is an allocated buffer for reassembled fragmentation units.
type H264NALUnit struct {
	NAL []byte
	DON uint16
}

// h264FragmentState tracks the NAL unit currently being reassembled from
// FU-B/FU-A fragmentation units.
type h264FragmentState struct {
	don       uint16
	timestamp uint32
	header    byte
	buffer    []byte
	hasDON    bool
}

// H264DONParser parses H264 RTP payloads into complete NAL units annotated
// with their 16-bit Decoding Order Number.
//
// It handles every packet type allowed by RFC 6184: single NAL unit,
// STAP-A, STAP-B, FU-B followed by FU-A fragments, and plain FU-A
// fragmentation. DON values are read from the wire for STAP-B and FU-B,
// following the STAP-B successor rule (DON + 1 modulo 65536). Packet types
// without a wire DON (single NAL unit, STAP-A and FU-A) receive synthesized
// consecutive DON values so the output always carries a usable ordering key.
//
// The parser is stateful and not safe for concurrent use.
type H264DONParser struct {
	fragment *h264FragmentState
	lastDON  uint16
}

// nextSyntheticDON returns the DON assigned to NAL units that do not carry a
// DON field on the wire.
func (p *H264DONParser) nextSyntheticDON() uint16 {
	don := p.lastDON
	p.lastDON++

	return don
}

// resetFragment drops any partially reassembled NAL unit.
func (p *H264DONParser) resetFragment() {
	p.fragment = nil
}

// Parse consumes one H264 RTP payload and returns the complete NAL units it
// contains. A fragmentation continuation returns no units, while a completed
// fragmentation returns the single reassembled NAL unit.
//
// timestamp is the RTP timestamp of the packet and is used to reject
// continuation fragments that belong to a different NAL unit.
func (p *H264DONParser) Parse(payload []byte, timestamp uint32) ([]H264NALUnit, error) { //nolint:cyclop
	if len(payload) == 0 {
		return nil, errShortPacket
	}

	naluType := payload[0] & naluTypeBitmask

	switch {
	case naluType > 0 && naluType < stapaNALUType:
		// A NAL unit of a different type abandons an unfinished fragmentation.
		p.resetFragment()

		return []H264NALUnit{{NAL: payload, DON: p.nextSyntheticDON()}}, nil

	case naluType == stapaNALUType:
		p.resetFragment()

		return p.parseSTAPA(payload)

	case naluType == stapbNALUType:
		p.resetFragment()

		return p.parseSTAPB(payload)

	case naluType == fuaNALUType:
		return p.parseFUA(payload, timestamp)

	case naluType == fubNALUType:
		return p.parseFUB(payload, timestamp)

	default:
		// MTAP16, MTAP24 and the reserved types 0, 30 and 31 are unsupported.
		return nil, fmt.Errorf("%w: %d", errUnhandledNALUType, naluType)
	}
}

// parseSTAPA splits a STAP-A packet into its NAL units. STAP-A carries no DON
// field, so consecutive DON values are synthesized.
func (p *H264DONParser) parseSTAPA(payload []byte) ([]H264NALUnit, error) {
	units, err := parseH264AggregationUnits(payload, stapaHeaderSize)
	if err != nil {
		return nil, err
	}

	nals := make([]H264NALUnit, len(units))
	for i, nalu := range units {
		nals[i] = H264NALUnit{NAL: nalu, DON: p.nextSyntheticDON()}
	}

	return nals, nil
}

// parseSTAPB splits a STAP-B packet into its NAL units. The packet carries the
// DON of its first NAL unit; every following NAL unit's DON is the previous
// one plus one, modulo 65536 (RFC 6184 section 5.7.1).
func (p *H264DONParser) parseSTAPB(payload []byte) ([]H264NALUnit, error) {
	if len(payload) < stapbHeaderSize {
		return nil, fmt.Errorf("%w: STAP-B header needs %d bytes, got %d",
			errShortPacket, stapbHeaderSize, len(payload))
	}

	firstDON := binary.BigEndian.Uint16(payload[1:3])

	units, err := parseH264AggregationUnits(payload, stapbHeaderSize)
	if err != nil {
		return nil, err
	}

	nals := make([]H264NALUnit, len(units))
	don := firstDON

	for i, nalu := range units {
		nals[i] = H264NALUnit{NAL: nalu, DON: don}
		don++
	}

	p.lastDON = don

	return nals, nil
}

// parseH264AggregationUnits walks the aggregation units of a STAP-A or STAP-B
// payload starting after headerSize header bytes.
func parseH264AggregationUnits(payload []byte, headerSize int) ([][]byte, error) {
	units := [][]byte{}
	offset := headerSize

	for offset < len(payload) {
		if len(payload)-offset < stapaNALULengthSize {
			return nil, fmt.Errorf("%w: truncated aggregation unit length", errShortPacket)
		}

		naluSize := int(binary.BigEndian.Uint16(payload[offset : offset+stapaNALULengthSize]))
		offset += stapaNALULengthSize

		if naluSize == 0 || len(payload)-offset < naluSize {
			return nil, fmt.Errorf(
				"%w: aggregation unit declared size %d but only %d bytes remain",
				errShortPacket, naluSize, len(payload)-offset)
		}

		units = append(units, payload[offset:offset+naluSize])
		offset += naluSize
	}

	return units, nil
}

// parseFUB starts the reassembly of a fragmented NAL unit. FU-B must be the
// first fragment, so the start bit has to be set and the end bit clear.
func (p *H264DONParser) parseFUB(payload []byte, timestamp uint32) ([]H264NALUnit, error) {
	if len(payload) < fubHeaderSize {
		return nil, fmt.Errorf("%w: FU-B header needs %d bytes, got %d",
			errShortPacket, fubHeaderSize, len(payload))
	}

	fuHeader := payload[1]
	if fuHeader&fuStartBitmask == 0 {
		return nil, errFragmentationUnitNotStart
	}
	if fuHeader&fuEndBitmask != 0 {
		return nil, errSingleFragmentationUnit
	}

	don := binary.BigEndian.Uint16(payload[2:4])

	p.fragment = &h264FragmentState{
		don:       don,
		timestamp: timestamp,
		header:    (payload[0] & naluRefIdcBitmask) | (fuHeader & naluTypeBitmask),
		buffer:    append([]byte{}, payload[fubHeaderSize:]...),
		hasDON:    true,
	}
	p.lastDON = don + 1

	return nil, nil
}

// parseFUA continues or completes a fragmented NAL unit. A FU-A with the
// start bit set begins a fragmentation without a wire DON; otherwise the
// fragment must continue an active fragmentation.
func (p *H264DONParser) parseFUA(payload []byte, timestamp uint32) ([]H264NALUnit, error) {
	if len(payload) < fuaHeaderSize {
		return nil, errShortPacket
	}

	fuHeader := payload[1]

	if fuHeader&fuStartBitmask != 0 {
		if fuHeader&fuEndBitmask != 0 {
			return nil, errSingleFragmentationUnit
		}

		// A new start unit replaces any fragmentation lost before its end.
		p.fragment = &h264FragmentState{
			timestamp: timestamp,
			header:    (payload[0] & naluRefIdcBitmask) | (fuHeader & naluTypeBitmask),
			buffer:    append([]byte{}, payload[fuaHeaderSize:]...),
		}

		return nil, nil
	}

	if p.fragment == nil {
		return nil, errH264ExpectFragmentationStart
	}
	if timestamp != p.fragment.timestamp {
		p.resetFragment()

		return nil, errFragmentTimestampMismatch
	}

	p.fragment.buffer = append(p.fragment.buffer, payload[fuaHeaderSize:]...)

	if fuHeader&fuEndBitmask == 0 {
		return nil, nil
	}

	return p.completeFragment()
}

// completeFragment rebuilds the NAL unit header and releases the finished
// NAL unit together with its DON.
func (p *H264DONParser) completeFragment() ([]H264NALUnit, error) {
	fragment := p.fragment
	p.resetFragment()

	nalu := make([]byte, 0, 1+len(fragment.buffer))
	nalu = append(nalu, fragment.header)
	nalu = append(nalu, fragment.buffer...)

	don := fragment.don
	if !fragment.hasDON {
		don = p.nextSyntheticDON()
	}

	return []H264NALUnit{{NAL: nalu, DON: don}}, nil
}

// H264Deinterleaver restores NAL unit decoding order from the interleaved
// transmission order used with STAP-B/FU-B packets.
//
// NAL units are buffered while their DON is ahead of the next expected DON.
// The window holds at most capacity NAL units: a unit that would need more
// than capacity slots of buffering is rejected instead of growing the buffer
// without bound. DON comparisons use the circular 16-bit arithmetic defined
// by RFC 6184 section 5.5, so wraparound from 65535 to 0 is handled.
//
// Until the first unit is released (priming, matching the initial buffering
// described in RFC 6184 section 7.2), an earlier DON may re-anchor the
// window, because the first transmitted unit is not necessarily the first in
// decoding order. After the first Pop the anchor is fixed.
//
// The deinterleaver is not safe for concurrent use.
type H264Deinterleaver struct {
	parser   H264DONParser
	pending  []H264NALUnit
	nextDON  uint16
	started  bool
	priming  bool
	capacity int
}

// NewH264Deinterleaver creates a H264Deinterleaver whose reorder window holds
// at most capacity NAL units. A non-positive capacity defaults to 64.
func NewH264Deinterleaver(capacity int) *H264Deinterleaver {
	if capacity <= 0 {
		capacity = defaultWindowCap
	}

	return &H264Deinterleaver{capacity: capacity}
}

// donDistance returns the circular forward distance from expectedDON to don,
// in the range [0, 65535]. Values below 32768 mean don is newer than
// expectedDON; larger values mean it is older.
func donDistance(expectedDON, don uint16) uint16 {
	return don - expectedDON
}

// sortPending keeps the window ordered by circular distance from nextDON.
func (d *H264Deinterleaver) sortPending() {
	sort.Slice(d.pending, func(i, j int) bool {
		return donDistance(d.nextDON, d.pending[i].DON) <
			donDistance(d.nextDON, d.pending[j].DON)
	})
}

// Push stores a NAL unit for ordered release. The unit is accepted when its
// DON equals the next expected DON or fits inside the reorder window.
func (d *H264Deinterleaver) Push(unit H264NALUnit) error { //nolint:cyclop
	if !d.started {
		d.started = true
		d.priming = true
		d.nextDON = unit.DON
		d.pending = append(d.pending, unit)

		return nil
	}

	distance := donDistance(d.nextDON, unit.DON)

	// A DON already present in the window is always a duplicate, regardless of
	// whether priming would otherwise re-anchor onto it.
	for _, pending := range d.pending {
		if pending.DON == unit.DON {
			return ErrDuplicateDON
		}
	}

	// During priming a unit older than the tentative anchor may move the
	// anchor backwards, as long as the whole buffered span stays bounded.
	// Once priming ended (a unit was released), the anchor stays fixed even
	// if the window has been drained empty.
	switch {
	case d.priming && distance >= halfDonSpace:
		back := donDistance(unit.DON, d.nextDON)
		farthest := back + donDistance(d.nextDON, d.pending[len(d.pending)-1].DON)
		if int(back) > d.capacity || int(farthest) > d.capacity {
			return ErrDeinterleaverFull
		}

		d.nextDON = unit.DON
		distance = 0
		d.sortPending()
	case distance >= halfDonSpace:
		return ErrNALUOutOfWindow
	case int(distance) > d.capacity:
		return ErrDeinterleaverFull
	}

	insertAt := sort.Search(len(d.pending), func(i int) bool {
		return donDistance(d.nextDON, d.pending[i].DON) >= distance
	})

	d.pending = append(d.pending, H264NALUnit{})
	copy(d.pending[insertAt+1:], d.pending[insertAt:])
	d.pending[insertAt] = unit

	return nil
}

// Pop removes and returns the next NAL unit in decoding order. It returns
// false when the next expected DON has not arrived yet. The first successful
// Pop ends the priming phase and fixes the ordering anchor.
func (d *H264Deinterleaver) Pop() (H264NALUnit, bool) {
	if len(d.pending) == 0 || donDistance(d.nextDON, d.pending[0].DON) != 0 {
		return H264NALUnit{}, false
	}

	unit := d.pending[0]
	d.pending = d.pending[1:]
	d.nextDON++
	d.priming = false

	return unit, true
}

// PushPacket parses one H264 RTP payload and feeds every complete NAL unit
// into the reorder window. It is the bounded reordering entry point for a
// packet stream: parse, reassemble and buffer in a single call.
func (d *H264Deinterleaver) PushPacket(payload []byte, timestamp uint32) error {
	units, err := d.parser.Parse(payload, timestamp)
	if err != nil {
		return err
	}

	for _, unit := range units {
		if err := d.Push(unit); err != nil {
			return err
		}
	}

	return nil
}

// Flush releases every buffered NAL unit in ascending DON order and empties
// the window. Use it when the stream ends or a packet loss makes further
// in-order release impossible.
func (d *H264Deinterleaver) Flush() []H264NALUnit {
	d.sortPending()

	flushed := d.pending
	d.pending = nil
	d.priming = false

	if len(flushed) > 0 {
		d.nextDON = flushed[len(flushed)-1].DON + 1
	}

	return flushed
}
