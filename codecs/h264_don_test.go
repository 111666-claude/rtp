// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildSTAPB assembles a STAP-B payload with the given first DON and NAL units.
func buildSTAPB(t *testing.T, firstDON uint16, nals ...[]byte) []byte {
	t.Helper()

	payload := []byte{stapbNALUType, 0x00, 0x00}
	binary.BigEndian.PutUint16(payload[1:3], firstDON)

	for _, nalu := range nals {
		size := make([]byte, stapaNALULengthSize)
		binary.BigEndian.PutUint16(size, uint16(len(nalu))) //nolint:gosec // test NAL units fit in 16 bits
		payload = append(payload, size...)
		payload = append(payload, nalu...)
	}

	return payload
}

// buildFUB assembles a FU-B start fragment for a NAL unit with the given DON.
func buildFUB(nalu []byte, don uint16, fragmentSize int) [][]byte {
	indicator := fubNALUType | (nalu[0] & naluRefIdcBitmask)
	nalType := nalu[0] & naluTypeBitmask

	first := []byte{indicator, fuStartBitmask | nalType, 0x00, 0x00}
	binary.BigEndian.PutUint16(first[2:4], don)
	first = append(first, nalu[1:1+fragmentSize]...)

	packets := [][]byte{first}
	rest := nalu[1+fragmentSize:]
	for len(rest) > fragmentSize {
		packets = append(packets,
			append([]byte{fuaNALUType | (nalu[0] & naluRefIdcBitmask), nalType}, rest[:fragmentSize]...))
		rest = rest[fragmentSize:]
	}

	end := []byte{fuaNALUType | (nalu[0] & naluRefIdcBitmask), fuEndBitmask | nalType}
	packets = append(packets, append(end, rest...))

	return packets
}

func TestH264DONParser_STAPB(t *testing.T) {
	nalu1 := []byte{0x67, 0x42, 0x00, 0x1f} // SPS
	nalu2 := []byte{0x68, 0xce, 0x38}       // PPS
	nalu3 := []byte{0x65, 0x88, 0x80, 0x40} // IDR slice

	parser := H264DONParser{}
	units, err := parser.Parse(buildSTAPB(t, 100, nalu1, nalu2, nalu3), 1000)
	require.NoError(t, err)
	require.Len(t, units, 3)

	// Exact NAL bytes and wire DON, with successor DONs derived modulo 65536.
	assert.Equal(t, H264NALUnit{NAL: nalu1, DON: 100}, units[0])
	assert.Equal(t, H264NALUnit{NAL: nalu2, DON: 101}, units[1])
	assert.Equal(t, H264NALUnit{NAL: nalu3, DON: 102}, units[2])
}

func TestH264DONParser_STAPB_DONWraparound(t *testing.T) {
	nalu1 := []byte{0x67, 0x01}
	nalu2 := []byte{0x68, 0x02}

	parser := H264DONParser{}
	units, err := parser.Parse(buildSTAPB(t, 65535, nalu1, nalu2), 1000)
	require.NoError(t, err)
	require.Len(t, units, 2)

	assert.Equal(t, uint16(65535), units[0].DON)
	assert.Equal(t, uint16(0), units[1].DON)
	assert.Equal(t, nalu1, units[0].NAL)
	assert.Equal(t, nalu2, units[1].NAL)
}

func TestH264DONParser_STAPB_Truncated(t *testing.T) {
	parser := H264DONParser{}

	// Header shorter than NAL header + DON.
	_, err := parser.Parse([]byte{stapbNALUType, 0x00}, 1000)
	assert.ErrorIs(t, err, errShortPacket)

	// Declared aggregation unit runs past the end of the payload.
	_, err = parser.Parse([]byte{stapbNALUType, 0x00, 0x01, 0x00, 0x05, 0x67, 0x42}, 1000)
	assert.ErrorIs(t, err, errShortPacket)

	// Truncated aggregation unit length field.
	_, err = parser.Parse([]byte{stapbNALUType, 0x00, 0x01, 0x00}, 1000)
	assert.ErrorIs(t, err, errShortPacket)

	// Zero-sized aggregation unit.
	_, err = parser.Parse([]byte{stapbNALUType, 0x00, 0x01, 0x00, 0x00}, 1000)
	assert.ErrorIs(t, err, errShortPacket)
}

func TestH264DONParser_STAPA_TruncatedAndFUAShort(t *testing.T) {
	parser := H264DONParser{}

	// STAP-A with an aggregation unit larger than the remaining payload.
	_, err := parser.Parse([]byte{stapaNALUType, 0x00, 0x05, 0x67, 0x42}, 1000)
	assert.ErrorIs(t, err, errShortPacket)

	// FU-A payload shorter than indicator + FU header.
	_, err = parser.Parse([]byte{fuaNALUType}, 1000)
	assert.ErrorIs(t, err, errShortPacket)
}

func TestH264Deinterleaver_DefaultCapacityAndPushPacketError(t *testing.T) {
	// A non-positive capacity falls back to the default window size.
	deinterleaver := NewH264Deinterleaver(0)
	assert.Equal(t, defaultWindowCap, deinterleaver.capacity)

	// Parser errors surface through the packet-level entry point.
	err := deinterleaver.PushPacket([]byte{stapbNALUType, 0x00}, 1000)
	assert.ErrorIs(t, err, errShortPacket)

	// A reorder-window rejection also surfaces through the packet entry point.
	small := NewH264Deinterleaver(1)
	require.NoError(t, small.Push(H264NALUnit{NAL: []byte{0x00}, DON: 0}))
	_, ok := small.Pop()
	require.True(t, ok)
	err = small.PushPacket([]byte{0x65, 0x09}, 1000)
	assert.Error(t, err, "synthesized DON 0 is stale against the fixed anchor 1")
}

func TestH264DONParser_FUBFollowedByFUA(t *testing.T) {
	nalu := []byte{0x65, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	packets := buildFUB(nalu, 4242, 2)
	require.Len(t, packets, 5) // FU-B start, three FU-A continuations, FU-A end

	// A second NAL split with a different fragment size exercises the same
	// builder across fragment boundaries.
	other := []byte{0x65, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	otherPackets := buildFUB(other, 4243, 3)
	require.Len(t, otherPackets, 3) // FU-B start, one FU-A continuation, FU-A end

	// First packet is really a FU-B carrying the DON.
	assert.Equal(t, byte(fubNALUType), packets[0][0]&naluTypeBitmask)
	assert.Equal(t, byte(fuStartBitmask|0x05), packets[0][1])
	assert.Equal(t, uint16(4242), uint16(packets[0][2])<<8|uint16(packets[0][3]))

	parser := H264DONParser{}

	units, err := parser.Parse(packets[0], 5000)
	require.NoError(t, err)
	assert.Empty(t, units, "start fragment must not emit a NAL unit")

	for i := 1; i < len(packets)-1; i++ {
		units, err = parser.Parse(packets[i], 5000)
		require.NoError(t, err)
		assert.Empty(t, units, "continuation fragment must not emit a NAL unit")
	}

	units, err = parser.Parse(packets[len(packets)-1], 5000)
	require.NoError(t, err)
	require.Len(t, units, 1)

	// Reassembled NAL byte-for-byte, DON taken from the FU-B.
	assert.Equal(t, nalu, units[0].NAL)
	assert.Equal(t, uint16(4242), units[0].DON)
}

func TestH264DONParser_FUB_Malformed(t *testing.T) {
	parser := H264DONParser{}

	// FU-B shorter than indicator + FU header + DON.
	_, err := parser.Parse([]byte{fubNALUType, fuStartBitmask | 0x05, 0x00}, 1000)
	assert.ErrorIs(t, err, errShortPacket)

	// FU-B without the start bit is illegal.
	_, err = parser.Parse([]byte{fubNALUType, 0x05, 0x00, 0x01, 0xaa}, 1000)
	assert.ErrorIs(t, err, errFragmentationUnitNotStart)

	// Start and end bits both set is illegal for a fragmentation unit.
	_, err = parser.Parse([]byte{
		fubNALUType, fuStartBitmask | fuEndBitmask | 0x05, 0x00, 0x01, 0xaa,
	}, 1000)
	assert.ErrorIs(t, err, errSingleFragmentationUnit)
}

func TestH264DONParser_FUA_MissingStartAndTimestampChange(t *testing.T) {
	parser := H264DONParser{}

	// Continuation without a preceding start unit.
	_, err := parser.Parse([]byte{fuaNALUType, 0x05, 0xaa, 0xbb}, 1000)
	assert.ErrorIs(t, err, errH264ExpectFragmentationStart)

	// FU-B start ...
	start := []byte{fubNALUType, fuStartBitmask | 0x05, 0x00, 0x07, 0x01, 0x02}
	_, err = parser.Parse(start, 1000)
	require.NoError(t, err)

	// ... then a continuation on a different RTP timestamp: the partial NAL is
	// dropped instead of concatenating across timestamps.
	_, err = parser.Parse([]byte{fuaNALUType, 0x05, 0x03, 0x04}, 2000)
	assert.ErrorIs(t, err, errFragmentTimestampMismatch)
	assert.Nil(t, parser.fragment, "partial fragmentation must be reset")

	// The dropped state must not silently accept later continuations.
	_, err = parser.Parse([]byte{fuaNALUType, 0x05, 0x05, 0x06}, 2000)
	assert.ErrorIs(t, err, errH264ExpectFragmentationStart)
}

func TestH264DONParser_FUAOnlyReassemblySynthesizesDON(t *testing.T) {
	// Original FU-A path (no wire DON) still reassembles and receives a
	// synthesized consecutive DON.
	indicator := byte(fuaNALUType | naluRefIdcBitmask)
	fragments := [][]byte{
		{indicator, fuStartBitmask | 0x05, 0x01, 0x02},
		{indicator, 0x05, 0x03, 0x04},
		{indicator, fuEndBitmask | 0x05, 0x05},
	}
	parser := H264DONParser{}

	for i, fragment := range fragments {
		units, err := parser.Parse(fragment, 3000)
		require.NoError(t, err)
		if i < len(fragments)-1 {
			assert.Empty(t, units)
		} else {
			require.Len(t, units, 1)
			assert.Equal(t, []byte{0x65, 0x01, 0x02, 0x03, 0x04, 0x05}, units[0].NAL)
			assert.Equal(t, uint16(0), units[0].DON)
		}
	}
}

func TestH264DONParser_LegacyPacketTypesKeepBehavior(t *testing.T) {
	parser := H264DONParser{}

	// Single NAL unit.
	units, err := parser.Parse([]byte{0x90, 0x90, 0x90}, 1000)
	require.NoError(t, err)
	require.Len(t, units, 1)
	assert.Equal(t, []byte{0x90, 0x90, 0x90}, units[0].NAL)
	assert.Equal(t, uint16(0), units[0].DON)

	// STAP-A with two aggregation units; DON values are synthesized.
	stapa := []byte{
		stapaNALUType,
		0x00, 0x02, 0x67, 0x42,
		0x00, 0x01, 0x68,
	}
	units, err = parser.Parse(stapa, 1000)
	require.NoError(t, err)
	require.Len(t, units, 2)
	assert.Equal(t, []byte{0x67, 0x42}, units[0].NAL)
	assert.Equal(t, uint16(1), units[0].DON)
	assert.Equal(t, []byte{0x68}, units[1].NAL)
	assert.Equal(t, uint16(2), units[1].DON)

	// Unknown packet types (MTAP16, MTAP24, reserved).
	_, err = parser.Parse([]byte{mtap16NALType, 0x00}, 1000)
	assert.ErrorIs(t, err, errUnhandledNALUType)

	_, err = parser.Parse([]byte{mtap24NALType, 0x00}, 1000)
	assert.ErrorIs(t, err, errUnhandledNALUType)

	_, err = parser.Parse([]byte{0xff, 0x00, 0x00}, 1000)
	assert.ErrorIs(t, err, errUnhandledNALUType)

	// Empty payload.
	_, err = parser.Parse(nil, 1000)
	assert.ErrorIs(t, err, errShortPacket)
}

func TestH264Deinterleaver_ReordersByDON(t *testing.T) {
	deinterleaver := NewH264Deinterleaver(8)

	// DON 0 can be released immediately; DON 2 must wait for the missing 1.
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x00}, DON: 0}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 2}))

	unit, ok := deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(0), unit.DON)

	_, ok = deinterleaver.Pop()
	assert.False(t, ok, "DON 1 has not arrived yet")

	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1}))

	unit, ok = deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(1), unit.DON)
	unit, ok = deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(2), unit.DON)

	_, ok = deinterleaver.Pop()
	assert.False(t, ok)
}

func TestH264Deinterleaver_Wraparound(t *testing.T) {
	deinterleaver := NewH264Deinterleaver(8)

	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0xfe}, DON: 65534}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x00}, DON: 0}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0xff}, DON: 65535}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1}))

	got := []uint16{}
	for {
		unit, ok := deinterleaver.Pop()
		if !ok {
			break
		}
		got = append(got, unit.DON)
	}

	assert.Equal(t, []uint16{65534, 65535, 0, 1}, got)
}

func TestH264Deinterleaver_DuplicateDON(t *testing.T) {
	deinterleaver := NewH264Deinterleaver(8)

	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x00}, DON: 5}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 7}))

	// Same DON while the original is buffered.
	err := deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 7})
	assert.ErrorIs(t, err, ErrDuplicateDON)

	// Pop DON 5, then re-pushing its DON is a stale duplicate.
	unit, ok := deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(5), unit.DON)

	err = deinterleaver.Push(H264NALUnit{NAL: []byte{0x00}, DON: 5})
	assert.ErrorIs(t, err, ErrNALUOutOfWindow)
}

func TestH264Deinterleaver_DuplicateDONDuringPriming(t *testing.T) {
	// While priming, an earlier DON re-anchors the window; a second push of
	// that same DON must still be rejected as a duplicate.
	deinterleaver := NewH264Deinterleaver(8)

	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 2}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1}))

	err := deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1})
	assert.ErrorIs(t, err, ErrDuplicateDON)

	// A duplicate of the later DON after the re-anchor is caught too.
	err = deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 2})
	assert.ErrorIs(t, err, ErrDuplicateDON)

	// The window content is untouched: order 1 then 2.
	unit, ok := deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(1), unit.DON)
	unit, ok = deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(2), unit.DON)
}

func TestH264Deinterleaver_OverflowAndOutOfWindow(t *testing.T) {
	deinterleaver := NewH264Deinterleaver(2)

	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x00}, DON: 0}))
	// Releasing the anchor ends priming and fixes the ordering window.
	unit, ok := deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(0), unit.DON)
	// The window may drain empty without resetting the anchor (nextDON = 1).

	// A gap larger than the two-slot window overflows the buffer.
	err := deinterleaver.Push(H264NALUnit{NAL: []byte{0x04}, DON: 4})
	assert.ErrorIs(t, err, ErrDeinterleaverFull)

	// A DON from the past half of the circular space is stale, regardless of
	// the window depth.
	err = deinterleaver.Push(H264NALUnit{NAL: []byte{0xee}, DON: 0x8001})
	assert.ErrorIs(t, err, ErrNALUOutOfWindow)

	// Units at and inside the window boundary still fit (distances 1 and 2).
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 2}))
}

func TestH264Deinterleaver_PrimingReanchorAndOverflow(t *testing.T) {
	deinterleaver := NewH264Deinterleaver(2)

	// The first transmitted unit is not the earliest in decoding order;
	// priming re-anchors the window onto the earlier DON.
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 2}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1}))

	got, ok := deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(1), got.DON)

	// An earlier DON whose re-anchor would exceed the capacity is rejected.
	small := NewH264Deinterleaver(1)
	require.NoError(t, small.Push(H264NALUnit{NAL: []byte{0x01}, DON: 1}))
	err := small.Push(H264NALUnit{NAL: []byte{0x7f}, DON: 0x7fff})
	assert.ErrorIs(t, err, ErrDeinterleaverFull)
}

func TestH264Deinterleaver_Flush(t *testing.T) {
	deinterleaver := NewH264Deinterleaver(8)

	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x00}, DON: 10}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x02}, DON: 12}))
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x01}, DON: 11}))

	flushed := deinterleaver.Flush()
	require.Len(t, flushed, 3)
	assert.Equal(t, []uint16{10, 11, 12}, []uint16{flushed[0].DON, flushed[1].DON, flushed[2].DON})
	assert.Empty(t, deinterleaver.pending)

	// After flush the next expected DON follows the last flushed unit.
	require.NoError(t, deinterleaver.Push(H264NALUnit{NAL: []byte{0x03}, DON: 13}))
}

func TestH264Deinterleaver_PushPacket_STAPB(t *testing.T) {
	nalu1 := []byte{0x67, 0x42, 0x00}
	nalu2 := []byte{0x68, 0xce}
	nalu3 := []byte{0x65, 0x88, 0x80}
	payload := buildSTAPB(t, 20, nalu1, nalu2, nalu3)

	deinterleaver := NewH264Deinterleaver(8)
	require.NoError(t, deinterleaver.PushPacket(payload, 4000))

	got := [][]byte{}
	for {
		unit, ok := deinterleaver.Pop()
		if !ok {
			break
		}
		got = append(got, unit.NAL)
	}

	assert.Equal(t, [][]byte{nalu1, nalu2, nalu3}, got)
}

func TestH264Deinterleaver_PushPacket_FUBReorder(t *testing.T) {
	// Each fragmented NAL unit is sent as one FU-B followed by FU-A
	// continuations (RFC 6184 requires the fragments to be consecutive).
	// Unit A is transmitted first but decodes after unit B, per their DON.
	naluA := []byte{0x65, 0xa1, 0xa2, 0xa3, 0xa4}
	naluB := []byte{0x41, 0xb1, 0xb2, 0xb3}

	packetsA := buildFUB(naluA, 300, 2)
	packetsB := buildFUB(naluB, 299, 2)

	deinterleaver := NewH264Deinterleaver(8)

	for _, packet := range packetsA {
		require.NoError(t, deinterleaver.PushPacket(packet, 9000))
	}
	for _, packet := range packetsB {
		require.NoError(t, deinterleaver.PushPacket(packet, 9000))
	}

	// Decoding order must put DON 299 before DON 300.
	unit, ok := deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(299), unit.DON)
	assert.Equal(t, naluB, unit.NAL)

	unit, ok = deinterleaver.Pop()
	require.True(t, ok)
	assert.Equal(t, uint16(300), unit.DON)
	assert.Equal(t, naluA, unit.NAL)

	_, ok = deinterleaver.Pop()
	assert.False(t, ok)
}

func TestH264Deinterleaver_PushPacket_MixedStream(t *testing.T) {
	// A spec-compliant interleaved stream (RFC 6184 packetization mode 2)
	// mixes STAP-B and FU-B/FU-A, every NAL carrying a wire DON. The STAP-B
	// (DON 8, 9) arrives after a fragmented unit (DON 11) and a single
	// aggregation unit wrapped in another STAP-B (DON 10).
	stapbEarly := buildSTAPB(t, 8, []byte{0x67, 0x11}, []byte{0x68, 0x22})
	stapbMid := buildSTAPB(t, 10, []byte{0x61, 0xaa, 0xbb})
	frag := []byte{0x65, 0x31, 0x32, 0x33, 0x34}
	fragPackets := buildFUB(frag, 11, 2)

	deinterleaver := NewH264Deinterleaver(8)

	// Out-of-order arrival: 11 (fragmented), then 10, then 8-9.
	for _, packet := range fragPackets {
		require.NoError(t, deinterleaver.PushPacket(packet, 7000))
	}
	require.NoError(t, deinterleaver.PushPacket(stapbMid, 7000))
	require.NoError(t, deinterleaver.PushPacket(stapbEarly, 7000))

	gotDON := []uint16{}
	gotNAL := [][]byte{}
	for {
		unit, ok := deinterleaver.Pop()
		if !ok {
			break
		}
		gotDON = append(gotDON, unit.DON)
		gotNAL = append(gotNAL, unit.NAL)
	}

	assert.Equal(t, []uint16{8, 9, 10, 11}, gotDON)
	assert.Equal(t, [][]byte{
		{0x67, 0x11},
		{0x68, 0x22},
		{0x61, 0xaa, 0xbb},
		frag,
	}, gotNAL)
}
