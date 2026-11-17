// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package reassembly

import (
	"fmt"
	"testing"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/rtp/codecs/av1/obu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildOBU constructs a size-framed AV1 OBU for testing.
func buildOBU(t *testing.T, obuType obu.Type, payload []byte) []byte {
	t.Helper()

	header := obu.Header{Type: obuType, HasSizeField: true}
	out := append(header.Marshal(), obu.WriteToLeb128(uint(len(payload)))...)
	out = append(out, payload...)

	return out
}

// packetizeTU splits an AV1 temporal unit into RTP packets using the real
// codecs.AV1Payloader. Only the last packet carries the marker bit.
func packetizeTU(t *testing.T, startSeq uint16, ts uint32, mtu uint16, unit []byte) []*rtp.Packet {
	t.Helper()

	payloader := &codecs.AV1Payloader{}
	payloads := payloader.Payload(mtu, unit)
	require.NotEmpty(t, payloads, "payloader produced no packets")

	packets := make([]*rtp.Packet, 0, len(payloads))
	for i, payload := range payloads {
		packets = append(packets, &rtp.Packet{
			Header: rtp.Header{
				SequenceNumber: startSeq + uint16(i), //nolint:gosec // G115 test sequences do not overflow here.
				Timestamp:      ts,
				Marker:         i == len(payloads)-1,
				PayloadType:    96,
				SSRC:           1,
			},
			Payload: payload,
		})
	}

	return packets
}

// pushAll pushes every packet and returns the last non-nil temporal unit.
func pushAll(t *testing.T, reassembler *AV1Reassembler, packets []*rtp.Packet) *TemporalUnit {
	t.Helper()

	var output *TemporalUnit
	for _, packet := range packets {
		unit, err := reassembler.Push(packet)
		require.NoError(t, err)
		if unit != nil {
			output = unit
		}
	}

	return output
}

// sampleTemporalUnit builds a temporal unit large enough to be split into at
// least three RTP packets, including a sequence header and tile groups.
func sampleTemporalUnit(t *testing.T) []byte {
	t.Helper()

	unit := buildOBU(t, obu.OBUSequenceHeader, []byte{0x10, 0x11, 0x12})
	unit = append(unit, buildOBU(t, obu.OBUFrameHeader, []byte{0x20, 0x21})...)
	unit = append(unit, buildOBU(t, obu.OBUTileGroup, make([]byte, 120))...)
	unit = append(unit, buildOBU(t, obu.OBUFrame, make([]byte, 120))...)

	return unit
}

func TestAV1Reassembler_threePacketOBUFragments(t *testing.T) {
	// A small MTU forces the large OBUs into multiple fragments; with this
	// payload and MTU the payloader emits more than three packets and at least
	// one OBU is split across three packets.
	const mtu = 40

	unit := sampleTemporalUnit(t)
	packets := packetizeTU(t, 1000, 90000, mtu, unit)
	require.GreaterOrEqual(t, len(packets), 3)

	reassembler := NewAV1Reassembler(0, 0)
	output := pushAll(t, reassembler, packets)

	require.NotNil(t, output)
	assert.Equal(t, uint32(90000), output.Timestamp)
	assert.Equal(t, unit, output.Payload, "reassembled bytes must match the temporal unit")
	assert.Equal(t, Stats{Outputs: 1}, reassembler.Stats())
}

func TestAV1Reassembler_inOrderMultipleUnits(t *testing.T) {
	const mtu = 100

	unit1 := append(buildOBU(t, obu.OBUSequenceHeader, []byte{1, 2}),
		buildOBU(t, obu.OBUTileGroup, make([]byte, 60))...)
	unit2 := append(buildOBU(t, obu.OBUFrameHeader, []byte{3, 4}),
		buildOBU(t, obu.OBUFrame, make([]byte, 60))...)

	packets1 := packetizeTU(t, 0, 1000, mtu, unit1)
	packets2 := packetizeTU(t, uint16(len(packets1)), 2000, mtu, unit2) //nolint:gosec // G115

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)

	var outputs []*TemporalUnit
	for _, packet := range append(packets1, packets2...) {
		unit, err := reassembler.Push(packet)
		require.NoError(t, err)
		if unit != nil {
			outputs = append(outputs, unit)
		}
	}

	require.Len(t, outputs, 2)
	assert.Equal(t, unit1, outputs[0].Payload)
	assert.Equal(t, uint32(1000), outputs[0].Timestamp)
	assert.Equal(t, unit2, outputs[1].Payload)
	assert.Equal(t, uint32(2000), outputs[1].Timestamp)
	assert.Equal(t, uint64(2), reassembler.Stats().Outputs)
}

func TestAV1Reassembler_reorderedPackets(t *testing.T) {
	const mtu = 40

	unit := sampleTemporalUnit(t)
	packets := packetizeTU(t, 500, 3000, mtu, unit)
	require.Greater(t, len(packets), 2)

	// Swap the second and third packets to introduce disorder within the unit.
	packets[1], packets[2] = packets[2], packets[1]

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)
	output := pushAll(t, reassembler, packets)

	require.NotNil(t, output)
	assert.Equal(t, unit, output.Payload, "reordered packets must reassemble identically")
	assert.Equal(t, Stats{Outputs: 1}, reassembler.Stats())
}

func TestAV1Reassembler_reorderedAcrossUnits(t *testing.T) {
	const mtu = 40

	unit1 := buildOBU(t, obu.OBUTileGroup, make([]byte, 120))
	unit2 := buildOBU(t, obu.OBUFrame, make([]byte, 120))

	packets1 := packetizeTU(t, 10, 7000, mtu, unit1)
	packets2 := packetizeTU(t, 10+uint16(len(packets1)), 8000, mtu, unit2) //nolint:gosec // G115
	require.Greater(t, len(packets1), 1)
	require.Greater(t, len(packets2), 1)

	packets := make([]*rtp.Packet, 0, len(packets1)+len(packets2))
	packets = append(packets, packets1...)
	packets = append(packets, packets2...)

	// Deliver the first packet of the second unit before the last packet of
	// the first unit: disorder crosses a temporal unit boundary.
	last := len(packets) - 1
	packets[last-1], packets[last] = packets[last], packets[last-1]

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)
	outputs := make([]*TemporalUnit, 0, 2)
	for _, packet := range packets {
		unit, err := reassembler.Push(packet)
		require.NoError(t, err)
		if unit != nil {
			outputs = append(outputs, unit)
		}
	}

	require.Len(t, outputs, 2)
	assert.Equal(t, unit1, outputs[0].Payload)
	assert.Equal(t, unit2, outputs[1].Payload)
	assert.Equal(t, Stats{Outputs: 2}, reassembler.Stats())
}

func TestAV1Reassembler_missingFragment(t *testing.T) {
	const mtu = 40

	unit1 := sampleTemporalUnit(t)
	unit2 := buildOBU(t, obu.OBUFrame, make([]byte, 120))

	packets1 := packetizeTU(t, 200, 4000, mtu, unit1)
	packets2 := packetizeTU(t, 200+uint16(len(packets1)), 5000, mtu, unit2) //nolint:gosec // G115
	require.Greater(t, len(packets1), 3)

	// Drop a middle packet of unit1: the unit must be discarded, not emitted
	// corrupted. The following unit triggers recovery at the next boundary.
	delivered := append([]*rtp.Packet{}, packets1[0])
	delivered = append(delivered, packets1[2:]...)
	delivered = append(delivered, packets2...)

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)
	outputs := make([]*TemporalUnit, 0)
	for _, packet := range delivered {
		unit, err := reassembler.Push(packet)
		require.NoError(t, err)
		if unit != nil {
			outputs = append(outputs, unit)
		}
	}

	require.Len(t, outputs, 1, "only the intact second unit is emitted")
	assert.Equal(t, unit2, outputs[0].Payload)
	assert.Equal(t, uint64(1), reassembler.Stats().LostPackets)
	assert.Equal(t, uint64(1), reassembler.Stats().DiscardedUnits)
	assert.Equal(t, uint64(1), reassembler.Stats().Outputs)
	assert.Equal(t, packets2[len(packets2)-1].SequenceNumber+1, reassembler.base,
		"window must resume and consume the whole recovery unit")
}

func TestAV1Reassembler_recoversAtNextBoundary(t *testing.T) {
	const mtu = 40

	unit1 := append(buildOBU(t, obu.OBUSequenceHeader, []byte{9}),
		buildOBU(t, obu.OBUTileGroup, make([]byte, 120))...)
	unit2 := buildOBU(t, obu.OBUFrame, make([]byte, 120))

	packets1 := packetizeTU(t, 300, 5000, mtu, unit1)
	packets2 := packetizeTU(t, 300+uint16(len(packets1)+1), 6000, mtu, unit2) //nolint:gosec // G115
	require.Greater(t, len(packets1), 1)

	// Drop the last packet of unit1 (its marker disappears with it), then
	// deliver unit2 intact. Unit1 is lost, unit2 must still be emitted.
	packets := make([]*rtp.Packet, 0, len(packets1)+len(packets2))
	packets = append(packets, packets1[:len(packets1)-1]...)
	packets = append(packets, packets2...)

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)
	outputs := make([]*TemporalUnit, 0)
	for _, packet := range packets {
		unit, err := reassembler.Push(packet)
		require.NoError(t, err)
		if unit != nil {
			outputs = append(outputs, unit)
		}
	}

	require.Len(t, outputs, 1)
	assert.Equal(t, unit2, outputs[0].Payload)
	assert.Equal(t, uint32(6000), outputs[0].Timestamp)
	stats := reassembler.Stats()
	assert.Equal(t, uint64(1), stats.DiscardedUnits)
	assert.Equal(t, uint64(1), stats.MissingMarkers)
	assert.Equal(t, uint64(1), stats.TimestampJumps)
	assert.Equal(t, uint64(2), stats.LostPackets)
	assert.Equal(t, uint64(1), stats.Outputs)
}

func TestAV1Reassembler_duplicatePackets(t *testing.T) {
	const mtu = 40

	unit1 := buildOBU(t, obu.OBUTileGroup, make([]byte, 120))
	unit2 := buildOBU(t, obu.OBUFrame, make([]byte, 120))

	packets1 := packetizeTU(t, 400, 9000, mtu, unit1)
	packets2 := packetizeTU(t, 400+uint16(len(packets1)), 10000, mtu, unit2) //nolint:gosec // G115
	require.Greater(t, len(packets1), 2)

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)

	// Feed the unit in order, but retransmit the second packet twice: the
	// first copy is consumed normally, every later copy is late and dropped.
	outputs := make([]*TemporalUnit, 0, 2)
	feed := func(packet *rtp.Packet) {
		unit, pushErr := reassembler.Push(packet)
		require.NoError(t, pushErr)
		if unit != nil {
			outputs = append(outputs, unit)
		}
	}

	feed(packets1[0])
	feed(packets1[1])
	feed(packets1[1]) // late retransmission
	for _, packet := range packets1[2:] {
		feed(packet)
	}
	for _, packet := range packets2 {
		feed(packet)
	}
	feed(packets2[0]) // late retransmission of an already consumed packet

	require.Len(t, outputs, 2)
	assert.Equal(t, unit1, outputs[0].Payload)
	assert.Equal(t, unit2, outputs[1].Payload)
	assert.Zero(t, reassembler.Stats().Duplicates)
	assert.Equal(t, uint64(2), reassembler.Stats().LatePackets)
	assert.Equal(t, uint64(2), reassembler.Stats().Outputs)
}

func TestAV1Reassembler_bufferedDuplicate(t *testing.T) {
	// Use single-packet temporal units so the buffered packet has Z=0 and the
	// continuation flags stay consistent.
	unit := buildOBU(t, obu.OBUTileGroup, make([]byte, 20))
	packets := packetizeTU(t, 400, 9000, 200, unit)
	require.Len(t, packets, 1)
	basePacket := packets[0]
	basePacket.Marker = false

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)

	// Sequence 400 establishes the base.
	out, err := reassembler.Push(basePacket)
	require.NoError(t, err)
	require.Nil(t, out)

	// A marker packet at sequence 402 is queued behind the missing 401 and
	// cannot be released on its own; its retransmission is a buffered
	// duplicate rather than a late packet.
	markerPacket := &rtp.Packet{
		Header:  rtp.Header{SequenceNumber: 402, Timestamp: 9000, Marker: true},
		Payload: basePacket.Payload,
	}
	out, err = reassembler.Push(markerPacket)
	require.NoError(t, err)
	assert.Nil(t, out)
	out, err = reassembler.Push(markerPacket)
	require.NoError(t, err)
	assert.Nil(t, out)
	assert.Equal(t, uint64(1), reassembler.Stats().Duplicates)
	assert.Zero(t, reassembler.Stats().LatePackets)
}

func TestAV1Reassembler_timestampJumpWithoutMarker(t *testing.T) {
	const mtu = 100

	unit1 := buildOBU(t, obu.OBUTileGroup, make([]byte, 40))
	unit2 := buildOBU(t, obu.OBUFrame, make([]byte, 40))

	packets1 := packetizeTU(t, 500, 10000, mtu, unit1)
	packets2 := packetizeTU(t, 500+uint16(len(packets1)), 11000, mtu, unit2) //nolint:gosec // G115

	// Clear the marker of the last packet of unit1 to simulate a missing marker.
	packets1[len(packets1)-1].Marker = false

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)
	outputs := make([]*TemporalUnit, 0)
	for _, packet := range append(packets1, packets2...) {
		unit, err := reassembler.Push(packet)
		require.NoError(t, err)
		if unit != nil {
			outputs = append(outputs, unit)
		}
	}

	require.Len(t, outputs, 1, "only unit2 is emitted; unit1 never closed")
	assert.Equal(t, unit2, outputs[0].Payload)
	stats := reassembler.Stats()
	assert.Equal(t, uint64(1), stats.MissingMarkers)
	assert.Equal(t, uint64(1), stats.TimestampJumps)
	assert.Zero(t, stats.DiscardedUnits, "an unfinished unit is not a corruption")
}

func TestAV1Reassembler_outOfWindowPacket(t *testing.T) {
	const window = 4

	inputUnit := buildOBU(t, obu.OBUTileGroup, make([]byte, 20))
	packets := packetizeTU(t, 0, 12000, 200, inputUnit)

	reassembler := NewAV1Reassembler(window, DefaultMaxTemporalUnitSize)

	// Establish the window base with a non-marker packet.
	first := packets[0]
	first.Marker = false
	out, err := reassembler.Push(first)
	require.NoError(t, err)
	assert.Nil(t, out)

	// A packet arriving beyond the window re-bases it; the skipped sequence
	// numbers are counted as lost.
	far := &rtp.Packet{
		Header:  rtp.Header{SequenceNumber: window + 5, Timestamp: 13000},
		Payload: first.Payload,
	}
	out, err = reassembler.Push(far)
	require.NoError(t, err)
	assert.Nil(t, out)

	// The held packet now falls behind the new window base and is dropped as late.
	out, err = reassembler.Push(first)
	require.NoError(t, err)
	assert.Nil(t, out)

	stats := reassembler.Stats()
	// Sequences 1..8 were never seen; sequence 0 was buffered and becomes
	// late once the window re-bases to sequence 9.
	assert.Equal(t, uint64(window+3), stats.LostPackets)
	assert.Equal(t, uint64(1), stats.LatePackets)
	assert.Zero(t, stats.Outputs)
}

func TestAV1Reassembler_oversizedTemporalUnit(t *testing.T) {
	const mtu = 100

	unit := buildOBU(t, obu.OBUTileGroup, make([]byte, 400))
	packets := packetizeTU(t, 600, 14000, mtu, unit)

	reassembler := NewAV1Reassembler(DefaultReorderWindow, 100)
	output := pushAll(t, reassembler, packets)

	assert.Nil(t, output)
	assert.Equal(t, uint64(1), reassembler.Stats().OversizedUnits)
	assert.Equal(t, uint64(1), reassembler.Stats().DiscardedUnits)

	// The next, smaller unit must be assembled normally.
	next := buildOBU(t, obu.OBUFrame, make([]byte, 20))
	nextPackets := packetizeTU(t, 700, 15000, mtu, next)
	output = pushAll(t, reassembler, nextPackets)
	require.NotNil(t, output)
	assert.Equal(t, next, output.Payload)
}

func TestAV1Reassembler_malformedPayload(t *testing.T) {
	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)

	bad := &rtp.Packet{
		Header:  rtp.Header{SequenceNumber: 1, Timestamp: 16000},
		Payload: []byte{0b00110000, 0x01, 0x01},
	}
	unit, err := reassembler.Push(bad)
	require.NoError(t, err, "malformed payload is reported via Stats, not as an error")
	assert.Nil(t, unit)
	assert.Equal(t, uint64(1), reassembler.Stats().ParseErrors)

	// A valid marker packet closes the unit, which must be discarded.
	goodOBU := buildOBU(t, obu.OBUTileGroup, []byte{1, 2, 3})
	good := packetizeTU(t, 2, 16000, 200, goodOBU)
	good[0].Marker = true
	output := pushAll(t, reassembler, good)

	assert.Nil(t, output)
	assert.Equal(t, uint64(1), reassembler.Stats().DiscardedUnits)
	assert.Zero(t, reassembler.Stats().Outputs)

	// And the following unit reassembles cleanly, proving the internal state
	// of the depacketizer was reset.
	recovery := packetizeTU(t, 3, 17000, 200, goodOBU)
	output = pushAll(t, reassembler, recovery)
	require.NotNil(t, output)
	assert.Equal(t, goodOBU, output.Payload)
}

func TestAV1Reassembler_nilAndEmptyPacket(t *testing.T) {
	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)

	_, err := reassembler.Push(nil)
	assert.ErrorIs(t, err, ErrNilPacket)

	_, err = reassembler.Push(&rtp.Packet{Header: rtp.Header{SequenceNumber: 1}})
	assert.ErrorIs(t, err, ErrEmptyPayload)
	assert.Zero(t, reassembler.Stats().Outputs)
}

func TestAV1Reassembler_sequenceWraparound(t *testing.T) {
	const mtu = 100

	unit := buildOBU(t, obu.OBUTileGroup, make([]byte, 30))

	reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)

	// First unit ends right before the uint16 space wraps around.
	before := packetizeTU(t, 0xFFFF, 18000, mtu, unit)
	require.Len(t, before, 1)
	output := pushAll(t, reassembler, before)
	require.NotNil(t, output)
	assert.Equal(t, unit, output.Payload)

	// Second unit starts at sequence 0 and must be accepted as the successor.
	after := packetizeTU(t, 0, 19000, mtu, unit)
	output = pushAll(t, reassembler, after)
	require.NotNil(t, output)
	assert.Equal(t, unit, output.Payload)
	assert.Equal(t, uint64(2), reassembler.Stats().Outputs)

	// A packet from the pre-wraparound range is now a late duplicate.
	late := &rtp.Packet{
		Header:  rtp.Header{SequenceNumber: 0xFFFF, Timestamp: 19000},
		Payload: before[0].Payload,
	}
	_, err := reassembler.Push(late)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), reassembler.Stats().LatePackets)
}

func TestAV1Reassembler_packetizerRoundTrip(t *testing.T) {
	// Same round trip the codecs package performs, but through the full
	// RTP packet entry point with markers and sequence numbers.
	obus := []struct {
		Type obu.Type
		Size int
	}{
		{obu.OBUSequenceHeader, 10},
		{obu.OBUFrameHeader, 20},
		{obu.OBUFrame, 3000},
		{obu.OBUFrame, 4800},
		{obu.OBUFrameHeader, 20},
		{obu.OBUFrame, 8000},
	}

	payload := make([]byte, 0)
	for _, spec := range obus {
		header := obu.Header{Type: spec.Type, HasSizeField: true}
		payload = append(payload, header.Marshal()...)
		payload = append(payload, obu.WriteToLeb128(uint(spec.Size))...)
		payload = append(payload, make([]byte, spec.Size)...)
	}

	for _, mtu := range []uint16{32, 215, 1500} {
		t.Run(fmt.Sprintf("MTU %d", mtu), func(t *testing.T) {
			packets := packetizeTU(t, 0, 20000, mtu, payload)
			reassembler := NewAV1Reassembler(DefaultReorderWindow, DefaultMaxTemporalUnitSize)
			output := pushAll(t, reassembler, packets)

			require.NotNil(t, output)
			assert.Equal(t, payload, output.Payload)
			assert.Equal(t, uint32(20000), output.Timestamp)
		})
	}
}

func TestSeqDistance(t *testing.T) {
	assert.Equal(t, 1, seqDistance(1, 0))
	assert.Equal(t, -1, seqDistance(0, 1))
	assert.Equal(t, 3, seqDistance(2, 0xFFFF))
	assert.Equal(t, -3, seqDistance(0xFFFD, 0))
	assert.Equal(t, 0, seqDistance(42, 42))
}
