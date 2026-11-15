// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package h264

import (
	"encoding/binary"
	"testing"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	asmTestClockRate = 90000
	asmTestSamples   = 3000
	asmTestFirstTS   = 1000
)

func annexbFrame(nalus ...[]byte) []byte {
	var out []byte
	for _, nalu := range nalus {
		out = append(out, 0x00, 0x00, 0x00, 0x01)
		out = append(out, nalu...)
	}

	return out
}

func testIDRNalu(size int) []byte {
	nalu := make([]byte, size)
	nalu[0] = 0x65
	for i := 1; i < size; i++ {
		nalu[i] = byte(i*7 + 3)
	}

	return nalu
}

func packetizeFrames(mtu uint16, disableStapA bool, startSeq uint16, frames ...[]byte) []*rtp.Packet {
	packetizer := rtp.NewPacketizerWithOptions(
		mtu,
		&codecs.H264Payloader{DisableStapA: disableStapA},
		rtp.NewFixedSequencer(startSeq),
		asmTestClockRate,
		rtp.WithTimestamp(asmTestFirstTS),
	)
	var pkts []*rtp.Packet
	for _, frame := range frames {
		pkts = append(pkts, packetizer.Packetize(frame, asmTestSamples)...)
	}

	return pkts
}

func feedPackets(t *testing.T, assembler *Assembler, pkts ...*rtp.Packet) []AccessUnit {
	t.Helper()
	var out []AccessUnit
	for _, pkt := range pkts {
		aus, err := assembler.Process(pkt)
		require.NoError(t, err)
		out = append(out, aus...)
	}

	return out
}

func TestAssemblerRoundTripSingleNalu(t *testing.T) {
	assert := assert.New(t)

	sps, pps := getH264SpsNal(), getH264PpsNal()
	frame1 := annexbFrame(sps, pps, testIDRNalu(50))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(1200, true, 1, frame1, frame2)
	require.Len(t, pkts, 4)

	assembler := NewAssembler(0)

	// nothing is emitted while the first unit is the newest buffered one
	out := feedPackets(t, assembler, pkts[:3]...)
	assert.Empty(out)
	assert.Equal(1, assembler.BufferedAccessUnits())

	// the first packet of the next unit seals and emits the previous one
	out = feedPackets(t, assembler, pkts[3])
	if assert.Len(out, 1) {
		assert.Equal(uint32(asmTestFirstTS), out[0].Timestamp)
		assert.Equal(frame1, out[0].Data)
	}

	out = assembler.Flush()
	if assert.Len(out, 1) {
		assert.Equal(uint32(asmTestFirstTS+asmTestSamples), out[0].Timestamp)
		assert.Equal(frame2, out[0].Data)
	}
	assert.Equal(uint64(0), assembler.DroppedAccessUnits())
	assert.Equal(0, assembler.BufferedAccessUnits())
}

func TestAssemblerRoundTripStapA(t *testing.T) {
	assert := assert.New(t)

	sps, pps := getH264SpsNal(), getH264PpsNal()
	frame1 := annexbFrame(sps, pps, testIDRNalu(40))
	frame2 := annexbFrame(testIDRNalu(40))
	// STAP-A enabled: SPS+PPS of the first frame are aggregated
	pkts := packetizeFrames(1200, false, 1, frame1, frame2)
	require.Len(t, pkts, 3)
	assert.Equal(byte(stapaNALUType), pkts[0].Payload[0]&naluTypeBitmask)

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, pkts...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
}

func TestAssemblerRoundTripFuA(t *testing.T) {
	assert := assert.New(t)

	sps, pps := getH264SpsNal(), getH264PpsNal()
	frame1 := annexbFrame(sps, pps, testIDRNalu(500))
	frame2 := annexbFrame(testIDRNalu(300))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)
	require.Greater(t, len(pkts), 10)

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, pkts...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
	assert.Equal(uint64(0), assembler.DroppedAccessUnits())
}

func TestAssemblerRoundTripAVC(t *testing.T) {
	assert := assert.New(t)

	sps, pps := getH264SpsNal(), getH264PpsNal()
	idr := testIDRNalu(50)
	frame1 := annexbFrame(sps, pps, idr)
	pkts := packetizeFrames(1200, false, 1, frame1)

	assembler := NewAssembler(0)
	assembler.IsAVC = true
	out := feedPackets(t, assembler, pkts...)
	out = append(out, assembler.Flush()...)

	expected := []byte{}
	for _, nalu := range [][]byte{sps, pps, idr} {
		expected = binary.BigEndian.AppendUint32(expected, uint32(len(nalu))) // nolint: gosec // G115 false positive
		expected = append(expected, nalu...)
	}
	if assert.Len(out, 1) {
		assert.Equal(expected, out[0].Data)
	}
}

func TestAssemblerPacketLossDoesNotPolluteNextUnit(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(500))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)
	require.Greater(t, len(pkts), 3)

	// drop a middle FU-A packet of the first unit
	lost := len(pkts)/2 - 1
	kept := append([]*rtp.Packet{}, pkts[:lost]...)
	kept = append(kept, pkts[lost+1:]...)

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, kept...)
	assert.Empty(out) // the broken unit blocks the front of the buffer

	out = assembler.Flush()
	if assert.Len(out, 1) {
		assert.Equal(uint32(asmTestFirstTS+asmTestSamples), out[0].Timestamp)
		assert.Equal(frame2, out[0].Data, "second unit must be reassembled exactly")
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())
}

func TestAssemblerLostFuAStartDropsUnit(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(500))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)

	// drop the FU-A start packet of the first unit
	kept := append([]*rtp.Packet{}, pkts[1:]...)

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, kept...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 1) {
		assert.Equal(frame2, out[0].Data)
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())
}

func TestAssemblerReorderedPackets(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(500))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)
	require.Greater(t, len(pkts), 10)

	// swap two middle FU-A packets of the first unit
	pkts[3], pkts[5] = pkts[5], pkts[3]

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, pkts...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
	assert.Equal(uint64(0), assembler.DroppedAccessUnits())
}

func TestAssemblerReorderedAcrossUnits(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(200))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)
	require.Greater(t, len(pkts), 3)

	// deliver the marker packet of the first unit after the first packet of the second
	last1 := len(pkts) - 2 // frame2 is a single packet
	reordered := append([]*rtp.Packet{}, pkts[:last1]...)
	reordered = append(reordered, pkts[last1+1], pkts[last1])

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, reordered...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
	assert.Equal(uint64(0), assembler.DroppedAccessUnits())
}

func TestAssemblerDuplicatePackets(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(200))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)

	assembler := NewAssembler(0)
	var out []AccessUnit
	for _, pkt := range pkts {
		out = append(out, feedPackets(t, assembler, pkt)...)
		out = append(out, feedPackets(t, assembler, pkt)...) // duplicate
	}
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
	assert.Equal(uint64(len(pkts)), assembler.DuplicatePackets())
	assert.Equal(uint64(0), assembler.DroppedAccessUnits())
}

func TestAssemblerSequenceNumberWrap(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(500))
	frame2 := annexbFrame(testIDRNalu(300))
	// start near the end of the uint16 space so the sequence wraps mid-unit
	pkts := packetizeFrames(64, true, 0xFFFC, frame1, frame2)
	require.Greater(t, len(pkts), 10)

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, pkts...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
	assert.Equal(uint64(0), assembler.DroppedAccessUnits())
}

func TestAssemblerMaxBufferedDropsOldest(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(100))
	frame2 := annexbFrame(testIDRNalu(60))
	frame3 := annexbFrame(testIDRNalu(70))
	pkts := packetizeFrames(64, true, 1, frame1, frame2, frame3)
	n1 := len(packetizeFrames(64, true, 1, frame1))
	n2 := len(packetizeFrames(64, true, 1, frame2))
	require.Greater(t, n1, 1)

	assembler := NewAssembler(2)

	// first unit never sees its marker packet
	out := feedPackets(t, assembler, pkts[:n1-1]...)
	assert.Empty(out)
	// still within the limit: the incomplete unit is kept
	out = append(out, feedPackets(t, assembler, pkts[n1:n1+n2]...)...)
	assert.Empty(out)
	assert.Equal(2, assembler.BufferedAccessUnits())
	// the third unit exceeds the limit: the oldest is dropped, the second is emitted
	out = append(out, feedPackets(t, assembler, pkts[n1+n2])...)
	if assert.Len(out, 1) {
		assert.Equal(frame2, out[0].Data)
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())

	out = append(out, feedPackets(t, assembler, pkts[n1+n2+1:]...)...)
	out = append(out, assembler.Flush()...)
	if assert.Len(out, 2) {
		assert.Equal(frame3, out[1].Data)
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())
}

func TestAssemblerClose(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(50))
	pkts := packetizeFrames(1200, true, 1, frame1)

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, pkts[0])
	assert.Empty(out)
	assert.Equal(1, assembler.BufferedAccessUnits())

	assert.NoError(assembler.Close())
	assert.Equal(0, assembler.BufferedAccessUnits())
	assert.Nil(assembler.Flush())

	_, err := assembler.Process(pkts[0])
	assert.ErrorIs(err, ErrAssemblerClosed)
}

func TestAssemblerReset(t *testing.T) {
	assert := assert.New(t)

	frame1 := annexbFrame(testIDRNalu(200))
	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(64, true, 1, frame1, frame2)

	assembler := NewAssembler(0)

	// buffer a broken unit (missing its last packet), then reset
	out := feedPackets(t, assembler, pkts[:len(pkts)-2]...)
	assert.Empty(out)
	assert.Equal(1, assembler.BufferedAccessUnits())

	assembler.Reset()
	assert.Equal(0, assembler.BufferedAccessUnits())

	// a fresh stream is reassembled cleanly, no state leaks across the reset
	pkts2 := packetizeFrames(64, true, 1, frame1, frame2)
	out = feedPackets(t, assembler, pkts2...)
	out = append(out, assembler.Flush()...)
	if assert.Len(out, 2) {
		assert.Equal(frame1, out[0].Data)
		assert.Equal(frame2, out[1].Data)
	}
}

func TestAssemblerCallErrors(t *testing.T) {
	assert := assert.New(t)

	assembler := NewAssembler(0)

	_, err := assembler.Process(nil)
	assert.ErrorIs(err, ErrNilPacket)

	_, err = assembler.Process(&rtp.Packet{})
	assert.ErrorIs(err, ErrEmptyPayload)

	assert.Nil(assembler.Flush())
}

func TestAssemblerCorruptStapAIsDropped(t *testing.T) {
	assert := assert.New(t)

	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(1200, true, 100, frame2)

	assembler := NewAssembler(0)

	// STAP-A declaring a NALU larger than the packet
	broken := &rtp.Packet{
		Header:  rtp.Header{Marker: true, SequenceNumber: 1, Timestamp: 500},
		Payload: []byte{0x18, 0x00, 0x78, 0x65, 0x01},
	}
	out := feedPackets(t, assembler, broken)
	assert.Empty(out)

	out = feedPackets(t, assembler, pkts...)
	out = append(out, assembler.Flush()...)
	if assert.Len(out, 1) {
		assert.Equal(frame2, out[0].Data)
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())
}

func TestAssemblerUnsupportedNaluTypeIsDropped(t *testing.T) {
	assert := assert.New(t)

	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(1200, true, 100, frame2)

	assembler := NewAssembler(0)

	// STAP-B (type 25) is not supported
	unsupported := &rtp.Packet{
		Header:  rtp.Header{Marker: true, SequenceNumber: 1, Timestamp: 500},
		Payload: []byte{0x19, 0x00, 0x00, 0x00, 0x02, 0x65, 0x01},
	}
	out := feedPackets(t, assembler, unsupported)
	out = append(out, feedPackets(t, assembler, pkts...)...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 1) {
		assert.Equal(frame2, out[0].Data)
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())
}

func TestAssemblerFuAEndWithoutStartIsDropped(t *testing.T) {
	assert := assert.New(t)

	frame2 := annexbFrame(testIDRNalu(60))
	pkts := packetizeFrames(1200, true, 100, frame2)

	assembler := NewAssembler(0)

	// a lone FU-A end fragment forms a contiguous chain but cannot be assembled
	broken := &rtp.Packet{
		Header:  rtp.Header{Marker: true, SequenceNumber: 1, Timestamp: 500},
		Payload: []byte{0x7C, 0x45, 0xAA, 0xBB},
	}
	out := feedPackets(t, assembler, broken)
	out = append(out, feedPackets(t, assembler, pkts...)...)
	out = append(out, assembler.Flush()...)

	if assert.Len(out, 1) {
		assert.Equal(frame2, out[0].Data)
	}
	assert.Equal(uint64(1), assembler.DroppedAccessUnits())
}

func TestAssemblerAudIsKeptAsRegularNalu(t *testing.T) {
	assert := assert.New(t)

	// the payloader strips AUD/filler NALUs, but a sender may forward them:
	// type 9 is a regular single NALU for the assembler
	aud := &rtp.Packet{
		Header:  rtp.Header{SequenceNumber: 1, Timestamp: asmTestFirstTS},
		Payload: []byte{0x09, 0xF0},
	}
	idr := &rtp.Packet{
		Header:  rtp.Header{Marker: true, SequenceNumber: 2, Timestamp: asmTestFirstTS},
		Payload: testIDRNalu(10),
	}

	assembler := NewAssembler(0)
	out := feedPackets(t, assembler, aud, idr)
	out = append(out, assembler.Flush()...)

	expected := annexbFrame([]byte{0x09, 0xF0}, testIDRNalu(10))
	if assert.Len(out, 1) {
		assert.Equal(expected, out[0].Data)
	}
}
