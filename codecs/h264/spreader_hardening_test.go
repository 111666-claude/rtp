// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package h264

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	hardeningRTPHeaderSize = 12
	hardeningFuaOverhead   = 2
)

// buildFuaStream builds n continuous FU-A packets carrying mediaSize media
// bytes each. The first packet sets the start bit and the last one the end
// bit. Every RTP packet is deliberately larger than the test MTU so that the
// spreader's FU-A path (including the trailing buffer) is always exercised.
func buildFuaStream(n, mediaSize int) [][]byte {
	pkts := make([][]byte, n)
	for i := range n {
		header := getRTPHeaderOffSet(uint16(i), i == n-1) // nolint:gosec // G115
		fuHeader := byte(0x05)
		switch {
		case i == 0:
			fuHeader = 0x85 // start bit
		case i == n-1:
			fuHeader = 0x45 // end bit
		}
		media := make([]byte, mediaSize)
		for j := range media {
			media[j] = byte((i + j) % 256) // nolint:gosec // G115
		}
		pkts[i] = append(header, append([]byte{0x7C, fuHeader}, media...)...)
	}

	return pkts
}

// Test10000FragmentsLinear drives 10000 oversized FU-A fragments through the
// spreader. It guards against panics and data loss on long streams, verifies
// the RTP invariants (MTU, continuous sequence numbers, marker placement and
// FU start/end bits) and checks that processing stays linear in the number of
// fragments instead of degrading quadratically.
func Test10000FragmentsLinear(t *testing.T) {
	assert := assert.New(t)

	const (
		mtu       = uint16(100)
		fragments = 10000
		// mediaSize keeps every input packet (12-byte header + 2 FU bytes +
		// 120 bytes = 134 bytes) above the 100-byte MTU so the FU-A spreading
		// path, including the trailing buffer, is always exercised.
		mediaSize = 120
	)

	pkts := buildFuaStream(fragments, mediaSize)
	// Spreading must be engaged so even sub-MTU re-emissions go through spreadFua.
	spreader := NewSpreader(mtu)
	spreader.Spreading = true

	var outs [][]byte
	var media []byte

	start := time.Now()
	for _, pkt := range pkts {
		out, err := spreader.Process(pkt)
		assert.NoError(err, "Process failed on a valid FU stream")
		outs = append(outs, out...)
	}
	elapsedLarge := time.Since(start)

	for _, rtpOut := range outs {
		media = append(media, rtpOut[hardeningRTPHeaderSize+hardeningFuaOverhead:]...)
	}

	// Every emitted packet must respect the MTU, carry continuous sequence
	// numbers, and only the final packet may carry the marker and the FU end
	// bit.
	if assert.NotEmpty(outs, "the stream should produce packets") {
		prevSeq := binary.BigEndian.Uint16(outs[0][rtpSeqNumOffset : rtpSeqNumOffset+rtpSeqNumLength])
		for i, rtpOut := range outs {
			assert.LessOrEqual(len(rtpOut), int(mtu), "packet %d exceeds the MTU", i)

			seq := binary.BigEndian.Uint16(rtpOut[rtpSeqNumOffset : rtpSeqNumOffset+rtpSeqNumLength])
			if i > 0 {
				assert.Equal(prevSeq+1, seq, "sequence numbers must be continuous at packet %d", i)
			}
			prevSeq = seq

			markerSet := rtpOut[rtpMPtOffset]&rtpMarkerBitMask != 0
			endBitSet := rtpOut[hardeningRTPHeaderSize+1]&fuEndBitmask != 0
			if i == len(outs)-1 {
				assert.True(markerSet, "marker must be set on the last packet only")
				assert.True(endBitSet, "FU end bit must be set on the last packet only")
			} else {
				assert.False(markerSet, "marker must not be set on non-final packet %d", i)
				assert.False(endBitSet, "FU end bit must not be set on non-final packet %d", i)
			}
		}

		// The first packet carries the FU start bit.
		assert.NotZero(outs[0][hardeningRTPHeaderSize+1] & fuStartBitmask)
	}

	// No media byte may be lost or reordered.
	expectedMedia := make([]byte, 0, fragments*mediaSize)
	for i := range fragments {
		for j := range mediaSize {
			expectedMedia = append(expectedMedia, byte((i+j)%256)) // nolint:gosec // G115
		}
	}
	assert.Equal(expectedMedia, media, "reassembled media must match the input exactly")

	// reqSubSize is mtu(100) - rtp header(12) - FU overhead(2) = 86 bytes per
	// emitted FU, so the 1200000 media bytes pack into 13953 full fragments
	// (1199958 bytes) plus one final fragment carrying the remaining 42.
	assert.Equal(13954, len(outs), "unexpected number of emitted packets")

	// Linearity guard: a 4x larger stream must not take disproportionately
	// longer. A quadratic implementation needs roughly 16x the time here; the
	// ceiling is intentionally loose to stay stable on contended CI runners.
	smallSpreader := NewSpreader(mtu)
	smallSpreader.Spreading = true
	smallStart := time.Now()
	for _, pkt := range buildFuaStream(fragments/4, mediaSize) {
		_, err := smallSpreader.Process(pkt)
		assert.NoError(err)
	}
	elapsedSmall := time.Since(smallStart)
	if elapsedSmall > 500*time.Microsecond {
		ratio := float64(elapsedLarge) / float64(elapsedSmall)
		assert.Less(ratio, 12.0, "processing does not look linear: 4x input took %fx time", ratio)
	}
}

func BenchmarkSpreader10000Fragments(b *testing.B) {
	pkts := buildFuaStream(10000, 120)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		spreader := NewSpreader(100)
		spreader.Spreading = true
		for _, pkt := range pkts {
			_, err := spreader.Process(pkt)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// TestOutOfOrderFuFlushesPending makes sure a sequence-number gap while a FU is
// in progress flushes the buffered trailing data instead of panicking, and
// that the stream can still finish cleanly with the end bit intact. Across a
// resync boundary the spreader cannot reconstruct the missing sequence number,
// so output sequence numbers stay strictly increasing rather than continuous;
// continuity is covered for well-ordered streams by Test10000FragmentsLinear.
func TestOutOfOrderFuFlushesPending(t *testing.T) {
	assert := assert.New(t)

	spreader := NewSpreader(100)
	fuaStart := append([]byte{0x7C, 0x85}, make([]byte, 136)...)
	fua1 := append(getRTPHeaderOffSet(0, false), fuaStart...)
	fuaGap := append(getRTPHeaderOffSet(5, false), 0x7C, 0x05, 0xAA)
	fuaEnd := append(getRTPHeaderOffSet(7, true), 0x7C, 0x45, 0xBB)

	out1, err1 := spreader.Process(fua1)
	outGap, errGap := spreader.Process(fuaGap)
	outEnd, errEnd := spreader.Process(fuaEnd)

	assert.NoError(err1)
	assert.NoError(errGap)
	assert.NoError(errEnd)

	outs := append(append(out1, outGap...), outEnd...)
	assert.NotEmpty(outs, "buffered data must be flushed on the sequence gap")

	var media []byte
	var prevSeq uint16
	for i, rtpOut := range outs {
		assert.LessOrEqual(len(rtpOut), 100, "packet %d exceeds the MTU", i)

		seq := binary.BigEndian.Uint16(rtpOut[rtpSeqNumOffset : rtpSeqNumOffset+rtpSeqNumLength])
		if i > 0 {
			assert.Greater(seq, prevSeq, "sequence numbers must be strictly increasing at packet %d", i)
		}
		prevSeq = seq

		media = append(media, rtpOut[hardeningRTPHeaderSize+hardeningFuaOverhead:]...)
	}

	assert.NotZero(outs[len(outs)-1][hardeningRTPHeaderSize+1]&fuEndBitmask,
		"the final packet must carry the FU end bit")
	assert.NotZero(outs[len(outs)-1][rtpMPtOffset]&rtpMarkerBitMask,
		"the final packet must carry the marker")
	assert.Len(media, 136+1+1, "no media byte may be lost across the gap")
}

func TestSpreaderEmptyInput(t *testing.T) {
	assert := assert.New(t)

	spreader := NewSpreader(100)

	out, err := spreader.Process(nil)
	assert.NoError(err)
	assert.Len(out, 0, "nil input must produce no packets")

	out, err = spreader.Process([]byte{})
	assert.NoError(err)
	assert.Len(out, 0, "empty input must produce no packets")
}

func TestSpreaderSingleNalPassthrough(t *testing.T) {
	assert := assert.New(t)

	spreader := NewSpreader(1200)
	rtpPkt := append(getRTPHeader(true), getH264SpsNal()...)

	out, err := spreader.Process(rtpPkt)
	if assert.NoError(err) && assert.Len(out, 1) {
		assert.Equal(rtpPkt, out[0], "a single NAL below the MTU must pass through unchanged")
		assert.NotZero(out[0][rtpMPtOffset]&rtpMarkerBitMask, "the marker must be preserved")
		assert.LessOrEqual(len(out[0]), 1200, "output must not exceed the MTU")
	}
}
