// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package h264

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Offsets inside an emitted FU-A packet: a 12-byte RTP header, then the FU
// indicator and FU header octets, then the FU payload.
const (
	testFuHeaderOffset  = minRTPHeaderSize + 1
	testFuPayloadOffset = minRTPHeaderSize + fuaOverhead
)

// fuRtp builds a minimal RTP packet (12-byte header) carrying an FU-A NAL unit.
// seq is the 0-based sequence number added to the header's base sequence.
func fuRtp(seq uint16, marker bool, fuIndicator, fuHeader byte, payload []byte) []byte {
	hdr := getRTPHeaderOffSet(seq, marker)
	nal := make([]byte, 0, fuaOverhead+len(payload))
	nal = append(nal, fuIndicator, fuHeader)
	nal = append(nal, payload...)

	return append(hdr, nal...)
}

// checkFuaInvariants validates the output of an FU-A fragmentation against the
// MTU, sequence-number continuity and RTP marker placement rules.
func checkFuaInvariants(t *testing.T, out [][]byte, mtu int, wantConcat []byte) {
	t.Helper()
	assert := assert.New(t)
	if len(out) == 0 {
		return
	}

	var concat []byte
	var firstSeq, lastSeq uint16
	markerCount := 0
	endCount := 0
	startCount := 0
	for i, pkt := range assertPacketSizes(assert, out, mtu) {
		seq := binary.BigEndian.Uint16(pkt[rtpSeqNumOffset : rtpSeqNumOffset+rtpSeqNumLength])
		if i == 0 {
			firstSeq = seq
		} else {
			assert.Equal(lastSeq+1, seq, "sequence numbers must be contiguous")
		}
		lastSeq = seq

		if pkt[rtpMPtOffset]&rtpMarkerBitMask != 0 {
			markerCount++
			assert.Equal(len(out)-1, i, "marker must only be set on the final packet")
		}

		// FU indicator + FU header + FU payload.
		fuHeader := pkt[testFuHeaderOffset]
		if fuHeader&fuStartBitmask != 0 {
			startCount++
			assert.Equal(0, i, "FU start bit must only be set on the first packet")
		}
		if fuHeader&fuEndBitmask != 0 {
			endCount++
			assert.Equal(len(out)-1, i, "FU end bit must only be set on the final packet")
		}
		concat = append(concat, pkt[testFuPayloadOffset:]...)
	}
	assert.Equal(1, startCount, "exactly one FU start fragment expected")
	assert.Equal(1, endCount, "exactly one FU end fragment expected")
	if markerCount != 0 {
		assert.Equal(1, markerCount, "at most one marked packet expected")
	}
	if wantConcat != nil {
		assert.Equal(wantConcat, concat, "reassembled FU payload mismatch")
	}
	assert.Equal(firstSeq+uint16(len(out)-1), lastSeq)
}

// assertPacketSizes fails if any emitted packet exceeds the MTU and returns out.
func assertPacketSizes(assert *assert.Assertions, out [][]byte, mtu int) [][]byte {
	for _, pkt := range out {
		assert.LessOrEqual(len(pkt), mtu, "emitted packet exceeds the MTU")
	}

	return out
}

// A single NAL unit larger than the MTU must be fragmented into FU-A packets,
// none larger than the MTU, with contiguous sequence numbers.
func TestMTUTooSmallForFuPayload(t *testing.T) {
	assert := assert.New(t)

	// MTU leaves no room after the 12-byte RTP header and 2-byte FU-A overhead.
	s := NewSpreader(minRTPHeaderSize + 1) // 13: reqSubSize = 13-12-2 = -1
	pkt := append(getRTPHeader(true), getH264SpsNal()...)

	out, err := s.Process(pkt)
	assert.Error(err, "an MTU with no FU payload room must return an error")
	assert.Nil(out, "no packet may be emitted on error")

	// MTU that leaves exactly zero payload bytes is rejected too (divide-by-zero guard).
	s2 := NewSpreader(minRTPHeaderSize + fuaOverhead) // 14: reqSubSize = 0
	out2, err2 := s2.Process(append(getRTPHeader(true), getH264SpsNal()...))
	assert.Error(err2)
	assert.Nil(out2)
}

// A STAP-A whose last NAL unit length field is truncated to a single byte must
// be reported as an error instead of panicking with an index out of range.
func TestStapaTrailingSingleByte(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(16) // packet (18 bytes) exceeds MTU so explodeStapA runs
	// STAP-A header, one valid 2-byte NAL unit, then a single dangling byte.
	stapa := []byte{0x18, 0x00, 0x02, 0x09, 0xF0, 0x00}
	pkt := append(getRTPHeader(false), stapa...)

	out, err := s.Process(pkt)
	assert.Error(err, "truncated STAP-A must return an error")
	assert.Nil(out)
	assert.Contains(err.Error(), "truncated")
}

// A STAP-A declaring a NAL unit larger than the remaining buffer is an error.
func TestStapaDeclaredSizeTooLarge(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(16) // small MTU forces the STAP-A through explodeStapA
	// Declares a 10-byte NAL unit but only 2 bytes follow.
	stapa := []byte{0x18, 0x00, 0x0A, 0x09, 0xF0}
	out, err := s.Process(append(getRTPHeader(false), stapa...))
	assert.Error(err)
	assert.Nil(out)
}

// An FU-A carrying only the End bit, with no media data and an empty cache,
// must return a checkable error rather than dereferencing a nil header.
func TestFuaEndBitWithoutMediaData(t *testing.T) {
	assert := assert.New(t)

	// A standalone end-only FU-A, large enough to enter the fragmentation path,
	// opens a fresh fragmentation with zero media data and immediately finishes.
	s := NewSpreader(22)
	big := fuRtp(0, false, 0x7C, 0x81, make([]byte, 24))
	_, err := s.Process(big)
	assert.NoError(err)

	// Sequence gap flushes the pending (cached) fragmentation and starts fresh.
	// The fresh FU-A carries only the End bit and no payload: empty cache, finish.
	end := fuRtp(9, true, 0x7C, 0x41, nil)
	endOut, err := s.Process(end)
	assert.Error(err)
	assert.Contains(err.Error(), "without any media data")
	assert.Nil(endOut)
	// The spreader recovered and holds no dangling fragmentation.
	assert.Nil(s.fuInProgress)
}

// An empty middle FU-A must not wipe the bytes already cached for the open
// fragmentation (a previous implementation overwrote the cache with nothing).
func TestEmptyMiddleFuaPreservesCache(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(22)
	big := fuRtp(0, false, 0x7C, 0x81, make([]byte, 24))
	_, err := s.Process(big)
	assert.NoError(err)
	assert.Equal(8, len(s.fuInProgress.Trailing))

	empty := fuRtp(1, false, 0x7C, 0x01, nil)
	out, err := s.Process(empty)
	assert.NoError(err)
	assert.Equal(0, len(out), "empty middle emits nothing")
	assert.Equal(8, len(s.fuInProgress.Trailing), "cached bytes must survive an empty FU-A")

	// Ending with one payload byte merges it onto the preserved 8-byte cache:
	// 9 bytes over the 8-byte FU payload cap emits a full fragment plus the end.
	end := fuRtp(2, true, 0x7C, 0x41, []byte{0x5A})
	endOut, err := s.Process(end)
	assert.NoError(err)
	if assert.Equal(2, len(endOut)) {
		var payload []byte
		for _, pkt := range endOut {
			assert.LessOrEqual(len(pkt), 22)
			payload = append(payload, pkt[testFuPayloadOffset:]...)
		}
		assert.Equal(9, len(payload), "all cached bytes plus the final byte must be emitted")
		// Only the last packet carries the marker and the FU end bit.
		assert.Equal(byte(0), endOut[0][rtpMPtOffset]&rtpMarkerBitMask)
		assert.NotEqual(byte(0), endOut[1][rtpMPtOffset]&rtpMarkerBitMask)
		assert.Equal(byte(0), endOut[0][testFuHeaderOffset]&fuEndBitmask)
		assert.NotEqual(byte(0), endOut[1][testFuHeaderOffset]&fuEndBitmask)
	}
}

// Two small FU-A fragments that each fit in the cache must be buffered and
// merged into a single legal end fragment when the End bit arrives.
func TestTwoSmallFuaMergedIntoEndFragment(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(24) // FU payload room = 24-12-2 = 10
	// Open the fragmentation with an oversized start FU-A.
	big := fuRtp(0, false, 0x7C, 0x81, make([]byte, 24))
	_, err := s.Process(big)
	assert.NoError(err)

	// First small FU-A: payload fits in the cache, emits nothing.
	small1 := fuRtp(1, false, 0x7C, 0x01, []byte{0xAA, 0xBB})
	out1, err := s.Process(small1)
	assert.NoError(err)
	assert.Equal(0, len(out1), "small fragment should be cached, not emitted")

	// Second small FU-A with the End bit: all cached fragments (the 4 bytes left
	// over from the opening FU plus the two small payloads) merge into one legal
	// end fragment.
	small2 := fuRtp(2, true, 0x7C, 0x41, []byte{0xCC, 0xDD})
	out2, err := s.Process(small2)
	assert.NoError(err)
	wantMerged := append(append(make([]byte, 0, 8), make([]byte, 4)...), 0xAA, 0xBB, 0xCC, 0xDD)
	if assert.Equal(1, len(out2), "cached fragments must merge into a single end packet") {
		pkt := out2[0]
		assert.LessOrEqual(len(pkt), 24, "merged packet must not exceed the MTU")
		assert.Equal(byte(0x41), pkt[testFuHeaderOffset]&(fuStartBitmask|fuEndBitmask|naluTypeBitmask),
			"merged packet must be an end (non-start) FU fragment")
		assert.Equal(wantMerged, pkt[testFuPayloadOffset:], "all cached payloads must be concatenated")
		assert.NotEqual(0, pkt[rtpMPtOffset]&rtpMarkerBitMask, "marker must land on the final packet")
	}
}

// Consecutive zero-output (fully cached) FU-A calls must not break sequence
// number continuity: the modular RTPOffset accounting keeps every emitted
// packet contiguous, and the marker is deferred onto the final packet.
func TestZeroOutputFuaKeepsSequenceContinuous(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(24) // FU payload room = 10
	var all [][]byte
	out, err := s.Process(fuRtp(0, false, 0x7C, 0x81, make([]byte, 24)))
	assert.NoError(err)
	all = append(all, out...)

	// Two middle fragments fully absorbed by the cache.
	middle := [][]byte{{0xAA}, {0xBB}}
	for i, payload := range middle {
		out, err := s.Process(fuRtp(uint16(i+1), false, 0x7C, 0x01, payload))
		assert.NoError(err)
		assert.Equal(0, len(out))
	}

	// The end fragment flushes the merged cache.
	out, err = s.Process(fuRtp(3, true, 0x7C, 0x41, []byte{0xCC}))
	assert.NoError(err)
	all = append(all, out...)

	for i := 1; i < len(all); i++ {
		prev := binary.BigEndian.Uint16(all[i-1][rtpSeqNumOffset:])
		cur := binary.BigEndian.Uint16(all[i][rtpSeqNumOffset:])
		assert.Equal(prev+1, cur, "emitted sequence numbers must stay contiguous")
	}
	for _, pkt := range all[:len(all)-1] {
		assert.Equal(byte(0), pkt[rtpMPtOffset]&rtpMarkerBitMask, "non-final packet must not be marked")
	}
	assert.NotEqual(byte(0), all[len(all)-1][rtpMPtOffset]&rtpMarkerBitMask,
		"the deferred marker must land on the final packet")
}

// Empty input and too-short payloads keep their existing behaviour.
func TestEmptyAndShortInput(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(1200)
	out, err := s.Process(nil)
	assert.NoError(err)
	assert.Equal(0, len(out))

	out, err = s.Process([]byte{0x80, 0x60})
	assert.Error(err)
	assert.Nil(out)
}

// An ordinary small NAL unit still passes through untouched.
func TestOrdinarySingleNalPassthrough(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(1200)
	pkt := append(getRTPHeader(false), getH264DelimiterNal()...)
	out, err := s.Process(pkt)
	assert.NoError(err)
	if assert.Equal(1, len(out)) {
		assert.Equal(pkt, out[0])
	}
}

// Out-of-order FU-A input (a sequence gap) flushes the pending fragmentation
// and restarts cleanly without panicking. The flushed cache packet continues
// the contiguous output stream; the restarted fragment keeps its own incoming
// sequence number (pre-existing behaviour this must not regress).
func TestFuaOutOfOrderFlushesAndRestarts(t *testing.T) {
	assert := assert.New(t)

	s := NewSpreader(24)
	start := fuRtp(0, false, 0x7C, 0x81, make([]byte, 24))
	openOut, err := s.Process(start)
	assert.NoError(err)

	// Skip sequence 1: jump to 5, forcing a flush of the pending fragment.
	gap := fuRtp(5, true, 0x7C, 0x41, []byte{0x11})
	out, err := s.Process(gap)
	assert.NoError(err)
	if assert.GreaterOrEqual(len(out), 2) {
		for _, pkt := range out {
			assert.LessOrEqual(len(pkt), 24)
		}
		// The flushed cache packet is contiguous with the opening output.
		lastOpen := binary.BigEndian.Uint16(openOut[len(openOut)-1][rtpSeqNumOffset:])
		firstGap := binary.BigEndian.Uint16(out[0][rtpSeqNumOffset:])
		assert.Equal(lastOpen+1, firstGap, "flushed fragment must continue the output stream")
		// The marker lands only on the final (restarted end) packet.
		assert.Equal(byte(0), out[0][rtpMPtOffset]&rtpMarkerBitMask)
		assert.NotEqual(byte(0), out[len(out)-1][rtpMPtOffset]&rtpMarkerBitMask)
	}
}

// Feeding 10000 small FU-A fragments must stay linear and never panic; the
// reassembled payload equals the concatenation of every input payload.
func TestTenThousandFragmentsLinear(t *testing.T) {
	assert := assert.New(t)

	const fragmentCount = 10000
	s := NewSpreader(1200) // room for many small payloads per emitted packet
	// Open with one oversized start FU-A so the fragmentation path is active.
	open := fuRtp(0, false, 0x7C, 0x81, make([]byte, 2000))
	var all [][]byte
	out, err := s.Process(open)
	assert.NoError(err)
	all = append(all, out...)

	var want []byte
	want = append(want, open[testFuPayloadOffset:]...)

	start := time.Now()
	for i := 1; i < fragmentCount; i++ {
		isLast := i == fragmentCount-1
		header := byte(0x01) // middle FU fragment
		marker := false
		if isLast {
			header = fuEndBitmask | 0x01
			marker = true
		}
		payload := []byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}
		pkt := fuRtp(uint16(i), marker, 0x7C, header, payload)
		out, err := s.Process(pkt)
		assert.NoError(err)
		all = append(all, out...)
		want = append(want, payload...)
	}
	assert.Less(time.Since(start), 10*time.Second, "processing 10000 fragments must stay fast/linear")

	// The fragmentation is fully closed.
	assert.Nil(s.fuInProgress)
	// All emitted packets respect the MTU, with contiguous sequence numbers, and
	// the last packet alone carries the marker and end bit.
	checkFuaInvariants(t, all, 1200, want)
	assert.NotEqual(0, all[len(all)-1][rtpMPtOffset]&rtpMarkerBitMask)
}

// FuzzSpreaderFua feeds random FU-A streams and asserts the process never
// panics and every emitted packet respects the MTU and sequence continuity.
func FuzzSpreaderFua(f *testing.F) {
	f.Add(uint16(24), uint8(5), []byte{3, 2, 4, 1, 2, 3, 0, 1, 1, 2})
	f.Fuzz(func(t *testing.T, mtu uint16, count uint8, flags []byte) {
		if int(mtu) < minRTPHeaderSize+fuaOverhead+1 {
			mtu = uint16(minRTPHeaderSize + fuaOverhead + 1)
		}
		if mtu > 4096 {
			mtu = 4096
		}
		if count == 0 {
			count = 1
		}
		s := NewSpreader(mtu)
		var all [][]byte
		for i := uint8(0); i < count; i++ {
			isFirst := i == 0
			isLast := i == count-1
			header := byte(0x01)
			if isFirst {
				header |= fuStartBitmask
			}
			// Pick a small random payload; middle fragments may be empty, but the
			// last one always carries data so the End bit never arrives on an empty
			// cache (that case is covered by TestFuaEndBitWithoutMediaData).
			n := 0
			if !isLast && i < uint8(len(flags)) {
				n = int(flags[i]) % 16
			} else if isLast {
				last := byte(7)
				if len(flags) > 0 {
					last = flags[len(flags)-1]
				}
				n = 1 + int(last)%15
			}
			payload := make([]byte, n)
			for j := range payload {
				payload[j] = byte(i) + byte(j)
			}
			if isLast {
				header |= fuEndBitmask
			}
			pkt := fuRtp(uint16(i), isLast, 0x7C, header, payload)
			// The first packet must exceed the MTU to enter the fragmentation path.
			// Preserve the End bit and marker when this single packet is both the
			// first and last fragment, so the fragmentation still closes cleanly.
			if isFirst && len(pkt) <= int(mtu) {
				openHeader := byte(0x81) // start, type 1
				if isLast {
					openHeader |= fuEndBitmask
				}
				pkt = fuRtp(0, isLast, 0x7C, openHeader, make([]byte, int(mtu)+8))
			}
			out, err := s.Process(pkt)
			if err != nil {
				// An error must leave no output and a clean (nil) fragmentation state.
				if len(out) != 0 {
					t.Fatalf("error returned with non-nil output: %v", err)
				}
				if s.fuInProgress != nil {
					t.Fatalf("error left a dangling fragmentation: %v", err)
				}

				return
			}
			all = append(all, out...)
		}
		// A clean run must close the fragmentation.
		if s.fuInProgress != nil {
			t.Fatal("fragmentation left open after the End fragment")
		}
		for _, pkt := range all {
			if len(pkt) > int(mtu) {
				t.Fatalf("packet of %d bytes exceeds MTU %d", len(pkt), mtu)
			}
		}
		for i := 1; i < len(all); i++ {
			prev := binary.BigEndian.Uint16(all[i-1][rtpSeqNumOffset:])
			cur := binary.BigEndian.Uint16(all[i][rtpSeqNumOffset:])
			if cur != prev+1 {
				t.Fatalf("non-contiguous sequence numbers at %d: %d -> %d", i, prev, cur)
			}
		}
	})
}
