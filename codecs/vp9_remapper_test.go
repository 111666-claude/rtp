// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vp9FlexibleDescriptor builds a flexible-mode (F=1) VP9 payload descriptor.
// pictureIDExtended selects the 15-bit PictureID form; withLayer adds the
// TID/U/SID/D byte; pDiff carries the flexible reference indices and makes
// the frame inter-picture predicted.
func vp9FlexibleDescriptor(
	pictureID uint16, pictureIDExtended, withLayer bool, tid, sid uint8,
	switchUp, interLayerDependency bool, pDiff []uint8,
) []byte {
	first := byte(vp9FlagI | vp9FlagF | 0x08 | 0x04) // I=1 F=1 B=1 E=1.
	if withLayer {
		first |= vp9FlagL
	}
	predicted := len(pDiff) > 0
	if predicted {
		first |= vp9FlagP
	}

	out := []byte{first}
	if pictureIDExtended {
		out = append(out, vp9FlagM|byte(pictureID>>8), byte(pictureID)) //nolint:gosec // high 7 bits, low 8 bits
	} else {
		out = append(out, byte(pictureID)) //nolint:gosec
	}
	if withLayer {
		layer := tid<<5 | (sid << 1) //nolint:gosec
		if switchUp {
			layer |= 0x10
		}
		if interLayerDependency {
			layer |= 0x01
		}
		out = append(out, layer)
	}
	for i, diff := range pDiff {
		ref := diff << 1 //nolint:gosec
		if i != len(pDiff)-1 {
			ref |= 0x01 // N=1: another P_DIFF follows.
		}
		out = append(out, ref)
	}

	return out
}

// vp9NonFlexibleDescriptor builds a non-flexible-mode (F=0) descriptor with
// layer indices and TL0PICIDX.
func vp9NonFlexibleDescriptor(
	pictureID uint16, pictureIDExtended bool, tid, sid uint8, switchUp bool, tl0PicIdx uint8,
) []byte {
	first := byte(vp9FlagI | vp9FlagL | 0x08 | 0x04) // I=1 L=1 B=1 E=1.
	out := []byte{first}
	if pictureIDExtended {
		out = append(out, vp9FlagM|byte(pictureID>>8), byte(pictureID)) //nolint:gosec
	} else {
		out = append(out, byte(pictureID)) //nolint:gosec
	}
	out = append(out, tid<<5|(sid<<1)) //nolint:gosec
	if switchUp {
		out[len(out)-1] |= 0x10
	}
	out = append(out, tl0PicIdx)

	return out
}

// withVideo appends fixed compressed-video bytes to a descriptor and returns
// the complete RTP payload.
func withVideo(descriptor []byte) []byte {
	return append(append([]byte{}, descriptor...), 0xDE, 0xAD, 0xBE, 0xEF)
}

// TestVP9PictureIDRemapper_TwoStreams drives two independently numbered VP9
// transport streams through one remapper. The second stream restarts its
// PictureID at zero while the first is still recent, which is the
// concatenation scenario the remapper exists for. Both streams use
// fragmentation, layer indices and flexible reference indices.
func TestVP9PictureIDRemapper_TwoStreams(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	// Stream 1: 15-bit PictureIDs, three frames, two fragments per frame.
	stream1 := []struct {
		pictureID uint16
		timestamp uint32
		tid, sid  uint8
		pDiff     []uint8
	}{
		{pictureID: 100, timestamp: 9000, tid: 0, sid: 0, pDiff: nil},
		{pictureID: 101, timestamp: 9001, tid: 1, sid: 0, pDiff: []uint8{1}},
		{pictureID: 102, timestamp: 9002, tid: 0, sid: 1, pDiff: []uint8{1, 2}},
	}
	// Stream 2: PictureID restarts from zero, different timestamp base.
	stream2 := []struct {
		pictureID uint16
		timestamp uint32
		tid, sid  uint8
		pDiff     []uint8
	}{
		{pictureID: 0, timestamp: 1000, tid: 0, sid: 0, pDiff: nil},
		{pictureID: 1, timestamp: 1001, tid: 1, sid: 0, pDiff: []uint8{1}},
		{pictureID: 2, timestamp: 1002, tid: 0, sid: 1, pDiff: []uint8{1, 2}},
	}

	remapFrame := func(
		frame struct {
			pictureID uint16
			timestamp uint32
			tid, sid  uint8
			pDiff     []uint8
		},
	) []VP9Packet {
		descriptor := vp9FlexibleDescriptor(
			frame.pictureID, true, true, frame.tid, frame.sid, true, true, frame.pDiff,
		)
		packets := make([]VP9Packet, 0, 2)
		// Two fragments: the first starts the frame, the second ends it.
		for fragment := range 2 {
			raw := withVideo(descriptor)
			if fragment == 1 {
				raw[0] &^= 0x08 // Clear B on the continuation fragment.
			}
			rewritten, err := remapper.Remap(frame.timestamp, raw)
			require.NoError(t, err)

			packet := VP9Packet{}
			_, err = packet.Unmarshal(rewritten)
			require.NoError(t, err)
			packets = append(packets, packet)
		}

		return packets
	}

	expectedID := uint16(0)
	for _, frame := range stream1 {
		packets := remapFrame(frame)
		require.Len(t, packets, 2)
		// Every fragment of one frame keeps the same mapped PictureID.
		assert.Equal(t, expectedID, packets[0].PictureID)
		assert.Equal(t, packets[0].PictureID, packets[1].PictureID)
		// Layers and flexible reference indices survive the rewrite.
		assert.Equal(t, frame.tid, packets[0].TID)
		assert.Equal(t, frame.sid, packets[0].SID)
		assert.Equal(t, frame.pDiff, packets[0].PDiff)
		// Compressed video bytes are untouched.
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, packets[0].Payload)
		expectedID++
	}

	for _, frame := range stream2 {
		packets := remapFrame(frame)
		require.Len(t, packets, 2)
		assert.Equal(t, expectedID, packets[0].PictureID)
		assert.Equal(t, packets[0].PictureID, packets[1].PictureID)
		assert.Equal(t, frame.tid, packets[0].TID)
		assert.Equal(t, frame.sid, packets[0].SID)
		assert.Equal(t, frame.pDiff, packets[0].PDiff)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, packets[0].Payload)
		expectedID++
	}
}

// TestVP9PictureIDRemapper_PreservesPDiffSemantics checks that reference
// differences expressed through P_DIFF stay valid under consecutive output
// IDs: a P_DIFF of n must point at the frame mapped n frames earlier.
func TestVP9PictureIDRemapper_PreservesPDiffSemantics(t *testing.T) {
	remapper := VP9PictureIDRemapper{}
	mappedIDs := map[uint16]uint16{}

	frames := []struct {
		pictureID uint16
		pDiff     []uint8
	}{
		{pictureID: 50, pDiff: nil},
		{pictureID: 51, pDiff: []uint8{1}},
		{pictureID: 52, pDiff: []uint8{2}},
		{pictureID: 53, pDiff: []uint8{1, 3}},
	}
	for i, frame := range frames {
		raw := withVideo(vp9FlexibleDescriptor(frame.pictureID, true, false, 0, 0, false, false, frame.pDiff))
		rewritten, err := remapper.Remap(uint32(5000+i), raw)
		require.NoError(t, err)

		packet := VP9Packet{}
		_, err = packet.Unmarshal(rewritten)
		require.NoError(t, err)

		mappedIDs[frame.pictureID] = packet.PictureID
		for _, diff := range frame.pDiff {
			referencedSource := frame.pictureID - uint16(diff)
			expected := mappedIDs[referencedSource]
			assert.Equal(t, expected, packet.PictureID-uint16(diff),
				"P_DIFF %d from frame %d must resolve to the mapped referenced frame", diff, frame.pictureID)
		}
	}
}

// TestVP9PictureIDRemapper_PDiffRecomputedOnGap proves P_DIFF is recomputed,
// not copied: with gaps in the source PictureID space the source difference
// and the difference in the dense output sequence differ.
func TestVP9PictureIDRemapper_PDiffRecomputedOnGap(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	// Source frames 10, 13, 16 (gaps of three). Each references the previous
	// one with P_DIFF=3; after dense remapping they become 0, 1, 2 and the
	// reference difference must become 1.
	sourceIDs := []uint16{10, 13, 16}
	expectedNewIDs := []uint16{0, 1, 2}
	for i, sourceID := range sourceIDs {
		timestamp := uint32(7000 + i)
		var pDiff []uint8
		if i > 0 {
			pDiff = []uint8{3}
		}
		raw := withVideo(vp9FlexibleDescriptor(sourceID, true, false, 0, 0, false, false, pDiff))
		rewritten, err := remapper.Remap(timestamp, raw)
		require.NoError(t, err)

		packet := VP9Packet{}
		_, err = packet.Unmarshal(rewritten)
		require.NoError(t, err)
		assert.Equal(t, expectedNewIDs[i], packet.PictureID)
		if i > 0 {
			assert.Equal(t, []uint8{1}, packet.PDiff,
				"P_DIFF must be recomputed against the dense output IDs")
		}
	}
}

// TestVP9PictureIDRemapper_UnknownReference rejects a flexible packet whose
// P_DIFF points at a frame the remapper never observed.
func TestVP9PictureIDRemapper_UnknownReference(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	// PID 20 references PID 15 (P_DIFF=5), but PID 15 was never remapped.
	raw := withVideo(vp9FlexibleDescriptor(20, true, false, 0, 0, false, false, []uint8{5}))
	rewritten, err := remapper.Remap(8000, raw)
	assert.Nil(t, rewritten)
	assert.ErrorIs(t, err, ErrVP9ReferenceUnresolved)

	// The failed reference must not consume an output PictureID.
	followUp := withVideo(vp9FlexibleDescriptor(21, true, false, 0, 0, false, false, nil))
	rewritten, err = remapper.Remap(8001, followUp)
	require.NoError(t, err)
	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(0), packet.PictureID)
}

// TestVP9PictureIDRemapper_SevenBitUpgrade verifies the 7-bit form is kept
// while the new ID fits, and transparently grown to 15-bit once it does not.
func TestVP9PictureIDRemapper_SevenBitUpgrade(t *testing.T) {
	// Start one value below the 7-bit ceiling so two frames fit before the
	// output ID reaches 0x80 and the descriptor has to grow.
	remapper := VP9PictureIDRemapper{InitialPictureID: vp9Max7BitPictureID - 1}

	// First new ID (0x7E) still fits in 7 bits: the descriptor keeps one
	// PictureID byte and the input is never mutated.
	firstSource := vp9FlexibleDescriptor(10, false, false, 0, 0, false, false, nil)
	first := withVideo(firstSource)
	rewritten, err := remapper.Remap(100, first)
	require.NoError(t, err)
	assert.Len(t, rewritten, len(first))
	assert.Equal(t, withVideo(firstSource), first, "Remap must never mutate the input")

	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(vp9Max7BitPictureID-1), packet.PictureID)

	// Second new ID (0x7F) is the largest 7-bit value and still fits.
	second := withVideo(vp9FlexibleDescriptor(11, false, false, 0, 0, false, false, nil))
	rewritten, err = remapper.Remap(200, second)
	require.NoError(t, err)
	assert.Len(t, rewritten, len(second))

	// Third new ID (0x80) no longer fits: the descriptor grows by one byte
	// and every following byte (here the video payload) shifts unchanged.
	third := withVideo(vp9FlexibleDescriptor(12, false, false, 0, 0, false, false, nil))
	rewritten, err = remapper.Remap(300, third)
	require.NoError(t, err)
	assert.Len(t, rewritten, len(third)+1)

	packet = VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(vp9Max7BitPictureID+1), packet.PictureID)
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, packet.Payload)
}

// TestVP9PictureIDRemapper_GrowthShiftsEveryField makes sure that when a
// 7-bit PictureID grows to 15-bit, every descriptor field after it is shifted
// unchanged: layer indices, TL0PICIDX and flexible P_DIFF all round-trip.
func TestVP9PictureIDRemapper_GrowthShiftsEveryField(t *testing.T) {
	t.Run("non-flexible layer and TL0PICIDX", func(t *testing.T) {
		remapper := VP9PictureIDRemapper{InitialPictureID: vp9Max7BitPictureID + 1}

		raw := withVideo(vp9NonFlexibleDescriptor(5, false, 1, 2, true, 77))
		rewritten, err := remapper.Remap(100, raw)
		require.NoError(t, err)
		assert.Len(t, rewritten, len(raw)+1)

		packet := VP9Packet{}
		_, err = packet.Unmarshal(rewritten)
		require.NoError(t, err)
		assert.Equal(t, uint16(vp9Max7BitPictureID+1), packet.PictureID)
		assert.Equal(t, uint8(1), packet.TID)
		assert.Equal(t, uint8(2), packet.SID)
		assert.True(t, packet.U)
		// TID=1 with no base frame seen yet: the source TL0PICIDX is kept.
		assert.Equal(t, uint8(77), packet.TL0PICIDX)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, packet.Payload)
	})

	t.Run("flexible layer and P_DIFF", func(t *testing.T) {
		remapper := VP9PictureIDRemapper{InitialPictureID: vp9Max7BitPictureID + 1}

		// First map the referenced frame so the later P_DIFF can resolve.
		base := withVideo(
			vp9FlexibleDescriptor(3, false, true, 0, 1, false, false, nil),
		)
		_, err := remapper.Remap(190, base)
		require.NoError(t, err)

		// Source PID 6 references PID 3 (P_DIFF=3); after dense remapping the
		// IDs become adjacent, so the rewritten P_DIFF must be 1.
		raw := withVideo(
			vp9FlexibleDescriptor(6, false, true, 2, 1, false, true, []uint8{3}),
		)
		rewritten, err := remapper.Remap(200, raw)
		require.NoError(t, err)
		assert.Len(t, rewritten, len(raw)+1)

		packet := VP9Packet{}
		_, err = packet.Unmarshal(rewritten)
		require.NoError(t, err)
		assert.Equal(t, uint16(vp9Max7BitPictureID+2), packet.PictureID)
		assert.Equal(t, uint8(2), packet.TID)
		assert.Equal(t, uint8(1), packet.SID)
		assert.True(t, packet.D)
		assert.Equal(t, []uint8{1}, packet.PDiff)
		assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, packet.Payload)
	})
}

// TestVP9PictureIDRemapper_Force15Bit forces every descriptor to the 15-bit
// form, including IDs that would fit in 7 bits.
func TestVP9PictureIDRemapper_Force15Bit(t *testing.T) {
	remapper := VP9PictureIDRemapper{Force15Bit: true}

	raw := withVideo(vp9FlexibleDescriptor(7, false, false, 0, 0, false, false, nil))
	rewritten, err := remapper.Remap(100, raw)
	require.NoError(t, err)
	assert.Len(t, rewritten, len(raw)+1)

	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(0), packet.PictureID)
}

// TestVP9PictureIDRemapper_InitialPictureIDAndReset checks the configurable
// starting ID and that Reset joins a second stream without restarting the
// output sequence or re-reading InitialPictureID.
func TestVP9PictureIDRemapper_InitialPictureIDAndReset(t *testing.T) {
	remapper := VP9PictureIDRemapper{InitialPictureID: 1000}

	// First stream: two frames start at the configured ID.
	first := withVideo(vp9FlexibleDescriptor(0, true, false, 0, 0, false, false, nil))
	rewritten, err := remapper.Remap(10, first)
	require.NoError(t, err)
	firstPacket := VP9Packet{}
	_, err = firstPacket.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(1000), firstPacket.PictureID)

	second := withVideo(vp9FlexibleDescriptor(1, true, false, 0, 0, false, false, nil))
	rewritten, err = remapper.Remap(20, second)
	require.NoError(t, err)

	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(1001), packet.PictureID)

	// Changing the initial ID after the first Remap must have no effect.
	remapper.InitialPictureID = 0
	remapper.Reset()

	// Second stream restarts its source PictureID, but the output sequence
	// continues right after the previous frame.
	third := withVideo(vp9FlexibleDescriptor(0, true, false, 0, 0, false, false, nil))
	rewritten, err = remapper.Remap(30, third)
	require.NoError(t, err)

	packet = VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(1002), packet.PictureID,
		"Reset must keep the output sequence continuous and ignore a later InitialPictureID change")
}

// TestVP9PictureIDRemapper_PictureIDFormSwitch verifies that switching the
// source between the 7-bit and 15-bit PictureID forms opens a fresh mapping
// context while the output sequence stays continuous.
func TestVP9PictureIDRemapper_PictureIDFormSwitch(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	// 15-bit first, then a 7-bit descriptor reusing the same numeric ID.
	first := withVideo(vp9FlexibleDescriptor(30, true, false, 0, 0, false, false, nil))
	rewritten, err := remapper.Remap(10, first)
	require.NoError(t, err)
	firstPacket := VP9Packet{}
	_, err = firstPacket.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(0), firstPacket.PictureID)

	second := withVideo(vp9FlexibleDescriptor(30, false, false, 0, 0, false, false, nil))
	rewritten, err = remapper.Remap(20, second)
	require.NoError(t, err)

	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(1), packet.PictureID,
		"a PictureID form switch must start a fresh frame but keep the output ID sequence")
}

// TestVP9PictureIDRemapper_NoTL0BaseYet covers a higher temporal layer
// arriving before any temporal layer zero frame: with no remapped base index
// to reference, the source TL0PICIDX is preserved.
func TestVP9PictureIDRemapper_NoTL0BaseYet(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	raw := withVideo(vp9NonFlexibleDescriptor(0, true, 2, 0, false, 55))
	rewritten, err := remapper.Remap(10, raw)
	require.NoError(t, err)

	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint8(55), packet.TL0PICIDX)
	assert.Equal(t, uint8(2), packet.TID)
}

// TestVP9PictureIDRemapper_TL0PICIDX exercises non-flexible mode: temporal
// layer zero frames get consecutive TL0PICIDX values and higher temporal
// layers reuse the current base index, while TID/SID/U stay intact.
func TestVP9PictureIDRemapper_TL0PICIDX(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	cases := []struct {
		pictureID     uint16
		timestamp     uint32
		tid           uint8
		sourceTL0     uint8
		expectedTL0   uint8
		expectedNewID uint16
	}{
		{pictureID: 0, timestamp: 10, tid: 0, sourceTL0: 40, expectedTL0: 0, expectedNewID: 0},
		{pictureID: 1, timestamp: 20, tid: 1, sourceTL0: 40, expectedTL0: 0, expectedNewID: 1},
		{pictureID: 2, timestamp: 30, tid: 0, sourceTL0: 41, expectedTL0: 1, expectedNewID: 2},
		{pictureID: 3, timestamp: 40, tid: 2, sourceTL0: 41, expectedTL0: 1, expectedNewID: 3},
		{pictureID: 4, timestamp: 50, tid: 0, sourceTL0: 42, expectedTL0: 2, expectedNewID: 4},
	}
	for _, tc := range cases {
		raw := withVideo(vp9NonFlexibleDescriptor(tc.pictureID, true, tc.tid, 2, true, tc.sourceTL0))
		rewritten, err := remapper.Remap(tc.timestamp, raw)
		require.NoError(t, err)

		packet := VP9Packet{}
		_, err = packet.Unmarshal(rewritten)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedNewID, packet.PictureID)
		assert.Equal(t, tc.expectedTL0, packet.TL0PICIDX, "frame %d", tc.pictureID)
		assert.Equal(t, tc.tid, packet.TID)
		assert.Equal(t, uint8(2), packet.SID)
		assert.True(t, packet.U)
	}

	// All fragments of one frame share the rewritten TL0PICIDX too.
	raw := withVideo(vp9NonFlexibleDescriptor(5, true, 0, 0, false, 42))
	rewritten, err := remapper.Remap(60, raw)
	require.NoError(t, err)
	rewritten[0] &^= 0x08 // Continuation fragment clears B.
	second, err := remapper.Remap(60, rewritten)
	require.NoError(t, err)

	packet := VP9Packet{}
	_, err = packet.Unmarshal(second)
	require.NoError(t, err)
	assert.Equal(t, uint8(3), packet.TL0PICIDX)
	assert.Equal(t, uint16(5), packet.PictureID)
}

// TestVP9PictureIDRemapper_Wrap verifies output wraparound from 0x7FFF to
// zero and that the remapper keeps assigning consecutive IDs across it.
func TestVP9PictureIDRemapper_Wrap(t *testing.T) {
	remapper := VP9PictureIDRemapper{InitialPictureID: vp9Max15BitPictureID}

	expected := []uint16{vp9Max15BitPictureID, 0, 1}
	for i, want := range expected {
		raw := withVideo(vp9FlexibleDescriptor(uint16(100+i), true, false, 0, 0, false, false, nil))
		rewritten, err := remapper.Remap(uint32(1000+i*10), raw)
		require.NoError(t, err)

		packet := VP9Packet{}
		_, err = packet.Unmarshal(rewritten)
		require.NoError(t, err)
		assert.Equal(t, want, packet.PictureID)
	}
}

// TestVP9PictureIDRemapper_MissingPictureID covers descriptors without an
// PictureID (I=0): they cannot be remapped and the input is left untouched.
func TestVP9PictureIDRemapper_MissingPictureID(t *testing.T) {
	remapper := VP9PictureIDRemapper{}
	raw := withVideo([]byte{0x18}) // No I flag, B=1 E=1.

	rewritten, err := remapper.Remap(100, raw)
	assert.Nil(t, rewritten)
	assert.ErrorIs(t, err, ErrVP9PictureIDMissing)
	assert.Equal(t, []byte{0x18, 0xDE, 0xAD, 0xBE, 0xEF}, raw)
}

// TestVP9PictureIDRemapper_BadDescriptor rejects truncated and otherwise
// malformed descriptors without mutating remapper state or the input.
func TestVP9PictureIDRemapper_BadDescriptor(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	cases := map[string][]byte{
		"empty":                 {},
		"extended id truncated": {vp9FlagI, vp9FlagM},
		"layer byte truncated":  {vp9FlagI | vp9FlagL, 0x05},
		"tl0 truncated":         {vp9FlagI | vp9FlagL, 0x05, 0x00},
		"p diff truncated":      {vp9FlagI | vp9FlagF | vp9FlagP, 0x05, 0x03},
		"too many p diff":       {vp9FlagI | vp9FlagF | vp9FlagP, 0x05, 0x03, 0x05, 0x07, 0x09},
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			original := append([]byte{}, raw...)
			rewritten, err := remapper.Remap(100, raw)
			assert.Nil(t, rewritten)
			assert.Error(t, err)
			assert.Equal(t, original, raw, "input must not be modified on error")
		})
	}

	// A failed parse must not consume an output PictureID.
	good := withVideo(vp9FlexibleDescriptor(1, true, false, 0, 0, false, false, nil))
	rewritten, err := remapper.Remap(200, good)
	require.NoError(t, err)
	packet := VP9Packet{}
	_, err = packet.Unmarshal(rewritten)
	require.NoError(t, err)
	assert.Equal(t, uint16(0), packet.PictureID)
}

// TestVP9PictureIDRemapper_ReorderedPackets feeds the fragments of two frames
// out of order. A reordered fragment of a known frame reuses its mapping; a
// fragment of a frame whose mapping has expired is reported as late.
func TestVP9PictureIDRemapper_ReorderedPackets(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	frameA := withVideo(vp9FlexibleDescriptor(10, true, false, 0, 0, false, false, nil))
	frameB := withVideo(vp9FlexibleDescriptor(11, true, false, 0, 0, false, false, nil))

	rewrittenB, err := remapper.Remap(200, frameB)
	require.NoError(t, err)
	// Frame A's fragment arrives after frame B but is still inside the
	// tracked window: it receives its own stable mapping, not frame B's.
	rewrittenA, err := remapper.Remap(100, frameA)
	require.NoError(t, err)
	// A second fragment of A, reordered after B, must reuse A's mapping.
	rewrittenALate, err := remapper.Remap(100, frameA)
	require.NoError(t, err)

	packetA := VP9Packet{}
	_, err = packetA.Unmarshal(rewrittenA)
	require.NoError(t, err)
	packetALate := VP9Packet{}
	_, err = packetALate.Unmarshal(rewrittenALate)
	require.NoError(t, err)
	packetB := VP9Packet{}
	_, err = packetB.Unmarshal(rewrittenB)
	require.NoError(t, err)

	assert.Equal(t, packetA.PictureID, packetALate.PictureID)
	assert.NotEqual(t, packetA.PictureID, packetB.PictureID)

	// A backward jump past half the PictureID space looks like either a
	// source wraparound or a second concatenated stream: the remapper drops
	// the old frame table and starts a fresh context while keeping the
	// output ID sequence continuous.
	remapper.Reset()
	first := withVideo(vp9FlexibleDescriptor(30, true, false, 0, 0, false, false, nil))
	rewrittenFirst, err := remapper.Remap(300, first)
	require.NoError(t, err)
	old := withVideo(vp9FlexibleDescriptor(20, true, false, 0, 0, false, false, nil))
	rewrittenOld, err := remapper.Remap(310, old)
	require.NoError(t, err)

	packetFirst := VP9Packet{}
	_, err = packetFirst.Unmarshal(rewrittenFirst)
	require.NoError(t, err)
	packetOld := VP9Packet{}
	_, err = packetOld.Unmarshal(rewrittenOld)
	require.NoError(t, err)
	assert.Equal(t, packetFirst.PictureID+1, packetOld.PictureID,
		"the concatenated output sequence must stay continuous across a reset")
}

// TestVP9PictureIDRemapper_TimestampSwitch distinguishes frame fragments from
// a PictureID reused by another frame: same timestamp means same frame, a
// different timestamp on a flushed ID is reported as late.
func TestVP9PictureIDRemapper_TimestampSwitch(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	raw := withVideo(vp9FlexibleDescriptor(40, true, false, 0, 0, false, false, nil))
	first, err := remapper.Remap(9000, raw)
	require.NoError(t, err)
	// Same source PictureID and timestamp: another fragment, same mapping.
	second, err := remapper.Remap(9000, raw)
	require.NoError(t, err)
	assert.Equal(t, first, second)

	// Same source PictureID but another timestamp while the entry is still
	// cached cannot be disambiguated and is rejected as late rather than
	// silently mislabeled as the cached frame.
	_, err = remapper.Remap(9500, raw)
	assert.ErrorIs(t, err, ErrVP9LatePacket)
}

// TestVP9PictureIDRemapper_SourceWrap continues the output sequence across a
// source-stream PictureID wraparound: output IDs never restart.
func TestVP9PictureIDRemapper_SourceWrap(t *testing.T) {
	remapper := VP9PictureIDRemapper{}

	before := withVideo(vp9FlexibleDescriptor(vp9Max15BitPictureID, true, false, 0, 0, false, false, nil))
	rewritten, err := remapper.Remap(10, before)
	require.NoError(t, err)
	after := withVideo(vp9FlexibleDescriptor(0, true, false, 0, 0, false, false, nil))
	rewrapped, err := remapper.Remap(20, after)
	require.NoError(t, err)

	packetBefore := VP9Packet{}
	_, err = packetBefore.Unmarshal(rewritten)
	require.NoError(t, err)
	packetAfter := VP9Packet{}
	_, err = packetAfter.Unmarshal(rewrapped)
	require.NoError(t, err)
	assert.Equal(t, uint16(0), packetBefore.PictureID)
	assert.Equal(t, uint16(1), packetAfter.PictureID)
}

// TestVP9PictureIDRemapper_PayloaderIntegration runs two real
// VP9Payloader-produced streams (one flexible, one non-flexible) through the
// remapper and checks every output packet round-trips through VP9Packet.
func TestVP9PictureIDRemapper_PayloaderIntegration(t *testing.T) {
	remapper := VP9PictureIDRemapper{}
	videoFrame := []byte{0x82, 0x49, 0x83, 0x42, 0x00, 0x77, 0xF0, 0x32, 0x34}

	var previousID *uint16
	for stream, flexible := range []bool{true, false} {
		if stream > 0 {
			// Both payloaders start their PictureID at zero: mark the stream
			// boundary explicitly instead of relying on jump detection.
			remapper.Reset()
		}
		payloader := VP9Payloader{
			FlexibleMode:       flexible,
			InitialPictureIDFn: func() uint16 { return 0 },
		}
		// Non-flexible key frames carry an 11-byte descriptor on the first
		// fragment, so the MTU must leave room for at least one video byte.
		mtu := uint16(12)
		timestampBase := uint32(stream * 1000)
		for frame := range 4 {
			packets := payloader.Payload(mtu, videoFrame)
			require.NotEmpty(t, packets)
			timestamp := timestampBase + uint32(frame)
			var expectedID uint16
			for i, raw := range packets {
				rewritten, err := remapper.Remap(timestamp, raw)
				require.NoError(t, err)

				packet := VP9Packet{}
				_, err = packet.Unmarshal(rewritten)
				require.NoError(t, err)
				if i == 0 {
					expectedID = packet.PictureID
					if previousID != nil {
						assert.Equal(t, *previousID+1, expectedID,
							"the output PictureID sequence must stay continuous at the stream join")
					}
					id := expectedID
					previousID = &id
				} else {
					assert.Equal(t, expectedID, packet.PictureID,
						"stream %d frame %d fragments must share one PictureID", stream, frame)
				}
				// The video bytes of the final fragment are preserved.
				if i == len(packets)-1 {
					assert.Equal(t, videoFrame[len(videoFrame)-len(packet.Payload):], packet.Payload)
				}
			}
		}
	}
}
