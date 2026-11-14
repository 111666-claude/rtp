// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVP9Packet_Unmarshal(t *testing.T) {
	cases := map[string]struct {
		b   []byte
		pkt VP9Packet
		err error
	}{
		"Nil": {
			b:   nil,
			err: errNilPacket,
		},
		"Empty": {
			b:   []byte{},
			err: errShortPacket,
		},
		"NonFlexible": {
			b: []byte{0x00, 0xAA},
			pkt: VP9Packet{
				Payload: []byte{0xAA},
			},
		},
		"NonFlexiblePictureID": {
			b: []byte{0x80, 0x02, 0xAA},
			pkt: VP9Packet{
				I:         true,
				PictureID: 0x02,
				Payload:   []byte{0xAA},
			},
		},
		"NonFlexiblePictureIDExt": {
			b: []byte{0x80, 0x81, 0xFF, 0xAA},
			pkt: VP9Packet{
				I:         true,
				PictureID: 0x01FF,
				Payload:   []byte{0xAA},
			},
		},
		"NonFlexiblePictureIDExt_ShortPacket0": {
			b:   []byte{0x80, 0x81},
			err: errShortPacket,
		},
		"NonFlexiblePictureIDExt_ShortPacket1": {
			b:   []byte{0x80},
			err: errShortPacket,
		},
		"NonFlexibleLayerIndicePictureID": {
			b: []byte{0xA0, 0x02, 0x23, 0x01, 0xAA},
			pkt: VP9Packet{
				I:         true,
				L:         true,
				PictureID: 0x02,
				TID:       0x01,
				SID:       0x01,
				D:         true,
				TL0PICIDX: 0x01,
				Payload:   []byte{0xAA},
			},
		},
		"FlexibleLayerIndicePictureID": {
			b: []byte{0xB0, 0x02, 0x23, 0x01, 0xAA},
			pkt: VP9Packet{
				F:         true,
				I:         true,
				L:         true,
				PictureID: 0x02,
				TID:       0x01,
				SID:       0x01,
				D:         true,
				Payload:   []byte{0x01, 0xAA},
			},
		},
		"NonFlexibleLayerIndicePictureID_ShortPacket0": {
			b:   []byte{0xA0, 0x02, 0x23},
			err: errShortPacket,
		},
		"NonFlexibleLayerIndicePictureID_ShortPacket1": {
			b:   []byte{0xA0, 0x02},
			err: errShortPacket,
		},
		"FlexiblePictureIDRefIndex": {
			b: []byte{0xD0, 0x02, 0x03, 0x04, 0xAA},
			pkt: VP9Packet{
				I:         true,
				P:         true,
				F:         true,
				PictureID: 0x02,
				PDiff:     []uint8{0x01, 0x02},
				Payload:   []byte{0xAA},
			},
		},
		"FlexiblePictureIDRefIndex_TooManyPDiff": {
			b:   []byte{0xD0, 0x02, 0x03, 0x05, 0x07, 0x09, 0x10, 0xAA},
			err: errTooManyPDiff,
		},
		"FlexiblePictureIDRefIndexNoPayload": {
			b: []byte{0xD0, 0x02, 0x03, 0x04},
			pkt: VP9Packet{
				I:         true,
				P:         true,
				F:         true,
				PictureID: 0x02,
				PDiff:     []uint8{0x01, 0x02},
				Payload:   []byte{},
			},
		},
		"FlexiblePictureIDRefIndex_ShortPacket0": {
			b:   []byte{0xD0, 0x02, 0x03},
			err: errShortPacket,
		},
		"FlexiblePictureIDRefIndex_ShortPacket1": {
			b:   []byte{0xD0, 0x02},
			err: errShortPacket,
		},
		"FlexiblePictureIDRefIndex_ShortPacket2": {
			b:   []byte{0xD0},
			err: errShortPacket,
		},
		"ScalabilityStructureResolutionsNoPayload": {
			b: []byte{
				0x0A,
				(1 << 5) | (1 << 4), // NS:1 Y:1 G:0
				640 >> 8, 640 & 0xff,
				360 >> 8, 360 & 0xff,
				1280 >> 8, 1280 & 0xff,
				720 >> 8, 720 & 0xff,
			},
			pkt: VP9Packet{
				B:       true,
				V:       true,
				NS:      1,
				Y:       true,
				G:       false,
				NG:      0,
				Width:   []uint16{640, 1280},
				Height:  []uint16{360, 720},
				Payload: []byte{},
			},
		},
		"ScalabilityStructureNoPayload": {
			b: []byte{
				0x0A,
				(1 << 5) | (0 << 4) | (1 << 3), // NS:1 Y:0 G:1
				2,
				(0 << 5) | (1 << 4) | (0 << 2), // T:0 U:1 R:0 -
				(2 << 5) | (0 << 4) | (1 << 2), // T:2 U:0 R:1 -
				33,
			},
			pkt: VP9Packet{
				B:       true,
				V:       true,
				NS:      1,
				Y:       false,
				G:       true,
				NG:      2,
				PGTID:   []uint8{0, 2},
				PGU:     []bool{true, false},
				PGPDiff: [][]uint8{{}, {33}},
				Payload: []byte{},
			},
		},
		"ScalabilityStructureReserved": {
			b: []byte{
				0x0A,
				(1 << 5) | (0 << 4) | (0 << 3) | (1 << 2) | (1 << 1) | 1, // NS:1 Y:0 G:0, reserved fields set to 1
			},
			pkt: VP9Packet{
				B:       true,
				V:       true,
				NS:      1,
				Y:       false,
				G:       false,
				NG:      0,
				Payload: []byte{},
			},
		},
		"ScalabilityStructure_ShortPacket0": {
			b:   []byte{0x0A, 0x10},
			err: errShortPacket,
		},
		"ScalabilityMissingWidth": {
			b:   []byte("200"),
			err: errShortPacket,
		},
		"ScalabilityMissingNG": {
			b:   []byte("b00800000000"),
			err: errShortPacket,
		},
		"ScalabilityMissingTemporalLayerIDs": {
			b:   []byte("20H0"),
			err: errShortPacket,
		},
		"ScalabilityMissingReferenceIndices": {
			b:   []byte("20H007"),
			err: errShortPacket,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			p := VP9Packet{}
			raw, err := p.Unmarshal(testCase.b)
			if testCase.err == nil {
				assert.NoError(t, err)
				assert.NotNil(t, raw)
				assert.Equal(t, testCase.pkt, p)
			} else {
				assert.Nil(t, raw, "Result should be nil in case of error")
				assert.ErrorIs(t, err, testCase.err)
			}
		})
	}
}

func TestVP9Payloader_Payload(t *testing.T) {
	r0 := int(rand.New(rand.NewSource(0)).Int31n(0x7FFF)) //nolint:gosec
	var rands [][2]byte
	for range 10 {
		rands = append(rands, [2]byte{byte(r0>>8) | 0x80, byte(r0 & 0xFF)}) //nolint:gosec // r0 is bounded to 0x7FFF
		r0++
	}

	cases := map[string]struct {
		b        [][]byte
		flexible bool
		mtu      uint16
		res      [][]byte
	}{
		"flexible NilPayload": {
			b:        [][]byte{nil},
			flexible: true,
			mtu:      100,
			res:      [][]byte{},
		},
		"flexible SmallMTU": {
			b:        [][]byte{{0x00, 0x00}},
			flexible: true,
			mtu:      1,
			res:      [][]byte{},
		},
		"flexible OnePacket": {
			b:        [][]byte{{0x01, 0x02}},
			flexible: true,
			mtu:      10,
			res: [][]byte{
				{0x9C, rands[0][0], rands[0][1], 0x01, 0x02},
			},
		},
		"flexible TwoPackets": {
			b:        [][]byte{{0x01, 0x02}},
			flexible: true,
			mtu:      4,
			res: [][]byte{
				{0x98, rands[0][0], rands[0][1], 0x01},
				{0x94, rands[0][0], rands[0][1], 0x02},
			},
		},
		"flexible ThreePackets": {
			b:        [][]byte{{0x01, 0x02, 0x03}},
			flexible: true,
			mtu:      4,
			res: [][]byte{
				{0x98, rands[0][0], rands[0][1], 0x01},
				{0x90, rands[0][0], rands[0][1], 0x02},
				{0x94, rands[0][0], rands[0][1], 0x03},
			},
		},
		"flexible TwoFramesFourPackets": {
			b:        [][]byte{{0x01, 0x02, 0x03}, {0x04}},
			flexible: true,
			mtu:      5,
			res: [][]byte{
				{0x98, rands[0][0], rands[0][1], 0x01, 0x02},
				{0x94, rands[0][0], rands[0][1], 0x03},
				{0x9C, rands[1][0], rands[1][1], 0x04},
			},
		},
		"non-flexible NilPayload": {
			b:   [][]byte{nil},
			mtu: 100,
			res: [][]byte{},
		},
		"non-flexible SmallMTU": {
			b:   [][]byte{{0x82, 0x49, 0x83, 0x42, 0x0, 0x77, 0xf0, 0x32, 0x34}},
			mtu: 1,
			res: [][]byte{},
		},
		"non-flexible OnePacket key frame": {
			b:   [][]byte{{0x82, 0x49, 0x83, 0x42, 0x0, 0x77, 0xf0, 0x32, 0x34}},
			mtu: 20,
			res: [][]byte{{
				0x8f, 0xa1, 0xf4, 0x18, 0x07, 0x80, 0x03, 0x24,
				0x01, 0x14, 0x01, 0x82, 0x49, 0x83, 0x42, 0x00,
				0x77, 0xf0, 0x32, 0x34,
			}},
		},
		"non-flexible TwoPackets key frame": {
			b:   [][]byte{{0x82, 0x49, 0x83, 0x42, 0x0, 0x77, 0xf0, 0x32, 0x34}},
			mtu: 12,
			res: [][]byte{
				{
					0x8b, 0xa1, 0xf4, 0x18, 0x07, 0x80, 0x03, 0x24,
					0x01, 0x14, 0x01, 0x82,
				},
				{
					0x85, 0xa1, 0xf4, 0x49, 0x83, 0x42, 0x00, 0x77,
					0xf0, 0x32, 0x34,
				},
			},
		},
		"non-flexible ThreePackets key frame": {
			b: [][]byte{{
				0x82, 0x49, 0x83, 0x42, 0x00, 0x77, 0xf0, 0x32,
				0x34, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08,
			}},
			mtu: 12,
			res: [][]byte{
				{
					0x8b, 0xa1, 0xf4, 0x18, 0x07, 0x80, 0x03, 0x24,
					0x01, 0x14, 0x01, 0x82,
				},
				{
					0x81, 0xa1, 0xf4, 0x49, 0x83, 0x42, 0x00, 0x77,
					0xf0, 0x32, 0x34, 0x01,
				},
				{
					0x85, 0xa1, 0xf4, 0x02, 0x03, 0x04, 0x05, 0x06,
					0x07, 0x08,
				},
			},
		},
		"non-flexible OnePacket non key frame": {
			b:   [][]byte{{0x86, 0x0, 0x40, 0x92, 0xe1, 0x31, 0x42, 0x8c, 0xc0, 0x40}},
			mtu: 20,
			res: [][]byte{{
				0xcd, 0xa1, 0xf4, 0x86, 0x00, 0x40, 0x92, 0xe1,
				0x31, 0x42, 0x8c, 0xc0, 0x40,
			}},
		},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			pck := VP9Payloader{
				FlexibleMode: testCase.flexible,
				InitialPictureIDFn: func() uint16 {
					return uint16(rand.New(rand.NewSource(0)).Int31n(0x7FFF)) //nolint:gosec
				},
			}

			res := [][]byte{}
			for _, b := range testCase.b {
				res = append(res, pck.Payload(testCase.mtu, b)...)
			}
			assert.Equal(t, testCase.res, res)
		})
	}

	t.Run("PictureIDOverflow", func(t *testing.T) {
		pck := VP9Payloader{
			FlexibleMode: true,
			InitialPictureIDFn: func() uint16 {
				return uint16(rand.New(rand.NewSource(0)).Int31n(0x7FFF)) //nolint:gosec
			},
		}
		pPrev := VP9Packet{}
		for i := range 0x8000 {
			res := pck.Payload(4, []byte{0x01})
			packet := VP9Packet{}
			_, err := packet.Unmarshal(res[0])
			assert.NoError(t, err)

			if i > 0 {
				if pPrev.PictureID == 0x7FFF {
					assert.Equal(
						t, uint16(0), packet.PictureID,
						"Picture ID next to 0x7FFF must be 0",
					)
				} else {
					assert.Equal(t, pPrev.PictureID+1, packet.PictureID, "Picture ID next must be incremented by 1")
				}
			}

			pPrev = packet
		}
	})
}

func TestVP9IsPartitionHead(t *testing.T) {
	vp9 := &VP9Packet{}
	t.Run("SmallPacket", func(t *testing.T) {
		assert.False(t, vp9.IsPartitionHead(nil), "Small packet should not be the head of a new partition")
	})
	t.Run("NormalPacket", func(t *testing.T) {
		assert.True(
			t, vp9.IsPartitionHead([]byte{0x18, 0x00, 0x00}),
			"VP9 RTP packet with B flag should be head of a new partition",
		)
		assert.False(
			t, vp9.IsPartitionHead([]byte{0x10, 0x00, 0x00}),
			"VP9 RTP packet without B flag should not be head of a new partition",
		)
	})
}

// Three spatial layers with resolutions and a prediction group of two pictures.
var vp9SSDataThreeLayers = []byte{
	0x0A,                           // B=1, V=1
	(2 << 5) | (1 << 4) | (1 << 3), // NS:2 Y:1 G:1
	0x02, 0x80, 0x01, 0x68,         // 640x360
	0x05, 0x00, 0x02, 0xD0, // 1280x720
	0x07, 0x80, 0x05, 0xA0, // 1920x1440
	2,                              // N_G=2
	(0 << 5) | (1 << 4) | (1 << 2), // T:0 U:1 R:1
	10,                             // P_DIFF
	(2 << 5) | (0 << 4) | (2 << 2), // T:2 U:0 R:2
	20, 30,                         // P_DIFF
	0xAA, // payload
}

// Two spatial layers with resolutions and a prediction group of one picture.
var vp9SSDataTwoLayers = []byte{
	0x0A,                           // B=1, V=1
	(1 << 5) | (1 << 4) | (1 << 3), // NS:1 Y:1 G:1
	0x02, 0x80, 0x01, 0x68,         // 640x360
	0x05, 0x00, 0x02, 0xD0, // 1280x720
	1,                              // N_G=1
	(1 << 5) | (0 << 4) | (1 << 2), // T:1 U:0 R:1
	5,                              // P_DIFF
	0xBB,                           // payload
}

func TestVP9Packet_UnmarshalReuse(t *testing.T) {
	unmarshalFresh := func(raw []byte) VP9Packet {
		t.Helper()
		pkt := VP9Packet{}
		_, err := pkt.Unmarshal(raw)
		assert.NoError(t, err)

		return pkt
	}

	// resetLengthsKeepCapacity simulates a caller that retains the slices of a
	// reused VP9Packet but zeroes their lengths before parsing the next packet.
	resetLengthsKeepCapacity := func(pkt *VP9Packet) {
		pkt.Width = pkt.Width[:0]
		pkt.Height = pkt.Height[:0]
		pkt.PGTID = pkt.PGTID[:0]
		pkt.PGU = pkt.PGU[:0]
		pkt.PGPDiff = pkt.PGPDiff[:0]
	}

	// assertSamePacket asserts that a reused packet holds the same values as a
	// freshly parsed one. Empty slices are normalized to nil: a reused packet
	// retains capacity, so its empty slices are non-nil unlike a fresh one's.
	assertSamePacket := func(expected, actual VP9Packet) {
		t.Helper()
		normalize := func(pkt *VP9Packet) {
			if len(pkt.Width) == 0 {
				pkt.Width = nil
			}
			if len(pkt.Height) == 0 {
				pkt.Height = nil
			}
			if len(pkt.PGTID) == 0 {
				pkt.PGTID = nil
			}
			if len(pkt.PGU) == 0 {
				pkt.PGU = nil
			}
			if len(pkt.PGPDiff) == 0 {
				pkt.PGPDiff = nil
			}
		}
		normalize(&expected)
		normalize(&actual)
		assert.Equal(t, expected, actual)
	}

	t.Run("ShrinkLayersAndPredictionGroup", func(t *testing.T) {
		reused := unmarshalFresh(vp9SSDataThreeLayers)
		assert.Equal(t, []uint16{640, 1280, 1920}, reused.Width)
		assert.Equal(t, []uint16{360, 720, 1440}, reused.Height)
		assert.Equal(t, []uint8{0, 2}, reused.PGTID)
		assert.Equal(t, []bool{true, false}, reused.PGU)
		assert.Equal(t, [][]uint8{{10}, {20, 30}}, reused.PGPDiff)

		resetLengthsKeepCapacity(&reused)

		_, err := reused.Unmarshal(vp9SSDataTwoLayers)
		assert.NoError(t, err)

		// The reused object must be indistinguishable from a freshly parsed one:
		// no stale layers or prediction group entries may leak into the new packet.
		assertSamePacket(unmarshalFresh(vp9SSDataTwoLayers), reused)
		assert.Equal(t, []uint16{640, 1280}, reused.Width)
		assert.Equal(t, []uint16{360, 720}, reused.Height)
		assert.Equal(t, []uint8{1}, reused.PGTID)
		assert.Equal(t, []bool{false}, reused.PGU)
		assert.Equal(t, [][]uint8{{5}}, reused.PGPDiff)
	})

	t.Run("PredictionGroupMissing", func(t *testing.T) {
		reused := unmarshalFresh(vp9SSDataThreeLayers)
		resetLengthsKeepCapacity(&reused)

		// Y:1 G:0, two layers, no prediction group.
		raw := []byte{
			0x0A,
			(1 << 5) | (1 << 4),
			0x02, 0x80, 0x01, 0x68,
			0x05, 0x00, 0x02, 0xD0,
			0xCC,
		}
		_, err := reused.Unmarshal(raw)
		assert.NoError(t, err)

		assertSamePacket(unmarshalFresh(raw), reused)
		assert.Empty(t, reused.PGTID)
		assert.Empty(t, reused.PGU)
		assert.Empty(t, reused.PGPDiff)
	})

	t.Run("ResolutionsMissing", func(t *testing.T) {
		reused := unmarshalFresh(vp9SSDataThreeLayers)
		resetLengthsKeepCapacity(&reused)

		// Y:0 G:0, no resolutions and no prediction group.
		raw := []byte{0x0A, (1 << 5), 0xDD}
		_, err := reused.Unmarshal(raw)
		assert.NoError(t, err)

		assertSamePacket(unmarshalFresh(raw), reused)
		assert.Empty(t, reused.Width)
		assert.Empty(t, reused.Height)
	})

	t.Run("GrowAfterShrink", func(t *testing.T) {
		reused := unmarshalFresh(vp9SSDataTwoLayers)
		resetLengthsKeepCapacity(&reused)

		// Growing past the retained capacity must still parse correctly.
		_, err := reused.Unmarshal(vp9SSDataThreeLayers)
		assert.NoError(t, err)
		assertSamePacket(unmarshalFresh(vp9SSDataThreeLayers), reused)
	})

	t.Run("ShortPacketAfterReuse", func(t *testing.T) {
		reused := unmarshalFresh(vp9SSDataThreeLayers)
		resetLengthsKeepCapacity(&reused)

		// Truncated resolution.
		_, err := reused.Unmarshal([]byte{0x0A, (0 << 5) | (1 << 4), 0x02})
		assert.ErrorIs(t, err, errShortPacket)

		// Truncated prediction group reference indices.
		_, err = reused.Unmarshal([]byte{
			0x0A,
			(0 << 5) | (0 << 4) | (1 << 3),
			1,
			(0 << 5) | (0 << 4) | (2 << 2), // R:2 but no P_DIFF bytes follow
		})
		assert.ErrorIs(t, err, errShortPacket)
	})
}

func TestVP9Packet_UnmarshalReuseNoAlloc(t *testing.T) {
	pkt := VP9Packet{}
	_, err := pkt.Unmarshal(vp9SSDataThreeLayers)
	assert.NoError(t, err)

	// Parsing a same-shaped packet into a reused VP9Packet must not allocate.
	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = pkt.Unmarshal(vp9SSDataThreeLayers)
	})
	assert.Zero(t, allocs, "reused VP9Packet should not allocate when parsing a same-shaped packet")

	assert.Equal(t, []uint16{640, 1280, 1920}, pkt.Width)
	assert.Equal(t, []uint16{360, 720, 1440}, pkt.Height)
	assert.Equal(t, []uint8{0, 2}, pkt.PGTID)
	assert.Equal(t, []bool{true, false}, pkt.PGU)
	assert.Equal(t, [][]uint8{{10}, {20, 30}}, pkt.PGPDiff)
}
