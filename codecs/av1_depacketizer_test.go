// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"

	"github.com/pion/rtp/codecs/av1/obu"
	"github.com/stretchr/testify/assert"
)

// Create an AV1 OBU for testing. Returns one without the obu_size_field and another with it included.
func createAV1OBU(obuType obu.Type, payload []byte) ([]byte, []byte) {
	header := obu.Header{Type: obuType}
	withoutSize := createTestPayload(header, payload)
	header.HasSizeField = true
	withSize := createTestPayload(header, payload)

	return withoutSize, withSize
}

func createTestPayload(obuHeader obu.Header, payload []byte) []byte {
	buf := make([]byte, 0)
	buf = append(buf, obuHeader.Marshal()...)
	if obuHeader.HasSizeField {
		buf = append(buf, obu.WriteToLeb128(uint(len(payload)))...)
	}

	buf = append(buf, payload...)

	return buf
}

func TestAV1Depacketizer_invalidPackets(t *testing.T) {
	depacketizer := AV1Depacketizer{}
	_, err := depacketizer.Unmarshal([]byte{})
	assert.ErrorIs(t, err, errShortPacket)

	_, err = depacketizer.Unmarshal([]byte{0b11000000, 0xFF})
	assert.ErrorIs(t, err, obu.ErrFailedToReadLEB128)

	_, err = depacketizer.Unmarshal(append([]byte{0b00000000}, obu.WriteToLeb128(0x99)...))
	assert.ErrorIs(t, err, errShortPacket)

	_, err = depacketizer.Unmarshal(append([]byte{0b00000000}, obu.WriteToLeb128(0x01)...))
	assert.ErrorIs(t, err, errShortPacket)

	_, err = depacketizer.Unmarshal(
		append(
			[]byte{0b00110000},
			append(
				obu.WriteToLeb128(1),
				[]byte{0x01}...,
			)...,
		),
	)
	assert.ErrorIs(t, err, errShortPacket)
}

func TestAV1Depacketizer_singleOBU(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	obuData, expectedOBU := createAV1OBU(4, payload)

	packet := make([]byte, 0)

	packet = append(packet, []byte{0b00000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuData)))...)
	packet = append(packet, obuData...)

	d := AV1Depacketizer{}
	obu, err := d.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU, obu)
}

func TestAV1Depacketizer_singleOBUWithPadding(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	obuData, expectedOBU := createAV1OBU(4, payload)

	packet := make([]byte, 0)

	packet = append(packet, []byte{0b00000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuData)))...)
	packet = append(packet, obuData...)
	// padding
	packet = append(packet, []byte{0x00, 0x00, 0x00}...)

	d := AV1Depacketizer{}
	obu, err := d.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU, obu)
}

// AV1 OBUs shouldn't include the obu_size_field when packetized in RTP,
// but we still support it since it's encountered in the wild (Including pion old clients).
func TestAV1Depacketizer_withOBUSize(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	_, obuData := createAV1OBU(4, payload)

	packet := make([]byte, 0)

	packet = append(packet, []byte{0b00000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuData)))...)
	packet = append(packet, obuData...)

	d := AV1Depacketizer{}
	obu, err := d.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, obuData, obu)
}

func TestAV1Depacketizer_validateOBUSize(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		expect  []byte
		err     error
	}{
		{
			name: "invalid OBU size",
			payload: []byte{
				0,    // Aggregation header
				0x02, // Length field
				0x22, // OBU header (has_size_field = 1)
				0xFF, // Invalid LEB128 size
			},
			err: obu.ErrFailedToReadLEB128,
		},
		{
			name: "OBU size larger than payload",
			payload: []byte{
				0,                // Aggregation header
				0x05,             // Length field
				0x22,             // OBU header (has_size_field = 1)
				0x04,             // LEB128 size
				0x03, 0x01, 0x02, // OBU data
			},
			expect: []byte{
				0x22,             // OBU header
				0x03,             // Corrected size
				0x03, 0x01, 0x02, // OBU data
			},
		},
		{
			name: "OBU size smaller than length field",
			payload: []byte{
				0,                // Aggregation header
				0x05,             // Length field
				0x22,             // OBU header (has_size_field = 1)
				0x02,             // LEB128 size
				0x03, 0x01, 0x02, // OBU data
			},
			expect: []byte{
				0x22,             // OBU header
				0x03,             // Corrected size
				0x03, 0x01, 0x02, // OBU data
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := AV1Depacketizer{}
			obu, err := d.Unmarshal(tt.payload)
			if tt.err != nil {
				assert.ErrorIs(t, err, tt.err)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expect, obu)
		})
	}
}

func TestAV1Depacketizer_dropBuffer(t *testing.T) {
	depacketizer := &AV1Depacketizer{}
	empty, err := depacketizer.Unmarshal([]byte{0x41, 0x02, 0x00, 0x01})
	assert.NoError(t, err)
	assert.Len(t, empty, 0)

	payload := []byte{0x08, 0x02, 0x03}
	obuData, expectedOBU := createAV1OBU(4, payload)

	packet := make([]byte, 0)

	// N=true, should clear buffer
	packet = append(packet, []byte{0b00001000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuData)))...)
	packet = append(packet, obuData...)

	obu, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU, obu)
}

func TestAV1Depacketizer_singleOBUWithW(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	obuData, expectedOBU := createAV1OBU(4, payload)

	packet := append([]byte{0b00010000}, obuData...)

	d := AV1Depacketizer{}
	obu, err := d.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU, obu)
}

func TestDepacketizer_multipleFullOBUs(t *testing.T) {
	obu1, expectedOBU1 := createAV1OBU(4, []byte{0x01, 0x02, 0x03})
	obu2, expectedOBU2 := createAV1OBU(4, []byte{0x04, 0x05, 0x06})
	obu3, expectedOBU3 := createAV1OBU(4, []byte{0x07, 0x08, 0x09})
	expected := append(append(expectedOBU1, expectedOBU2...), expectedOBU3...)

	packet := make([]byte, 0)

	packet = append(packet, []byte{0b00000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu1)))...)
	packet = append(packet, obu1...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2)))...)
	packet = append(packet, obu2...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu3)))...)
	packet = append(packet, obu3...)

	d := AV1Depacketizer{}
	obus, err := d.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)
}

func TestAV1Depacketizer_multipleFullOBUsWithW(t *testing.T) {
	obu1, expectedOBU1 := createAV1OBU(4, []byte{0x01, 0x02, 0x03})
	obu2, expectedOBU2 := createAV1OBU(4, []byte{0x04, 0x05, 0x06})
	obu3, expectedOBU3 := createAV1OBU(4, []byte{0x07, 0x08, 0x09})
	expected := append(append(expectedOBU1, expectedOBU2...), expectedOBU3...)

	packet := make([]byte, 0)

	packet = append(packet, []byte{0b00110000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu1)))...)
	packet = append(packet, obu1...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2)))...)
	packet = append(packet, obu2...)
	// Last MUST NOT be preceded by a length field if W is not 0
	packet = append(packet, obu3...)

	depacketizer := AV1Depacketizer{}
	obus, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)
}

func TestDepacketizer_fragmentedOBUS(t *testing.T) {
	// Not up to spec AV1 stream but it should be depacketized.
	// [ SH MD ] Frag(MD(0,0)) [ FH(0,0) TG(0,0) ] Frag(MD(0,1)) [ FH(0,1) ] [ TG(0,1) ]
	obu1, expectedOBU1 := createAV1OBU(1, []byte{0x01, 0x02, 0x03})
	obu2, expectedOBU2 := createAV1OBU(7, []byte{0x04, 0x05, 0x06})
	obu3, expectedOBU3 := createAV1OBU(7, []byte{0x07, 0x08, 0x09})
	obu3f1 := obu3[:2]
	obu3f2 := obu3[2:]
	obu4, expectedOBU4 := createAV1OBU(3, []byte{0x0A, 0x0B, 0x0C})
	obu5, expectedOBU5 := createAV1OBU(6, []byte{0x0D, 0x0E, 0x0F})
	obu6, expectedOBU6 := createAV1OBU(7, []byte{0x10, 0x11, 0x12})
	obu6f1 := obu6[:2]
	obu6f2 := obu6[2:]
	obu7, expectedOBU7 := createAV1OBU(3, []byte{0x13, 0x14, 0x15})
	obu8, expectedOBU8 := createAV1OBU(6, []byte{0x16, 0x17, 0x18})

	depacketizer := AV1Depacketizer{}

	packet := make([]byte, 0)
	packet = append(packet, []byte{0b01000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu1)))...)
	packet = append(packet, obu1...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2)))...)
	packet = append(packet, obu2...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu3f1)))...)
	packet = append(packet, obu3f1...)

	obus, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)

	expected := make([]byte, 0)
	expected = append(expected, expectedOBU1...)
	expected = append(expected, expectedOBU2...)
	assert.Equal(t, expected, obus)

	packet = make([]byte, 0)
	packet = append(packet, []byte{0b11000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu3f2)))...)
	packet = append(packet, obu3f2...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu4)))...)
	packet = append(packet, obu4...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu5)))...)
	packet = append(packet, obu5...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu6f1)))...)
	packet = append(packet, obu6f1...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)

	expected = append(append(expectedOBU3, expectedOBU4...), expectedOBU5...)
	assert.Equal(t, expected, obus)

	packet = make([]byte, 0)
	packet = append(packet, []byte{0b10100000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu6f2)))...)
	packet = append(packet, obu6f2...)
	// W is defined as 2, so the last OBU MUST NOT have a length field
	packet = append(packet, obu7...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)

	expected = make([]byte, 0)
	expected = append(expected, expectedOBU6...)
	expected = append(expected, expectedOBU7...)
	assert.Equal(t, expected, obus)

	packet = make([]byte, 0)
	packet = append(packet, []byte{0b00000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obu8)))...)
	packet = append(packet, obu8...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU8, obus)
}

func TestAV1Depacketizer_dropLostFragment(t *testing.T) {
	depacketizer := AV1Depacketizer{}

	obus, err := depacketizer.Unmarshal(
		append(
			append([]byte{0b01000000}, obu.WriteToLeb128(3)...),
			[]byte{0x01, 0x02, 0x03}...,
		),
	)
	assert.NoError(t, err)
	assert.Len(t, obus, 0, "Expected empty OBU for fragmented OBU")

	newOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{0x04, 0x05, 0x06})
	obus, err = depacketizer.Unmarshal(
		append(
			append([]byte{0b00000000}, obu.WriteToLeb128(uint(len(newOBU)))...),
			newOBU...,
		),
	)
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)
}

func TestAV1Depacketizer_dropIfLostFragment(t *testing.T) {
	depacketizer := AV1Depacketizer{}

	obus, err := depacketizer.Unmarshal(
		append(
			append([]byte{0b10000000}, obu.WriteToLeb128(3)...),
			[]byte{0x01, 0x02, 0x03}...,
		),
	)
	assert.NoError(t, err)
	assert.Len(t, obus, 0, "Expected empty OBU for fragmented OBU")

	newOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{0x04, 0x05, 0x06})
	obus, err = depacketizer.Unmarshal(
		append(
			append([]byte{0b00000000}, obu.WriteToLeb128(uint(len(newOBU)))...),
			newOBU...,
		),
	)
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)

	packet := make([]byte, 0)
	packet = append(packet, []byte{0b10000000}...)
	packet = append(packet, obu.WriteToLeb128(3)...)
	packet = append(packet, []byte{0x01, 0x02, 0x03}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(newOBU)))...)
	packet = append(packet, newOBU...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)
}

func TestAV1Depacketizer_IsPartitionTail(t *testing.T) {
	depacketizer := &AV1Depacketizer{
		buffer: []byte{1, 2},
	}

	assert.False(t, depacketizer.IsPartitionTail(false, []byte{1, 2}))
	assert.Equal(t, depacketizer.buffer, []byte{1, 2})
	assert.True(t, depacketizer.IsPartitionTail(true, []byte{1, 2}))
}

func TestAV1Depacketizer_IsPartitionHead(t *testing.T) {
	depacketizer := &AV1Depacketizer{}

	assert.False(t, depacketizer.IsPartitionHead(nil))
	assert.False(t, depacketizer.IsPartitionHead([]byte{}))
	assert.False(t, depacketizer.IsPartitionHead([]byte{0b11000000}))
	assert.True(t, depacketizer.IsPartitionHead([]byte{0b00000000}))
}

func TestAV1Depacketizer_ignoreBadOBUs(t *testing.T) {
	shouldIgnore := []obu.Type{
		obu.OBUTemporalDelimiter,
		obu.OBUTileList,
	}

	for _, obuType := range shouldIgnore {
		payload := []byte{0x01, 0x02, 0x03}
		obuData, _ := createAV1OBU(obuType, payload)

		packet := make([]byte, 0)
		packet = append(packet, []byte{0b00000000}...)
		packet = append(packet, obu.WriteToLeb128(uint(len(obuData)))...)
		packet = append(packet, obuData...)

		depacketizer := AV1Depacketizer{}
		obu, err := depacketizer.Unmarshal(packet)
		assert.NoError(t, err)
		assert.Len(t, obu, 0, "Expected empty payload for OBU type %d", obuType)
	}
}

func TestAV1Depacketizer_fragmentedOverMultiple(t *testing.T) {
	fullOBU, expected := createAV1OBU(
		obu.OBUTileGroup,
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	)
	obuf1 := fullOBU[:2]
	obuf2 := fullOBU[2:5]
	obuf3 := fullOBU[5:7]
	obuf4 := fullOBU[7:]

	depacketizer := AV1Depacketizer{}

	packet := make([]byte, 0)
	packet = append(packet, []byte{0b01000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuf1)))...)
	packet = append(packet, obuf1...)

	obus, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Len(t, obus, 0, "Expected empty OBU for fragmented OBU")

	packet = make([]byte, 0)
	packet = append(packet, []byte{0b11000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuf2)))...)
	packet = append(packet, obuf2...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Len(t, obus, 0, "Expected empty OBU for fragmented OBU")

	packet = make([]byte, 0)
	packet = append(packet, []byte{0b11000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuf3)))...)
	packet = append(packet, obuf3...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Len(t, obus, 0, "Expected empty OBU for fragmented OBU")

	packet = make([]byte, 0)
	packet = append(packet, []byte{0b10000000}...)
	packet = append(packet, obu.WriteToLeb128(uint(len(obuf4)))...)
	packet = append(packet, obuf4...)

	obus, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)
}

func TestAV1Depacketizer_shortOBUHeader(t *testing.T) {
	d := AV1Depacketizer{}

	payload, err := d.Unmarshal([]byte{0x00, 0x01, 0x04})
	assert.Error(t, err)
	assert.Len(t, payload, 0, "Expected empty payload for short OBU header")
}

func TestAV1Depacketizer_aggregationHeader(t *testing.T) {
	depacketizer := AV1Depacketizer{}
	tests := []struct {
		name    string
		input   []byte
		payload []byte
		Z, Y, N bool
	}{
		{
			name: "Z=0, Y=0, N=0",
			// aggregation header = 0, length field = 1, obu header = 0x30
			input: []byte{0x00, 0x01, 0x30},
			// obu header = 0x32, obu size = 0
			payload: []byte{0x32, 0x00},
		},
		{
			name: "Z=1, Y=0, N=0",
			// aggregation header = z = 1, length field = 1, obu header = 0x20
			input: []byte{0x80, 0x01, 0x20},
			// packet is fragmented, with missing previous packet, so the result is empty
			payload: []byte{},
			Z:       true,
		},
		{
			name: "Z=0, Y=1, N=0",
			// aggregation header = Y = 1, length field = 1, obu header = 0x20
			input: []byte{0x40, 0x01, 0x04},
			// Packet is fragmented with the next packet.
			payload: []byte{},
			Y:       true,
		},
		{
			name: "Z=0, Y=0, N=1",
			// aggregation header = N = 1, length field = 1, obu header = 0x30
			input: []byte{0x08, 0x01, 0x30},
			// obu header = 0x32, obu size = 0
			payload: []byte{0x32, 0x00},
			N:       true,
		},
		{
			name: "Z=1, Y=1, N=1",
			// aggregation header = N, Y, Z = 1, length field = 1, obu header = 0x30
			input: []byte{0xC8, 0x01, 0x30},
			// Packet is fragmented no payload.
			payload: []byte{},
			Z:       true,
			Y:       true,
			N:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := depacketizer.Unmarshal(tt.input)
			assert.NoError(t, err)

			assert.Equal(t, tt.payload, payload)
			assert.Equal(t, tt.Z, depacketizer.Z)
			assert.Equal(t, tt.Y, depacketizer.Y)
			assert.Equal(t, tt.N, depacketizer.N)
		})
	}
}

// buildAV1FragmentedOBUSequence builds an OBU of obuType split into a first fragment of
// firstLen bytes followed by contCount continuation fragments of contLen bytes each.
// It returns the RTP payloads (aggregation header + length field + fragment) and the
// expected depacketized output (OBU with a calculated obu_size_field).
func buildAV1FragmentedOBUSequence(obuType obu.Type, firstLen, contCount, contLen int) ([][]byte, []byte) {
	total := firstLen + contCount*contLen
	obuData := make([]byte, total)
	header := obu.Header{Type: obuType}
	obuData[0] = header.Marshal()[0]
	for i := 1; i < total; i++ {
		obuData[i] = byte(i)
	}

	header.HasSizeField = true
	expected := header.Marshal()
	expected = append(expected, obu.WriteToLeb128(uint(total-1))...) //nolint:gosec // G115
	expected = append(expected, obuData[1:]...)

	fragment := func(data []byte, z, y bool) []byte {
		var hdr byte
		if z {
			hdr |= av1ZMask
		}
		if y {
			hdr |= av1YMask
		}
		pkt := []byte{hdr}
		pkt = append(pkt, obu.WriteToLeb128(uint(len(data)))...) //nolint:gosec // G115

		return append(pkt, data...)
	}

	packets := make([][]byte, 0, contCount+1)
	packets = append(packets, fragment(obuData[:firstLen], false, true))
	for i := 0; i < contCount; i++ {
		frag := obuData[firstLen+i*contLen : firstLen+(i+1)*contLen]
		packets = append(packets, fragment(frag, true, i != contCount-1))
	}

	return packets, expected
}

// Reassembling a long fragment sequence must not allocate per fragment:
// the reassembly buffer is owned by the depacketizer and grows geometrically.
func TestAV1Depacketizer_longFragmentSequenceAllocations(t *testing.T) {
	packets, expected := buildAV1FragmentedOBUSequence(obu.OBUTileGroup, 1025, 512, 1024)

	depacketizer := &AV1Depacketizer{}
	var out []byte
	for _, pkt := range packets {
		var err error
		out, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
	}
	assert.Equal(t, expected, out)

	allocs := testing.AllocsPerRun(1, func() {
		d := &AV1Depacketizer{}
		for _, pkt := range packets {
			if _, err := d.Unmarshal(pkt); err != nil {
				t.Fatal(err)
			}
		}
	})
	assert.Less(t, allocs, float64(64),
		"reassembly of %d fragments allocated %.0f times, want geometric growth", len(packets), allocs)
}

// The depacketizer must own its reassembly state: bytes kept across Unmarshal
// calls are copied, so a caller reusing its packet buffer cannot corrupt them.
func TestAV1Depacketizer_fragmentStateDoesNotAliasPayload(t *testing.T) {
	fullOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
		0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
	})
	frag1 := fullOBU[:11]
	frag2 := fullOBU[11:]

	depacketizer := &AV1Depacketizer{}

	// Reuse one backing array for both packets, as a caller reading from a socket would.
	pkt := []byte{av1YMask}
	pkt = append(pkt, obu.WriteToLeb128(uint(len(frag1)))...)
	pkt = append(pkt, frag1...)

	obus, err := depacketizer.Unmarshal(pkt)
	assert.NoError(t, err)
	assert.Len(t, obus, 0)

	next := []byte{av1ZMask}
	next = append(next, obu.WriteToLeb128(uint(len(frag2)))...)
	next = append(next, frag2...)
	copy(pkt, next) // the next packet arrives into the same buffer

	obus, err = depacketizer.Unmarshal(pkt[:len(next)])
	assert.NoError(t, err)
	assert.Equal(t, expected, obus)
}

// Slices returned by Unmarshal are owned by the caller: later packets,
// including fragmented ones that reuse the internal buffer, must not modify them.
func TestAV1Depacketizer_returnedSlicesNotSharedAcrossCalls(t *testing.T) {
	obuData1, expected1 := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02, 0x03})
	obuData2, expected2 := createAV1OBU(obu.OBUFrameHeader, []byte{0x04, 0x05, 0x06})

	depacketizer := &AV1Depacketizer{}

	packet := append([]byte{0x00}, obu.WriteToLeb128(uint(len(obuData1)))...)
	packet = append(packet, obuData1...)
	first, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expected1, first)
	saved := append([]byte(nil), first...)

	// Interleave a fragmented OBU so the internal reassembly buffer is exercised.
	packets, expectedFrag := buildAV1FragmentedOBUSequence(obu.OBUTileGroup, 8, 3, 8)
	var fragOut []byte
	for _, pkt := range packets {
		fragOut, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
	}
	assert.Equal(t, expectedFrag, fragOut)

	packet = append([]byte{0x00}, obu.WriteToLeb128(uint(len(obuData2)))...)
	packet = append(packet, obuData2...)
	second, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expected2, second)

	assert.Equal(t, saved, first, "first returned slice was modified by later packets")
}

// Fragment state must not leak across resets, empty fragments, truncated
// packets, or into frames that begin and end within a single packet.
func TestAV1Depacketizer_fragmentStateIsolation(t *testing.T) {
	newOBU, expectedNewOBU := createAV1OBU(obu.OBUTileGroup, []byte{0x04, 0x05, 0x06})
	singlePacket := append([]byte{0x00}, obu.WriteToLeb128(uint(len(newOBU)))...)
	singlePacket = append(singlePacket, newOBU...)

	t.Run("firstAndLastFragmentInSamePacket", func(t *testing.T) {
		depacketizer := &AV1Depacketizer{}

		// A complete OBU in a single packet must not leave reassembly state behind.
		obus, err := depacketizer.Unmarshal(singlePacket)
		assert.NoError(t, err)
		assert.Equal(t, expectedNewOBU, obus)
		assert.Len(t, depacketizer.buffer, 0)

		// A following continuation packet has nothing to continue and is dropped.
		obus, err = depacketizer.Unmarshal(
			append(append([]byte{av1ZMask}, obu.WriteToLeb128(3)...), 0x01, 0x02, 0x03),
		)
		assert.NoError(t, err)
		assert.Len(t, obus, 0)
	})

	t.Run("emptyFragment", func(t *testing.T) {
		depacketizer := &AV1Depacketizer{}

		// An empty first fragment (Y=1, zero length) stores nothing.
		obus, err := depacketizer.Unmarshal([]byte{av1YMask, 0x00})
		assert.NoError(t, err)
		assert.Len(t, obus, 0)
		assert.Len(t, depacketizer.buffer, 0)

		// The continuation is treated as a lost fragment and dropped.
		obus, err = depacketizer.Unmarshal(
			append(append([]byte{av1ZMask}, obu.WriteToLeb128(3)...), 0x01, 0x02, 0x03),
		)
		assert.NoError(t, err)
		assert.Len(t, obus, 0)

		// And a fresh frame decodes cleanly.
		obus, err = depacketizer.Unmarshal(singlePacket)
		assert.NoError(t, err)
		assert.Equal(t, expectedNewOBU, obus)
	})

	t.Run("truncatedLengthDoesNotCorruptState", func(t *testing.T) {
		depacketizer := &AV1Depacketizer{}

		fullOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02, 0x03, 0x04})
		frag1, frag2 := fullOBU[:3], fullOBU[3:]

		pkt := append([]byte{av1YMask}, obu.WriteToLeb128(uint(len(frag1)))...)
		pkt = append(pkt, frag1...)
		_, err := depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)

		// Truncated: the length field promises more than the payload holds.
		_, err = depacketizer.Unmarshal(
			append(append([]byte{av1ZMask}, obu.WriteToLeb128(0x99)...), 0x01),
		)
		assert.ErrorIs(t, err, errShortPacket)

		// A new frame (Z=0) resets the fragment state and decodes cleanly.
		obus, err := depacketizer.Unmarshal(singlePacket)
		assert.NoError(t, err)
		assert.Equal(t, expectedNewOBU, obus)

		// A well-formed fragmented OBU still reassembles.
		pkt = append([]byte{av1YMask}, obu.WriteToLeb128(uint(len(frag1)))...)
		pkt = append(pkt, frag1...)
		_, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
		pkt = append([]byte{av1ZMask}, obu.WriteToLeb128(uint(len(frag2)))...)
		pkt = append(pkt, frag2...)
		obus, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
		assert.Equal(t, expected, obus)
	})

	t.Run("newFrameAfterReset", func(t *testing.T) {
		depacketizer := &AV1Depacketizer{}

		fullOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02, 0x03, 0x04})
		frag1, frag2 := fullOBU[:3], fullOBU[3:]

		// Start a fragmented OBU.
		pkt := append([]byte{av1YMask}, obu.WriteToLeb128(uint(len(frag1)))...)
		pkt = append(pkt, frag1...)
		_, err := depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)

		// N=1 announces a new frame: the stored fragment is discarded.
		resetPacket := append([]byte{av1NMask}, obu.WriteToLeb128(uint(len(newOBU)))...)
		resetPacket = append(resetPacket, newOBU...)
		obus, err := depacketizer.Unmarshal(resetPacket)
		assert.NoError(t, err)
		assert.Equal(t, expectedNewOBU, obus)

		// The stale fragment must not leak into the next reassembly:
		// a continuation now is a lost fragment and gets dropped.
		obus, err = depacketizer.Unmarshal(
			append(append([]byte{av1ZMask}, obu.WriteToLeb128(uint(len(frag2)))...), frag2...),
		)
		assert.NoError(t, err)
		assert.Len(t, obus, 0)

		// Reassemble the same OBU properly after the reset.
		pkt = append([]byte{av1YMask}, obu.WriteToLeb128(uint(len(frag1)))...)
		pkt = append(pkt, frag1...)
		_, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
		pkt = append([]byte{av1ZMask}, obu.WriteToLeb128(uint(len(frag2)))...)
		pkt = append(pkt, frag2...)
		obus, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
		assert.Equal(t, expected, obus)
	})
}

func FuzzAV1DepacketizerUnmarshal(f *testing.F) {
	f.Add([]byte{0x10, 0x01, 0x00})
	f.Add([]byte{0x20, 0x01, 0x00, 0x01, 0x00})
	f.Add([]byte{0x00, 0x01, 0x00})
	f.Add([]byte{0x80, 0x01, 0x00})
	f.Add([]byte{0x40, 0x01, 0x00})
	f.Add([]byte{0x08, 0x01, 0x00})
	f.Add([]byte{0xC0, 0x01, 0x00})
	f.Add([]byte{0x30, 0x01, 0x00, 0x01, 0x00, 0x00})

	obuData, _ := createAV1OBU(obu.OBUFrameHeader, []byte{0x01, 0x02, 0x03})
	packet := append([]byte{0x00}, obu.WriteToLeb128(uint(len(obuData)))...)
	packet = append(packet, obuData...)
	f.Add(packet)

	obuData2, _ := createAV1OBU(obu.OBUFrame, []byte{0x04, 0x05})
	packet2 := append([]byte{0x10}, obuData2...)
	f.Add(packet2)

	// just check for crashes :)
	f.Fuzz(func(t *testing.T, data []byte) {
		depacketizer := &AV1Depacketizer{}
		_, err := depacketizer.Unmarshal(data)
		_ = err
	})
}
