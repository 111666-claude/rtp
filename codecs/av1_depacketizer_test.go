// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"

	"github.com/pion/rtp/codecs/av1/obu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// buildLongFragmentStream builds an OBU split into a 1025-byte first packet
// (aggregation header + 1024 OBU bytes) followed by 512 continuation packets
// carrying 1024 OBU bytes each. The last continuation terminates the OBU
// (Y=0); every intermediate packet keeps it fragmented (Y=1).
func buildLongFragmentStream(t *testing.T) (packets [][]byte, expectedOBU []byte) {
	t.Helper()

	// One OBU without obu_size_field: 1-byte header (tile group) + payload.
	// The first packet holds the header plus 1023 payload bytes; the 512
	// continuations carry the remaining 1024 each.
	payloadSize := 1023 + 512*1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	rawOBU := append([]byte{0x20}, payload...)

	// Expected low-overhead bitstream output: header with obu_has_size_field,
	// LEB128 payload size, then the payload.
	expectedOBU = append([]byte{0x22}, obu.WriteToLeb128(uint(payloadSize))...)
	expectedOBU = append(expectedOBU, payload...)

	// First packet: Z=0, Y=1, W=1. A single OBU element without a length field,
	// 1024 OBU bytes (1025 bytes including the aggregation header).
	first := make([]byte, 0, 1025)
	first = append(first, 0x50)
	first = append(first, rawOBU[:1024]...)
	packets = append(packets, first)

	off := 1024
	for i := 0; i < 512; i++ {
		agg := byte(0xd0) // Z=1, Y=1, W=1
		if i == 511 {
			agg = 0x90 // Z=1, Y=0, W=1: final fragment
		}
		pkt := make([]byte, 0, 1025)
		pkt = append(pkt, agg)
		pkt = append(pkt, rawOBU[off:off+1024]...)
		packets = append(packets, pkt)
		off += 1024
	}

	require.Equal(t, len(rawOBU), off)

	return packets, expectedOBU
}

func TestAV1Depacketizer_fragmentAllocationGrowth(t *testing.T) {
	packets, expectedOBU := buildLongFragmentStream(t)

	allocations := testing.AllocsPerRun(1, func() {
		depacketizer := AV1Depacketizer{}
		_, err := depacketizer.Unmarshal(packets[0])
		require.NoError(t, err)
		for _, pkt := range packets[1:] {
			_, err = depacketizer.Unmarshal(pkt)
			require.NoError(t, err)
		}
	})
	assert.Less(t, allocations, float64(64))

	// The reassembled OBU must be the exact byte-wise concatenation of every
	// fragment, framed as a low-overhead bitstream OBU.
	depacketizer := AV1Depacketizer{}
	var output []byte
	for i, pkt := range packets {
		out, err := depacketizer.Unmarshal(pkt)
		require.NoError(t, err)
		if i < len(packets)-1 {
			assert.Empty(t, out, "no OBU should be emitted before the final fragment")
			continue
		}
		output = out
	}
	assert.Equal(t, expectedOBU, output)
}

// TestAV1Depacketizer_fragmentReassembly verifies that a fragment sequence is
// reassembled in order, one segment at a time, even when the caller mutates or
// reuses every input packet after Unmarshal returns.
func TestAV1Depacketizer_fragmentReassembly(t *testing.T) {
	packets, expectedOBU := buildLongFragmentStream(t)

	depacketizer := AV1Depacketizer{}
	var output []byte
	for i, pkt := range packets {
		out, err := depacketizer.Unmarshal(pkt)
		require.NoError(t, err)

		// The depacketizer must own its reassembly state: scribbling over the
		// packet it was just handed must not affect any retained fragment.
		for j := range pkt {
			pkt[j] = 0xFF
		}

		if i < len(packets)-1 {
			assert.Empty(t, out)
			continue
		}
		output = out
	}
	require.NotNil(t, output)
	assert.Equal(t, expectedOBU, output)
}

// TestAV1Depacketizer_fragmentBufferNoAlias ensures the retained fragment
// never aliases the caller's packet while the OBU is in progress.
func TestAV1Depacketizer_fragmentBufferNoAlias(t *testing.T) {
	depacketizer := AV1Depacketizer{}

	first := []byte{0x50, 0x20, 0x01, 0x02, 0x03}
	out, err := depacketizer.Unmarshal(first)
	require.NoError(t, err)
	require.Empty(t, out)
	require.NotEmpty(t, depacketizer.buffer)

	first[1] = 0xEE
	first[2] = 0xFF
	assert.Equal(t, []byte{0x20, 0x01, 0x02, 0x03}, depacketizer.buffer,
		"retained fragment must not alias the input packet")

	// A continuation that extends the fragment keeps the same ownership rule.
	continuation := []byte{0xd0, 0x04, 0x05}
	_, err = depacketizer.Unmarshal(continuation)
	require.NoError(t, err)
	continuation[1] = 0xEE
	assert.Equal(t, []byte{0x20, 0x01, 0x02, 0x03, 0x04, 0x05}, depacketizer.buffer)
}

// TestAV1Depacketizer_completedOutputNoAlias verifies that a slice returned
// for a completed OBU is not polluted by packets processed afterwards. This
// covers a packet that completes one OBU and starts the next fragment.
func TestAV1Depacketizer_completedOutputNoAlias(t *testing.T) {
	depacketizer := AV1Depacketizer{}

	// First packet: start a fragmented OBU (Z=0, Y=1, W=1, no length field).
	_, err := depacketizer.Unmarshal([]byte{0x50, 0x20, 0x01, 0x02, 0x03})
	require.NoError(t, err)

	// Second packet (Z=1, Y=1, W=0): completes OBU #1 and starts OBU #2.
	compound := []byte{
		0xc0,                   // Z=1, Y=1, W=0
		0x03, 0x04, 0x05, 0x06, // length 3: tail of OBU #1
		0x04, 0x20, 0x0a, 0x0b, 0x0c, // length 4: head of OBU #2
	}
	firstOutput, err := depacketizer.Unmarshal(compound)
	require.NoError(t, err)
	expectedFirst := []byte{0x22, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	require.Equal(t, expectedFirst, firstOutput)
	snapshot := append([]byte(nil), firstOutput...)

	// Final packet (Z=1, Y=0, W=1): tail of OBU #2.
	secondOutput, err := depacketizer.Unmarshal([]byte{0x90, 0x0d})
	require.NoError(t, err)
	expectedSecond := []byte{0x22, 0x04, 0x0a, 0x0b, 0x0c, 0x0d}
	assert.Equal(t, expectedSecond, secondOutput)

	// The earlier result must survive the later packet untouched.
	assert.Equal(t, snapshot, firstOutput,
		"returned OBU must not be mutated by subsequent packets")
	assert.Nil(t, depacketizer.buffer, "buffer is released once the fragment completes")
}

// TestAV1Depacketizer_fragmentedFirstAndLastSamePacket covers an OBU whose
// first and last (only) element in a packet is itself fragmented: the retained
// buffer and the emitted output must both be independent of the input packet.
func TestAV1Depacketizer_fragmentedFirstAndLastSamePacket(t *testing.T) {
	depacketizer := AV1Depacketizer{}

	pkt := []byte{0x50, 0x20, 0x07, 0x08}
	out, err := depacketizer.Unmarshal(pkt)
	require.NoError(t, err)
	require.Empty(t, out)
	require.Equal(t, []byte{0x20, 0x07, 0x08}, depacketizer.buffer)

	pkt[1] = 0x11
	require.Equal(t, []byte{0x20, 0x07, 0x08}, depacketizer.buffer)

	out, err = depacketizer.Unmarshal([]byte{0x90, 0x09})
	require.NoError(t, err)
	// OBU payload is 07 08 09: 3 bytes (the 0x20 header is excluded from the size).
	assert.Equal(t, []byte{0x22, 0x03, 0x07, 0x08, 0x09}, out)
	assert.Nil(t, depacketizer.buffer)
}

// TestAV1Depacketizer_emptyFragmentAndTruncation exercises empty elements,
// truncated length fields and the OBU-count mismatch error semantics.
func TestAV1Depacketizer_emptyFragmentAndTruncation(t *testing.T) {
	t.Run("empty length-prefixed element", func(t *testing.T) {
		d := AV1Depacketizer{}
		out, err := d.Unmarshal([]byte{0x00, 0x00})
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("truncated length field", func(t *testing.T) {
		d := AV1Depacketizer{}
		// LEB128 claims 0x99 bytes but the packet ends immediately.
		_, err := d.Unmarshal(append([]byte{0x00}, obu.WriteToLeb128(0x99)...))
		assert.ErrorIs(t, err, errShortPacket)
	})

	t.Run("truncated OBU header", func(t *testing.T) {
		d := AV1Depacketizer{}
		_, err := d.Unmarshal([]byte{0x00, 0x01, 0x04})
		assert.Error(t, err)
	})

	t.Run("W count mismatch", func(t *testing.T) {
		d := AV1Depacketizer{}
		// W=3 but the packet only contains one element.
		_, err := d.Unmarshal([]byte{0x30, 0x01, 0x00})
		assert.ErrorIs(t, err, errShortPacket)
	})

	t.Run("short packet", func(t *testing.T) {
		d := AV1Depacketizer{}
		_, err := d.Unmarshal([]byte{0x00})
		assert.ErrorIs(t, err, errShortPacket)
	})
}

// TestAV1Depacketizer_resetDoesNotLeakState makes sure N=0/Z=0 resets and an
// N=1 keyframe start cannot bleed one frame's fragment into the next frame.
func TestAV1Depacketizer_resetDoesNotLeakState(t *testing.T) {
	t.Run("non-continuation drops stale fragment", func(t *testing.T) {
		d := AV1Depacketizer{}
		_, err := d.Unmarshal([]byte{0x50, 0x20, 0x01, 0x02})
		require.NoError(t, err)
		require.NotEmpty(t, d.buffer)

		// Z=0 starts a fresh OBU; the stale fragment must be discarded.
		newOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{0x04, 0x05})
		pkt := append([]byte{0x00}, obu.WriteToLeb128(uint(len(newOBU)))...)
		pkt = append(pkt, newOBU...)
		out, err := d.Unmarshal(pkt)
		require.NoError(t, err)
		assert.Equal(t, expected, out)
		assert.Nil(t, d.buffer)
	})

	t.Run("N bit clears fragment and starts new coded video sequence", func(t *testing.T) {
		d := AV1Depacketizer{}
		_, err := d.Unmarshal([]byte{0x50, 0x20, 0x01, 0x02})
		require.NoError(t, err)
		require.NotEmpty(t, d.buffer)

		newOBU, expected := createAV1OBU(obu.OBUTileGroup, []byte{0x06})
		// N=1, Z=0, W=0
		pkt := append([]byte{0x08}, obu.WriteToLeb128(uint(len(newOBU)))...)
		pkt = append(pkt, newOBU...)
		out, err := d.Unmarshal(pkt)
		require.NoError(t, err)
		assert.Equal(t, expected, out)
		assert.True(t, d.N)
		assert.Nil(t, d.buffer)
	})

	t.Run("two small frames back to back", func(t *testing.T) {
		d := AV1Depacketizer{}
		obu1, expected1 := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02})
		obu2, expected2 := createAV1OBU(obu.OBUTileGroup, []byte{0x03, 0x04})

		pkt1 := append([]byte{0x10}, obu1...)
		out1, err := d.Unmarshal(pkt1)
		require.NoError(t, err)
		assert.Equal(t, expected1, out1)

		pkt2 := append([]byte{0x10}, obu2...)
		out2, err := d.Unmarshal(pkt2)
		require.NoError(t, err)
		assert.Equal(t, expected2, out2)
		assert.Equal(t, expected1, out1, "first frame output must remain stable")
		assert.Nil(t, d.buffer)
	})
}
