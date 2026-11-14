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

// buildAV1FragmentedSequence builds an OBU of firstFragment+n*continuationSize
// bytes packetized as a first fragment (Z=0,Y=1), n-1 middle fragments (Z=1,Y=1)
// and a final fragment (Z=1,Y=0). It returns the OBU, the RTP payloads and the
// expected depacketized output (OBU with a calculated obu_size_field).
func buildAV1FragmentedSequence(t *testing.T, firstFragment, continuations, continuationSize int) (
	fullOBU []byte, packets [][]byte, expected []byte,
) {
	t.Helper()

	total := firstFragment + continuations*continuationSize
	fullOBU = make([]byte, total)
	// OBU header: tile group, no obu_size_field (as required by the RTP spec).
	noSizeHeader := obu.Header{Type: obu.OBUTileGroup}
	fullOBU[0] = noSizeHeader.Marshal()[0]
	for i := 1; i < total; i++ {
		fullOBU[i] = byte(i * 31)
	}

	fragment := func(z, y byte, data []byte) []byte {
		pkt := []byte{z | y}
		pkt = append(pkt, obu.WriteToLeb128(uint(len(data)))...)
		pkt = append(pkt, data...)

		return pkt
	}

	packets = append(packets, fragment(0x00, 0x40, fullOBU[:firstFragment])) // Z=0, Y=1
	offset := firstFragment
	for i := 0; i < continuations-1; i++ {
		packets = append(packets, fragment(0x80, 0x40, fullOBU[offset:offset+continuationSize])) // Z=1, Y=1
		offset += continuationSize
	}
	packets = append(packets, fragment(0x80, 0x00, fullOBU[offset:])) // Z=1, Y=0

	// The depacketizer outputs the OBU with a calculated obu_size_field:
	// header with has_size_field set, LEB128 size, then the OBU payload.
	expectedHeader := obu.Header{Type: obu.OBUTileGroup, HasSizeField: true}
	expected = expectedHeader.Marshal()
	expected = append(expected, obu.WriteToLeb128(uint(total-expectedHeader.Size()))...)
	expected = append(expected, fullOBU[expectedHeader.Size():]...)

	return fullOBU, packets, expected
}

// A 1025 byte first fragment followed by 512 continuations of 1024 bytes must
// not cause quadratic allocation growth: the reassembly buffer is reused and
// grows amortized.
func TestAV1Depacketizer_longFragmentSequenceAllocations(t *testing.T) {
	_, packets, expected := buildAV1FragmentedSequence(t, 1025, 512, 1024)

	depacketizer := &AV1Depacketizer{}
	var out []byte
	for _, pkt := range packets {
		var err error
		out, err = depacketizer.Unmarshal(pkt)
		assert.NoError(t, err)
	}
	assert.Equal(t, expected, out)

	allocs := testing.AllocsPerRun(5, func() {
		d := &AV1Depacketizer{}
		for _, pkt := range packets {
			if _, err := d.Unmarshal(pkt); err != nil {
				t.Fatal(err)
			}
		}
	})
	assert.Less(t, allocs, float64(64), "expected amortized reassembly, got %f allocations", allocs)
}

// Callers commonly reuse a single read buffer for every packet. Fragments that
// must survive across Unmarshal calls have to be copied into memory the
// depacketizer owns; the next packet must not rewrite the previous fragment.
func TestAV1Depacketizer_fragmentOwnedAcrossCalls(t *testing.T) {
	_, packets, expected := buildAV1FragmentedSequence(t, 100, 4, 64)

	// Copy every packet into one reused buffer before unmarshaling, as a
	// caller reading from a socket into a fixed buffer would.
	depacketizer := &AV1Depacketizer{}
	reused := make([]byte, 0, 256)
	var out []byte
	for _, pkt := range packets {
		reused = reused[:len(pkt)]
		copy(reused, pkt)

		var err error
		out, err = depacketizer.Unmarshal(reused)
		assert.NoError(t, err)
	}
	assert.Equal(t, expected, out)
}

// Slices returned by Unmarshal must not be polluted by subsequent calls.
func TestAV1Depacketizer_returnedSlicesAreStable(t *testing.T) {
	obu1, expectedOBU1 := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02, 0x03})
	obu2, expectedOBU2 := createAV1OBU(obu.OBUTileGroup, []byte{0x04, 0x05, 0x06, 0x07})

	packet1 := append([]byte{0b00000000}, obu.WriteToLeb128(uint(len(obu1)))...)
	packet1 = append(packet1, obu1...)
	packet2 := append([]byte{0b00000000}, obu.WriteToLeb128(uint(len(obu2)))...)
	packet2 = append(packet2, obu2...)

	depacketizer := &AV1Depacketizer{}
	out1, err := depacketizer.Unmarshal(packet1)
	assert.NoError(t, err)
	saved := append([]byte(nil), out1...)

	out2, err := depacketizer.Unmarshal(packet2)
	assert.NoError(t, err)

	assert.Equal(t, expectedOBU1, out1, "first result changed after second Unmarshal")
	assert.Equal(t, saved, out1)
	assert.Equal(t, expectedOBU2, out2)
}

// A packet that is both the first and the last fragment (Z=0,Y=0), packets
// carrying the tail of one OBU together with the head of the next, and a
// reset (N=1) followed by a new frame must not leak reassembly state.
func TestAV1Depacketizer_fragmentStateIsolation(t *testing.T) {
	obu1, expectedOBU1 := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02, 0x03})
	obu2, expectedOBU2 := createAV1OBU(obu.OBUFrameHeader, []byte{0x04, 0x05})
	obu2f1, obu2f2 := obu2[:2], obu2[2:]
	obu3, expectedOBU3 := createAV1OBU(obu.OBUTileGroup, []byte{0x06, 0x07, 0x08})

	depacketizer := &AV1Depacketizer{}

	// First and last fragment in the same packet: complete OBU, no state kept.
	packet := append([]byte{0b00000000}, obu.WriteToLeb128(uint(len(obu1)))...)
	packet = append(packet, obu1...)
	out, err := depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU1, out)
	assert.Len(t, depacketizer.buffer, 0)

	// Start a fragmented OBU (obu2).
	packet = []byte{0b01000000} // Z=0, Y=1
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2f1)))...)
	packet = append(packet, obu2f1...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Len(t, out, 0)

	// One packet carries the tail of obu2 and, as its last element, the head
	// of obu3 (Y=1). The next packet completes obu3.
	packet = []byte{0b11000000} // Z=1, Y=1
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2f2)))...)
	packet = append(packet, obu2f2...)
	packet = append(packet, obu.WriteToLeb128(2)...)
	packet = append(packet, obu3[:2]...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU2, out)

	packet = []byte{0b10000000} // Z=1, Y=0
	packet = append(packet, obu.WriteToLeb128(uint(len(obu3)-2))...)
	packet = append(packet, obu3[2:]...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU3, out)
	assert.Len(t, depacketizer.buffer, 0)

	// Start a fragmented OBU, then reset with N=1: the stale fragment must
	// not leak into the new frame.
	packet = []byte{0b01000000} // Z=0, Y=1
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2f1)))...)
	packet = append(packet, obu2f1...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Len(t, out, 0)

	packet = []byte{0b00001000} // N=1, Z=0, Y=0
	packet = append(packet, obu.WriteToLeb128(uint(len(obu1)))...)
	packet = append(packet, obu1...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU1, out)
	assert.Len(t, depacketizer.buffer, 0)

	// A new fragmented frame after the reset reassembles cleanly.
	packet = []byte{0b01000000} // Z=0, Y=1
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2f1)))...)
	packet = append(packet, obu2f1...)
	_, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)

	packet = []byte{0b10000000} // Z=1, Y=0
	packet = append(packet, obu.WriteToLeb128(uint(len(obu2f2)))...)
	packet = append(packet, obu2f2...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU2, out)
}

// Empty fragments (zero-length OBU elements) must not corrupt reassembly state.
func TestAV1Depacketizer_emptyFragments(t *testing.T) {
	obuData, expectedOBU := createAV1OBU(obu.OBUTileGroup, []byte{0x01, 0x02, 0x03})
	f1, f2 := obuData[:2], obuData[2:]

	depacketizer := &AV1Depacketizer{}

	// Empty first fragment, then the real first fragment.
	out, err := depacketizer.Unmarshal([]byte{0b01000000, 0x00}) // Z=0, Y=1, len=0
	assert.NoError(t, err)
	assert.Len(t, out, 0)

	packet := []byte{0b01000000} // Z=0, Y=1 restarts the OBU
	packet = append(packet, obu.WriteToLeb128(uint(len(f1)))...)
	packet = append(packet, f1...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Len(t, out, 0)

	// Empty continuation in the middle of the sequence.
	out, err = depacketizer.Unmarshal([]byte{0b11000000, 0x00}) // Z=1, Y=1, len=0
	assert.NoError(t, err)
	assert.Len(t, out, 0)

	packet = []byte{0b10000000} // Z=1, Y=0
	packet = append(packet, obu.WriteToLeb128(uint(len(f2)))...)
	packet = append(packet, f2...)
	out, err = depacketizer.Unmarshal(packet)
	assert.NoError(t, err)
	assert.Equal(t, expectedOBU, out)
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
