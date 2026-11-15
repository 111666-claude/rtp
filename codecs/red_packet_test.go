// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/pion/rtp"
	"github.com/stretchr/testify/assert"
)

var _ rtp.Depacketizer = (*REDPacket)(nil)

// rfc2198Section7 builds the packet described in RFC 2198 Section 7: one LPC
// redundancy block (PT 7, 14 bytes) plus a DVI4 primary block (PT 5, 84
// bytes), both 20 ms frames at 8 kHz so the timestamp offset is 160.
func rfc2198Section7Packet(t *testing.T) REDPacket {
	t.Helper()

	redundant := make([]byte, 14)
	primary := make([]byte, 84)
	_, err := rand.Read(redundant)
	assert.NoError(t, err)
	_, err = rand.Read(primary)
	assert.NoError(t, err)

	return REDPacket{
		Redundancy: []REDBlock{{
			PayloadType:     7,
			TimestampOffset: 160,
			Payload:         redundant,
		}},
		Primary: REDBlock{
			PayloadType: 5,
			Payload:     primary,
		},
	}
}

func rfc2198Section7Raw(t *testing.T) ([]byte, REDPacket) {
	t.Helper()

	packet := rfc2198Section7Packet(t)
	raw, err := packet.Marshal()
	assert.NoError(t, err)

	return raw, packet
}

func TestREDPacket_MarshalRFC2198Section7(t *testing.T) {
	raw, packet := rfc2198Section7Raw(t)

	// 4 octet redundant header + 14 octet redundant data
	// + 1 octet primary header + 84 octet primary data.
	assert.Len(t, raw, 4+14+1+84)

	// Redundant header: F=1, PT=7 -> 0x87.
	assert.Equal(t, byte(0x87), raw[0])
	// Timestamp offset 160 occupies the high 14 bits of octets 1-2:
	// 160<<2 = 0x0280, and block length 14 contributes no high bits.
	assert.Equal(t, byte(0x02), raw[1])
	assert.Equal(t, byte(0x80), raw[2]&0xFC)
	// Block length 14 = 0x00E, split over 10 bits (high 2 in octet 2, low 8 in octet 3).
	assert.Equal(t, byte(0x00), raw[2]&0x03)
	assert.Equal(t, byte(0x0E), raw[3])

	// All headers come first; the primary header follows the redundant one.
	assert.Equal(t, byte(0x05), raw[4])

	// Then the data blocks in header order: 14 redundant, then 84 primary.
	assert.Equal(t, packet.Redundancy[0].Payload, raw[5:19])
	assert.Equal(t, packet.Primary.Payload, raw[19:])
}

func TestREDPacket_MarshalZeroRedundancy(t *testing.T) {
	packet := REDPacket{
		Primary: REDBlock{
			PayloadType: 111,
			Payload:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	raw, err := packet.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x6F, 0xDE, 0xAD, 0xBE, 0xEF}, raw)
}

func TestREDPacket_MarshalFieldBoundaries(t *testing.T) {
	// 14 bit offset (0x3FFF) and 10 bit length (0x3FF) must pack exactly.
	maxPayload := make([]byte, redBlockLengthMax)
	for i := range maxPayload {
		maxPayload[i] = byte(i)
	}

	packet := REDPacket{
		Redundancy: []REDBlock{{
			PayloadType:     redBlockPTBits,
			TimestampOffset: redTimestampOffsetMax,
			Payload:         maxPayload,
		}},
		Primary: REDBlock{PayloadType: redBlockPTBits, Payload: []byte{0x01}},
	}

	raw, err := packet.Marshal()
	assert.NoError(t, err)

	assert.Equal(t, byte(0x80|redBlockPTBits), raw[0])
	// offset 0x3FFF shifted into the high 14 bits: octet 1 is 0xFF,
	// octet 2 is 0xFC before the length's high 2 bits are ORed in.
	assert.Equal(t, byte(0xFF), raw[1])
	assert.Equal(t, byte(0xFC|0x03), raw[2]) // offset low 8 + length high 2, all ones
	assert.Equal(t, byte(0xFF), raw[3])      // length low 8

	// Sanity check the non-max packing against explicit bit positions.
	simplePacket := REDPacket{
		Redundancy: []REDBlock{{
			PayloadType:     7,
			TimestampOffset: 160,
			Payload:         []byte{0xAA, 0xBB},
		}},
		Primary: REDBlock{PayloadType: 5, Payload: []byte{0xCC}},
	}
	simple, err := simplePacket.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0x87,       // F=1, PT=7
		0x02, 0x80, // offset 160<<2 = 0x0280, length 2 high bits 0
		0x02,             // length low 8
		0x05,             // primary header F=0, PT=5
		0xAA, 0xBB, 0xCC, // data blocks
	}, simple)

	t.Run("Overflow", func(t *testing.T) {
		tooLong := make([]byte, redBlockLengthMax+1)
		cases := map[string]REDPacket{
			"primary PT":           {Primary: REDBlock{PayloadType: 0x80, Payload: []byte{1}}},
			"redundant PT":         {Redundancy: []REDBlock{{PayloadType: 0x80, Payload: []byte{1}}}, Primary: REDBlock{PayloadType: 1, Payload: []byte{1}}},
			"redundant offset":     {Redundancy: []REDBlock{{PayloadType: 1, TimestampOffset: redTimestampOffsetMax + 1, Payload: []byte{1}}}, Primary: REDBlock{PayloadType: 1, Payload: []byte{1}}},
			"redundant block size": {Redundancy: []REDBlock{{PayloadType: 1, Payload: tooLong}}, Primary: REDBlock{PayloadType: 1, Payload: []byte{1}}},
		}
		for name, overflow := range cases {
			t.Run(name, func(t *testing.T) {
				_, err := overflow.Marshal()
				assert.ErrorIs(t, err, errREDFieldOverflow)
			})
		}
	})
}

func TestREDPacket_RoundTrip(t *testing.T) {
	cases := map[string]REDPacket{
		"zero redundancy": {
			Primary: REDBlock{PayloadType: 96, Payload: []byte{1, 2, 3, 4, 5}},
		},
		"one redundancy (RFC 2198 section 7)": rfc2198Section7Packet(t),
		"multiple redundancy": {
			Redundancy: []REDBlock{
				{PayloadType: 7, TimestampOffset: 320, Payload: []byte{0xA0, 0xA1}},
				{PayloadType: 7, TimestampOffset: 160, Payload: []byte{0xB0, 0xB1, 0xB2}},
			},
			Primary: REDBlock{PayloadType: 5, Payload: []byte{0xC0, 0xC1, 0xC2, 0xC3}},
		},
		"empty primary data": {
			Redundancy: []REDBlock{{PayloadType: 7, TimestampOffset: 160, Payload: []byte{1, 2}}},
			Primary:    REDBlock{PayloadType: 5},
		},
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := original.Marshal()
			if !assert.NoError(t, err) {
				return
			}

			parsed := REDPacket{}
			primary, err := parsed.Unmarshal(raw)
			if !assert.NoError(t, err) {
				return
			}

			assert.Len(t, parsed.Redundancy, len(original.Redundancy))
			for i := range original.Redundancy {
				assertREDBlockEqual(t, original.Redundancy[i], parsed.Redundancy[i])
			}
			assertREDBlockEqual(t, original.Primary, parsed.Primary)
			assert.Equal(t, parsed.Primary.Payload, primary)
		})
	}
}

// assertREDBlockEqual compares two blocks, treating nil and zero-length
// payloads as equivalent since they carry the same media content.
func assertREDBlockEqual(t *testing.T, expected, actual REDBlock) {
	t.Helper()
	assert.Equal(t, expected.PayloadType, actual.PayloadType)
	assert.Equal(t, expected.TimestampOffset, actual.TimestampOffset)
	// bytes.Equal treats nil and zero-length payloads as equivalent.
	assert.True(t, bytes.Equal(expected.Payload, actual.Payload),
		"payload mismatch: %v != %v", expected.Payload, actual.Payload)
}

func TestREDPacket_UnmarshalDoesNotAliasInput(t *testing.T) {
	packet := rfc2198Section7Packet(t)
	raw, err := packet.Marshal()
	assert.NoError(t, err)

	parsed := REDPacket{}
	_, err = parsed.Unmarshal(raw)
	assert.NoError(t, err)

	// Reuse the input buffer for unrelated data; parsed blocks must keep
	// their original contents.
	for i := range raw {
		raw[i] = 0
	}

	assert.Equal(t, packet.Redundancy[0].Payload, parsed.Redundancy[0].Payload)
	assert.Equal(t, packet.Primary.Payload, parsed.Primary.Payload)
}

func TestREDPacket_UnmarshalResetsBetweenPackets(t *testing.T) {
	parsed := REDPacket{}

	first := REDPacket{
		Redundancy: []REDBlock{
			{PayloadType: 1, TimestampOffset: 10, Payload: []byte{1}},
			{PayloadType: 2, TimestampOffset: 20, Payload: []byte{2, 3}},
		},
		Primary: REDBlock{PayloadType: 3, Payload: []byte{4}},
	}
	raw, err := first.Marshal()
	assert.NoError(t, err)
	_, err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Len(t, parsed.Redundancy, 2)

	// A second packet with fewer blocks must not leave stale blocks or
	// primary data from the first packet reachable.
	second := REDPacket{
		Redundancy: []REDBlock{{PayloadType: 9, TimestampOffset: 5, Payload: []byte{9}}},
		Primary:    REDBlock{PayloadType: 8, Payload: []byte{7}},
	}
	raw, err = second.Marshal()
	assert.NoError(t, err)
	_, err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Len(t, parsed.Redundancy, 1)
	assertREDBlockEqual(t, second.Redundancy[0], parsed.Redundancy[0])
	assertREDBlockEqual(t, second.Primary, parsed.Primary)

	// A third packet with no redundancy must clear the slice entirely.
	third := REDPacket{Primary: REDBlock{PayloadType: 6, Payload: []byte{5}}}
	raw, err = third.Marshal()
	assert.NoError(t, err)
	_, err = parsed.Unmarshal(raw)
	assert.NoError(t, err)
	assert.Empty(t, parsed.Redundancy)
	assertREDBlockEqual(t, third.Primary, parsed.Primary)
}

func TestREDPacket_UnmarshalErrors(t *testing.T) {
	valid, _ := rfc2198Section7Raw(t)

	cases := map[string][]byte{
		"nil packet":                 nil,
		"empty packet":               {},
		"truncated redundant header": {0x87, 0x00, 0xA0},
		"truncated before primary": {
			0x87, 0x00, 0x00, 0x05,
			0x87, 0x00, 0x00, 0x05,
		},
		"block length exceeds remaining data": func() []byte {
			// Redundant header claiming 255 bytes, primary header, one data byte.
			return []byte{0x87, 0x00, 0x03, 0xFF, 0x05, 0xAA}
		}(),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			packet := REDPacket{}
			media, err := packet.Unmarshal(raw)
			assert.Error(t, err)
			assert.Nil(t, media)
		})
	}

	// Exact sentinel checks for the required error classes.
	t.Run("sentinels", func(t *testing.T) {
		_, err := (&REDPacket{}).Unmarshal(nil)
		assert.ErrorIs(t, err, errNilPacket)

		_, err = (&REDPacket{}).Unmarshal([]byte{})
		assert.ErrorIs(t, err, errREDNoPrimaryBlock)

		_, err = (&REDPacket{}).Unmarshal([]byte{0x87, 0x00, 0x00, 0x05})
		assert.ErrorIs(t, err, errREDNoPrimaryBlock)

		// 4 byte header claiming 6 bytes of data but only 1 byte present.
		_, err = (&REDPacket{}).Unmarshal([]byte{0x87, 0x00, 0x00, 0x06, 0x05, 0xAA})
		assert.ErrorIs(t, err, errREDDataOverflow)
	})

	// The valid packet must still parse after all the failure cases.
	parsed := REDPacket{}
	_, err := parsed.Unmarshal(valid)
	assert.NoError(t, err)
	assert.Len(t, parsed.Redundancy, 1)
}

func TestREDPacket_RoundTripRandom(t *testing.T) {
	parsed := REDPacket{}

	for trial := range 50 {
		redundancyCount := trial % 4
		packet := REDPacket{
			Redundancy: make([]REDBlock, redundancyCount),
			Primary: REDBlock{
				PayloadType: uint8(trial%128) + 1, // nolint: gosec // G115 bounded
				Payload:     make([]byte, trial%64),
			},
		}
		for i := range packet.Redundancy {
			packet.Redundancy[i] = REDBlock{
				PayloadType:     uint8((trial + i) % 128), // nolint: gosec // G115 bounded
				TimestampOffset: uint16(trial*17 + i),     // nolint: gosec // G115 under 0x3FFF
				Payload:         make([]byte, (trial+i)%128),
			}
			_, err := rand.Read(packet.Redundancy[i].Payload)
			assert.NoError(t, err)
		}
		_, err := rand.Read(packet.Primary.Payload)
		assert.NoError(t, err)

		raw, err := packet.Marshal()
		assert.NoError(t, err)

		media, err := parsed.Unmarshal(raw)
		assert.NoError(t, err)
		assert.True(t, bytes.Equal(packet.Primary.Payload, media))
		if assert.Len(t, parsed.Redundancy, len(packet.Redundancy)) {
			for i := range packet.Redundancy {
				assertREDBlockEqual(t, packet.Redundancy[i], parsed.Redundancy[i])
			}
		}
		assertREDBlockEqual(t, packet.Primary, parsed.Primary)
	}
}

func TestREDPacket_RTPPacketRoundTrip(t *testing.T) {
	red := REDPacket{
		Redundancy: []REDBlock{{
			PayloadType:     7,
			TimestampOffset: 160,
			Payload:         []byte{0x01, 0x02, 0x03},
		}},
		Primary: REDBlock{PayloadType: 111, Payload: []byte{0x10, 0x20, 0x30, 0x40}},
	}

	payload, err := red.Marshal()
	assert.NoError(t, err)

	// The RED payload is used directly as an RTP packet payload.
	sent := &rtp.Packet{
		Header: rtp.Header{
			PayloadType:    63, // dynamic PT negotiated for RED
			SequenceNumber: 42,
			Timestamp:      1000,
			SSRC:           1234,
		},
		Payload: payload,
	}

	raw, err := sent.Marshal()
	assert.NoError(t, err)

	var received rtp.Packet
	assert.NoError(t, received.Unmarshal(raw))
	assert.Equal(t, payload, received.Payload)

	parsed := REDPacket{}
	media, err := parsed.Unmarshal(received.Payload)
	assert.NoError(t, err)
	assert.Len(t, parsed.Redundancy, 1)
	assertREDBlockEqual(t, red.Redundancy[0], parsed.Redundancy[0])
	assertREDBlockEqual(t, red.Primary, parsed.Primary)
	assert.Equal(t, red.Primary.Payload, media)
}

func FuzzREDPacketUnmarshal(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x05})
	f.Add([]byte{0x87, 0x02, 0x80, 0x03, 0x05, 0xAA, 0xBB, 0xCC})
	f.Add([]byte{0x87, 0x00, 0xA0})
	f.Add([]byte{0x87, 0x00, 0x03, 0xFF, 0x05, 0xAA})

	// Any input must return cleanly instead of panicking.
	f.Fuzz(func(t *testing.T, data []byte) {
		packet := REDPacket{}
		_, err := packet.Unmarshal(data)
		if err != nil {
			return
		}

		// Anything that parsed must marshal back to the same bytes.
		reencoded, marshalErr := packet.Marshal()
		assert.NoError(t, marshalErr)
		assert.Equal(t, data, reencoded)
	})
}
