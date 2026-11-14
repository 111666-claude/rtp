// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHeaderExtension_RFC8285OneByteExtension(t *testing.T) {
	p := &OneByteHeaderExtension{}

	rawPkt := []byte{
		0xBE, 0xDE, 0x00, 0x01, 0x50, 0xAA, 0x00, 0x00,
		0x98, 0x36, 0xbe, 0x88, 0x9e,
	}
	_, err := p.Unmarshal(rawPkt)
	assert.NoError(t, err, "Unmarshal err for valid extension")

	dstData, _ := p.Marshal()
	assert.Equal(t, rawPkt, dstData)
}

func TestHeaderExtension_RFC8285OneByteTwoExtensionOfTwoBytes(t *testing.T) {
	ext := &OneByteHeaderExtension{}

	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       0xBE    |    0xDE       |           length=1            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  ID   | L=0   |     data      |  ID   |  L=0  |   data...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	rawPkt := []byte{
		0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x20, 0xBB,
	}
	_, err := ext.Unmarshal(rawPkt)
	assert.NoError(t, err, "Unmarshal err for valid extension")

	ext1 := ext.Get(1)
	ext1Expect := []byte{0xAA}
	assert.Equal(t, ext1Expect, ext1, "Extension has incorrect data")

	ext2 := ext.Get(2)
	ext2Expect := []byte{0xBB}
	assert.Equal(t, ext2Expect, ext2, "Extension has incorrect data")

	dstData, _ := ext.Marshal()
	assert.Equal(t, rawPkt, dstData)
}

func TestHeaderExtension_RFC8285OneByteMultipleExtensionsWithPadding(t *testing.T) {
	ext := &OneByteHeaderExtension{}

	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       0xBE    |    0xDE       |           length=3            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  ID   | L=0   |     data      |  ID   |  L=1  |   data...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//       ...data   |    0 (pad)    |    0 (pad)    |  ID   | L=3   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                          data                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	rawPkt := []byte{
		0xBE, 0xDE, 0x00, 0x03, 0x10, 0xAA, 0x21, 0xBB,
		0xBB, 0x00, 0x00, 0x33, 0xCC, 0xCC, 0xCC, 0xCC,
	}
	_, err := ext.Unmarshal(rawPkt)
	assert.NoError(t, err, "Unmarshal err for valid extension")

	ext1 := ext.Get(1)
	ext1Expect := []byte{0xAA}
	assert.Equal(t, ext1Expect, ext1, "Extension has incorrect data")

	ext2 := ext.Get(2)
	ext2Expect := []byte{0xBB, 0xBB}
	assert.Equal(t, ext2Expect, ext2, "Extension has incorrect data")

	ext3 := ext.Get(3)
	ext3Expect := []byte{0xCC, 0xCC, 0xCC, 0xCC}
	assert.Equal(t, ext3Expect, ext3, "Extension has incorrect data")

	dstBuf := map[string][]byte{
		"CleanBuffer": make([]byte, 1000),
		"DirtyBuffer": make([]byte, 1000),
	}
	for i := range dstBuf["DirtyBuffer"] {
		dstBuf["DirtyBuffer"][i] = 0xFF
	}
	for name, buf := range dstBuf {
		buf := buf
		t.Run(name, func(t *testing.T) {
			n, err := ext.MarshalTo(buf)
			assert.NoError(t, err)

			assert.Equal(t, rawPkt, buf[:n])
		})
	}
}

func TestHeaderExtension_RFC8285TwoByteExtension(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	rawPkt := []byte{
		0x10, 0x00, 0x00, 0x07, 0x05, 0x18, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0x00, 0x00,
	}
	_, err := ext.Unmarshal(rawPkt)
	assert.NoError(t, err, "Unmarshal err for valid extension")

	dstData, _ := ext.Marshal()
	assert.Equal(t, rawPkt, dstData)
}

func TestHeaderExtension_RFC8285TwoByteMultipleExtensionsWithPadding(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       0x10    |    0x00       |           length=3            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      ID=1     |     L=0       |     ID=2      |     L=1       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       data    |    0 (pad)    |       ID=3    |      L=4      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                          data                                 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	rawPkt := []byte{
		0x10, 0x00, 0x00, 0x03, 0x01, 0x00, 0x02, 0x01,
		0xBB, 0x00, 0x03, 0x04, 0xCC, 0xCC, 0xCC, 0xCC,
	}

	_, err := ext.Unmarshal(rawPkt)
	assert.NoError(t, err, "Unmarshal err for valid extension")

	ext1 := ext.Get(1)
	ext1Expect := []byte{}
	assert.Equal(t, ext1Expect, ext1, "Extension has incorrect data")

	ext2 := ext.Get(2)
	ext2Expect := []byte{0xBB}
	assert.Equal(t, ext2Expect, ext2, "Extension has incorrect data")

	ext3 := ext.Get(3)
	ext3Expect := []byte{0xCC, 0xCC, 0xCC, 0xCC}
	assert.Equal(t, ext3Expect, ext3, "Extension has incorrect data")
}

func TestHeaderExtension_RFC8285TwoByteMultipleExtensionsWithLargeExtension(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	// 0                   1                   2                   3
	// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       0x10    |    0x00       |           length=3            |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |      ID=1     |     L=0       |     ID=2      |     L=1       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       data    |       ID=3    |      L=17      |    data...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                            ...data...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                            ...data...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                            ...data...
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//                            ...data...                           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	rawPkt := []byte{
		0x10, 0x00, 0x00, 0x06, 0x01, 0x00, 0x02, 0x01,
		0xBB, 0x03, 0x11, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	}

	_, err := ext.Unmarshal(rawPkt)
	assert.NoError(t, err, "Unmarshal err for valid extension")

	ext1 := ext.Get(1)
	ext1Expect := []byte{}
	assert.Equal(t, ext1Expect, ext1, "Extension has incorrect data")

	ext2 := ext.Get(2)
	ext2Expect := []byte{0xBB}
	assert.Equal(t, ext2Expect, ext2, "Extension has incorrect data")

	ext3 := ext.Get(3)
	ext3Expect := []byte{
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	}
	assert.Equal(t, ext3Expect, ext3, "Extension has incorrect data")

	dstData, _ := ext.Marshal()
	assert.Equal(t, rawPkt, dstData)
}

func TestHeaderExtension_RFC8285OneByteExtensionInvalid(t *testing.T) {
	p := &OneByteHeaderExtension{}

	// Invalid extension IDs
	assert.Error(t, p.Set(0, nil))
	assert.Error(t, p.Set(15, nil))

	// Extension too large
	assert.Error(t, p.Set(10, make([]byte, 255)))
}

func TestHeaderExtension_RFC8285OneByteDelExtension(t *testing.T) {
	ext := &OneByteHeaderExtension{}

	_, err := ext.Unmarshal([]byte{0xBE, 0xDE, 0x00, 0x00})
	assert.NoError(t, err, "Unmarshal err for valid extension")
	assert.NoError(t, ext.Set(1, []byte{0xBB}), "Set err for valid extension")
	assert.NotNil(t, ext.Get(1), "Extension should exist")
	assert.NoError(t, ext.Del(1), "Should successfully delete extension")
	assert.Nil(t, ext.Get(1), "Extension should not")
	assert.Error(t, ext.Del(1), "Should return error when deleting extension that doesnt exist")
}

func TestHeaderExtension_RFC8285TwoByteDelExtension(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	_, err := ext.Unmarshal([]byte{0x10, 0x00, 0x00, 0x00})
	assert.NoError(t, err, "Unmarshal err for valid extension")

	assert.NoError(t, ext.Set(1, []byte{0xBB}), "Set err for valid extension")

	extExtension := ext.Get(1)
	assert.NotNil(t, extExtension, "Extension should exist")

	assert.NoError(t, ext.Del(1), "Should successfully delete extension")

	extExtension = ext.Get(1)
	assert.Nil(t, extExtension, "Extension should exist")
	assert.Error(t, ext.Del(1), "Should return error when deleting extension that doesnt exist")
}

func TestHeaderExtension_RFC8285TwoByteExtensionRewrite(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	// First Set on an empty extension must generate the full two-byte profile header.
	assert.NoError(t, ext.Set(200, []byte{0x01, 0x02, 0x03}))
	res, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x10, 0x00, 0x00, 0x02, 0xC8, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00}, res)

	// Rewriting the same ID must replace the payload, not duplicate the ID.
	assert.NoError(t, ext.Set(200, []byte{0x04, 0x05, 0x06}))
	res, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x10, 0x00, 0x00, 0x02, 0xC8, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x00}, res)
	assert.Equal(t, []uint8{200}, ext.GetIDs())
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, ext.Get(200))

	// A second ID is appended and both remain readable in insertion order.
	assert.NoError(t, ext.Set(50, []byte{0x07, 0x08, 0x09}))
	res, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0x10, 0x00, 0x00, 0x03, 0xC8, 0x03, 0x04, 0x05,
		0x06, 0x32, 0x03, 0x07, 0x08, 0x09, 0x00, 0x00,
	}, res)
	assert.Equal(t, []uint8{200, 50}, ext.GetIDs())
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, ext.Get(200))
	assert.Equal(t, []byte{0x07, 0x08, 0x09}, ext.Get(50))
}

func TestHeaderExtension_RFC8285TwoByteExtensionRewriteVariableLength(t *testing.T) {
	ext := &TwoByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0x01, 0x02, 0x03}))
	assert.NoError(t, ext.Set(2, []byte{0x0A, 0x0B}))

	// Rewrite the first ID with a shorter payload: no stale tail bytes may remain
	// and the following element must stay intact.
	assert.NoError(t, ext.Set(1, []byte{0x04}))
	assert.Equal(t, []byte{0x04}, ext.Get(1))
	assert.Equal(t, []byte{0x0A, 0x0B}, ext.Get(2))
	assert.Equal(t, []uint8{1, 2}, ext.GetIDs())

	// Rewrite with a longer payload.
	assert.NoError(t, ext.Set(1, []byte{0x05, 0x06, 0x07, 0x08, 0x09}))
	assert.Equal(t, []byte{0x05, 0x06, 0x07, 0x08, 0x09}, ext.Get(1))
	assert.Equal(t, []byte{0x0A, 0x0B}, ext.Get(2))
	assert.Equal(t, []uint8{1, 2}, ext.GetIDs())

	// The marshaled result must round-trip through Unmarshal.
	res, err := ext.Marshal()
	assert.NoError(t, err)
	parsed := &TwoByteHeaderExtension{}
	_, err = parsed.Unmarshal(res)
	assert.NoError(t, err)
	assert.Equal(t, []uint8{1, 2}, parsed.GetIDs())
	assert.Equal(t, []byte{0x05, 0x06, 0x07, 0x08, 0x09}, parsed.Get(1))
	assert.Equal(t, []byte{0x0A, 0x0B}, parsed.Get(2))
}

func TestHeaderExtension_RFC8285TwoByteExtensionSetAfterDel(t *testing.T) {
	ext := &TwoByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0x01}))
	assert.NoError(t, ext.Set(2, []byte{0x02}))
	assert.NoError(t, ext.Del(1))
	assert.NoError(t, ext.Del(2))
	assert.Equal(t, []uint8{}, ext.GetIDs())

	// Setting again after clearing all extensions must still produce a valid profile.
	assert.NoError(t, ext.Set(3, []byte{0x03, 0x03}))
	assert.Equal(t, []uint8{3}, ext.GetIDs())
	assert.Equal(t, []byte{0x03, 0x03}, ext.Get(3))

	res, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x10, 0x00, 0x00, 0x01, 0x03, 0x02, 0x03, 0x03}, res)
}

func TestHeaderExtension_RFC8285TwoByteExtensionBoundary(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	// ID 0 is reserved and must be rejected.
	assert.Error(t, ext.Set(0, []byte{0x01}))

	// Payloads of up to 255 bytes are encodable, 256 is not.
	assert.Error(t, ext.Set(1, make([]byte, 256)))

	big := make([]byte, 255)
	for i := range big {
		big[i] = byte(i)
	}
	assert.NoError(t, ext.Set(1, big))
	assert.Equal(t, big, ext.Get(1))

	res, err := ext.Marshal()
	assert.NoError(t, err)
	// 4 byte header + 2 byte element header + 255 bytes of data, padded to 264.
	assert.Equal(t, 264, len(res))
	assert.Equal(t, []byte{0x10, 0x00, 0x00, 0x41}, res[:4])

	// A zero-length payload is encodable.
	assert.NoError(t, ext.Set(2, []byte{}))
	assert.Equal(t, []byte{}, ext.Get(2))
	assert.Equal(t, []uint8{1, 2}, ext.GetIDs())
}

func TestHeaderExtension_RFC8285TwoByteExtensionTruncated(t *testing.T) {
	ext := &TwoByteHeaderExtension{}

	// Buffers too small to hold the extension header must return an error, not panic.
	_, err := ext.Unmarshal([]byte{})
	assert.Error(t, err)
	_, err = ext.Unmarshal([]byte{0x10, 0x00})
	assert.Error(t, err)

	// A one-byte profile must be rejected by the two-byte parser.
	_, err = ext.Unmarshal([]byte{0xBE, 0xDE, 0x00, 0x00})
	assert.Error(t, err)

	// Truncated element header and payload must not panic the readers.
	truncated := &TwoByteHeaderExtension{payload: []byte{0x10, 0x00, 0x00, 0x01, 0x05}}
	assert.Nil(t, truncated.Get(5))
	assert.Equal(t, []uint8{}, truncated.GetIDs())
	assert.Error(t, truncated.Del(5))

	truncated = &TwoByteHeaderExtension{payload: []byte{0x10, 0x00, 0x00, 0x01, 0x05, 0x04, 0xAA}}
	assert.Nil(t, truncated.Get(5))
	assert.Equal(t, []uint8{}, truncated.GetIDs())
	assert.Error(t, truncated.Del(5))

	// GetIDs on a zero-value extension must not panic.
	empty := &TwoByteHeaderExtension{}
	assert.Nil(t, empty.GetIDs())
	assert.Nil(t, empty.Get(1))
}

func TestHeaderExtension_RFC8285TwoBytePacketLevelMarshal(t *testing.T) {
	// Extensions built with TwoByteHeaderExtension.Set must be parseable at the packet level.
	ext := &TwoByteHeaderExtension{}
	assert.NoError(t, ext.Set(200, []byte{0x01, 0x02, 0x03}))
	assert.NoError(t, ext.Set(200, []byte{0x04, 0x05, 0x06}))
	assert.NoError(t, ext.Set(50, []byte{0x07, 0x08, 0x09}))

	rawExt, err := ext.Marshal()
	assert.NoError(t, err)

	pkt := &Packet{
		Header: Header{
			Extension:        true,
			ExtensionProfile: ExtensionProfileTwoByte,
		},
		Payload: []byte{0xFF},
	}
	assert.NoError(t, pkt.Header.SetExtension(200, []byte{0x04, 0x05, 0x06}))
	assert.NoError(t, pkt.Header.SetExtension(50, []byte{0x07, 0x08, 0x09}))

	rawPkt, err := pkt.Marshal()
	assert.NoError(t, err)

	parsed := &Packet{}
	assert.NoError(t, parsed.Unmarshal(rawPkt))
	assert.Equal(t, uint16(ExtensionProfileTwoByte), parsed.Header.ExtensionProfile)
	assert.Equal(t, []byte{0x04, 0x05, 0x06}, parsed.Header.GetExtension(200))
	assert.Equal(t, []byte{0x07, 0x08, 0x09}, parsed.Header.GetExtension(50))

	// The raw extension block produced by Set must match the packet-level layout.
	assert.Equal(t, rawExt, rawPkt[12:12+len(rawExt)])
}

func TestHeaderExtension_RFC8285OneByteExtensionRewrite(t *testing.T) {
	ext := &OneByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0x01, 0x02, 0x03}))
	res, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, res, []byte{0xBE, 0xDE, 0x00, 0x01, 0x12, 0x01, 0x02, 0x03})

	assert.NoError(t, ext.Set(1, []byte{0x04, 0x05, 0x06}))
	res, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, res, []byte{0xBE, 0xDE, 0x00, 0x01, 0x12, 0x04, 0x05, 0x06})

	assert.NoError(t, ext.Set(3, []byte{0x07, 0x08, 0x09}))
	res, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, res, []byte{0xBE, 0xDE, 0x00, 0x02, 0x12, 0x04, 0x05, 0x06, 0x32, 0x07, 0x08, 0x09})
}
