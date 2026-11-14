// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"encoding/binary"
	"strconv"
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

func TestHeaderExtension_RFC8285OneByteExtensionFirstSet(t *testing.T) {
	ext := &OneByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0x01, 0x02, 0x03}))

	dstData, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xBE, 0xDE, 0x00, 0x01, 0x12, 0x01, 0x02, 0x03}, dstData)
	assert.Equal(t, 1, int(dstData[3]), "length field must match the padded payload")

	// Marshal returns an independent slice.
	dstData[4] = 0xFF
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, ext.Get(1), "Marshal must not alias the stored payload")
	assert.Len(t, ext.GetIDs(), 1)
}

func TestHeaderExtension_RFC8285OneByteExtensionRewrite(t *testing.T) {
	ext := &OneByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0x01, 0x02, 0x03}))

	// Same length.
	assert.NoError(t, ext.Set(1, []byte{0x04, 0x05, 0x06}))
	dstData, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xBE, 0xDE, 0x00, 0x01, 0x12, 0x04, 0x05, 0x06}, dstData)

	// Shorter, then verify no stale tail is left behind.
	assert.NoError(t, ext.Set(1, []byte{0x07}))
	dstData, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xBE, 0xDE, 0x00, 0x01, 0x10, 0x07, 0x00, 0x00}, dstData)
	assert.Equal(t, []byte{0x07}, ext.Get(1))

	// Longer than the original.
	assert.NoError(t, ext.Set(1, []byte{0x08, 0x09, 0x0A, 0x0B, 0x0C}))
	dstData, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0xBE, 0xDE, 0x00, 0x02, 0x14, 0x08, 0x09, 0x0A,
		0x0B, 0x0C, 0x00, 0x00,
	}, dstData)
	assert.Equal(t, []byte{0x08, 0x09, 0x0A, 0x0B, 0x0C}, ext.Get(1))
	assert.Equal(t, []uint8{1}, ext.GetIDs(), "rewrite must not duplicate the ID")

	// Adding another ID keeps the original data and insertion order.
	assert.NoError(t, ext.Set(3, []byte{0x0D, 0x0E, 0x0F}))
	dstData, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0xBE, 0xDE, 0x00, 0x03, 0x14, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x32, 0x0D, 0x0E, 0x0F, 0x00, 0x00,
	}, dstData)
	assert.Equal(t, []uint8{1, 3}, ext.GetIDs())
	assert.Equal(t, []byte{0x08, 0x09, 0x0A, 0x0B, 0x0C}, ext.Get(1))
	assert.Equal(t, []byte{0x0D, 0x0E, 0x0F}, ext.Get(3))
}

func TestHeaderExtension_RFC8285OneByteExtensionRewriteMiddle(t *testing.T) {
	ext := &OneByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0xAA}))
	assert.NoError(t, ext.Set(2, []byte{0xBB, 0xBB}))
	assert.NoError(t, ext.Set(3, []byte{0xCC, 0xCC, 0xCC}))

	// Rewrite the middle extension to a longer payload; neighbours must survive.
	assert.NoError(t, ext.Set(2, []byte{0x11, 0x22, 0x33, 0x44}))

	dstData, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0xBE, 0xDE, 0x00, 0x03, 0x10, 0xAA, 0x23, 0x11,
		0x22, 0x33, 0x44, 0x32, 0xCC, 0xCC, 0xCC, 0x00,
	}, dstData)
	assert.Equal(t, []uint8{1, 2, 3}, ext.GetIDs())
	assert.Equal(t, []byte{0xAA}, ext.Get(1))
	assert.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, ext.Get(2))
	assert.Equal(t, []byte{0xCC, 0xCC, 0xCC}, ext.Get(3))
}

func TestHeaderExtension_RFC8285OneByteExtensionRoundTrip(t *testing.T) {
	ext := &OneByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0x01, 0x02, 0x03}))
	assert.NoError(t, ext.Set(3, []byte{0x04}))
	assert.NoError(t, ext.Set(14, []byte{0x05, 0x06}))

	dstData, err := ext.Marshal()
	assert.NoError(t, err)

	parsed := &OneByteHeaderExtension{}
	n, err := parsed.Unmarshal(dstData)
	assert.NoError(t, err)
	assert.Equal(t, len(dstData), n)

	assert.Equal(t, ext.GetIDs(), parsed.GetIDs())
	for _, id := range ext.GetIDs() {
		assert.Equal(t, ext.Get(id), parsed.Get(id))
	}

	// A rewrite after a round trip must behave the same.
	assert.NoError(t, parsed.Set(1, []byte{0x09}))
	assert.Equal(t, []byte{0x09}, parsed.Get(1))
	assert.Equal(t, []byte{0x04}, parsed.Get(3))
	assert.Equal(t, []byte{0x05, 0x06}, parsed.Get(14))
	parsedData, err := parsed.Marshal()
	assert.NoError(t, err)
	// id=1 is now one byte: body = 2+2+3 = 7 bytes, padded to 8 -> two words.
	assert.Equal(t, 2, int(parsedData[3]))
}

func TestHeaderExtension_RFC8285OneByteExtensionBoundaryLengths(t *testing.T) {
	for _, size := range []int{1, 15, 16} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			ext := &OneByteHeaderExtension{}
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i + 1)
			}
			assert.NoError(t, ext.Set(5, payload))
			assert.Equal(t, payload, ext.Get(5))

			dstData, err := ext.Marshal()
			assert.NoError(t, err)
			assert.Equal(t, ExtensionProfileOneByte, int(binary.BigEndian.Uint16(dstData[0:2])))
			assert.Zero(t, len(dstData)%4)
			// The length field counts 4-byte words of the padded extension body.
			assert.Equal(t, ((1+size+3)/4)*4, int(dstData[3])*4,
				"length field must cover the padded extension")

			parsed := &OneByteHeaderExtension{}
			_, err = parsed.Unmarshal(dstData)
			assert.NoError(t, err)
			assert.Equal(t, payload, parsed.Get(5))
		})
	}
}

func TestHeaderExtension_RFC8285OneByteExtensionInvalid(t *testing.T) {
	ext := &OneByteHeaderExtension{}

	// Invalid extension IDs.
	assert.Error(t, ext.Set(0, []byte{0xAA}))
	assert.Error(t, ext.Set(15, []byte{0xAA}))

	// Empty and oversized payloads.
	assert.Error(t, ext.Set(1, nil))
	assert.Error(t, ext.Set(1, []byte{}))
	assert.Error(t, ext.Set(10, make([]byte, 17)))
	assert.Error(t, ext.Set(10, make([]byte, 255)))

	// Nothing was stored by the rejected calls.
	assert.Empty(t, ext.GetIDs())
	dstData, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Empty(t, dstData)

	// A failed Set must not disturb already stored extensions.
	assert.NoError(t, ext.Set(1, []byte{0xAA}))
	assert.Error(t, ext.Set(1, make([]byte, 17)))
	assert.Error(t, ext.Set(0, []byte{0xBB}))
	assert.Equal(t, []byte{0xAA}, ext.Get(1))
	assert.Equal(t, []uint8{1}, ext.GetIDs())

	assert.Error(t, ext.Del(2), "deleting an absent extension must error")
	assert.Equal(t, []byte{0xAA}, ext.Get(1), "failed Del must not change stored extensions")
}

func TestHeaderExtension_RFC8285OneByteMalformedPayload(t *testing.T) {
	// Every prefix and a few bit-flipped variants of a valid payload must be
	// handled without panicking by the accessors.
	valid := []byte{
		0xBE, 0xDE, 0x00, 0x02, 0x10, 0xAA, 0x21, 0xBB,
		0xBB, 0x00, 0x00, 0x00,
	}

	for i := 0; i <= len(valid); i++ {
		ext := &OneByteHeaderExtension{}
		assert.NotPanics(t, func() {
			ext.payload = append([]byte(nil), valid[:i]...)
			_ = ext.GetIDs()
			_ = ext.Get(1)
			assert.NotPanics(t, func() { _ = ext.Del(1) })
			assert.NotPanics(t, func() { _ = ext.Set(2, []byte{0xCC}) })
			_, err := ext.Marshal()
			assert.NoError(t, err)
		})
	}

	// Unmarshal rejects buffers that are shorter than the declared length.
	for _, buf := range [][]byte{
		{},
		{0xBE},
		{0xBE, 0xDE},
		{0xBE, 0xDE, 0x00, 0x01},
		{0xBE, 0xDE, 0x00, 0xFF, 0x10, 0xAA},
	} {
		_, err := (&OneByteHeaderExtension{}).Unmarshal(buf)
		assert.Error(t, err, "truncated extension must be rejected")
	}

	// A payload whose declared length exceeds the buffer is rejected.
	ext := &OneByteHeaderExtension{}
	_, err := ext.Unmarshal([]byte{0xBE, 0xDE, 0x00, 0x01, 0x12, 0xAA})
	assert.Error(t, err, "declared length exceeds the buffer")
}

func TestHeaderExtension_RFC8285OneByteDelMultiple(t *testing.T) {
	ext := &OneByteHeaderExtension{}
	assert.NoError(t, ext.Set(1, []byte{0xAA}))
	assert.NoError(t, ext.Set(2, []byte{0xBB, 0xBB}))
	assert.NoError(t, ext.Set(3, []byte{0xCC, 0xCC, 0xCC}))

	assert.NoError(t, ext.Del(2))
	assert.Equal(t, []uint8{1, 3}, ext.GetIDs())
	assert.Equal(t, []byte{0xAA}, ext.Get(1))
	assert.Nil(t, ext.Get(2))
	assert.Equal(t, []byte{0xCC, 0xCC, 0xCC}, ext.Get(3))

	dstData, err := ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{
		0xBE, 0xDE, 0x00, 0x02, 0x10, 0xAA, 0x32, 0xCC,
		0xCC, 0xCC, 0x00, 0x00,
	}, dstData)

	assert.NoError(t, ext.Del(1))
	assert.NoError(t, ext.Del(3))
	assert.Empty(t, ext.GetIDs())
	dstData, err = ext.Marshal()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xBE, 0xDE, 0x00, 0x00}, dstData)
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
