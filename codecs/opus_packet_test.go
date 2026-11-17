// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOpusPacket_Unmarshal(t *testing.T) {
	pck := OpusPacket{}

	// Nil packet
	raw, err := pck.Unmarshal(nil)
	assert.ErrorIs(t, err, errNilPacket)
	assert.Nil(t, raw, "Result should be nil in case of error")

	// Empty packet
	raw, err = pck.Unmarshal([]byte{})
	assert.ErrorIs(t, err, errShortPacket)
	assert.Nil(t, raw, "Result should be nil in case of error")

	// Normal packet
	raw, err = pck.Unmarshal([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x90})
	assert.NoError(t, err)
	assert.NotNil(t, raw, "Result shouldn't be nil in case of success")
}

func TestOpusPayloader_Payload(t *testing.T) {
	pck := OpusPayloader{}
	payload := []byte{0x90, 0x90, 0x90}

	// Positive MTU, nil payload
	res := pck.Payload(1, nil)
	assert.Len(t, res, 0, "Generated payload should be empty")

	// Positive MTU, small payload
	res = pck.Payload(1, payload)
	assert.Len(t, res, 1, "Generated payload should be the 1")

	// Positive MTU, small payload
	res = pck.Payload(2, payload)
	assert.Len(t, res, 1, "Generated payload should be the 1")
}

func TestOpusIsPartitionHead(t *testing.T) {
	opus := &OpusPacket{}
	t.Run("NormalPacket", func(t *testing.T) {
		assert.True(
			t, opus.IsPartitionHead([]byte{0x00, 0x00}),
			"All OPUS RTP packet should be the head of a new partition",
		)
	})
}

func TestParseOpusPacketInfo(t *testing.T) {
	cases := []struct {
		name          string
		packet        []byte
		frameCount    int
		frameDuration time.Duration
		samples       int
	}{
		{
			// Code 0, config 16 (CELT 2.5ms): one frame, 120 samples.
			name:          "Code0",
			packet:        []byte{0x80, 0xAA, 0xBB},
			frameCount:    1,
			frameDuration: 2500 * time.Microsecond,
			samples:       120,
		},
		{
			// Code 1, config 9 (SILK WB 20ms): two equal frames, 960 samples each.
			name:          "Code1",
			packet:        []byte{0x49, 0x01, 0x02, 0x03, 0x04},
			frameCount:    2,
			frameDuration: 20 * time.Millisecond,
			samples:       1920,
		},
		{
			// Code 2, config 0 (SILK NB 10ms): two frames, first length 3, second length 2.
			name:          "Code2",
			packet:        []byte{0x02, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05},
			frameCount:    2,
			frameDuration: 10 * time.Millisecond,
			samples:       960,
		},
		{
			// Code 3 CBR, config 31 (CELT FB 20ms): three frames of 2 bytes.
			name:          "Code3CBR",
			packet:        []byte{0xFB, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			frameCount:    3,
			frameDuration: 20 * time.Millisecond,
			samples:       2880,
		},
		{
			// Code 3 VBR with padding, config 16 (CELT 2.5ms): two frames
			// (lengths 2 and 3), 3 padding bytes.
			name: "Code3VBRPadding",
			packet: []byte{
				0x83, 0xC2, 0x03, 0x02,
				0x01, 0x02, // frame 1
				0x03, 0x04, 0x05, // frame 2
				0x00, 0x00, 0x00, // padding
			},
			frameCount:    2,
			frameDuration: 2500 * time.Microsecond,
			samples:       240,
		},
		{
			// Code 3 VBR with a two-byte frame length (252 -> 4*0+252).
			name: "Code3VBRTwoByteLength",
			packet: append(
				[]byte{0x83, 0x82, 0xFC, 0x00},
				append(make([]byte, 252), 0x01)...,
			),
			frameCount:    2,
			frameDuration: 2500 * time.Microsecond,
			samples:       240,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info, err := ParseOpusPacketInfo(c.packet)
			assert.NoError(t, err)
			assert.Equal(t, c.frameCount, info.FrameCount)
			assert.Equal(t, c.frameDuration, info.FrameDuration)
			assert.Equal(t, c.samples, info.Samples)
			total := info.Duration()
			assert.Equal(t, c.frameDuration*time.Duration(c.frameCount), total)
			// 48 kHz: samples and duration must agree.
			assert.Equal(t, c.samples, int(total.Microseconds()*48/1000))
		})
	}
}

func TestParseOpusPacketInfoErrors(t *testing.T) {
	cases := []struct {
		name   string
		packet []byte
		err    error
	}{
		{"Nil", nil, errNilPacket},
		{"Empty", []byte{}, errShortPacket},
		// Code 0 with no frame data.
		{"Code0NoFrame", []byte{0x80}, errOpusInvalidFrameLength},
		// Code 1 with an odd number of frame bytes.
		{"Code1OddLength", []byte{0x49, 0x01, 0x02, 0x03}, errOpusInvalidFrameLength},
		// Code 2 missing the length byte.
		{"Code2Truncated", []byte{0x02}, errShortPacket},
		// Code 2 length byte larger than the remaining packet.
		{"Code2LengthExceedsPacket", []byte{0x02, 0x05, 0x01}, errShortPacket},
		// Code 3 truncated before the frame count byte.
		{"Code3Truncated", []byte{0x83}, errShortPacket},
		// Code 3 with a frame count of zero.
		{"Code3ZeroFrames", []byte{0x83, 0x00}, errOpusZeroFrames},
		// Code 3 CBR, config 31 (960 samples/frame): 7 frames = 6720 > 5760 (120ms).
		{"TooMuchAudio", []byte{0xFB, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, errOpusTooMuchAudio},
		// Code 3 with padding flag but no padding length byte.
		{"PaddingLengthTruncated", []byte{0x83, 0x42}, errShortPacket},
		// Code 3 padding length larger than the packet.
		{"PaddingExceedsPacket", []byte{0x83, 0x42, 0x10, 0x01, 0x02}, errShortPacket},
		// Code 3 VBR two-byte length missing its second byte.
		{"VBRTwoByteLengthTruncated", []byte{0x83, 0x82, 0xFC}, errShortPacket},
		// Code 3 VBR zero-length frame.
		{"VBRZeroLengthFrame", []byte{0x83, 0x82, 0x00, 0x01}, errOpusInvalidFrameLength},
		// Code 3 CBR payload not divisible by the frame count.
		{"CBRNotDivisible", []byte{0xFB, 0x03, 0x01, 0x02, 0x03, 0x04, 0x05}, errOpusInvalidFrameLength},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseOpusPacketInfo(c.packet)
			assert.ErrorIs(t, err, c.err)
		})
	}
}

func TestOpusPacket_PacketInfo(t *testing.T) {
	pck := OpusPacket{}

	// Unmarshal behavior is unchanged and PacketInfo works on the result.
	raw, err := pck.Unmarshal([]byte{0x49, 0x01, 0x02, 0x03, 0x04})
	assert.NoError(t, err)
	assert.NotNil(t, raw)

	info, err := pck.PacketInfo()
	assert.NoError(t, err)
	assert.Equal(t, 2, info.FrameCount)
	assert.Equal(t, 20*time.Millisecond, info.FrameDuration)
	assert.Equal(t, 1920, info.Samples)
}
