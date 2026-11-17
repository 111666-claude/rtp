// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import "time"

const (
	// opusSampleRate is the clock rate of the Opus RTP payload format (RFC 7587).
	opusSampleRate = 48000
	// opusMaxSamples is the maximum duration of a single Opus packet: 120 ms at 48 kHz (RFC 6716 3.2.1).
	opusMaxSamples = 5760
	// opusMaxFrameSize is the maximum size of a single Opus frame in bytes (RFC 6716 3.2.1).
	opusMaxFrameSize = 1275
)

// opusFrameSamples maps the 5-bit TOC configuration number to the number of
// 48 kHz samples per frame, per RFC 6716 Table 2.
var opusFrameSamples = [32]int{ //nolint:gochecknoglobals
	480, 960, 1920, 2880, // 0-3:  SILK-only NB (10, 20, 40, 60 ms)
	480, 960, 1920, 2880, // 4-7:  SILK-only MB
	480, 960, 1920, 2880, // 8-11: SILK-only WB
	960, 1920, // 12-13: Hybrid SWB
	960, 1920, // 14-15: Hybrid FB
	120, 240, 480, 960, // 16-19: CELT-only NB (2.5, 5, 10, 20 ms)
	120, 240, 480, 960, // 20-23: CELT-only WB
	120, 240, 480, 960, // 24-27: CELT-only SWB
	120, 240, 480, 960, // 28-31: CELT-only FB
}

// OpusPacketInfo describes the timing layout of an Opus RTP payload, parsed
// from the TOC byte and frame count byte per RFC 6716 3.2. The audio itself
// is not decoded.
type OpusPacketInfo struct {
	// FrameCount is the number of Opus frames in the packet.
	FrameCount int
	// FrameDuration is the duration of each frame. All frames in a packet
	// have the same duration.
	FrameDuration time.Duration
	// Samples is the total number of 48 kHz samples covered by the packet.
	Samples int
}

// Duration returns the total duration of audio covered by the packet.
func (i OpusPacketInfo) Duration() time.Duration {
	return i.FrameDuration * time.Duration(i.FrameCount)
}

// PacketInfo parses the timing layout of the payload stored in this
// OpusPacket. See ParseOpusPacketInfo.
func (p *OpusPacket) PacketInfo() (OpusPacketInfo, error) {
	return ParseOpusPacketInfo(p.Payload)
}

// ParseOpusPacketInfo parses an Opus RTP payload and returns the number of
// frames it contains, the duration of each frame and the total number of
// 48 kHz samples it covers, without decoding the audio.
//
// The TOC byte and, for frame count code 3, the frame count byte are parsed
// per RFC 6716 3.2, including VBR length fields and padding. Empty or
// truncated packets, invalid frame lengths, packets with zero frames and
// packets covering more than 120 ms of audio are rejected.
func ParseOpusPacketInfo(payload []byte) (OpusPacketInfo, error) {
	if payload == nil {
		return OpusPacketInfo{}, errNilPacket
	}
	if len(payload) == 0 {
		return OpusPacketInfo{}, errShortPacket
	}

	toc := payload[0]
	frameSamples := opusFrameSamples[toc>>3]

	var frameCount int

	switch toc & 0x03 {
	case 0:
		// One frame in the packet.
		if valid := checkOpusFrameLength(len(payload) - 1); !valid {
			return OpusPacketInfo{}, errOpusInvalidFrameLength
		}
		frameCount = 1
	case 1:
		// Two frames, each half the payload.
		remaining := len(payload) - 1
		if remaining%2 != 0 || !checkOpusFrameLength(remaining/2) {
			return OpusPacketInfo{}, errOpusInvalidFrameLength
		}
		frameCount = 2
	case 2:
		// Two frames, the first with an explicit length byte.
		if len(payload) < 2 {
			return OpusPacketInfo{}, errShortPacket
		}
		if !checkOpusFrameLength(int(payload[1])) {
			return OpusPacketInfo{}, errOpusInvalidFrameLength
		}
		second := len(payload) - 2 - int(payload[1])
		if second < 0 {
			return OpusPacketInfo{}, errShortPacket
		}
		if !checkOpusFrameLength(second) {
			return OpusPacketInfo{}, errOpusInvalidFrameLength
		}
		frameCount = 2
	case 3:
		// Arbitrary frame count, optionally VBR and/or padded.
		var err error
		if frameCount, err = parseOpusFrameCount(payload); err != nil {
			return OpusPacketInfo{}, err
		}
	}

	samples := frameCount * frameSamples
	if samples > opusMaxSamples {
		return OpusPacketInfo{}, errOpusTooMuchAudio
	}

	return OpusPacketInfo{
		FrameCount:    frameCount,
		FrameDuration: time.Duration(frameSamples) * time.Second / opusSampleRate,
		Samples:       samples,
	}, nil
}

// checkOpusFrameLength reports whether n is a permissible Opus frame size.
func checkOpusFrameLength(n int) bool {
	return n >= 1 && n <= opusMaxFrameSize
}

// parseOpusFrameCount parses a frame count code 3 packet: the frame count
// byte, optional padding length and optional VBR frame lengths, and returns
// the frame count after validating the framing.
func parseOpusFrameCount(payload []byte) (int, error) {
	if len(payload) < 2 {
		return 0, errShortPacket
	}

	header := payload[1]
	vbr := header&0x80 != 0
	hasPadding := header&0x40 != 0
	frameCount := int(header & 0x3F)
	if frameCount == 0 {
		return 0, errOpusZeroFrames
	}

	pos := 2
	padLen := 0

	// Padding length bytes precede the frame data; the padding itself
	// sits at the very end of the packet.
	if hasPadding {
		for {
			if pos >= len(payload) {
				return 0, errShortPacket
			}
			b := payload[pos]
			pos++
			padLen += int(b)
			if b != 255 {
				break
			}
		}
		if padLen > len(payload)-pos {
			return 0, errShortPacket
		}
	}

	dataEnd := len(payload) - padLen

	if vbr {
		sum := 0
		for i := 0; i < frameCount-1; i++ {
			if pos >= dataEnd {
				return 0, errShortPacket
			}
			frameLen := int(payload[pos])
			if frameLen >= 252 {
				// Two-byte length: 4*second + first, first in [252, 255].
				if pos+1 >= dataEnd {
					return 0, errShortPacket
				}
				frameLen = 4*int(payload[pos+1]) + frameLen
				pos++
			}
			pos++
			if !checkOpusFrameLength(frameLen) {
				return 0, errOpusInvalidFrameLength
			}
			sum += frameLen
		}
		last := dataEnd - pos - sum
		if last < 0 {
			return 0, errShortPacket
		}
		if !checkOpusFrameLength(last) {
			return 0, errOpusInvalidFrameLength
		}
	} else {
		remaining := dataEnd - pos
		if remaining < 0 {
			return 0, errShortPacket
		}
		if remaining%frameCount != 0 || !checkOpusFrameLength(remaining/frameCount) {
			return 0, errOpusInvalidFrameLength
		}
	}

	return frameCount, nil
}

// OpusPayloader payloads Opus packets.
type OpusPayloader struct{}

// Payload fragments an Opus packet across one or more byte arrays.
func (p *OpusPayloader) Payload(_ uint16, payload []byte) [][]byte {
	if payload == nil {
		return [][]byte{}
	}

	out := make([]byte, len(payload))
	copy(out, payload)

	return [][]byte{out}
}

// OpusPacket represents the Opus header that is stored in the payload of an RTP Packet.
type OpusPacket struct {
	Payload []byte

	audioDepacketizer
}

// Unmarshal parses the passed byte slice and stores the result in the OpusPacket this method is called upon.
func (p *OpusPacket) Unmarshal(packet []byte) ([]byte, error) {
	if packet == nil {
		return nil, errNilPacket
	} else if len(packet) == 0 {
		return nil, errShortPacket
	}

	p.Payload = packet

	return packet, nil
}

// OpusPartitionHeadChecker checks Opus partition head.
//
// Deprecated: replaced by OpusPacket.IsPartitionHead().
type OpusPartitionHeadChecker struct{}

// IsPartitionHead checks whether if this is a head of the Opus partition.
//
// Deprecated: replaced by OpusPacket.IsPartitionHead().
func (*OpusPartitionHeadChecker) IsPartitionHead(packet []byte) bool {
	return (&OpusPacket{}).IsPartitionHead(packet)
}
