// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"fmt"

	"github.com/pion/rtp/codecs/av1/obu"
)

// AV1Depacketizer is a AV1 RTP Packet depacketizer.
// Reads AV1 packets from a RTP stream and outputs AV1 low overhead bitstream.
type AV1Depacketizer struct {
	// holds the fragmented OBU from the previous packet.
	// The backing array is owned by the depacketizer (it never aliases the
	// caller's payload) and is reused across calls, growing geometrically.
	buffer []byte

	// Z, Y, N are flags from the AV1 Aggregation Header.
	Z, Y, N bool

	videoDepacketizer
}

// appendOBUFragment appends a fragment to the reassembly buffer, growing the
// backing array geometrically so reassembling long fragment sequences costs
// amortized O(n) copies instead of O(n^2).
func appendOBUFragment(buf, fragment []byte) []byte {
	if cap(buf)-len(buf) >= len(fragment) {
		return append(buf, fragment...)
	}

	newCap := 2 * cap(buf)
	if need := len(buf) + len(fragment); newCap < need {
		newCap = need
	}
	newBuf := make([]byte, len(buf), newCap)
	copy(newBuf, buf)

	return append(newBuf, fragment...)
}

// growOutput ensures buff has room for need more bytes, growing geometrically.
func growOutput(buff []byte, need int) []byte {
	if cap(buff)-len(buff) >= need {
		return buff
	}

	newCap := 2 * cap(buff)
	if want := len(buff) + need; newCap < want {
		newCap = want
	}
	newBuff := make([]byte, len(buff), newCap)
	copy(newBuff, buff)

	return newBuff
}

func (d *AV1Depacketizer) appendOBUWithCalculatedSize(
	buff []byte,
	obuHeader *obu.Header,
	obuBuffer []byte,
	payloadOffset int,
) []byte {
	obuPayloadSize := len(obuBuffer) - payloadOffset
	// header + LEB128 size field + payload, with slack for the encoding.
	buff = growOutput(buff, obuPayloadSize+16)
	buff = append(buff, obuHeader.Marshal()...)
	buff = append(buff, obu.WriteToLeb128(uint(obuPayloadSize))...) // nolint: gosec // G104
	buff = append(buff, obuBuffer[payloadOffset:]...)

	return buff
}

// Unmarshal parses an AV1 RTP payload into its constituent OBUs stream with obu_size_field,
// It assumes that the payload is in order (e.g. the caller is responsible for reordering RTP packets).
// If the last OBU in the payload is fragmented, it will be stored in the buffer until the
// it is completed.
//
//nolint:gocognit,cyclop
func (d *AV1Depacketizer) Unmarshal(payload []byte) (buff []byte, err error) {
	buff = make([]byte, 0)

	if len(payload) <= 1 {
		return nil, errShortPacket
	}

	// |Z|Y| W |N|-|-|-|
	obuZ := (av1ZMask & payload[0]) != 0     // Z
	obuY := (av1YMask & payload[0]) != 0     // Y
	obuCount := (av1WMask & payload[0]) >> 4 // W
	obuN := (av1NMask & payload[0]) != 0     // N
	d.Z = obuZ
	d.Y = obuY
	d.N = obuN
	if obuN {
		d.buffer = d.buffer[:0]
	}

	// Make sure we clear the buffer if Z is not 0.
	if !obuZ && len(d.buffer) > 0 {
		d.buffer = d.buffer[:0]
	}

	obuOffset := 0
	for offset := 1; offset < len(payload); obuOffset++ {
		isFirst := obuOffset == 0
		isLast := obuCount != 0 && obuOffset == int(obuCount)-1

		// https://aomediacodec.github.io/av1-rtp-spec/#44-av1-aggregation-header
		// W: two bit field that describes the number of OBU elements in the packet.
		// This field MUST be set equal to 0 or equal to the number of OBU elements contained in the packet.
		// If set to 0, each OBU element MUST be preceded by a length field. If not set to 0
		// (i.e., W = 1, 2 or 3) the last OBU element MUST NOT be preceded by a length field.
		var lengthField, n int
		if obuCount == 0 || !isLast {
			obuSizeVal, nVal, err := obu.ReadLeb128(payload[offset:]) //nolint:gosec //guard from loop
			lengthField = int(obuSizeVal)                             //nolint:gosec // G115 false positive
			n = int(nVal)                                             //nolint:gosec // G115 false positive
			if err != nil {
				return nil, err
			}

			offset += n
			if obuCount == 0 && offset+lengthField == len(payload) {
				isLast = true
			}
		} else {
			// https://aomediacodec.github.io/av1-rtp-spec/#44-av1-aggregation-header
			// Length of the last OBU element =
			// length of the RTP payload
			// - length of aggregation header
			// - length of previous OBU elements including length fields
			lengthField = len(payload) - offset
		}

		if offset+lengthField > len(payload) {
			return nil, fmt.Errorf(
				"%w: OBU size %d + %d offset exceeds payload length %d",
				errShortPacket, lengthField, offset, len(payload),
			)
		}

		var obuBuffer []byte
		fromBuffer := false
		if isFirst && obuZ {
			// We lost the first fragment of the OBU
			// We drop the buffer and continue
			if len(d.buffer) == 0 {
				if isLast {
					break
				}
				offset += lengthField

				continue
			}

			// Append the continuation fragment to the owned reassembly buffer,
			// then hand the assembled OBU to obuBuffer and release d.buffer
			// (keeping its capacity) for the next fragmented OBU.
			d.buffer = appendOBUFragment(d.buffer, payload[offset:offset+lengthField])
			obuBuffer = d.buffer
			d.buffer = d.buffer[:0]
			fromBuffer = true
		} else {
			obuBuffer = payload[offset : offset+lengthField]
		}
		offset += lengthField

		if isLast && obuY {
			// The OBU continues in the next packet: retain the fragment in the
			// owned reassembly buffer. Fragments that must survive across calls
			// are copied, since the caller may reuse the payload's backing array.
			if fromBuffer {
				d.buffer = obuBuffer
			} else {
				d.buffer = appendOBUFragment(d.buffer[:0], obuBuffer)
			}

			break
		}

		if len(obuBuffer) == 0 {
			continue
		}

		obuHeader, err := obu.ParseOBUHeader(obuBuffer)
		if err != nil {
			return nil, err
		}

		// The temporal delimiter OBU, if present, SHOULD be removed when transmitting,
		// and MUST be ignored by receivers. Tile list OBUs are not supported.
		// They SHOULD be removed when transmitted, and MUST be ignored by receivers.
		// https://aomediacodec.github.io/av1-rtp-spec/#5-packetization-rules
		if obuHeader.Type == obu.OBUTemporalDelimiter || obuHeader.Type == obu.OBUTileList {
			continue
		}

		// obu_has_size_field should be set to 0 for AV1 RTP packets.
		// But we still check it to be sure, if we get obu size we just use it, instead of calculating it.
		if obuHeader.HasSizeField {
			obuSize, n, err := obu.ReadLeb128(obuBuffer[obuHeader.Size():])
			if err != nil {
				return nil, err
			}

			// Ignore obu_size_field if it is present and doesn't match the calculated size.
			sizeFromOBUSize := obuHeader.Size() + int(obuSize) + int(n) //nolint:gosec
			if lengthField != sizeFromOBUSize {
				payloadOffset := obuHeader.Size() + int(n) //nolint:gosec // n is small, LEB128.
				buff = d.appendOBUWithCalculatedSize(buff, obuHeader, obuBuffer, payloadOffset)
			} else {
				buff = append(growOutput(buff, len(obuBuffer)), obuBuffer...)
			}
		} else {
			obuHeader.HasSizeField = true
			buff = d.appendOBUWithCalculatedSize(buff, obuHeader, obuBuffer, obuHeader.Size())
		}

		if isLast {
			break
		}
	}

	if obuCount != 0 && obuOffset != int(obuCount-1) {
		return nil, fmt.Errorf(
			"%w: OBU count %d does not match number of OBUs %d",
			errShortPacket, obuCount, obuOffset,
		)
	}

	return buff, nil
}

// IsPartitionHead returns true if Z in the AV1 Aggregation Header
// is set to 0.
func (d *AV1Depacketizer) IsPartitionHead(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}

	return (payload[0] & av1ZMask) == 0
}
