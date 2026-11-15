// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

// RED (RFC 2198) field sizes and limits.
//
//	 0 1 2 3 4 5 6 7
//	+-+-+-+-+-+-+-+-+
//	|F|   block PT  |  redundant block header, 4 octets
//	+-+-+-+-+-+-+-+-+
//	| timestamp offset|
//	|        +-------+
//	|        | block |
//	+-+-+-+-+-------+
//	 length
const (
	redPrimaryHeaderSize   = 1
	redRedundantHeaderSize = 4
	redBlockPTBits         = 0x7F
	redTimestampOffsetMax  = 0x3FFF
	redBlockLengthMax      = 0x3FF
)

// REDBlock is one encoded audio block carried inside a RED payload. The
// primary block always comes last and has no timestamp offset or length
// fields on the wire; TimestampOffset is ignored when marshaling the
// primary block.
type REDBlock struct {
	// PayloadType is the 7 bit RTP payload type of the encoding used for
	// this block.
	PayloadType uint8

	// TimestampOffset is the unsigned difference between the RTP header
	// timestamp and the timestamp of this redundant block, in clock units.
	// It is only present on the wire for redundant (non-primary) blocks.
	TimestampOffset uint16

	// Payload is the original encoded audio data for this block.
	Payload []byte
}

// REDPacket represents an RTP payload encoded according to RFC 2198. It
// carries one primary block in Primary and zero or more older redundant
// blocks in Redundancy, oldest first, matching the wire order.
type REDPacket struct {
	// Redundancy holds the redundant blocks in the order they are
	// transmitted, oldest first.
	Redundancy []REDBlock

	// Primary is the primary (current, newest) audio block.
	Primary REDBlock

	audioDepacketizer
}

// Marshal serializes the packet into the RFC 2198 wire format: every block
// header first (redundant blocks, then the single-octet primary header),
// followed by all data blocks in the same order. The returned slice never
// aliases the input block payloads.
func (p *REDPacket) Marshal() ([]byte, error) {
	if p.Primary.PayloadType > redBlockPTBits {
		return nil, errREDFieldOverflow
	}

	size := redPrimaryHeaderSize + len(p.Primary.Payload)

	for i := range p.Redundancy {
		block := &p.Redundancy[i]
		if block.PayloadType > redBlockPTBits ||
			block.TimestampOffset > redTimestampOffsetMax ||
			len(block.Payload) > redBlockLengthMax {
			return nil, errREDFieldOverflow
		}

		size += redRedundantHeaderSize + len(block.Payload)
	}

	out := make([]byte, size)

	// RFC 2198 places every header block first, followed immediately by all
	// data blocks in the same order. There is no delimiter between them.
	headerEnd := redRedundantHeaderSize*len(p.Redundancy) + redPrimaryHeaderSize
	index := 0

	for i := range p.Redundancy {
		block := &p.Redundancy[i]

		// F = 1, block PT (7 bits)
		out[index] = 0x80 | block.PayloadType
		// timestamp offset (14 bits) occupies the high bits of the next
		// 16 bits; block length (10 bits) takes the low 2 bits of octet 3.
		encodedOffset := block.TimestampOffset << 2
		out[index+1] = uint8(encodedOffset >> 8) // nolint: gosec // G115 range checked above
		out[index+2] = uint8(encodedOffset)      // nolint: gosec // G115
		// block length (10 bits), high 2 bits share the third octet
		blockLength := len(block.Payload)
		out[index+2] |= uint8(blockLength >> 8) // nolint: gosec // G115 max 0x3FF
		out[index+3] = uint8(blockLength)       // nolint: gosec // G115

		index += redRedundantHeaderSize
	}

	// F = 0 marks the final, primary header block.
	out[index] = p.Primary.PayloadType

	// Data blocks follow the headers in header order.
	index = headerEnd
	for i := range p.Redundancy {
		blockLength := len(p.Redundancy[i].Payload)
		copy(out[index:], p.Redundancy[i].Payload)
		index += blockLength
	}
	copy(out[index:], p.Primary.Payload)

	return out, nil
}

// Unmarshal parses an RFC 2198 payload and stores the result in the
// REDPacket this method is called upon. Every block payload is copied, so
// later reuse or overwriting of the input buffer cannot change the parsed
// result. The primary block payload is also returned. On error the packet
// is left empty rather than holding a partially parsed result.
func (p *REDPacket) Unmarshal(packet []byte) ([]byte, error) {
	if packet == nil {
		return nil, errNilPacket
	}

	parsed, primary, err := parseREDPayload(packet)
	if err != nil {
		p.Redundancy = nil
		p.Primary = REDBlock{}

		return nil, err
	}

	p.Redundancy = parsed
	p.Primary = primary

	return primary.Payload, nil
}

// parseREDPayload does all parsing into local values so that a malformed
// input never produces a half-populated packet.
func parseREDPayload(packet []byte) ([]REDBlock, REDBlock, error) {
	lengths := make([]int, 0, len(packet)/redRedundantHeaderSize+1)

	// Phase 1: walk the header blocks. Redundant headers are 4 octets each,
	// the final primary header is a single octet with F = 0.
	index := 0
	for {
		if index >= len(packet) {
			return nil, REDBlock{}, errREDNoPrimaryBlock
		}

		header := packet[index]
		if header&0x80 == 0 {
			index += redPrimaryHeaderSize

			break
		}

		if index+redRedundantHeaderSize > len(packet) {
			return nil, REDBlock{}, errShortPacket
		}

		blockLength := int(packet[index+2]&0x03)<<8 | int(packet[index+3])
		lengths = append(lengths, blockLength)
		index += redRedundantHeaderSize
	}

	dataStart := index

	// Phase 2: the data blocks follow in header order, with the primary
	// block taking everything left after the redundant data blocks.
	totalRedundant := 0
	for _, blockLength := range lengths {
		totalRedundant += blockLength
	}

	if totalRedundant > len(packet)-dataStart {
		return nil, REDBlock{}, errREDDataOverflow
	}

	// Allocate fresh blocks and copy every payload so the result never
	// aliases the input buffer.
	redundancy := make([]REDBlock, len(lengths))

	dataIndex := dataStart
	for i, blockLength := range lengths {
		headerStart := i * redRedundantHeaderSize
		block := &redundancy[i]
		block.PayloadType = packet[headerStart] & redBlockPTBits
		block.TimestampOffset = (uint16(packet[headerStart+1])<<8 |
			uint16(packet[headerStart+2])) >> 2
		if blockLength > 0 {
			block.Payload = make([]byte, blockLength)
			copy(block.Payload, packet[dataIndex:dataIndex+blockLength])
		}
		dataIndex += blockLength
	}

	primary := REDBlock{
		PayloadType: packet[dataStart-redPrimaryHeaderSize] & redBlockPTBits,
	}
	primaryLength := len(packet) - dataIndex
	if primaryLength > 0 {
		primary.Payload = make([]byte, primaryLength)
		copy(primary.Payload, packet[dataIndex:])
	}

	return redundancy, primary, nil
}
