// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createTestH266Header(pType, layerID, tid uint8, f, z bool) h266NALUHeader {
	var fVal, zVal uint16
	if f {
		fVal = 1 << 15
	}
	if z {
		zVal = 1 << 14
	}

	return h266NALUHeader(uint16(tid) | (uint16(pType) << 3) | (uint16(layerID) << 8) | fVal | zVal)
}

func TestH266_AggregationRoundtrip(t *testing.T) {
	simplePacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 1, false, false),
		nil,
		[]byte{0x00, 0x01, 0x02, 0x03},
	}
	diffPacket := h266SingleNALUnitPacket{
		newH266NALUHeader(0b1000000, 0b00010000),
		nil,
		[]byte{0x03, 0x02, 0x01, 0x00, 0x12},
	}
	testAggregation := func(expected []h266SingleNALUnitPacket) {
		created, err := newH266AggregationPacket(expected)
		assert.Nil(t, err)
		packet := created.packetize(make([]byte, 0))
		parsed, err := parseH266Packet(packet, false)
		assert.Nil(t, err)
		aggr, ok := parsed.(*h266AggregationPacket)
		assert.True(t, ok)
		split, err := splitH266AggregationPacket(*aggr)
		assert.Equal(t, len(expected), len(split))
		assert.Nil(t, err)

		assert.True(t, slices.EqualFunc(split, expected, func(a, b h266SingleNALUnitPacket) bool {
			return slices.Equal(a.payload, b.payload) && a.payloadHeader == b.payloadHeader
		}))
	}
	testAggregation([]h266SingleNALUnitPacket{simplePacket, simplePacket, simplePacket})
	testAggregation([]h266SingleNALUnitPacket{diffPacket, simplePacket, simplePacket})
	testAggregation([]h266SingleNALUnitPacket{diffPacket, diffPacket, simplePacket})
}

func TestH266_AggregationHeader(t *testing.T) {
	simplePacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, false, false),
		nil,
		[]byte{0x00, 0x01, 0x02, 0x03},
	}
	// packet with F bit set
	fPacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, true, false),
		nil,
		[]byte{0x03, 0x02, 0x01, 0x00, 0x12},
	}
	// packet with Z bit set
	zPacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, false, true),
		nil,
		[]byte{0x03, 0x02, 0x01, 0x00, 0x12},
	}
	// packet with layer ID 1
	layerOnePacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 1, 0, false, false),
		nil,
		[]byte{0x03, 0x02, 0x01, 0x00, 0x12},
	}
	// packet with TID 1
	tidOnePacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 1, false, false),
		nil,
		[]byte{0x03, 0x02, 0x01, 0x00, 0x12},
	}

	testAggregation := func(toAggregate []h266SingleNALUnitPacket, expectedHeader h266NALUHeader, message string) {
		created, err := newH266AggregationPacket(toAggregate)
		assert.Nil(t, err)
		assert.Equal(t, expectedHeader, created.payloadHeader, message)
	}

	testAggregation(
		[]h266SingleNALUnitPacket{simplePacket, simplePacket, simplePacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		"Expected all fields to match",
	)

	testAggregation(
		[]h266SingleNALUnitPacket{simplePacket, simplePacket, fPacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, true, false),
		"Expected F bit to be set if any of the packets has it",
	)

	testAggregation(
		[]h266SingleNALUnitPacket{simplePacket, simplePacket, zPacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		"Expected Z bit to be ignored",
	)
	testAggregation(
		[]h266SingleNALUnitPacket{zPacket, zPacket, zPacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		"Expected Z bit to be ignored",
	)

	testAggregation(
		[]h266SingleNALUnitPacket{layerOnePacket, layerOnePacket, layerOnePacket},
		createTestH266Header(h266NaluAggregationPacketType, 1, 0, false, false),
		"Expected layer ID to be equal to 1",
	)

	testAggregation(
		[]h266SingleNALUnitPacket{layerOnePacket, simplePacket, layerOnePacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		"Expected layer ID to be equal to the lowest of aggregated packets",
	)
	testAggregation(
		[]h266SingleNALUnitPacket{tidOnePacket, tidOnePacket, tidOnePacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 1, false, false),
		"Expected TID to be equal to 1",
	)

	testAggregation(
		[]h266SingleNALUnitPacket{tidOnePacket, tidOnePacket, simplePacket},
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		"Expected TID to be equal to the lowest of aggregated packets",
	)
}

func TestH266_AggregationMalformed(t *testing.T) {
	noPackets := h266AggregationPacket{
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		nil,
		[]byte{},
	}
	_, err := splitH266AggregationPacket(noPackets)
	assert.ErrorIs(t, err, errNotEnoughPackets)

	onlyOnePacket := h266AggregationPacket{
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		nil,
		[]byte{0x00, 0x03, 0x00, 0x00, 0x01},
	}
	_, err = splitH266AggregationPacket(onlyOnePacket)
	assert.ErrorIs(t, err, errNotEnoughPackets)

	// length field (0x00ff) too large for payload size
	tooShortPacket := h266AggregationPacket{
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		nil,
		[]byte{0x00, 0xff, 0x00, 0x00, 0xff},
	}
	_, err = splitH266AggregationPacket(tooShortPacket)
	assert.ErrorIs(t, err, errShortPacket)

	// contains an aggregation packet
	containsAggregation := h266AggregationPacket{
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		nil,
		[]byte{0x00, 0x03, 0x00, 0xe0, 0xff},
	}
	_, err = splitH266AggregationPacket(containsAggregation)
	assert.ErrorIs(t, err, errInvalidNalType)

	// contains a fragmentation packet
	containsFragmentation := h266AggregationPacket{
		createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		nil,
		[]byte{0x00, 0x04, 0x00, 0xe8, 0xff, 0xff, 0xff},
	}
	_, err = splitH266AggregationPacket(containsFragmentation)
	assert.ErrorIs(t, err, errInvalidNalType)
}

func TestH266_AggregationDONL(t *testing.T) {
	initialDonl := uint16(100)
	// packet with 3 inner packets
	testPacket := h266AggregationPacket{
		payloadHeader: createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
		donl:          &initialDonl,
		payload:       []byte{0x00, 0x03, 0xff, 0xff, 0xff, 0x00, 0x03, 0xff, 0xff, 0xff, 0x00, 0x03, 0xff, 0xff, 0xff},
	}
	packets, err := splitH266AggregationPacket(testPacket)
	assert.Nil(t, err)
	for i, p := range packets {
		assert.Equal(t, initialDonl+uint16(i), *p.donl) // nolint: gosec // idc
	}
}

func TestH266_FragmentationRoundtrip(t *testing.T) {
	testFragmentation := func(packet h266SingleNALUnitPacket) {
		fragments, err := newH266FragmentationPackets(100, &packet)
		assert.Nil(t, err)

		rebuilt, err := rebuildH266FragmentationPackets(fragments)
		assert.Nil(t, err)

		assert.Equal(
			t,
			packet.packetize(make([]byte, 0)),
			rebuilt.packetize(make([]byte, 0)),
			"Expected packets to match after fragmentation",
		)
	}

	payload := make([]byte, 0)
	testDonl := uint16(100)

	for i := 0; i < 200; i++ {
		payload = append(payload, uint8(i)) //nolint: gosec // idc
	}

	simplePacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, false, false),
		nil,
		payload,
	}

	testFragmentation(simplePacket)

	packetWithDonl := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, false, false),
		&testDonl,
		payload,
	}
	testFragmentation(packetWithDonl)

	everyFlagSet := h266SingleNALUnitPacket{
		createTestH266Header(1, 1, 1, true, true),
		&testDonl,
		payload,
	}

	testFragmentation(everyFlagSet)
}

func TestH266_FragmentationHeader(t *testing.T) {
	simplePacket := h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 1, false, false),
		nil,
		make([]byte, 0),
	}

	for i := 0; i < 1000; i++ {
		simplePacket.payload = append(simplePacket.payload, uint8(i)) //nolint: gosec // idc
	}

	fragments, err := newH266FragmentationPackets(100, &simplePacket)
	assert.Nil(t, err)

	assert.True(t, fragments[0].fuHeader.S(), "Expected first fragmentation packet to have S flag")
	assert.True(t, fragments[len(fragments)-1].fuHeader.E(), "Expected last fragmentation packet to have E flag")

	for _, fragment := range fragments {
		assert.Equal(
			t,
			simplePacket.payloadHeader.Type(),
			fragment.fuHeader.FuType(),
			"Expected each fragment to have the same type as contained packet",
		)
	}
}

func TestH266_FragmentationEdgeCase(t *testing.T) {
	// Exacly large enough to fill two full FUs
	simplePacket := h266SingleNALUnitPacket{
		createTestH266Header(1, 1, 1, false, false),
		nil,
		make([]byte, 0),
	}

	for i := 0; i < 200; i++ {
		simplePacket.payload = append(simplePacket.payload, uint8(i)) //nolint: gosec // idc
	}

	// (payload length / 2) + payloadHeader length + fuHeader length
	fragments, err := newH266FragmentationPackets(103, &simplePacket)
	assert.Nil(t, err)

	assert.Equal(t, 2, len(fragments), "Expected exactly two, completely full packets")

	// Exactly large enough to fill one FU

	simplePacket.payload = make([]byte, 0)
	for i := 0; i < 100; i++ {
		simplePacket.payload = append(simplePacket.payload, uint8(i)) //nolint: gosec // idc
	}

	// payload length + payloadHeader length + fuHeader length
	fragments, err = newH266FragmentationPackets(103, &simplePacket)
	assert.NotNil(t, err)

	assert.Equal(t, 0, len(fragments), "Expected exactly one, completely full packets")
}

func TestH266_PacketParsing(t *testing.T) {
	testParser := func(packet []byte, withDONL bool, expected isH266Packet) {
		parsed, err := parseH266Packet(packet, withDONL)
		assert.Nil(t, err)
		assert.Equal(t, expected, parsed)
	}

	// nothingburger packet
	testParser(
		[]byte{0x00, 0x00, 1, 2, 3},
		false,
		&h266SingleNALUnitPacket{
			createTestH266Header(0, 0, 0, false, false),
			nil,
			[]byte{1, 2, 3},
		},
	)

	// nothingburger packet with DONL
	testDONL := uint16(123)
	testParser(
		[]byte{0x00, 0x00, 0, 123, 1, 2, 3},
		true,
		&h266SingleNALUnitPacket{
			createTestH266Header(0, 0, 0, false, false),
			&testDONL,
			[]byte{1, 2, 3},
		},
	)

	// aggregation packet, with 2 1 byte long packets
	testParser(
		[]byte{0x00, 0xe0, 0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		false,
		&h266AggregationPacket{
			createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
			nil,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
	)

	// aggregation packet, with 2 1 byte long packets, with DONL
	testParser(
		[]byte{0x00, 0xe0, 0x00, 123, 0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		true,
		&h266AggregationPacket{
			createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
			&testDONL,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
	)

	// fragmentation packet
	testParser(
		[]byte{0x00, 0xe8, 0x00, 0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		false,
		&h266FragmentationPacket{
			createTestH266Header(h266NaluFragmentationUnitType, 0, 0, false, false),
			newH266FragmentationUnitHeader(newH266NALUHeader(0x00, 0x01), false, false, false),
			nil,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
	)
}

func TestH266_PacketRoundtrip(t *testing.T) {
	testRoundtrip := func(packet isH266Packet, hasDONL bool) {
		packetized := packet.packetize(make([]byte, 0))
		parsed, err := parseH266Packet(packetized, hasDONL)
		assert.Nil(t, err)
		assert.Equal(t, packet, parsed)
	}

	// nothingburger packet
	testRoundtrip(
		&h266SingleNALUnitPacket{
			createTestH266Header(0, 0, 0, false, false),
			nil,
			[]byte{1, 2, 3},
		},
		false,
	)

	// nothingburger packet with DONL
	testDONL := uint16(123)
	testRoundtrip(
		&h266SingleNALUnitPacket{
			createTestH266Header(0, 0, 0, false, false),
			&testDONL,
			[]byte{1, 2, 3},
		},
		true,
	)

	// aggregation packet, with 2 1 byte long packets
	testRoundtrip(
		&h266AggregationPacket{
			createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
			nil,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
		false,
	)

	// aggregation packet, with 2 1 byte long packets, with DONL
	testRoundtrip(
		&h266AggregationPacket{
			createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
			&testDONL,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
		true,
	)

	// fragmentation packet, with 2 1 byte long packets
	testRoundtrip(
		&h266AggregationPacket{
			createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
			nil,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
		false,
	)

	// fragmentation packet, with 2 1 byte long packets, with DONL
	testRoundtrip(
		&h266AggregationPacket{
			createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false),
			&testDONL,
			[]byte{0x00, 0x01, 0x42, 0x00, 0x01, 0x42},
		},
		true,
	)
}

func TestH266Packetizer_Single(t *testing.T) {
	packetizer := H266Packetizer{}

	// type 1, 8 payload length NALU
	basicPacket := make([]byte, 0)
	basicPacket = append(basicPacket, annexbNALUStartCode...)
	header := createTestH266Header(1, 0, 0, false, false)
	basicPacket = binary.BigEndian.AppendUint16(basicPacket, uint16(header))
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	basicPacket = append(basicPacket, payload...)

	packets := packetizer.Payload(100, basicPacket)
	assert.Equal(t, 1, len(packets), "Expected only 1 NALU to be generated")
	assert.Equal(t, uint16(header), binary.BigEndian.Uint16(packets[0][0:2]), "Expected headers to match")
	assert.Equal(t, payload, packets[0][2:], "Expected payloads to match")
}

func TestH266Packetizer_Aggregated(t *testing.T) {
	packetizer := H266Packetizer{}
	// type 0, 8 payload length
	basicPacket := make([]byte, 0)
	basicPacket = append(basicPacket, annexbNALUStartCode...)
	header := createTestH266Header(1, 0, 0, false, false)
	basicPacket = binary.BigEndian.AppendUint16(basicPacket, uint16(header))
	payload := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	basicPacket = append(basicPacket, payload...)

	two := make([]byte, len(basicPacket)*2)
	copy(two, basicPacket)
	copy(two[len(basicPacket):], basicPacket)

	packets := packetizer.Payload(100, two)

	assert.Equal(t, 1, len(packets), "Expected only 1 NALU to be generated")
	aggregated := packets[0]
	parsedHeader := h266NALUHeader(binary.BigEndian.Uint16(aggregated[0:2]))

	assert.Equal(t, h266NaluAggregationPacketType, int(parsedHeader.Type()), "NALU header should be type 28")

	assert.Equal(
		t,
		h266NaluHeaderSize+len(payload),
		int(binary.BigEndian.Uint16(aggregated[2:4])),
		"Expected length to match",
	)
	assert.Equal(t, uint16(header), binary.BigEndian.Uint16(aggregated[4:6]), "Expected headers to match")
	assert.Equal(t, payload, aggregated[6:14], "Expected payloads to match")

	assert.Equal(
		t,
		h266NaluHeaderSize+len(payload),
		int(binary.BigEndian.Uint16(aggregated[14:16])),
		"Expected length to match",
	)
	assert.Equal(t, uint16(header), binary.BigEndian.Uint16(aggregated[16:18]), "Expected headers to match")
	assert.Equal(t, payload, aggregated[18:], "Expected payloads to match")
}

func TestH266Packetizer_Fragmented(t *testing.T) {
	initSequence := []byte{0x00, 0x00, 0x00, 0x01, 0x00}

	packetizer := H266Packetizer{}
	// type 0, 50 payload length
	bigPacket := make([]byte, 0)
	bigPacket = append(bigPacket, initSequence...)
	header := createTestH266Header(1, 0, 0, false, false)

	bigPacket = binary.BigEndian.AppendUint16(bigPacket, uint16(header))

	payload := make([]byte, 0)
	for i := 0; i < 50; i++ {
		payload = append(payload, 0xff)
	}
	bigPacket = append(bigPacket, payload...)

	packets := packetizer.Payload(50, bigPacket)

	assert.Equal(t, 2, len(packets), "Expected 2 NALUs to be generated")
	parsedHeader := h266NALUHeader(binary.BigEndian.Uint16(packets[0][0:2]))

	assert.Equal(t, h266NaluFragmentationUnitType, int(parsedHeader.Type()), "NALU header should be type 28")
	assert.True(t, H265FragmentationUnitHeader(packets[0][2]).S(), "First FU header should be S")
	assert.True(t, H265FragmentationUnitHeader(packets[1][2]).E(), "Second FU header should be E")
}

func TestH266Depacketizer_Roundtrip(t *testing.T) {
	testDepacketizer := func(packets [][]byte, expected []isH266Packet, withDonl bool) {
		depacketizer := H266Depacketizer{
			hasDonl: withDonl,
		}
		output := make([]isH266Packet, 0)
		for _, packet := range packets {
			p, err := depacketizer.Unmarshal(packet)
			assert.Nil(t, err)

			if p == nil {
				continue
			}

			// the depacketizer output is Annex-B and must never contain the
			// transport-only DONL field, even when the stream carries it
			emitH266Nalus(p, func(b []byte) {
				parsed, err := parseH266Packet(b, false)
				assert.Nil(t, err)
				if err != nil {
					return
				}
				output = append(output, parsed)
			})
		}
		assert.Equal(t, expected, output)
	}

	withoutDonl := func(p *h266SingleNALUnitPacket) *h266SingleNALUnitPacket {
		cpy := *p
		cpy.donl = nil

		return &cpy
	}

	testDonl := uint16(100)
	testDonl2 := uint16(101)

	// Single NAL

	basicPacket := &h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, false, false),
		nil,
		[]byte{0xff, 0xff, 0xff},
	}

	testDepacketizer([][]byte{basicPacket.packetize(make([]byte, 0))}, []isH266Packet{basicPacket}, false)

	// with DONL

	basicPacket.donl = &testDonl

	testDepacketizer([][]byte{basicPacket.packetize(make([]byte, 0))}, []isH266Packet{withoutDonl(basicPacket)}, true)

	// Multiple NALs aggregated

	firstPacket := &h266SingleNALUnitPacket{
		createTestH266Header(0, 0, 0, false, false),
		nil,
		[]byte{0xff, 0xff, 0xff},
	}

	secondPacket := &h266SingleNALUnitPacket{
		createTestH266Header(1, 2, 3, true, true),
		nil,
		[]byte{0x67, 0x67, 0x67},
	}

	aggregation, err := newH266AggregationPacket([]h266SingleNALUnitPacket{*firstPacket, *secondPacket})
	assert.Nil(t, err)
	aggregationPacketized := aggregation.packetize(make([]byte, 0))

	testDepacketizer([][]byte{aggregationPacketized}, []isH266Packet{firstPacket, secondPacket}, false)

	// with DONL

	firstPacket.donl = &testDonl
	secondPacket.donl = &testDonl2

	donlAggregation, err := newH266AggregationPacket([]h266SingleNALUnitPacket{*firstPacket, *secondPacket})
	assert.Nil(t, err)
	donlAggregationPacketized := donlAggregation.packetize(make([]byte, 0))

	testDepacketizer(
		[][]byte{donlAggregationPacketized},
		[]isH266Packet{withoutDonl(firstPacket), withoutDonl(secondPacket)},
		true,
	)

	// Large NAL that gets fragmented

	largePacket := &h266SingleNALUnitPacket{
		createTestH266Header(1, 1, 1, false, false),
		nil,
		make([]byte, 0),
	}
	for i := 0; i < 512; i++ {
		largePacket.payload = append(largePacket.payload, uint8(i)) // nolint:gosec
	}

	fragments, err := newH266FragmentationPackets(100, largePacket)
	assert.Nil(t, err)

	fragmentsPacketized := make([][]byte, 0)

	for _, f := range fragments {
		fragmentsPacketized = append(fragmentsPacketized, f.packetize(make([]byte, 0)))
	}

	testDepacketizer(fragmentsPacketized, []isH266Packet{largePacket}, false)

	// with DONL

	largePacket.donl = &testDonl

	donlFragments, err := newH266FragmentationPackets(100, largePacket)
	assert.Nil(t, err)

	donlFragmentsPacketized := make([][]byte, 0)

	for _, f := range donlFragments {
		donlFragmentsPacketized = append(donlFragmentsPacketized, f.packetize(make([]byte, 0)))
	}

	testDepacketizer(donlFragmentsPacketized, []isH266Packet{withoutDonl(largePacket)}, true)
}

func TestH266Depacketizer_DONLStrippedAllPaths(t *testing.T) {
	donl := uint16(42)
	header := createTestH266Header(1, 0, 1, false, false)
	payload := make([]byte, 0, 300)
	for i := 0; i < 300; i++ {
		payload = append(payload, uint8(i)) // nolint:gosec
	}

	nalu := h266SingleNALUnitPacket{header, &donl, payload}

	// the expected Annex-B output: start code + NALU header + payload, no DONL
	expectedNalu := (&h266SingleNALUnitPacket{header, nil, payload}).packetize(make([]byte, 0))
	expectedAnnexB := append(append(make([]byte, 0), annexbNALUStartCode...), expectedNalu...)

	// Single NAL unit packet
	singleDepacketizer := H266Depacketizer{hasDonl: true}
	singleOut, err := singleDepacketizer.Unmarshal(nalu.packetize(make([]byte, 0)))
	assert.Nil(t, err)
	assert.Equal(t, expectedAnnexB, singleOut, "single NALU output must not contain the DONL field")

	// Aggregation packet containing the same NALU twice
	aggregation, err := newH266AggregationPacket([]h266SingleNALUnitPacket{nalu, nalu})
	assert.Nil(t, err)
	apDepacketizer := H266Depacketizer{hasDonl: true}
	apOut, err := apDepacketizer.Unmarshal(aggregation.packetize(make([]byte, 0)))
	assert.Nil(t, err)
	expectedAP := append(append(make([]byte, 0), expectedAnnexB...), expectedAnnexB...)
	assert.Equal(t, expectedAP, apOut, "aggregation output must not contain DONL fields")

	// Fragmentation units reassembling the same NALU
	fragments, err := newH266FragmentationPackets(100, &nalu)
	assert.Nil(t, err)
	assert.Greater(t, len(fragments), 1, "expected the NALU to be split into multiple FUs")
	fuDepacketizer := H266Depacketizer{hasDonl: true}
	var fuOut []byte
	for i, f := range fragments {
		out, err := fuDepacketizer.Unmarshal(f.packetize(make([]byte, 0)))
		assert.Nil(t, err)
		if i < len(fragments)-1 {
			assert.Nil(t, out, "FU must only produce output once complete")
		} else {
			fuOut = out
		}
	}
	assert.Equal(t, expectedAnnexB, fuOut, "rebuilt FU output must not contain the DONL field")

	// all three paths must yield identical media content
	assert.Equal(t, singleOut, fuOut, "single and FU paths must produce identical Annex-B output")
}

func TestH266Depacketizer_TruncatedDONL(t *testing.T) {
	depacketizer := H266Depacketizer{hasDonl: true}

	// single NALU with no room for the DONL field
	_, err := depacketizer.Unmarshal([]byte{0x00, 0x01})
	assert.ErrorIs(t, err, errShortPacket)

	// single NALU with a truncated DONL field
	_, err = depacketizer.Unmarshal([]byte{0x00, 0x01, 0x05})
	assert.ErrorIs(t, err, errShortPacket)

	// aggregation packet with a truncated DONL field
	apHeader := createTestH266Header(h266NaluAggregationPacketType, 0, 0, false, false)
	_, err = depacketizer.Unmarshal([]byte{byte(uint16(apHeader) >> 8), byte(uint16(apHeader)), 0x05})
	assert.ErrorIs(t, err, errShortPacket)

	// fragmentation unit with S bit set but a truncated DONL field
	fuPayloadHeader := newH266FragmentationPacketHeader(createTestH266Header(1, 0, 1, false, false))
	fuHeader := newH266FragmentationUnitHeader(createTestH266Header(1, 0, 1, false, false), true, false, false)
	_, err = depacketizer.Unmarshal([]byte{byte(uint16(fuPayloadHeader) >> 8), byte(uint16(fuPayloadHeader)), uint8(fuHeader), 0x05})
	assert.ErrorIs(t, err, errShortPacket)

	// non-start FU without any partials must keep returning the existing error
	middleFu := h266FragmentationPacket{
		payloadHeader: fuPayloadHeader,
		fuHeader:      newH266FragmentationUnitHeader(createTestH266Header(1, 0, 1, false, false), false, false, false),
		payload:       []byte{0x01, 0x02},
	}
	_, err = depacketizer.Unmarshal(middleFu.packetize(make([]byte, 0)))
	assert.ErrorIs(t, err, errExpectFragmentationStartUnit)
}

func TestH266Depacketizer_NoResidualDONLState(t *testing.T) {
	depacketizer := H266Depacketizer{hasDonl: true}
	header := createTestH266Header(1, 0, 1, false, false)
	fuPayloadHeader := newH266FragmentationPacketHeader(header)
	donl1 := uint16(5)
	donl2 := uint16(7)

	startFu := func(donl *uint16, payload []byte) *h266FragmentationPacket {
		return &h266FragmentationPacket{
			payloadHeader: fuPayloadHeader,
			fuHeader:      newH266FragmentationUnitHeader(header, true, false, false),
			donl:          donl,
			payload:       payload,
		}
	}
	endFu := func(payload []byte) *h266FragmentationPacket {
		return &h266FragmentationPacket{
			payloadHeader: fuPayloadHeader,
			fuHeader:      newH266FragmentationUnitHeader(header, false, true, false),
			payload:       payload,
		}
	}

	// an abandoned FU series must not make the next series' DONL be
	// misinterpreted as payload
	out, err := depacketizer.Unmarshal(startFu(&donl1, []byte{0xaa}).packetize(make([]byte, 0)))
	assert.Nil(t, err)
	assert.Nil(t, out)

	out, err = depacketizer.Unmarshal(startFu(&donl2, []byte{0xbb}).packetize(make([]byte, 0)))
	assert.Nil(t, err)
	assert.Nil(t, out)

	out, err = depacketizer.Unmarshal(endFu([]byte{0xcc}).packetize(make([]byte, 0)))
	assert.Nil(t, err)
	expected := (&h266SingleNALUnitPacket{header, nil, []byte{0xbb, 0xcc}}).packetize(make([]byte, 0))
	assert.Equal(t, append(annexbNALUStartCode, expected...), out)

	// a single NALU in the middle of a FU series resets the series and is
	// output with its own DONL removed
	out, err = depacketizer.Unmarshal(startFu(&donl1, []byte{0xaa}).packetize(make([]byte, 0)))
	assert.Nil(t, err)
	assert.Nil(t, out)

	single := h266SingleNALUnitPacket{createTestH266Header(0, 0, 0, false, false), &donl1, []byte{0x01, 0x02, 0x03}}
	out, err = depacketizer.Unmarshal(single.packetize(make([]byte, 0)))
	assert.Nil(t, err)
	expectedSingle := (&h266SingleNALUnitPacket{single.payloadHeader, nil, single.payload}).packetize(make([]byte, 0))
	assert.Equal(t, append(annexbNALUStartCode, expectedSingle...), out)

	// a FU series started right after still parses its DONL correctly
	out, err = depacketizer.Unmarshal(startFu(&donl2, []byte{0xbb}).packetize(make([]byte, 0)))
	assert.Nil(t, err)
	assert.Nil(t, out)

	out, err = depacketizer.Unmarshal(endFu([]byte{0xcc}).packetize(make([]byte, 0)))
	assert.Nil(t, err)
	assert.Equal(t, append(annexbNALUStartCode, expected...), out)
}

func TestH266Depacketizer_NoDONLBytesPreserved(t *testing.T) {
	depacketizer := H266Depacketizer{hasDonl: false}

	header := createTestH266Header(1, 2, 3, false, false)
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := (&h266SingleNALUnitPacket{header, nil, payload}).packetize(make([]byte, 0))

	out, err := depacketizer.Unmarshal(raw)
	assert.Nil(t, err)
	assert.Equal(t, append(annexbNALUStartCode, raw...), out, "output must keep the original header and payload bytes")
}
