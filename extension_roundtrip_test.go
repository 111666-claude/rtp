package rtp

import (
	"bytes"
	"testing"
)

// TestMultipleExtensionsRoundTrip reproduces a camera RTP packet that carries
// two one-byte header extensions (RFC 5285/8285) in the same extension block.
//
// The extension data length field counts 32-bit words, not extensions: both
// extensions live inside a single length=1 (4 bytes) block. The old parser
// treated the value as an extension count, stopped after the first extension
// and swallowed the second one (0xBB) plus part of the media payload.
func TestMultipleExtensionsRoundTrip(t *testing.T) {
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |V=2|P|X|CC=0  |M|   PT=96     |       sequence number         |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                           timestamp                           |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                              SSRC                             |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |       0xBE    |    0xDE       |           length=1 (4 bytes)  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |  ID=1 | L=0   |     0xAA      |  ID=2 |  L=0  |     0xBB      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |                          payload ...                          |
	rawPkt := []byte{
		0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
		0x27, 0x82, 0xBE, 0xDE, 0x00, 0x01, 0x10, 0xAA, 0x20, 0xBB,
		// Audio/video payload, must not be eaten by extension parsing.
		0x98, 0x36, 0xbe, 0x88, 0x9e,
	}
	wantPayload := rawPkt[20:]

	for round := 0; round < 100; round++ {
		p := &Packet{}
		if err := p.Unmarshal(rawPkt); err != nil {
			t.Fatalf("round %d: Unmarshal err: %v", round, err)
		}

		// Both extensions must be retained, with id, content and order.
		if len(p.Extensions) != 2 {
			t.Fatalf("round %d: got %d extensions, want 2", round, len(p.Extensions))
		}
		if p.Extensions[0].id != 1 || !bytes.Equal(p.Extensions[0].payload, []byte{0xAA}) {
			t.Fatalf("round %d: first extension wrong: %#v", round, p.Extensions[0])
		}
		if p.Extensions[1].id != 2 || !bytes.Equal(p.Extensions[1].payload, []byte{0xBB}) {
			t.Fatalf("round %d: second extension wrong: %#v", round, p.Extensions[1])
		}

		if got := p.GetExtension(2); !bytes.Equal(got, []byte{0xBB}) {
			t.Fatalf("round %d: GetExtension(2) = %v, want [0xBB]", round, got)
		}

		// Payload starts exactly after the extension block.
		if p.PayloadOffset != 20 {
			t.Fatalf("round %d: PayloadOffset = %d, want 20", round, p.PayloadOffset)
		}
		if !bytes.Equal(p.Payload, wantPayload) {
			t.Fatalf("round %d: payload got %v, want %v", round, p.Payload, wantPayload)
		}

		// Byte-exact round trip.
		out, err := p.Marshal()
		if err != nil {
			t.Fatalf("round %d: Marshal err: %v", round, err)
		}
		if !bytes.Equal(out, rawPkt) {
			t.Fatalf("round %d: round trip mismatch\n got %v\nwant %v", round, out, rawPkt)
		}
	}
}

// TestSingleAndNoExtensionRoundTrip guards the single-extension and
// extension-free packets against regressions in the same code paths.
func TestSingleAndNoExtensionRoundTrip(t *testing.T) {
	cases := map[string][]byte{
		"singleOneByteExtension": {
			0x90, 0xe0, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
			0x27, 0x82, 0xBE, 0xDE, 0x00, 0x01, 0x50, 0xAA, 0x00, 0x00,
			0x98, 0x36, 0xbe, 0x88, 0x9e,
		},
		"noExtension": {
			0x80, 0x60, 0x69, 0x8f, 0xd9, 0xc2, 0x93, 0xda, 0x1c, 0x64,
			0x27, 0x82, 0x98, 0x36, 0xbe, 0x88, 0x9e,
		},
	}

	for name, rawPkt := range cases {
		rawPkt := rawPkt
		t.Run(name, func(t *testing.T) {
			for round := 0; round < 100; round++ {
				p := &Packet{}
				if err := p.Unmarshal(rawPkt); err != nil {
					t.Fatalf("round %d: Unmarshal err: %v", round, err)
				}

				wantPayload := rawPkt[p.PayloadOffset:]
				if !bytes.Equal(p.Payload, wantPayload) {
					t.Fatalf("round %d: payload got %v, want %v", round, p.Payload, wantPayload)
				}

				out, err := p.Marshal()
				if err != nil {
					t.Fatalf("round %d: Marshal err: %v", round, err)
				}
				if !bytes.Equal(out, rawPkt) {
					t.Fatalf("round %d: round trip mismatch\n got %v\nwant %v", round, out, rawPkt)
				}
			}
		})
	}
}
