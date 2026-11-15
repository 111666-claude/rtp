package codecs

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/pions/rtp"
)

// Boundary inputs (invalid mtu, empty payload) must not panic and must not
// produce fabricated payloads for any of the four payloaders.
func TestPayloaderBoundaryConditions(t *testing.T) {
	payloaders := map[string]rtp.Payloader{
		"G722": &G722Payloader{},
		"H264": &H264Payloader{},
		"Opus": &OpusPayloader{},
		"VP8":  &VP8Payloader{},
	}

	// mtu values that are invalid for every payloader
	invalidMTUs := []int{-1500, -1, 0}
	// mtu values too small to hold a fragment for the headered formats
	tooSmallMTUs := map[string][]int{
		"G722": {},
		"H264": {1, 2}, // mtu <= fuaHeaderSize
		"Opus": {},     // Opus is never fragmented, mtu is irrelevant
		"VP8":  {1},    // mtu <= vp8HeaderSize
	}

	for name, p := range payloaders {
		// Empty / nil payloads must yield no packets, even with a valid mtu
		for _, mtu := range append([]int{1500}, invalidMTUs...) {
			if out := p.Payload(mtu, nil); len(out) != 0 {
				t.Fatalf("%s: nil payload with mtu %d generated %d payloads", name, mtu, len(out))
			}
			if out := p.Payload(mtu, []byte{}); len(out) != 0 {
				t.Fatalf("%s: empty payload with mtu %d generated %d payloads", name, mtu, len(out))
			}
		}

		// Invalid / tiny mtu with a non-empty payload must not panic and
		// must not generate fabricated payloads. Opus ignores mtu entirely
		// (never fragmented) and is verified separately below.
		if name == "Opus" {
			continue
		}
		sample := []byte{0x01, 0x02, 0x03}
		for _, mtu := range append(invalidMTUs, tooSmallMTUs[name]...) {
			if out := p.Payload(mtu, sample); len(out) != 0 {
				t.Fatalf("%s: mtu %d generated %d payloads for 3-byte sample", name, mtu, len(out))
			}
		}
	}

	// Opus is never fragmented: any mtu yields exactly one payload holding
	// an untouched copy of the input
	opus := &OpusPayloader{}
	sample := []byte{0x01, 0x02, 0x03}
	for _, mtu := range []int{-1500, -1, 0, 1, 1500} {
		out := opus.Payload(mtu, sample)
		if len(out) != 1 || !bytes.Equal(out[0], sample) {
			t.Fatalf("Opus: mtu %d generated %v for 3-byte sample", mtu, out)
		}
	}

	// The original crash case: G722 with a 3-byte sample and a negative mtu
	p := &G722Payloader{}
	if out := p.Payload(-1, []byte{0x01, 0x02, 0x03}); len(out) != 0 {
		t.Fatalf("G722: negative mtu generated %d payloads", len(out))
	}
}

// Valid payloads must round-trip: concatenating the fragments in order
// restores the original bytes, and the input must not be modified.
func TestPayloaderRoundTrip(t *testing.T) {
	const (
		testlen = 10000
		testmtu = 1500
	)

	samples := make([]byte, testlen)
	if _, err := rand.Read(samples); err != nil {
		t.Fatal("RNG Error: ", err)
	}

	samplesIn := make([]byte, testlen)
	copy(samplesIn, samples)

	// G722 and VP8 fragments concatenate directly back to the input
	for name, p := range map[string]rtp.Payloader{
		"G722": &G722Payloader{},
		"VP8":  &VP8Payloader{},
	} {
		payloads := p.Payload(testmtu, samplesIn)
		if len(payloads) == 0 {
			t.Fatalf("%s: no payloads generated", name)
		}
		if !bytes.Equal(samplesIn, samples) {
			t.Fatalf("%s: modified input samples", name)
		}

		// Strip per-fragment headers before reassembly
		var joined []byte
		for _, pl := range payloads {
			if name == "VP8" {
				joined = append(joined, pl[vp8HeaderSize:]...)
			} else {
				joined = append(joined, pl...)
			}
		}
		if !bytes.Equal(joined, samples) {
			t.Fatalf("%s: reassembled output doesn't match input", name)
		}
	}

	// Opus is never fragmented
	{
		p := &OpusPayloader{}
		payloads := p.Payload(testmtu, samplesIn)
		if len(payloads) != 1 {
			t.Fatalf("Opus: generated %d payloads instead of 1", len(payloads))
		}
		if !bytes.Equal(payloads[0], samples) {
			t.Fatal("Opus: payload doesn't match input")
		}
		if !bytes.Equal(samplesIn, samples) {
			t.Fatal("Opus: modified input samples")
		}
	}

	// H264 single-NALU input round-trips as one packet
	{
		p := &H264Payloader{}
		// Non-zero filler avoids accidental Annex-B start codes; the first
		// byte is a NAL header with a type that is always packetized
		nalu := make([]byte, 100)
		if _, err := rand.Read(nalu); err != nil {
			t.Fatal("RNG Error: ", err)
		}
		nalu[0] = 0x65 // naluRefIdc=3, type=5 (IDR)
		for i := 1; i < len(nalu); i++ {
			if nalu[i] == 0x00 {
				nalu[i] = 0x01
			}
		}
		naluIn := make([]byte, len(nalu))
		copy(naluIn, nalu)

		payloads := p.Payload(testmtu, naluIn)
		if len(payloads) != 1 {
			t.Fatalf("H264: generated %d payloads instead of 1", len(payloads))
		}
		if !bytes.Equal(payloads[0], nalu) {
			t.Fatal("H264: payload doesn't match input")
		}
		if !bytes.Equal(naluIn, nalu) {
			t.Fatal("H264: modified input")
		}
	}
}

// The G722 10000-byte sample at mtu 1500 must remain stable at 7 packets.
func TestG722PayloaderBoundaryStable(t *testing.T) {
	p := G722Payloader{}

	const (
		testlen = 10000
		testmtu = 1500
	)

	samples := make([]byte, testlen)
	if _, err := rand.Read(samples); err != nil {
		t.Fatal("RNG Error: ", err)
	}

	payloads := p.Payload(testmtu, samples)
	if len(payloads) != 7 {
		t.Fatalf("Generated %d payloads instead of 7", len(payloads))
	}
}
