// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import (
	"bytes"
	"math/rand"
	"testing"
)

// 17 byte VP9 keyframe: frame marker + profile, frame sync bytes (0x49 0x83 0x42),
// color config and a 16x16 frame size. The remaining bytes are frame payload.
var vp9StressKeyFrame = []byte{
	0x82, 0x49, 0x83, 0x42, 0x00,
	0x00, 0x0f, 0x00, 0x0f,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
}

// 10 byte VP9 inter (non-key) frame.
var vp9StressInterFrame = []byte{
	0x86, 0x00, 0x40, 0x92, 0xe1, 0x31, 0x42, 0x8c, 0xc0, 0x40,
}

func newStressPayloader(flexible bool) VP9Payloader {
	return VP9Payloader{
		FlexibleMode: flexible,
		InitialPictureIDFn: func() uint16 {
			return 0 // deterministic picture IDs for the stress test
		},
	}
}

// TestVP9Payloader_KeyFrame17Bytes verifies the exact scenario from the iOS
// black screen report: a 17 byte keyframe with a 12 byte packet limit.
//
// The legacy flexible mode emits 2 packets whose first descriptor byte is
// 0x98. The non-flexible mode emits 3 packets whose first descriptor byte is
// 0x8b (I+B+V+Z on the first packet), and no packet exceeds the 12 byte limit.
func TestVP9Payloader_KeyFrame17Bytes(t *testing.T) {
	t.Run("flexible mode keeps legacy behavior", func(t *testing.T) {
		pck := newStressPayloader(true)
		packets := pck.Payload(12, vp9StressKeyFrame)

		if len(packets) != 2 {
			t.Fatalf("expected 2 packets, got %d", len(packets))
		}
		if packets[0][0] != 0x98 {
			t.Errorf("expected first descriptor byte 0x98, got 0x%02x", packets[0][0])
		}

		// Legacy flexible mode is unchanged: every packet carries the F flag
		// and no scalability structure is emitted.
		var reassembled bytes.Buffer
		for i, pkt := range packets {
			if len(pkt) > 12 {
				t.Errorf("packet %d exceeds limit: %d bytes", i, len(pkt))
			}
			p := VP9Packet{}
			payload, err := p.Unmarshal(pkt)
			if err != nil {
				t.Fatalf("packet %d: %v", i, err)
			}
			if !p.F || !p.I || p.V {
				t.Errorf("packet %d is not a legacy flexible packet: %+v", i, p)
			}
			reassembled.Write(payload)
		}
		if !bytes.Equal(reassembled.Bytes(), vp9StressKeyFrame) {
			t.Errorf("reassembled frame does not match original payload")
		}
	})

	t.Run("non-flexible mode emits three packets", func(t *testing.T) {
		pck := newStressPayloader(false)
		packets := pck.Payload(12, vp9StressKeyFrame)

		if len(packets) != 3 {
			t.Fatalf("expected 3 packets, got %d", len(packets))
		}
		if packets[0][0] != 0x8b {
			t.Errorf("expected first descriptor byte 0x8b, got 0x%02x", packets[0][0])
		}
		for i, pkt := range packets {
			if len(pkt) > 12 {
				t.Errorf("packet %d exceeds limit: %d bytes", i, len(pkt))
			}
		}

		// First packet: start of frame (B), scalability structure (V), not the
		// end of the frame yet (E cleared), non-flexible (F cleared).
		first := VP9Packet{}
		if _, err := first.Unmarshal(packets[0]); err != nil {
			t.Fatalf("unmarshal first packet: %v", err)
		}
		if !first.B || !first.I || !first.V || first.F || first.E || first.P {
			t.Errorf("unexpected first packet flags: %+v", first)
		}

		// Last packet must carry the end of frame flag.
		last := VP9Packet{}
		if _, err := last.Unmarshal(packets[len(packets)-1]); err != nil {
			t.Fatalf("unmarshal last packet: %v", err)
		}
		if !last.E || last.B {
			t.Errorf("unexpected last packet flags: %+v", last)
		}

		// The depacketized payloads must reassemble the original frame.
		var reassembled bytes.Buffer
		for _, pkt := range packets {
			p := VP9Packet{}
			payload, err := p.Unmarshal(pkt)
			if err != nil {
				t.Fatalf("unmarshal packet: %v", err)
			}
			reassembled.Write(payload)
		}
		if !bytes.Equal(reassembled.Bytes(), vp9StressKeyFrame) {
			t.Errorf("reassembled frame does not match original payload")
		}
	})
}

// TestVP9Payloader_KeyFrameThenInterFrame verifies that a keyframe followed by
// an ordinary inter frame is split into independently reconstructable frames,
// with consistent picture IDs and start/end fragment flags.
func TestVP9Payloader_KeyFrameThenInterFrame(t *testing.T) {
	pck := newStressPayloader(false)

	frames := [][]byte{vp9StressKeyFrame, vp9StressInterFrame}
	expectedPictureID := uint16(0)
	frameIndex := 0

	for _, frame := range frames {
		packets := pck.Payload(12, frame)
		if len(packets) == 0 {
			t.Fatalf("frame %d produced no packets", frameIndex)
		}

		var reassembled bytes.Buffer
		for i, raw := range packets {
			pkt := VP9Packet{}
			payload, err := pkt.Unmarshal(raw)
			if err != nil {
				t.Fatalf("frame %d packet %d: %v", frameIndex, i, err)
			}

			if pkt.PictureID != expectedPictureID {
				t.Errorf("frame %d packet %d: picture ID %d, want %d",
					frameIndex, i, pkt.PictureID, expectedPictureID)
			}
			if (i == 0) != pkt.B {
				t.Errorf("frame %d packet %d: B flag %v, want %v",
					frameIndex, i, pkt.B, i == 0)
			}
			if (i == len(packets)-1) != pkt.E {
				t.Errorf("frame %d packet %d: E flag %v, want %v",
					frameIndex, i, pkt.E, i == len(packets)-1)
			}
			if len(raw) > 12 {
				t.Errorf("frame %d packet %d exceeds limit: %d bytes",
					frameIndex, i, len(raw))
			}
			reassembled.Write(payload)
		}

		if !bytes.Equal(reassembled.Bytes(), frame) {
			t.Errorf("frame %d was not reconstructed correctly", frameIndex)
		}

		expectedPictureID++
		frameIndex++
	}
}

// TestVP9Payloader_1024Frames exercises continuous sending of 1024 keyframes.
// The legacy flexible mode produces 2 flexible-mode packets per frame
// (2048 packets), while the non-flexible mode produces 3 packets per frame
// (3072 packets) that satisfy the keyframe descriptor constraints.
func TestVP9Payloader_1024Frames(t *testing.T) {
	t.Run("flexible mode produces 2048 packets", func(t *testing.T) {
		pck := newStressPayloader(true)
		total := 0
		expectedPictureID := uint16(0)
		for i := 0; i < 1024; i++ {
			packets := pck.Payload(12, vp9StressKeyFrame)
			if len(packets) != 2 {
				t.Fatalf("frame %d: expected 2 packets, got %d", i, len(packets))
			}
			for j, raw := range packets {
				if len(raw) > 12 {
					t.Fatalf("frame %d packet %d exceeds limit: %d bytes",
						i, j, len(raw))
				}
				pkt := VP9Packet{}
				if _, err := pkt.Unmarshal(raw); err != nil {
					t.Fatalf("frame %d: %v", i, err)
				}
				if !pkt.F {
					t.Fatalf("frame %d: flexible mode flag missing", i)
				}
				if pkt.PictureID != expectedPictureID {
					t.Fatalf("frame %d: picture ID %d, want %d",
						i, pkt.PictureID, expectedPictureID)
				}
			}
			total += len(packets)
			expectedPictureID++
		}
		if total != 2048 {
			t.Errorf("expected 2048 packets, got %d", total)
		}
	})

	t.Run("non-flexible mode produces 3072 packets", func(t *testing.T) {
		pck := newStressPayloader(false)
		total := 0
		expectedPictureID := uint16(0)

		for i := 0; i < 1024; i++ {
			packets := pck.Payload(12, vp9StressKeyFrame)
			if len(packets) != 3 {
				t.Fatalf("frame %d: expected 3 packets, got %d", i, len(packets))
			}

			var reassembled bytes.Buffer
			for j, raw := range packets {
				if len(raw) > 12 {
					t.Fatalf("frame %d packet %d exceeds limit: %d bytes",
						i, j, len(raw))
				}

				pkt := VP9Packet{}
				payload, err := pkt.Unmarshal(raw)
				if err != nil {
					t.Fatalf("frame %d packet %d: %v", i, j, err)
				}
				if pkt.PictureID != expectedPictureID {
					t.Fatalf("frame %d packet %d: picture ID %d, want %d",
						i, j, pkt.PictureID, expectedPictureID)
				}
				if pkt.F {
					t.Fatalf("frame %d packet %d: must not use flexible mode", i, j)
				}
				if j == 0 {
					if !pkt.B || !pkt.V || pkt.E {
						t.Fatalf("frame %d: invalid first packet flags: %+v", i, pkt)
					}
					if raw[0] != 0x8b {
						t.Fatalf("frame %d: first descriptor byte 0x%02x, want 0x8b",
							i, raw[0])
					}
				}
				if j == len(packets)-1 && !pkt.E {
					t.Fatalf("frame %d: last packet missing end of frame flag", i)
				}
				reassembled.Write(payload)
			}

			if !bytes.Equal(reassembled.Bytes(), vp9StressKeyFrame) {
				t.Fatalf("frame %d was not reconstructed correctly", i)
			}

			total += len(packets)
			expectedPictureID++
		}

		if total != 3072 {
			t.Errorf("expected 3072 packets, got %d", total)
		}
		if expectedPictureID != 1024 {
			t.Errorf("expected picture ID 1024 after the run, got %d", expectedPictureID)
		}
	})
}

// TestVP9Payloader_ShortFrames keeps the legacy flexible-mode short frame
// coverage and mirrors it for the non-flexible path.
func TestVP9Payloader_ShortFrames(t *testing.T) {
	for _, flexible := range []bool{false, true} {
		pck := newStressPayloader(flexible)

		// MTU equal to the minimum header size leaves no room for payload.
		if packets := pck.Payload(3, vp9StressInterFrame); len(packets) != 0 {
			t.Errorf("flexible=%v: expected no packets for tiny MTU, got %d",
				flexible, len(packets))
		}

		// A frame that fits into a single packet must carry both B and E flags.
		packets := pck.Payload(100, vp9StressInterFrame)
		if len(packets) != 1 {
			t.Fatalf("flexible=%v: expected 1 packet, got %d", flexible, len(packets))
		}
		pkt := VP9Packet{}
		if _, err := pkt.Unmarshal(packets[0]); err != nil {
			t.Fatalf("flexible=%v: %v", flexible, err)
		}
		if !pkt.B || !pkt.E || pkt.F != flexible {
			t.Errorf("flexible=%v: unexpected flags: %+v", flexible, pkt)
		}
	}

	// Random payloads must never make the payloader panic or exceed the MTU.
	rng := rand.New(rand.NewSource(1)) //nolint:gosec
	for _, flexible := range []bool{false, true} {
		pck := newStressPayloader(flexible)
		for n := 1; n <= 64; n++ {
			payload := make([]byte, n)
			_, _ = rng.Read(payload)
			for _, mtu := range []uint16{4, 12, 50} {
				for _, pkt := range pck.Payload(mtu, payload) {
					if len(pkt) > int(mtu) {
						t.Errorf("flexible=%v n=%d mtu=%d: packet of %d bytes",
							flexible, n, mtu, len(pkt))
					}
				}
			}
		}
	}
}
