// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import "errors"

var (
	// ErrVP9PictureIDMissing is returned when a VP9 payload descriptor does
	// not carry a PictureID (descriptor byte I=0). Such a packet cannot be
	// remapped and is returned untouched.
	ErrVP9PictureIDMissing = errors.New("VP9 payload descriptor has no PictureID")

	// ErrVP9LatePacket is returned when an out-of-order packet cannot be
	// remapped: its PictureID belongs to a frame that is no longer known to
	// the remapper (for example after a PictureID wraparound or a stream
	// restart). The packet is returned untouched.
	ErrVP9LatePacket = errors.New("VP9 packet is older than the remapper state")

	// ErrVP9ReferenceUnresolved is returned when a flexible-mode packet
	// references (through P_DIFF) a frame that the remapper has never seen,
	// so the reference difference cannot be re-expressed against the new
	// PictureID sequence. The packet is returned untouched.
	ErrVP9ReferenceUnresolved = errors.New("VP9 P_DIFF references an unknown frame")
)

const (
	vp9FlagI = 0x80 // PictureID present.
	vp9FlagP = 0x40 // Inter-picture predicted frame.
	vp9FlagL = 0x20 // Layer indices present.
	vp9FlagF = 0x10 // Flexible mode.
	vp9FlagM = 0x80 // 15-bit PictureID marker.

	vp9Max7BitPictureID  = 0x7F
	vp9Max15BitPictureID = 0x7FFF

	// vp9PictureIDCount is the number of distinct PictureID values (15-bit
	// space); the counter wraps back to zero after 0x7FFF.
	vp9PictureIDCount = 0x8000
)

// vp9PictureIDMapping records how one source frame's descriptor fields are
// translated into the concatenated stream.
type vp9PictureIDMapping struct {
	newPictureID uint16
	timestamp    uint32
	tl0PicIdx    uint8
	hasTL0       bool

	// Snapshot of the remapper state before this mapping was created, so a
	// new frame that later fails reference validation can be fully rolled
	// back. Only meaningful for a freshly created mapping.
	prevHaveLast         bool
	prevLastPictureID    uint16
	prevLastExtendedForm bool
	prevHaveTL0Base      bool
	prevTL0PicIdxCounter uint8
}

// VP9PictureIDRemapper rewrites the PictureID of VP9 RTP payload descriptors
// so that several independently numbered VP9 transport streams can be
// concatenated into one continuous stream.
//
// Every packet of the same source frame (identified by RTP timestamp and
// source PictureID) receives the same new PictureID. New frames receive
// consecutive IDs that wrap from 0x7FFF back to zero, matching the VP9 RTP
// payload format. Layer indices (TID/U/SID/D) are copied unchanged.
// TL0PICIDX is re-sequenced alongside the PictureID, and flexible-mode
// P_DIFF is recomputed against the new dense ID sequence so a reference still
// points at the same frame even when source PictureIDs were skipped.
//
// The compressed VP9 video bytes are never modified.
type VP9PictureIDRemapper struct {
	// Force15Bit makes every remapped descriptor use the 15-bit PictureID
	// form, even while the new ID still fits in 7 bits. By default the
	// source descriptor's 7-bit/15-bit form is preserved as long as the new
	// ID fits; a new ID larger than 0x7F transparently upgrades a 7-bit
	// descriptor to 15-bit.
	Force15Bit bool

	// InitialPictureID is the PictureID assigned to the first remapped
	// frame. It is read once, on the first Remap call; changing it afterwards
	// (including across Reset) has no effect. The zero value starts the
	// sequence at zero.
	InitialPictureID uint16

	// initialized reports whether InitialPictureID has been consumed.
	initialized bool

	// nextPictureID is the PictureID assigned to the next unseen frame.
	nextPictureID uint16
	// tl0PicIdxCounter is the next TL0PICIDX value handed to a temporal
	// layer zero frame.
	tl0PicIdxCounter uint8
	// haveTL0Base reports whether a temporal layer zero frame has already
	// been remapped, giving higher temporal layers an index to reference.
	haveTL0Base bool

	// mappings is keyed by the source PictureID. The entry is replaced when
	// the source PictureID space wraps or the stream restarts.
	mappings map[uint16]vp9PictureIDMapping
	// lastPictureID tracks the most recent source frame so that backward
	// jumps in the source PictureID space can be detected.
	lastPictureID    uint16
	lastExtendedForm bool
	haveLast         bool
}

// Reset marks the start of a new source stream, for example when two
// independently numbered VP9 transport streams are concatenated. Frame
// mappings and temporal-layer base state of the previous stream are dropped,
// while the output PictureID sequence keeps running: the next frame still
// receives the next consecutive ID, so the concatenated stream never
// restarts its PictureID.
func (r *VP9PictureIDRemapper) Reset() {
	r.mappings = nil
	r.haveLast = false
	r.haveTL0Base = false
}

// Remap rewrites the VP9 payload descriptor of one RTP packet.
//
// timestamp is the RTP timestamp of the packet; all fragments of one frame
// share it. On success it returns a newly allocated payload with the
// rewritten descriptor; the input payload is never modified, so every
// fragment of a frame can be remapped independently. The descriptor grows by
// one byte when a 7-bit PictureID is upgraded to 15-bit. On error the
// returned slice is nil.
func (r *VP9PictureIDRemapper) Remap(timestamp uint32, payload []byte) ([]byte, error) {
	if !r.initialized {
		r.nextPictureID = r.InitialPictureID & vp9Max15BitPictureID
		r.initialized = true
	}

	desc, err := parseVP9Descriptor(payload)
	if err != nil {
		return nil, err
	}

	if !desc.hasPictureID {
		return nil, ErrVP9PictureIDMissing
	}

	mapping, isNew, err := r.lookupMapping(timestamp, payload, desc)
	if err != nil {
		return nil, err
	}

	newPDiff, err := r.resolvePDiff(desc, mapping)
	if err != nil {
		if isNew {
			// The frame must not consume an output ID or leave partial state
			// when its references cannot be resolved.
			r.rollbackNewMapping(desc, mapping)
		}

		return nil, err
	}

	return rewriteVP9Descriptor(payload, desc, mapping, newPDiff, r.Force15Bit), nil
}

// rollbackNewMapping undoes the state a failed remap just installed for a
// previously unseen frame by restoring the snapshot taken at its creation.
func (r *VP9PictureIDRemapper) rollbackNewMapping(desc vp9Descriptor, mapping vp9PictureIDMapping) {
	delete(r.mappings, desc.pictureID)

	r.nextPictureID = mapping.newPictureID
	r.haveLast = mapping.prevHaveLast
	r.lastPictureID = mapping.prevLastPictureID
	r.lastExtendedForm = mapping.prevLastExtendedForm
	r.haveTL0Base = mapping.prevHaveTL0Base
	r.tl0PicIdxCounter = mapping.prevTL0PicIdxCounter
}

// resolvePDiff recomputes every flexible-mode P_DIFF against the new
// PictureID sequence. The source P_DIFF identifies a referenced frame by its
// source PictureID; that frame's mapping gives its new ID, and the
// difference is re-derived modulo the 15-bit PictureID space. Returning an
// explicit difference (rather than keeping the source bytes) keeps every
// reference valid when source frames are skipped or several streams are
// joined. An unknown referenced frame yields ErrVP9ReferenceUnresolved.
func (r *VP9PictureIDRemapper) resolvePDiff(
	desc vp9Descriptor, mapping vp9PictureIDMapping,
) ([]uint8, error) {
	if len(desc.refDiff) == 0 {
		return nil, nil
	}

	newPDiff := make([]uint8, len(desc.refDiff))
	for i, diff := range desc.refDiff {
		referencedID := (desc.pictureID - uint16(diff)) & vp9Max15BitPictureID
		reference, ok := r.mappings[referencedID]
		if !ok {
			return nil, ErrVP9ReferenceUnresolved
		}
		// The difference is always small enough for the 7-bit P_DIFF field:
		// the referenced frame was mapped before the current one, so the
		// forward distance is in [1, 0x7FFF].
		newPDiff[i] = uint8((mapping.newPictureID - reference.newPictureID) & vp9Max15BitPictureID) //nolint:gosec
	}

	return newPDiff, nil
}

// vp9Descriptor is the subset of a parsed VP9 payload descriptor that the
// remapper needs to locate and rewrite its fields.
type vp9Descriptor struct {
	hasPictureID bool
	flexible     bool
	predicted    bool
	hasLayer     bool

	extendedPictureID bool
	pictureID         uint16
	pictureIDOffset   int // Offset of the first PictureID byte.

	tid             uint8 // Temporal layer ID, valid when hasLayer is true.
	layerOffset     int   // Offset of the TID/U/SID/D byte, or -1.
	tl0PicIdxOffset int   // Offset of TL0PICIDX, or -1.

	// refOffsets/refDiff mark every flexible-mode P_DIFF byte: its offset in
	// the source payload and the parsed difference value.
	refOffsets []int
	refDiff    []uint8
}

// parseVP9Descriptor walks the descriptor bytes and records the offsets of
// the fields the remapper rewrites. It validates every mandatory field the
// same way VP9Packet.Unmarshal does, so a malformed descriptor is rejected
// before any state is touched.
func parseVP9Descriptor(payload []byte) (vp9Descriptor, error) { //nolint:cyclop
	desc := vp9Descriptor{
		layerOffset:     -1,
		tl0PicIdxOffset: -1,
	}
	if len(payload) < 1 {
		return desc, errShortPacket
	}

	first := payload[0]
	desc.hasPictureID = first&vp9FlagI != 0
	desc.predicted = first&vp9FlagP != 0
	desc.hasLayer = first&vp9FlagL != 0
	desc.flexible = first&vp9FlagF != 0

	pos := 1
	if desc.hasPictureID {
		if len(payload) <= pos {
			return desc, errShortPacket
		}
		desc.pictureIDOffset = pos
		desc.extendedPictureID = payload[pos]&vp9FlagM != 0
		desc.pictureID = uint16(payload[pos] & 0x7F) //nolint:gosec // G115, masked to 7 bits
		pos++
		if desc.extendedPictureID {
			if len(payload) <= pos {
				return desc, errShortPacket
			}
			desc.pictureID = desc.pictureID<<8 | uint16(payload[pos]) //nolint:gosec // G115
			pos++
		}
	}

	if desc.hasLayer {
		if len(payload) <= pos {
			return desc, errShortPacket
		}
		desc.layerOffset = pos
		desc.tid = payload[pos] >> 5
		pos++
		if !desc.flexible {
			if len(payload) <= pos {
				return desc, errShortPacket
			}
			desc.tl0PicIdxOffset = pos
			pos++
		}
	}

	// Flexible mode reference indices are present on predicted frames and
	// must be walked so that the video payload offset is validated. Their
	// offsets and values are recorded because P_DIFF is recomputed against
	// the new PictureID sequence.
	if desc.flexible && desc.predicted {
		for ref := 0; ; ref++ {
			if len(payload) <= pos {
				return desc, errShortPacket
			}
			desc.refOffsets = append(desc.refOffsets, pos)
			desc.refDiff = append(desc.refDiff, payload[pos]>>1)
			continuation := payload[pos]&0x01 != 0
			pos++
			if !continuation {
				break
			}
			if ref >= maxVP9RefPics-1 {
				return desc, errTooManyPDiff
			}
		}
	}

	return desc, nil
}

// lookupMapping returns the frame mapping for the packet's source PictureID,
// creating a new one for the first packet of a previously unseen frame. The
// boolean reports whether a new mapping (and a new output PictureID) was
// consumed, so the caller can roll it back if a later validation step fails.
func (r *VP9PictureIDRemapper) lookupMapping(
	timestamp uint32, payload []byte, desc vp9Descriptor,
) (vp9PictureIDMapping, bool, error) {
	modulus := vp9Max7BitPictureID + 1
	if desc.extendedPictureID {
		modulus = vp9PictureIDCount
	}
	halfSpace := uint64(modulus) / 2

	if r.haveLast && r.lastExtendedForm != desc.extendedPictureID {
		// The source switched between the 7-bit and 15-bit PictureID forms:
		// the two numbering spaces are not comparable, so start a fresh
		// mapping context instead of guessing across them.
		r.Reset()
	}

	distance := uint64(0)
	if r.haveLast {
		distance = (uint64(desc.pictureID) - uint64(r.lastPictureID)) & uint64(modulus-1)
		if distance > halfSpace {
			// A backward jump past half the PictureID space means the source
			// space wrapped or a new stream started: old frames can no longer
			// be referenced by PictureID alone.
			r.Reset()
		}
	}

	if mapping, ok := r.mappings[desc.pictureID]; ok {
		// The same PictureID reused with a different timestamp is a different
		// frame whose state was already flushed above; if it survived, the
		// packet must belong to that newer frame and is therefore late.
		if mapping.timestamp != timestamp {
			return vp9PictureIDMapping{}, false, ErrVP9LatePacket
		}

		return mapping, false, nil
	}

	if r.haveLast && distance > halfSpace {
		// Older than the last frame and its mapping has expired.
		return vp9PictureIDMapping{}, false, ErrVP9LatePacket
	}

	mapping := r.newMapping(timestamp, payload, payloadHasTL0(desc), desc)
	r.lastPictureID = desc.pictureID
	r.lastExtendedForm = desc.extendedPictureID
	r.haveLast = true

	return mapping, true, nil
}

// newMapping assigns the next consecutive IDs to an unseen frame and stores
// them so that every later fragment receives the same rewrite.
func (r *VP9PictureIDRemapper) newMapping(
	timestamp uint32, payload []byte, hasTL0 bool, desc vp9Descriptor,
) vp9PictureIDMapping {
	if r.mappings == nil {
		r.mappings = map[uint16]vp9PictureIDMapping{}
	}

	mapping := vp9PictureIDMapping{
		newPictureID: r.nextPictureID,
		timestamp:    timestamp,
		// Capture every field the creation below mutates.
		prevHaveLast:         r.haveLast,
		prevLastPictureID:    r.lastPictureID,
		prevLastExtendedForm: r.lastExtendedForm,
		prevHaveTL0Base:      r.haveTL0Base,
		prevTL0PicIdxCounter: r.tl0PicIdxCounter,
	}
	r.nextPictureID++
	if r.nextPictureID >= vp9PictureIDCount {
		r.nextPictureID = 0
	}

	if hasTL0 {
		mapping.hasTL0 = true
		// Only temporal layer zero frames own a new TL0PICIDX; higher
		// temporal layers reference the current base-layer index.
		switch {
		case desc.tid == 0:
			mapping.tl0PicIdx = r.tl0PicIdxCounter
			r.tl0PicIdxCounter++
			r.haveTL0Base = true
		case r.haveTL0Base:
			mapping.tl0PicIdx = r.tl0PicIdxCounter - 1
		default:
			// No base frame seen yet; keep the source index rather than
			// inventing a reference to an unknown frame.
			mapping.tl0PicIdx = sourceTL0PicIdx(payload, desc)
		}
	}

	r.mappings[desc.pictureID] = mapping

	return mapping
}

// payloadHasTL0 reports whether the descriptor carries a TL0PICIDX byte,
// which is only the case in non-flexible mode with layer indices.
func payloadHasTL0(desc vp9Descriptor) bool {
	return desc.hasLayer && !desc.flexible && desc.tl0PicIdxOffset >= 0
}

// sourceTL0PicIdx reads the source TL0PICIDX at the recorded offset.
func sourceTL0PicIdx(payload []byte, desc vp9Descriptor) uint8 {
	if desc.tl0PicIdxOffset < 0 || len(payload) <= desc.tl0PicIdxOffset {
		return 0
	}

	return payload[desc.tl0PicIdxOffset]
}

// rewriteVP9Descriptor writes the mapped IDs into the descriptor. When the
// PictureID grows from one byte to two the descriptor is grown by one byte;
// every byte following the PictureID (layers, reference indices, SS data and
// the compressed video payload) is shifted unchanged.
func rewriteVP9Descriptor(
	payload []byte, desc vp9Descriptor, mapping vp9PictureIDMapping, newPDiff []uint8, force15Bit bool,
) []byte {
	use15Bit := force15Bit || desc.extendedPictureID || mapping.newPictureID > vp9Max7BitPictureID
	grew := use15Bit && !desc.extendedPictureID

	// Always allocate the output: rewriting in place would overwrite the
	// source PictureID, so a later fragment of the same frame could no longer
	// resolve its mapping. When the descriptor grows, every byte after the
	// PictureID shifts by one.
	outSize := len(payload)
	if grew {
		outSize++
	}
	out := make([]byte, outSize)
	copy(out, payload[:desc.pictureIDOffset])
	if grew {
		copy(out[desc.pictureIDOffset+2:], payload[desc.pictureIDOffset+1:])
	} else {
		copy(out[desc.pictureIDOffset:], payload[desc.pictureIDOffset:])
	}

	writeVP9PictureID(out, desc.pictureIDOffset, use15Bit, mapping.newPictureID)
	writeRemappedFields(out, desc, mapping, newPDiff, grew)

	return out
}

// writeRemappedFields writes the recomputed TL0PICIDX and P_DIFF values. When
// the descriptor grew, every offset after the PictureID shifts by one; the
// low N (continuation) bit of each P_DIFF byte is preserved.
func writeRemappedFields(
	out []byte, desc vp9Descriptor, mapping vp9PictureIDMapping, newPDiff []uint8, grew bool,
) {
	if mapping.hasTL0 && desc.tl0PicIdxOffset >= 0 {
		tl0Offset := desc.tl0PicIdxOffset
		if grew {
			tl0Offset++
		}
		out[tl0Offset] = mapping.tl0PicIdx
	}

	for i, offset := range desc.refOffsets {
		if grew {
			offset++
		}
		out[offset] = newPDiff[i]<<1 | (out[offset] & 0x01) //nolint:gosec
	}
}

// writeVP9PictureID encodes the new ID in 7-bit or 15-bit form.
func writeVP9PictureID(payload []byte, offset int, extended bool, pictureID uint16) {
	if extended {
		payload[offset] = vp9FlagM | byte(pictureID>>8) //nolint:gosec // G115, high 7 bits
		payload[offset+1] = byte(pictureID)             //nolint:gosec // G115, low 8 bits

		return
	}

	payload[offset] = byte(pictureID) //nolint:gosec // G115, value fits in 7 bits
}
