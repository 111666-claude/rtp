// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import "errors"

var errH265TruncatedRBSP = errors.New("truncated H265 RBSP while parsing parameter set")

// Bit widths used while skipping a profile_tier_level() syntax structure.
// Reference: ITU-T H.265 section 7.3.3.
const (
	h265PTLGeneralFixedBits = 8 + // general_profile_space(2) general_tier_flag(1) general_profile_idc(5)
		32 + // general_profile_compatibility_flag[32]
		48 + // general_*_constraint_flags + general_reserved_zero_42bits
		8 // general_level_idc
	h265PTLSubLayerProfileBits = 2 + 1 + 5 + 32 + 48 // sub_layer_profile_space .. sub_layer_reserved_zero_44bits
)

// h265EbspToRbsp removes the emulation prevention bytes (0x03 after 0x00 0x00)
// from an Encapsulated Byte Sequence Payload to recover the Raw Byte Sequence
// Payload. The input is never modified.
func h265EbspToRbsp(ebsp []byte) []byte {
	rbsp := make([]byte, 0, len(ebsp))

	zeroCount := 0

	for _, b := range ebsp {
		if zeroCount >= 2 && b == 0x03 {
			zeroCount = 0

			continue
		}
		rbsp = append(rbsp, b)

		if b == 0x00 {
			zeroCount++
		} else {
			zeroCount = 0
		}
	}

	return rbsp
}

// h265BitReader consumes an RBSP bit by bit, most significant bit first.
type h265BitReader struct {
	rbsp   []byte
	bitPos uint
}

func newH265BitReader(rbsp []byte) h265BitReader {
	return h265BitReader{rbsp: rbsp}
}

func (r *h265BitReader) readBits(count uint) (uint32, error) {
	if count == 0 {
		return 0, nil
	} else if count > 32 || count > uint(len(r.rbsp))*8-r.bitPos {
		return 0, errH265TruncatedRBSP
	}

	var value uint32

	for range count {
		byteIndex := r.bitPos / 8
		bitIndex := 7 - r.bitPos%8

		value = (value << 1) | uint32((r.rbsp[byteIndex]>>bitIndex)&0b1)
		r.bitPos++
	}

	return value, nil
}

// skipBits discards count bits, including counts larger than 32.
func (r *h265BitReader) skipBits(count uint) error {
	if count > uint(len(r.rbsp))*8-r.bitPos {
		return errH265TruncatedRBSP
	}

	r.bitPos += count

	return nil
}

func (r *h265BitReader) readFlag() (bool, error) {
	value, err := r.readBits(1)

	return value == 1, err
}

// readUE reads an unsigned Exp-Golomb coded value, ue(v).
func (r *h265BitReader) readUE() (uint32, error) {
	leadingZeros := uint(0)

	for {
		bit, err := r.readBits(1)
		if err != nil {
			return 0, err
		} else if bit == 1 {
			break
		}

		leadingZeros++
		// CodeNum values of 2^32 and above cannot be represented by uint32.
		if leadingZeros > 32 {
			return 0, errH265TruncatedRBSP
		}
	}

	if leadingZeros == 0 {
		return 0, nil
	}

	rest, err := r.readBits(leadingZeros)
	if err != nil {
		return 0, err
	}

	return (uint32(1) << leadingZeros) - 1 + rest, nil // nolint: gosec // leadingZeros is bounded above
}

// skipProfileTierLevel skips a profile_tier_level() structure.
// Reference: ITU-T H.265 section 7.3.3.
func (r *h265BitReader) skipProfileTierLevel(profilePresentFlag bool, maxSubLayersMinus1 uint32) error {
	if profilePresentFlag {
		if err := r.skipBits(h265PTLGeneralFixedBits); err != nil {
			return err
		}
	}

	subLayerLevelPresentFlag := make([]bool, maxSubLayersMinus1)
	subLayerProfilePresentFlag := make([]bool, maxSubLayersMinus1)

	var err error

	for index := range maxSubLayersMinus1 {
		if subLayerProfilePresentFlag[index], err = r.readFlag(); err != nil {
			return err
		}
		if subLayerLevelPresentFlag[index], err = r.readFlag(); err != nil {
			return err
		}
	}

	if _, err := r.readBits(2); err != nil { // sub_layer_reserved_zero_2bits
		return err
	}

	for index := range maxSubLayersMinus1 {
		if subLayerProfilePresentFlag[index] {
			if err := r.skipBits(h265PTLSubLayerProfileBits); err != nil {
				return err
			}
		}
		if subLayerLevelPresentFlag[index] {
			if _, err := r.readBits(8); err != nil {
				return err
			}
		}
	}

	return nil
}

// h265ParameterSetID parses the parameter set ID carried by a VPS/SPS/PPS NAL
// unit. A non-nil error is returned for truncated or otherwise unparseable
// parameter sets so the caller can avoid polluting its cache with them.
// Reference: ITU-T H.265 sections 7.3.2.1 (VPS), 7.3.2.2.1 (SPS) and
// 7.3.2.3 (PPS).
func h265ParameterSetID(naluType uint8, naluPayload []byte) (uint32, error) {
	reader := newH265BitReader(h265EbspToRbsp(naluPayload))

	switch naluType {
	case h265NaluVpsType:
		vpsVideoParameterSetID, err := reader.readBits(4)
		if err != nil {
			return 0, err
		}

		return vpsVideoParameterSetID, nil
	case h265NaluSpsType:
		maxSubLayersMinus1, err := reader.readBits(3) // sps_max_sub_layers_minus1
		if err != nil {
			return 0, err
		}

		if _, err = reader.readFlag(); err != nil { // sps_temporal_id_nesting_flag
			return 0, err
		}

		if err = reader.skipProfileTierLevel(true, maxSubLayersMinus1); err != nil {
			return 0, err
		}

		return reader.readUE() // sps_seq_parameter_set_id
	case h265NaluPpsType:
		ppsPicParameterSetID, err := reader.readUE()
		if err != nil {
			return 0, err
		}

		return ppsPicParameterSetID, nil
	default:
		return 0, errInvalidH265PacketType
	}
}
