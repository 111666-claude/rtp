// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package codecs

import "errors"

var (
	errShortPacket          = errors.New("packet is not large enough")
	errNilPacket            = errors.New("invalid nil packet")
	errTooManyPDiff         = errors.New("too many PDiff")
	errTooManySpatialLayers = errors.New("too many spatial layers")
	errUnhandledNALUType    = errors.New("NALU Type is unhandled")

	// AV1 Errors.
	errIsKeyframeAndFragment = errors.New(
		"bits Z and N are set. Not possible to have OBU be tail fragment and be keyframe",
	)

	// RED (RFC 2198) Errors.
	errREDFieldOverflow = errors.New(
		"RED field exceeds its on-wire width (7 bit PT, 14 bit offset or 10 bit length)",
	)
	errREDNoPrimaryBlock = errors.New("RED payload has no primary block")
	errREDDataOverflow   = errors.New("RED block length exceeds the remaining payload data")
)
