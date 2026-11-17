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

	// Telephone-event Errors.
	ErrUnknownTelephoneEvent          = errors.New("unknown telephone event")
	ErrTelephoneEventPayloadTooShort  = errors.New("telephone-event payload is not large enough")
	ErrTelephoneEventVolumeOutOfRange = errors.New("telephone-event volume out of range")
	ErrTelephoneEventDurationRollback = errors.New("telephone-event duration must not decrease")
	ErrTelephoneEventDurationOverflow = errors.New("telephone-event duration overflows the duration field")
	ErrTelephoneEventNoUpdates        = errors.New("telephone event requires at least one duration update")
)
