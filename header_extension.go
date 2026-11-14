// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtp

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	headerExtensionIDReserved = 0xF

	oneByteHeaderExtensionHeaderSize = 4
)

// HeaderExtension represents an RTP extension header.
type HeaderExtension interface {
	Set(id uint8, payload []byte) error
	GetIDs() []uint8
	Get(id uint8) []byte
	Del(id uint8) error

	Unmarshal(buf []byte) (int, error)
	Marshal() ([]byte, error)
	MarshalTo(buf []byte) (int, error)
	MarshalSize() int
}

// OneByteHeaderExtension is an RFC8285 one-byte header extension.
type OneByteHeaderExtension struct {
	payload []byte
}

// extensions parses the stored payload into an ordered list of extensions.
// Malformed or truncated elements are ignored instead of being allowed to
// trigger out-of-bounds accesses.
func (e *OneByteHeaderExtension) extensions() []Extension {
	if len(e.payload) < oneByteHeaderExtensionHeaderSize {
		return nil
	}

	// Only the region described by the length field is meaningful.
	end := oneByteHeaderExtensionHeaderSize +
		int(binary.BigEndian.Uint16(e.payload[2:4]))*4
	if end > len(e.payload) {
		end = len(e.payload)
	}

	// Each element occupies at least two bytes (ID/length and one payload byte).
	extensions := make([]Extension, 0, (end-oneByteHeaderExtensionHeaderSize)/2)
	for n := oneByteHeaderExtensionHeaderSize; n < end; {
		if e.payload[n] == 0x00 { // padding
			n++

			continue
		}

		extid := e.payload[n] >> 4
		// ID 0 is padding and 15 is reserved; neither may appear as an element.
		if extid == headerExtensionIDReserved || extid == 0 {
			break
		}

		payloadLen := int(e.payload[n]&^0xF0) + 1
		n++

		if n+payloadLen > end {
			break
		}

		extensions = append(extensions, Extension{
			id:      extid,
			payload: e.payload[n : n+payloadLen],
		})
		n += payloadLen
	}

	return extensions
}

// setExtensions rebuilds the extension header from the given ordered list of
// extensions. The length field is derived from the (padded) payload so it can
// never drift out of sync with the actual data.
func (e *OneByteHeaderExtension) setExtensions(extensions []Extension) {
	bodySize := 0
	for _, extension := range extensions {
		bodySize += 1 + len(extension.payload)
	}

	// The extension body must be padded to a 32-bit boundary.
	roundedBodySize := ((bodySize + 3) / 4) * 4

	payload := make([]byte, oneByteHeaderExtensionHeaderSize+roundedBodySize)
	binary.BigEndian.PutUint16(payload[0:2], ExtensionProfileOneByte)
	// nolint: gosec // G115 false positive, roundedBodySize/4 always fits
	binary.BigEndian.PutUint16(payload[2:4], uint16(roundedBodySize/4))

	n := oneByteHeaderExtensionHeaderSize
	for _, extension := range extensions {
		// nolint: gosec // G115 false positive, payload length is at most 16
		payload[n] = extension.id<<4 | uint8(len(extension.payload)-1)
		n++
		n += copy(payload[n:], extension.payload)
	}

	e.payload = payload
}

// Set sets the extension payload for the specified ID.
func (e *OneByteHeaderExtension) Set(id uint8, buf []byte) error {
	if id < 1 || id > 14 {
		return fmt.Errorf("%w actual(%d)", errRFC8285OneByteHeaderIDRange, id)
	}
	if len(buf) == 0 {
		return fmt.Errorf("%w actual(%d)", errHeaderExtensionEmptyPayload, len(buf))
	}
	if len(buf) > 16 {
		return fmt.Errorf("%w actual(%d)", errRFC8285OneByteHeaderSize, len(buf))
	}

	extensions := e.extensions()
	updated := make([]Extension, 0, len(extensions)+1)
	replaced := false
	for _, extension := range extensions {
		if extension.id != id {
			updated = append(updated, extension)

			continue
		}

		if replaced {
			// Drop duplicates so a rewrite always leaves a single entry.
			continue
		}

		// setExtensions() copies the data, so a caller-owned buffer is never
		// aliased into the stored payload.
		updated = append(updated, Extension{id: id, payload: buf})
		replaced = true
	}

	if !replaced {
		updated = append(updated, Extension{id: id, payload: buf})
	}

	e.setExtensions(updated)

	return nil
}

// GetIDs returns the available IDs.
func (e *OneByteHeaderExtension) GetIDs() []uint8 {
	extensions := e.extensions()
	ids := make([]uint8, 0, len(extensions))
	for _, extension := range extensions {
		ids = append(ids, extension.id)
	}

	return ids
}

// Get returns the payload of the extension with the given ID.
func (e *OneByteHeaderExtension) Get(id uint8) []byte {
	for _, extension := range e.extensions() {
		if extension.id == id {
			return extension.payload
		}
	}

	return nil
}

// Del deletes the extension with the specified ID.
func (e *OneByteHeaderExtension) Del(id uint8) error {
	extensions := e.extensions()
	for i := range extensions {
		if extensions[i].id == id {
			e.setExtensions(append(extensions[:i:i], extensions[i+1:]...))

			return nil
		}
	}

	return errHeaderExtensionNotFound
}

// Unmarshal parses the extension payload.
func (e *OneByteHeaderExtension) Unmarshal(buf []byte) (int, error) {
	if len(buf) < oneByteHeaderExtensionHeaderSize {
		return 0, errTooSmall
	}

	profile := binary.BigEndian.Uint16(buf[0:2])
	if profile != ExtensionProfileOneByte {
		return 0, fmt.Errorf("%w actual(%x)", errHeaderExtensionNotFound, buf[0:2])
	}

	if extLen := oneByteHeaderExtensionHeaderSize +
		int(binary.BigEndian.Uint16(buf[2:4]))*4; len(buf) < extLen {
		return 0, errTooSmall
	}

	e.payload = buf

	return len(buf), nil
}

// Marshal returns the extension payload.
func (e OneByteHeaderExtension) Marshal() ([]byte, error) {
	payload := make([]byte, len(e.payload))
	copy(payload, e.payload)

	return payload, nil
}

// MarshalTo writes the extension payload to the given buffer.
func (e OneByteHeaderExtension) MarshalTo(buf []byte) (int, error) {
	size := e.MarshalSize()
	if size > len(buf) {
		return 0, io.ErrShortBuffer
	}

	return copy(buf, e.payload), nil
}

// MarshalSize returns the size of the extension payload.
func (e OneByteHeaderExtension) MarshalSize() int {
	return len(e.payload)
}

// TwoByteHeaderExtension is an RFC8285 two-byte header extension.
type TwoByteHeaderExtension struct {
	payload []byte
}

// Set sets the extension payload for the specified ID.
func (e *TwoByteHeaderExtension) Set(id uint8, buf []byte) error {
	if id < 1 {
		return fmt.Errorf("%w actual(%d)", errRFC8285TwoByteHeaderIDRange, id)
	}
	if len(buf) > 255 {
		return fmt.Errorf("%w actual(%d)", errRFC8285TwoByteHeaderSize, len(buf))
	}

	for n := 4; n < len(e.payload); {
		if e.payload[n] == 0x00 { // padding
			n++

			continue
		}

		extid := e.payload[n]
		n++

		payloadLen := int(e.payload[n])
		n++

		if extid == id {
			e.payload = append(e.payload[:n+2], append(buf, e.payload[n+2+payloadLen:]...)...)

			return nil
		}
		n += payloadLen
	}
	e.payload = append(e.payload, id, uint8(len(buf))) // nolint: gosec // G115
	e.payload = append(e.payload, buf...)
	binary.BigEndian.PutUint16(e.payload[2:4], binary.BigEndian.Uint16(e.payload[2:4])+1)

	return nil
}

// GetIDs returns the available IDs.
func (e *TwoByteHeaderExtension) GetIDs() []uint8 {
	ids := make([]uint8, 0, binary.BigEndian.Uint16(e.payload[2:4]))
	for n := 4; n < len(e.payload); {
		if e.payload[n] == 0x00 { // padding
			n++

			continue
		}

		extid := e.payload[n]
		n++

		payloadLen := int(e.payload[n])
		n++

		ids = append(ids, extid)
		n += payloadLen
	}

	return ids
}

// Get returns the payload of the extension with the given ID.
func (e *TwoByteHeaderExtension) Get(id uint8) []byte {
	for n := 4; n < len(e.payload); {
		if e.payload[n] == 0x00 { // padding
			n++

			continue
		}

		extid := e.payload[n]
		n++

		payloadLen := int(e.payload[n])
		n++

		if extid == id {
			return e.payload[n : n+payloadLen]
		}
		n += payloadLen
	}

	return nil
}

// Del deletes the extension with the specified ID.
func (e *TwoByteHeaderExtension) Del(id uint8) error {
	for n := 4; n < len(e.payload); {
		if e.payload[n] == 0x00 { // padding
			n++

			continue
		}

		extid := e.payload[n]

		payloadLen := int(e.payload[n+1])

		if extid == id {
			e.payload = append(e.payload[:n], e.payload[n+2+payloadLen:]...)

			return nil
		}
		n += payloadLen + 2
	}

	return errHeaderExtensionNotFound
}

// Unmarshal parses the extension payload.
func (e *TwoByteHeaderExtension) Unmarshal(buf []byte) (int, error) {
	profile := binary.BigEndian.Uint16(buf[0:2])
	if profile != ExtensionProfileTwoByte {
		return 0, fmt.Errorf("%w actual(%x)", errHeaderExtensionNotFound, buf[0:2])
	}
	e.payload = buf

	return len(buf), nil
}

// Marshal returns the extension payload.
func (e TwoByteHeaderExtension) Marshal() ([]byte, error) {
	return e.payload, nil
}

// MarshalTo marshals the extension to the given buffer.
func (e TwoByteHeaderExtension) MarshalTo(buf []byte) (int, error) {
	size := e.MarshalSize()
	if size > len(buf) {
		return 0, io.ErrShortBuffer
	}

	return copy(buf, e.payload), nil
}

// MarshalSize returns the size of the extension payload.
func (e TwoByteHeaderExtension) MarshalSize() int {
	return len(e.payload)
}

// RawExtension represents an RFC3550 header extension.
type RawExtension struct {
	payload []byte
}

// Set sets the extension payload for the specified ID.
func (e *RawExtension) Set(id uint8, payload []byte) error {
	if id != 0 {
		return fmt.Errorf("%w actual(%d)", errRFC3550HeaderIDRange, id)
	}
	e.payload = payload

	return nil
}

// GetIDs returns the available IDs.
func (e *RawExtension) GetIDs() []uint8 {
	return []uint8{0}
}

// Get returns the payload of the extension with the given ID.
func (e *RawExtension) Get(id uint8) []byte {
	if id == 0 {
		return e.payload
	}

	return nil
}

// Del deletes the extension with the specified ID.
func (e *RawExtension) Del(id uint8) error {
	if id == 0 {
		e.payload = nil

		return nil
	}

	return fmt.Errorf("%w actual(%d)", errRFC3550HeaderIDRange, id)
}

// Unmarshal parses the extension from the given buffer.
func (e *RawExtension) Unmarshal(buf []byte) (int, error) {
	profile := binary.BigEndian.Uint16(buf[0:2])
	if profile == ExtensionProfileOneByte || profile == ExtensionProfileTwoByte {
		return 0, fmt.Errorf("%w actual(%x)", errHeaderExtensionNotFound, buf[0:2])
	}
	e.payload = buf

	return len(buf), nil
}

// Marshal returns the raw extension payload.
func (e RawExtension) Marshal() ([]byte, error) {
	return e.payload, nil
}

// MarshalTo marshals the extension to the given buffer.
func (e RawExtension) MarshalTo(buf []byte) (int, error) {
	size := e.MarshalSize()
	if size > len(buf) {
		return 0, io.ErrShortBuffer
	}

	return copy(buf, e.payload), nil
}

// MarshalSize returns the size of the extension when marshaled.
func (e RawExtension) MarshalSize() int {
	return len(e.payload)
}
