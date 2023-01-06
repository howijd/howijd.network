// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import (
	"bytes"
	"encoding/binary"
)

const (
	// Version is the current version of the Cryptdatum format.
	// Implementations of the Cryptdatum library should set the version field in
	// Cryptdatum headers to this value.
	Version uint16 = 1

	// MinVersion is the minimum supported version of the Cryptdatum format.
	// If the version field in a Cryptdatum header is lower than this value, the
	// header should be considered invalid.
	MinVersion uint16 = 1

	// HeaderSize is the size of a Cryptdatum header in bytes. It can be used by
	// implementations of the Cryptdatum library to allocate sufficient memory for
	// a Cryptdatum header, or to check the size of a Cryptdatum header that has
	// been read from a stream.
	HeaderSize = 80

	// date which datum can not be older
	magicDate = 1652155382000000001
)

const (
	DatumInvalid uint64 = 1 << iota
	DatumDraft
	DatumEmpty
	DatumChecksum
	DatumOPC
	DatumCompressed
	DatumEncrypted
	DatumExtractable
	DatumSigned
	DatumStreamable
	DatumCustom
	DatumCompromised
)

var (
	// Magic is the magic number used to identify Cryptdatum headers. If the magic
	// number field in a Cryptdatum header does not match this value, the header
	// should be considered invalid.
	Magic = [8]byte{0xA7, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0xE1}

	// Delimiter is the delimiter used to mark the end of a Cryptdatum header. If
	// the delimiter field in a Cryptdatum header does not match this value, the
	// header should be considered invalid.
	Delimiter = [8]byte{0xC8, 0xB7, 0xA6, 0xE5, 0xD4, 0xC3, 0xB2, 0xF1}

	// empty
	empty = [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	flagLookup = map[uint64]bool{
		DatumDraft:       true,
		DatumCompromised: true,
		DatumOPC:         true,
		DatumChecksum:    true,
		DatumEmpty:       true,
		DatumCompressed:  true,
		DatumEncrypted:   true,
		DatumExtractable: true,
		DatumSigned:      true,
	}
)

// Header represents a Cryptdatum header. It contains metadata about the data
// payload, such as the version of the Cryptdatum format, the time when the
// data was created, and the features used by the datum.
type Header struct {
	// magic is a byte array that identifies the header as a Cryptdatum header.
	magic [8]byte
	// Version indicates the version of the Cryptdatum format.
	Version uint16
	// Timestamp is a Unix timestamp in nanoseconds, indicating the time when the
	// data was created.
	Timestamp uint64
	// OPC is a unique operation ID for the data.
	OPC uint16
	// Checksum is a CRC64 checksum for verifying the integrity of the data.
	Checksum uint64
	// Flags is a bit field that indicates which Cryptdatum features are used by
	// the datum, such as whether the data is encrypted, compressed, or has a
	// checksum.
	Flags uint64
	// Size is the total size of the data, including the header and optional
	// signature. It can be used by implementations of the Cryptdatum library to
	// allocate sufficient memory for the data, or to check the size of the data
	// that has been read from a stream.
	Size uint64
	// SignatureSize indicates the size of the signature, if any.
	SignatureSize uint32
	// CompressionAlgorithm indicates the compression algorithm used, if any.
	CompressionAlgorithm uint8
	// EncryptionAlgorithm indicates the encryption algorithm used, if any.
	EncryptionAlgorithm uint8
	// SignatureType indicates the signature type helping implementations to
	// identify how the signature should be verified.
	SignatureType uint8
	// reserved is a byte array reserved for future use.
	reserved [5]byte
	// Delimiter is a byte array that marks the end of the header.
	delimiter [8]byte
}

// Verify verifies the integrity of a Cryptdatum header. It checks the magic
// number, delimiter, and other fields to ensure that the header is valid. If the
// header is valid, the function returns true. Otherwise, it returns false.
//
// The data argument should contain the entire Cryptdatum header, as a byte slice.
// The function will read the first HeaderSize bytes of the slice to validate the
// header.
//
// If the data slice is smaller than HeaderSize bytes, the function will return
// false, as the header is considered incomplete.
func VerifyHeader(data []byte) bool {
	if len(data) < HeaderSize {
		return false
	}

	// check magic and delimiter
	if !bytes.Equal(Magic[:], data[:8]) || !bytes.Equal(Delimiter[:], data[72:80]) {
		return false
	}

	// check version is >= 1
	if binary.LittleEndian.Uint16(data[8:10]) < 1 {
		return false
	}

	// break here if DatumDraft is set
	flags := binary.LittleEndian.Uint64(data[10:18])

	if flags&DatumDraft != 0 || flags&DatumCompromised != 0 {
		return true
	}

	// It it was not a draft it must have timestamp
	if binary.LittleEndian.Uint64(data[18:26]) < magicDate {
		return false
	}

	// DatumOPC is set then counter value must be gte 1
	if flags&DatumOPC != 0 {
		if binary.LittleEndian.Uint32(data[26:30]) < 1 {
			return false
		}
	}

	// DatumChecksum Checksum must be set
	if flags&DatumChecksum != 0 && bytes.Equal(data[30:38], empty[:]) {
		return false
	}

	// DatumEmpty and DatumDraft
	if flags&DatumEmpty != 0 {
		// Size field must be set
		if binary.LittleEndian.Uint64(data[38:46]) < 1 {
			return false
		}

		// DatumCompressed compression algorithm must be set
		if flags&DatumCompressed != 0 && binary.LittleEndian.Uint16(data[46:48]) < 1 {
			return false
		}
		// DatumEncrypted encryption algorithm must be set
		if flags&DatumEncrypted != 0 && binary.LittleEndian.Uint16(data[48:50]) < 1 {
			return false
		}
		// DatumExtractable payl;oad can be extracted then filename must be set
		if flags&DatumExtractable != 0 && bytes.Equal(data[50:58], empty[:]) {
			return false
		}
	}

	// DatumSigned then Signature Type must be also set
	// however value of the signature Size may depend on Signature Type
	if flags&DatumSigned != 0 && binary.LittleEndian.Uint16(data[58:60]) < 1 {
		return false
	}

	return true
}
