// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
)

var (
	Err              = errors.New("cryptdatum")
	ErrIO            = fmt.Errorf("%w: i/o error", Err)
	ErrEOF           = fmt.Errorf("%w: EOF", Err)
	ErrNoHeader      = fmt.Errorf("%w: no header", Err)
	ErrInvalidHeader = fmt.Errorf("%w: invalid header", Err)
)

// Header represents a Cryptdatum header. It contains metadata about the data
// payload, such as the version of the Cryptdatum format, the time when the
// data was created, and the features used by the datum.
type Header struct {
	// magic identifies the header as a Cryptdatum header.
	magic [8]byte

	// Version indicates the version of the Cryptdatum format.
	Version uint16

	// Cryptdatum format features flags to indicate which Cryptdatum features are
	// used by that datum e.g whether the data is encrypted, compressed, or has
	// a checksum. has operation counter set is signed etc.
	Flags uint64

	// Timestamp is Unix timestamp in nanoseconds, indicating the time when the data was created.
	Timestamp uint64

	// OPC Operation Counter - Unique operation ID for the data.
	OPC uint32

	// Total size of the data, including the header and optional signature.
	Size uint64

	// CRC64 checksum for verifying the integrity of the data.
	Checksum uint64

	// CompressionAlg indicates the compression algorithm used, if any.
	CompressionAlg uint16

	// EncryptionAlg indicates the encryption algorithm used, if any.
	EncryptionAlg uint16

	// SignatureType indicates the signature type helping implementations to
	// identify how the signature should be verified.
	SignatureType uint16

	// SignatureSize indicates the size of the signature, if any.
	SignatureSize uint32

	// File Extension
	FileExt string

	// Custom field
	Custom [8]byte

	// Delimiter is a byte array that marks the end of the header.
	delimiter [8]byte
}

// HasHeader checks if the provided data contains a Cryptdatum header. It looks for specific header
// fields and checks their alignment, but does not perform any further validations. If the data
// is likely to be Cryptdatum, the function returns true. Otherwise, it returns false.
// If you want to verify the integrity of the header as well, use the HasValidHeader function
// or use DecodeHeader and perform the validation yourself.
//
// The data argument should contain the entire Cryptdatum data, as a byte slice. The function will
// read the first HeaderSize bytes of the slice to check for the presence of a header.
func HasHeader(data []byte) bool {
	if len(data) < HeaderSize {
		return false
	}

	// check magic and delimiter
	return bytes.Equal(Magic[:], data[:8]) && bytes.Equal(Delimiter[:], data[72:80])
}

// HasValidHeader checks if the provided data contains a valid Cryptdatum header. It verifies the
// integrity of the header by checking the magic number, delimiter, and other fields. If the header
// is valid, the function returns true. Otherwise, it returns false.
//
// The data argument can contain any data as a byte slice, but should be at least HeaderSize in length
// and start with the header. The function will read the first HeaderSize bytes of the slice to
// validate the header. If the data slice is smaller than HeaderSize bytes, the function will
// return false, as the header is considered incomplete.
func HasValidHeader(data []byte) bool {
	if !HasHeader(data) {
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

// DecodeHeader returns the header information of a Cryptdatum data without decoding the entire data.
// The header information is read from the provided reader, which should contain the Cryptdatum data.
// If the header is invalid or an error occurs while reading, an error is returned.
//
// Caller is responsible to close the source e.g FILE
func DecodeHeader(r io.Reader) (header Header, err error) {
	headb := make([]byte, HeaderSize)

	n, err := r.Read(headb)
	if err != nil {
		return header, err
	}
	if n < HeaderSize {
		return header, io.ErrUnexpectedEOF
	}
	if !HasHeader(headb) {
		return Header{}, ErrNoHeader
	}
	copy(header.magic[:], headb[:8])

	header.Version = binary.LittleEndian.Uint16(headb[8:10])
	header.Flags = binary.LittleEndian.Uint64(headb[10:18])
	header.Timestamp = binary.LittleEndian.Uint64(headb[18:26])
	header.OPC = binary.LittleEndian.Uint32(headb[26:30])
	header.Checksum = binary.LittleEndian.Uint64(headb[30:38])
	header.Size = binary.LittleEndian.Uint64(headb[38:46])
	header.CompressionAlg = binary.LittleEndian.Uint16(headb[46:48])
	header.EncryptionAlg = binary.LittleEndian.Uint16(headb[48:50])
	header.SignatureType = binary.LittleEndian.Uint16(headb[50:52])
	header.SignatureSize = binary.LittleEndian.Uint32(headb[52:56])
	header.FileExt = string(headb[56:64])
	copy(header.Custom[:], headb[64:72])
	copy(header.delimiter[:], headb[72:80])
	return header, nil
}
