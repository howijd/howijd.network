// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package main

import (
	"encoding/binary"
	"os"
	"time"

	"golang.org/x/exp/slog"
)

var (
	magic = [8]byte{0xA7, 0xF6, 0xE5, 0xD4, 0xC3, 0xB2, 0xA1, 0xE1}

	delimiter = [8]byte{0xC8, 0xB7, 0xA6, 0xE5, 0xD4, 0xC3, 0xB2, 0xF1}
)

func main() {
	var generators = []func() (string, error){
		createTestHasValidHeader,
	}
	for _, gen := range generators {
		if name, err := gen(); err != nil {
			slog.Error("failed to create", err, slog.String("file", name))
			os.Exit(1)
		}
	}
}

// specV1createValidForTesting outputs empty cdt for testing
// header field alignment.
func createTestHasValidHeader() (string, error) {
	const name = "has-aligned-header.cdt"
	var header [80]byte

	// Set Magic
	copy(header[0:8], magic[:])

	// Set version, must be 1
	binary.LittleEndian.PutUint16(header[8:10], 1)

	ts := time.Date(2022, 5, 10, 4, 3, 2, 1, time.UTC).UnixNano()

	// Set flags
	flagDatumEmpty := 4
	flagDatumChecksum := 8
	flagDatumOPC := 16
	flagDatumCompressed := 32
	flagDatumEncrypted := 64
	flagDatumExtractable := 128
	flagDatumSigned := 256
	flagDatumCustom := 1024

	flag := uint64(flagDatumEmpty | flagDatumChecksum | flagDatumOPC | flagDatumEncrypted | flagDatumCompressed | flagDatumSigned | flagDatumCustom | flagDatumExtractable)
	binary.LittleEndian.PutUint64(header[10:18], flag)

	// Set unix time in nanoseconds
	binary.LittleEndian.PutUint64(header[18:26], uint64(ts))

	// Op counter
	binary.LittleEndian.PutUint32(header[26:30], 2)

	// Checksum
	copy(header[30:38], []byte{'c', 'h', 'e', 'c', 'k', 's', 'u', 'm'})

	// Size
	binary.LittleEndian.PutUint64(header[38:46], 3)

	// Compression Algorithm
	binary.LittleEndian.PutUint16(header[46:48], 4)

	// Encryption Algorithm
	binary.LittleEndian.PutUint16(header[48:50], 5)

	// Signature Type
	binary.LittleEndian.PutUint16(header[50:52], 6)

	// Signature Size
	binary.LittleEndian.PutUint32(header[52:56], 7)

	// File extension
	copy(header[56:64], []byte{'a', 'f', 'f', 'i', 'x', 'i', 'n', 'g'})

	// Custom data
	copy(header[64:72], []byte{'t', 'a', 'i', 'l', 'o', 'r', 'e', 'd'})

	// delimiter
	copy(header[72:80], delimiter[:])

	return name, os.WriteFile(name, header[:], 0640)
}
