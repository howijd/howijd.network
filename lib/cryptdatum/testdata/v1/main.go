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
	if err := specV1createValidDraft(); err != nil {
		slog.Error("failed to create spec v1 valid-header-only.cdt", err)
		os.Exit(1)
	}
}

func specV1createValidDraft() error {
	var header [80]byte

	// Set Magic
	copy(header[0:8], magic[:])

	// Set version, must be 1
	binary.LittleEndian.PutUint16(header[8:10], 1)

	ts := time.Date(2022, 5, 10, 4, 3, 2, 1, time.UTC).UnixNano()

	// 18-25 Set flag
	flagDatumEmpty := 4
	flagDatumChecksum := 8
	flagDatumOPC := 16
	flagDatumEncrypted := 32
	flagDatumCompressed := 64
	flagDatumSigned := 128
	flagDatumCustom := 512

	flag := uint64(flagDatumEmpty | flagDatumChecksum | flagDatumOPC | flagDatumEncrypted | flagDatumCompressed | flagDatumSigned | flagDatumCustom)
	binary.LittleEndian.PutUint64(header[10:18], flag)

	// Set unix time in nanoseconds
	binary.LittleEndian.PutUint64(header[18:26], uint64(ts))

	// Op counter
	binary.LittleEndian.PutUint32(header[26:30], 1<<32/2)

	// Checksum
	copy(header[30:38], []byte{'c', 'h', 'e', 'c', 'k', 's', 'u', 'm'})

	// Size
	binary.LittleEndian.PutUint64(header[38:46], 1<<64/2)

	// Compression Algorithm
	binary.LittleEndian.PutUint16(header[46:48], 1<<16/2)

	// Encryption Algorithm
	binary.LittleEndian.PutUint16(header[48:50], 1<<16/4)

	// File extension
	copy(header[50:58], []byte{'a', 'f', 'f', 'i', 'x', 'i', 'n', 'g'})

	// Signature Type
	binary.LittleEndian.PutUint16(header[58:60], 1<<16/2)

	// Signature Size
	binary.LittleEndian.PutUint16(header[60:64], 1<<16/4)

	// Custom data
	copy(header[64:72], []byte{'t', 'a', 'i', 'l', 'o', 'r', 'e', 'd'})

	copy(header[72:80], delimiter[:])

	return os.WriteFile("valid-header.cdt", header[:], 0640)
}
