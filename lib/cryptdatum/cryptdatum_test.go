// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestHasValidHeaderMagic(t *testing.T) {
	header := make([]byte, HeaderSize, HeaderSize)
	copy(header[:], Magic[:])
	binary.LittleEndian.PutUint16(header[8:10], Version)     // version
	binary.LittleEndian.PutUint64(header[10:18], DatumDraft) // draft flag
	copy(header[72:80], Delimiter[:])

	// Valid magic
	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid")
	}

	// Invalid magic
	copy(header[0:8], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid")
	}
}

func TestHasValidHeaderTooSmallData(t *testing.T) {
	var header []byte
	for range [65]byte{} {
		if HasValidHeader(header) {
			t.Errorf("expected header to be invalid")
		} else {
			header = append(header, 0xFF)
		}
	}
}

func TestHasValidHeaderDelimiter(t *testing.T) {
	header := make([]byte, HeaderSize, HeaderSize)
	copy(header[:], Magic[:])
	binary.LittleEndian.PutUint16(header[8:10], Version)     // version
	binary.LittleEndian.PutUint64(header[10:18], DatumDraft) // draft flag
	copy(header[72:80], Delimiter[:])

	// Valid delimiter
	if !HasValidHeader(header) {
		t.Errorf("expected header to be valid")
	}

	// Invalid delimiter
	copy(header[72:80], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if HasValidHeader(header) {
		t.Errorf("expected header to be invalid")
	}
}

func TestHasValidHeaderSpecV1(t *testing.T) {
	head, err := os.ReadFile("testdata/v1/has-aligned-header.cdt")
	if err != nil {
		t.Error(err)
	}
	if !HasValidHeader(head) {
		t.Errorf("expected header to be invalid")
	}
}
