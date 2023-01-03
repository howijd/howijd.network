// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package cryptdatum

import "testing"

func TestVerifyHeaderMagic(t *testing.T) {
	header := make([]byte, HeaderSize, HeaderSize)
	copy(header[:], Magic[:])
	copy(header[56:64], Delimiter[:])

	// Valid magic
	if !VerifyHeader(header) {
		t.Errorf("expected header to be valid")
	}

	// Invalid magic
	copy(header[0:8], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if VerifyHeader(header) {
		t.Errorf("expected header to be invalid")
	}
}

func TestVerifyHeaderTooSmallData(t *testing.T) {
	var header []byte
	for range [65]byte{} {
		if VerifyHeader(header) {
			t.Errorf("expected header to be invalid")
		} else {
			header = append(header, 0xFF)
		}
	}
}

func TestVerifyHeaderDelimiter(t *testing.T) {
	header := make([]byte, HeaderSize, HeaderSize)
	copy(header[:], Magic[:])
	copy(header[56:64], Delimiter[:])

	// Valid delimiter
	if !VerifyHeader(header) {
		t.Errorf("expected header to be valid")
	}

	// Invalid delimiter
	copy(header[56:64], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if VerifyHeader(header) {
		t.Errorf("expected header to be invalid")
	}
}
