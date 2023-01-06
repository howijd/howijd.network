// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package main

import (
	"errors"
	"io"
	"log"
	"os"

	"howijd.network/lib/cryptdatum"
)

func main() {
	switch os.Args[1] {
	case "verify":
		cmdVerify(os.Args[2])
	default:
		log.Fatal("invalid command")
	}
}

func cmdVerify(file string) {
	if len(os.Args) < 2 {
		log.Fatal("error: no subcommand provided.")
	}
	ctd, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer ctd.Close()
	headb := make([]byte, cryptdatum.HeaderSize)

	if _, err := ctd.Read(headb); err != nil && !errors.Is(err, io.EOF) {
		log.Fatal(err)
	}
	if !cryptdatum.VerifyHeader(headb) {
		os.Exit(1)
	}
	os.Exit(0)
}
