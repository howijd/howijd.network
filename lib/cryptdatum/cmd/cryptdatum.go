// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"howijd.network/lib/cryptdatum"
)

var verboseFlag = flag.Bool("v", false, "verbose output")

func main() {
	flag.Parse()

	args := flag.Args()

	if len(args) < 2 {
		log.Fatal("error: no subcommand provided.")
	}

	switch args[0] {
	case "file-has-header":
		cmdFileHasHeader(args[1])
	case "file-has-valid-header":
		cmdFileHasValidHeader(args[1])
	case "file-info":
		cmdFileInfo(args[1])
	default:
		log.Fatalf("invalid command %s", args[0])
	}
}

func exit(printalways bool, err error) {
	if printalways || *verboseFlag {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}

func cmdFileHasHeader(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	defer ctd.Close()
	headb := make([]byte, cryptdatum.HeaderSize)

	if _, err := ctd.Read(headb); err != nil && !errors.Is(err, io.EOF) {
		exit(false, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	if !cryptdatum.HasHeader(headb) {
		exit(false, cryptdatum.ErrNoHeader)
	}
	os.Exit(0)
}

func cmdFileHasValidHeader(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	defer ctd.Close()
	headb := make([]byte, cryptdatum.HeaderSize)

	if _, err := ctd.Read(headb); err != nil && !errors.Is(err, io.EOF) {
		exit(false, err)
	}
	if !cryptdatum.HasHeader(headb) {
		exit(false, cryptdatum.ErrNoHeader)
	}
	if !cryptdatum.HasValidHeader(headb) {
		exit(false, cryptdatum.ErrInvalidHeader)
	}
	os.Exit(0)
}

func cmdFileInfo(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, err)
	}
	defer ctd.Close()

	header, err := cryptdatum.DecodeHeader(ctd)
	if err != nil {
		exit(true, fmt.Errorf("%w: failed to decode header", err))
	}
	printHeader(&header)
	os.Exit(0)
}

func prettySize(size uint64) string {
	var units = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	i := 0
	for size >= 1024 && i < 8 {
		size /= 1024
		i++
	}
	return fmt.Sprintf("%d %s", size, units[i])
}

func printHeader(header *cryptdatum.Header) {
	// swithc to text/template when the api is frozen
	datumsize := prettySize(header.Size)
	created := time.Unix(0, int64(header.Timestamp)).UTC().Format(time.RFC3339Nano)
	fmt.Printf("+--------------+------------+-----------------------------+-------------------+---------------------------------+\n")
	fmt.Printf("| CRYPTDATUM   | SIZE: %34s | CREATED:%43s | \n", datumsize, created)
	fmt.Printf("+--------------+------------+-----------------------------+-------------------+---------------------------------+\n")
	fmt.Printf("| Field        | Size (B)   | Description                 | Type              | Value                           |\n")
	fmt.Printf("+--------------+------------+-----------------------------+-------------------+---------------------------------+\n")
	fmt.Printf("| Version      | 2          | Version number              | uint16            | %-31d |\n", header.Version)
	fmt.Printf("| Flags        | 8          | Flags                       | uint64            | %-31d |\n", header.Flags)
	fmt.Printf("| Timestamp    | 8          | Timestamp                   | uint64            | %-31d |\n", header.Timestamp)
	fmt.Printf("| OPC          | 4          | Operation Counter           | uint32            | %-31d |\n", header.OPC)
	fmt.Printf("| Checksum     | 8          | Checksum                    | uint64            | %-31d |\n", header.Checksum)
	fmt.Printf("| Size         | 8          | Total size                  | uint64            | %-31d |\n", header.Size)
	fmt.Printf("| Comp. Alg.   | 2          | Compression algorithm       | uint16            | %-31d |\n", header.CompressionAlg)
	fmt.Printf("| Encrypt. Alg | 2          | Encryption algorithm        | uint16            | %-31d |\n", header.EncryptionAlg)
	fmt.Printf("| Sign. Type   | 2          | Signature type              | uint16            | %-31d |\n", header.SignatureType)
	fmt.Printf("| Sign. Size   | 4          | Signature size              | uint32            | %-31d |\n", header.SignatureSize)
	fmt.Printf("| File Ext.    | 8          | File extension              | char[8]           | %-31s |\n", header.FileExt)
	fmt.Printf("| Custom       | 8          | Custom                      | uint8[8]          | %03d %03d %03d %03d %03d %03d %03d %03d |\n",
		header.Custom[0], header.Custom[1], header.Custom[2], header.Custom[3],
		header.Custom[4], header.Custom[5], header.Custom[6], header.Custom[7])
	fmt.Printf("+--------------+------------+----------------------------+--------------------+---------------------------------+\n")
	fmt.Printf("| FLAGS                                                                                                         |\n")
	fmt.Printf("+------------+--------+-------------+--------+--------------+--------+------------------------------------------+\n")
	fmt.Printf("| Invalid    | %-6t | OPC         | %-6t | Signed       | %-6t |                                          |\n",
		(header.Flags&cryptdatum.DatumInvalid != 0), (header.Flags&cryptdatum.DatumOPC != 0), (header.Flags&cryptdatum.DatumSigned != 0))
	fmt.Printf("| Draft      | %-6t | Compressed  | %-6t | Streamable   | %-6t |                                          |\n",
		(header.Flags&cryptdatum.DatumDraft != 0), (header.Flags&cryptdatum.DatumCompressed != 0), (header.Flags&cryptdatum.DatumStreamable != 0))
	fmt.Printf("| Empty      | %-6t | Encrypted   | %-6t | Custom       | %-6t |                                          |\n",
		(header.Flags&cryptdatum.DatumEmpty != 0), (header.Flags&cryptdatum.DatumEncrypted != 0), (header.Flags&cryptdatum.DatumCustom != 0))
	fmt.Printf("| Checksum   | %-6t | Extractable | %-6t | Compromised  | %-6t |                                          |\n",
		(header.Flags&cryptdatum.DatumChecksum != 0), (header.Flags&cryptdatum.DatumExtractable != 0), (header.Flags&cryptdatum.DatumCompromised != 0))
	fmt.Printf("+------------+--------+-------------+--------+--------------+--------+------------------------------------------+\n")
}
