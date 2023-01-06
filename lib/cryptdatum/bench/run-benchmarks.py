#!/usr/bin/env python3

# import os
# import logging as log


# import sys
# import subprocess


# log.debug(cwd)
# log.debug(benchdir)
# log.debug(libdir)

from benchmark import *
from logging import DEBUG

bench = new_bench(DEBUG)

bench.add("go", {
  "bin": "cryptdatum-bench-go",
  "build": [
    ["go", "build", "-x", "-o", "bin/cryptdatum-bench-go", "cmd/cryptdatum-bench.go"]
  ],
})
bench.add("c", {
  "bin": "cryptdatum-bench-c",
  "build": [
    ["gcc", "-o", "bin/cryptdatum-bench-c", "cmd/cryptdatum-bench.c", "../cryptdatum.c"]
  ],
})
bench.add("rust", {
  "bin": "cryptdatum-bench-rust",
  "build": [
    ["rustc", "--crate-type=lib", "-o", "bin/libcryptdatum.rlib",  "../cryptdatum.rs"],
    ["rustc", "cmd/cryptdatum-bench.rs", "--extern", "cryptdatum=bin/libcryptdatum.rlib", "--edition", "2021", "--crate-type", "bin", "-o", "bin/cryptdatum-bench-rust"],
  ],
})

bench.build()

# Benchmark verify header with valid dra
bench.run("Verify valid draft header", ["verify", bench.path("testdata/v1/valid-header.cdt")], "verify-valid-draft")

bench.print()


