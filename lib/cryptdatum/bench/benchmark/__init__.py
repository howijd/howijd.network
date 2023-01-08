# Copyright 2022 The howijd.network Authors
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file.
"""Worker to collect and generate Cryptdatum benchmarks"""

import logging

from .benchmark import Benchmark
from .logger import LogFormatter

__all__ = ["new_bench", "get_logger"]

lh = logging.StreamHandler()
lh.setFormatter(LogFormatter())
logging.basicConfig(
    level=logging.NOTSET,
    handlers=[lh]
)

logger = logging.getLogger("bench")

def new_bench(level=logging.NOTSET) -> Benchmark:
  return Benchmark(get_logger(level))

def get_logger(level=logging.NOTSET) -> logging.Logger:
  logger.setLevel(level)
  return logger
