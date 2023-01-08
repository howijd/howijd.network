# Copyright 2022 The howijd.network Authors
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file.
import os
import subprocess
import matplotlib.pyplot as plt
import numpy as np
import json

from logging import Logger
from math import sqrt

class Benchmark:
  def __init__(
    self,
    log: Logger
  ) -> None:
    self.log = log
    log.debug("starting worker")

    self.cwd = os.getcwd()
    log.debug("cwd: %s", self.cwd)

    self.benchdir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
    log.debug("benchdir: %s", self.benchdir)

    self.libdir = os.path.abspath(os.path.join(self.benchdir, "../"))
    log.debug("libdir: %s", self.libdir)

    self.bindir = os.path.abspath(os.path.join(self.libdir, "build/bin"))
    log.debug("bindir: %s", self.bindir)

    self.config = {}
    self.stats = {}

  def add(self, lang: str, config = {}):
    self.config[lang] = config

  def path(self, path: str) -> str:
    """Converts provided path to absolute path

    Args:
      path relative path to cryptdatum library
    """
    return os.path.abspath(os.path.join(self.libdir, path))

  def run(self, name: str, args: any, svg: str) -> str:
    """Run benchmark on cli apps with given args.

    Args:
      name name of the benchmark
      args arguments passed to cli app
      svg filename for of the svg graph to be saved to ./docs
    """
    os.chdir(self.benchdir)
    self.stats[name] = {}

    failedbench = False
    haslang = False
    for lang, cnf in self.config.items():
      if args[0] not in cnf["cmds"]:
        self.log.info("skip(%s): %s", name, lang)
        continue

      haslang = True
      self.log.info("benchmarking(%s): %s", name, lang)
      bench = subprocess.Popen(
        [
          "perf", "stat", "--sync", "--repeat=100", "--json-output",
          "-e", "cpu-clock,task-clock,cache-misses,branch-misses,context-switches,cpu-cycles,instructions",
          os.path.join(self.bindir, cnf["bin"]),
        ] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
         encoding="utf-8",
      )
      # pid = bench.pid
      self.log.info("cmd: %s", ' '.join(bench.args))
      self.stats[name][lang] = {}

      while True:
        line = bench.stdout.readline()
        if not line:
          break
        clean = line.rstrip()
        try:
          event = json.loads(clean)
          self.stats[name][lang][event["event"]] = event
          self.log.debug("%s", clean)
        except Exception as e:
          self.log.debug(clean)
          # self.log.error(e)

      code = bench.wait()
      if code != 0:
        self.log.critical("bench failed: %s %s exit %d %s", name, lang, code, ' '.join(bench.args))
        failedbench = True

    if failedbench:
      self.log.error("some of the benchmarks failed")
      exit(1)

    if not haslang:
      return

    # Create Report SVG
    labels = []
    res_cpu_clock = []
    res_task_clock = []
    res_cache_misses = []
    res_branch_misses = []
    res_context_switches = []
    res_instructions = []
    res_cpu_cycles = []
    res_standard_deviation = []

    for x, y in self.stats[name].items():
      labels.append('{name} ({ms} {unit})'.format(name = x, ms = y["cpu-clock:u"]["counter-value"], unit = y["cpu-clock:u"]["unit"]))
      res_cpu_clock.append(float(y["cpu-clock:u"]["counter-value"]))
      res_task_clock.append(float(y["task-clock:u"]["counter-value"]))
      res_cache_misses.append(float(y["cache-misses:u"]["counter-value"]))
      res_branch_misses.append(float(y["branch-misses:u"]["counter-value"]))
      res_context_switches.append(float(y["context-switches:u"]["counter-value"]))
      res_instructions.append(float(y["instructions:u"]["counter-value"]))
      res_cpu_cycles.append(float(y["cpu-cycles:u"]["counter-value"]))
      res_standard_deviation.append(self.calculate_perf_standard_deviation(y))

    # scale standard_deviation
    scpu_clock = self.scale_graph_data(res_cpu_clock)
    stask_clock = self.scale_graph_data(res_task_clock)
    scache_misses = self.scale_graph_data(res_cache_misses)
    sbranch_misses = self.scale_graph_data(res_branch_misses)
    scontext_switches = self.scale_graph_data(res_context_switches)
    sinstructions = self.scale_graph_data(res_instructions)
    scpu_cycles = self.scale_graph_data(res_cpu_cycles)
    standard_deviation = self.scale_graph_data(res_standard_deviation)

    score = [(s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8) / 6 for (s1, s2, s3, s4, s5, s6, s7, s8) in zip(
      scpu_clock,
      stask_clock,
      scache_misses,
      sbranch_misses,
      scontext_switches,
      standard_deviation,
      sinstructions,
      scpu_cycles,
    )]
    zipped = sorted(zip(labels, score), key=lambda x: x[1], reverse=True)
    sorted_labels, sorted_score = zip(*zipped)

    plt.style.use('dark_background')
    plt.set_loglevel("info")
    x = np.arange(len(sorted_labels))  # the label locations
    width = 0.05  # the width of the bars
    fig, ax = plt.subplots()
    ax.barh(x - width/2, sorted_score, width, label='score')

    ax.set_title(name)
    ax.set_yticks(x, sorted_labels)
    # ax.legend()
    ax.invert_yaxis()

    fig.tight_layout()
    ax.set_xlabel('Performance score')
    plt.savefig(self.path("docs/"+svg +".svg"))

  def calculate_perf_standard_deviation(self, data):
    variance = 0
    for datum in data:
      variance += data[datum]["variance"]

    variance /= len(data.keys())
    # Calculate the standard deviation
    standard_deviation = sqrt(variance)
    return standard_deviation

  def scale_to_range(self, value, min_value, max_value):
    """Scale bench data for graph"""
    if value == min_value == max_value:
      return 1
    return 1.1 - (0.1 + (value - min_value) * (1 - 0.1) / (max_value - min_value))

  def scale_graph_data(self, data):
    scaled_data = []
    if min(data) == max(data) and min(data) == 0:
      # All values in data are 0
      scaled_data = [0.1 for x in data]
    else:
      scaled_data = [self.scale_to_range(x, min(data), max(data)) for x in data]
    return scaled_data

  def print(self):
    pretty = json.dumps(self.stats, indent=4)
    print(pretty)

  def __del__(self):
    os.chdir(self.cwd)
    self.log.info("worker exited")
