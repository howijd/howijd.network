
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
    self.bindir = os.path.abspath(os.path.join(self.benchdir, "bin"))
    log.debug("bindir: %s", self.bindir)
    self.resdir = os.path.abspath(os.path.join(self.benchdir, "result"))
    log.debug("resdir: %s", self.resdir)

    self.config = {}
    self.stats = {}

  def add(self, lang: str, config = {}):
    self.config[lang] = config

  def build(self):
    """Build bench cli apps for all languages language
    """
    os.chdir(self.benchdir)

    for lang, cnf in self.config.items():
      self.log.info("building: %s", lang)
      for cmd in cnf["build"]:
        build = subprocess.Popen(
          cmd,
          stdout=subprocess.PIPE,
          stderr=subprocess.STDOUT,
          encoding="utf-8",
        )
        self.log.debug("cmd: %s", ' '.join(build.args))
        while True:
          line = build.stdout.readline()
          if not line:
            break
          self.log.debug("%s", line.rstrip())
        code = build.wait()
        if code != 0:
          self.log.critical("building complete: %s", lang)
          exit(code)

        self.log.info("building complete: %s", lang)

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
    for lang, cnf in self.config.items():
      self.log.info("benchmarking(%s): %s", name, lang)
      bench = subprocess.Popen(
        [
          "perf", "stat", "--sync", "--repeat=100", "--json-output",
          "-e", "cpu-clock,task-clock,cache-misses,branch-misses,context-switches,cpu-migrations",
          os.path.join(self.bindir, cnf["bin"]),
        ] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
         encoding="utf-8",
      )
      pid = bench.pid
      self.log.info("cmd: %s", ' '.join(bench.args))
      self.stats[name][lang] = {}

      while True:
        line = bench.stdout.readline()
        if not line:
          break
        clean = line.rstrip()
        event = json.loads(clean)
        self.stats[name][lang][event["event"]] = event
        self.log.debug("%s", clean)

      code = bench.wait()
      if code != 0:
        self.log.critical("bench failed: %s %s exit %d %s", name, lang, code, ' '.join(bench.args))
        failedbench = True

    if failedbench:
      self.log.error("some of the benchmarks failed")
      exit(1)

    # Create Report SVG
    labels = []
    res_cpu_clock = []
    res_task_clock = []
    res_cache_misses = []
    res_branch_misses = []
    res_context_switches = []
    res_standard_deviation = []

    for x, y in self.stats[name].items():
      labels.append(x)
      res_cpu_clock.append(float(y["cpu-clock:u"]["counter-value"]))
      res_task_clock.append(float(y["task-clock:u"]["counter-value"]))
      res_cache_misses.append(float(y["cache-misses:u"]["counter-value"]))
      res_branch_misses.append(float(y["branch-misses:u"]["counter-value"]))
      res_context_switches.append(float(y["context-switches:u"]["counter-value"]))
      res_standard_deviation.append(self.calculate_perf_standard_deviation(y))

    # scale standard_deviation
    scaled_cpu_clock = self.scale_graph_data(res_cpu_clock)
    scaled_task_clock = self.scale_graph_data(res_task_clock)
    scaled_cache_misses = self.scale_graph_data(res_cache_misses)
    scaled_branch_misses = self.scale_graph_data(res_branch_misses)
    scaled_context_switches = self.scale_graph_data(res_context_switches)
    scaled_standard_deviation = self.scale_graph_data(res_standard_deviation)

    plt.style.use('dark_background')

    x = np.arange(len(labels))  # the label locations
    width = 0.05  # the width of the bars
    fig, ax = plt.subplots()
    ax.barh(x - width*2.5, scaled_cpu_clock, width, label='cpu clock')
    ax.barh(x - width*1.5, scaled_task_clock, width, label='task clock')
    ax.barh(x - width/2, scaled_cache_misses, width, label='cache misses')
    ax.barh(x + width/2, scaled_branch_misses, width, label='branch misses')
    ax.barh(x + width*1.5, scaled_context_switches, width, label='context switches')
    ax.barh(x + width*2.5, scaled_standard_deviation, width, label='stability over 100 exec')

    ax.set_title(name)
    ax.set_yticks(x, labels)
    ax.legend()
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
