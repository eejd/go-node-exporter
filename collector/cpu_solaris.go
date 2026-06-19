// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !nocpu

package collector

import (
	"log/slog"
	"strconv"

	"github.com/illumos/go-kstat"
	"github.com/prometheus/client_golang/prometheus"
)

// #include <unistd.h>
import "C"

type cpuCollector struct {
	cpu    typedDesc
	logger *slog.Logger
}

func init() {
	registerCollector("cpu", defaultEnabled, NewCpuCollector)
}

func NewCpuCollector(logger *slog.Logger) (Collector, error) {
	return &cpuCollector{
		cpu:    typedDesc{nodeCPUSecondsDesc, prometheus.CounterValue},
		logger: logger,
	}, nil
}

func (c *cpuCollector) Update(ch chan<- prometheus.Metric) error {
	ncpus := C.sysconf(C._SC_NPROCESSORS_ONLN)

	tok, err := kstat.Open()
	if err != nil {
		return err
	}

	defer tok.Close()

	for cpu := 0; cpu < int(ncpus); cpu++ {
		ksCPU, err := tok.Lookup("cpu", cpu, "sys")
		if err != nil {
			return err
		}

		for k, v := range map[string]string{
			"idle":   "cpu_nsec_idle",
			"kernel": "cpu_nsec_kernel",
			"user":   "cpu_nsec_user",
		} {
			kstatValue, err := ksCPU.GetNamed(v)
			if err != nil {
				return err
			}

			ch <- c.cpu.mustNewConstMetric(float64(kstatValue.UintVal)/1e9, strconv.Itoa(cpu), k)
		}

		// "wait" time is reported as cpu_nsec_wait on Oracle Solaris but as
		// cpu_ticks_wait (in clock ticks) on illumos, which lacks cpu_nsec_wait.
		// Try nsec first; fall back to ticks converted via CLK_TCK; skip if neither.
		if kstatValue, err := ksCPU.GetNamed("cpu_nsec_wait"); err == nil {
			ch <- c.cpu.mustNewConstMetric(float64(kstatValue.UintVal)/1e9, strconv.Itoa(cpu), "wait")
		} else if kstatValue, err := ksCPU.GetNamed("cpu_ticks_wait"); err == nil {
			clkTck := float64(C.sysconf(C._SC_CLK_TCK))
			ch <- c.cpu.mustNewConstMetric(float64(kstatValue.UintVal)/clkTck, strconv.Itoa(cpu), "wait")
		} else {
			c.logger.Debug("cpu wait kstat unavailable", "cpu", cpu)
		}
	}
	return nil
}
