// Copyright 2024 The Prometheus Authors
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

//go:build !novmstat

package collector

// #include <mach/mach_host.h>
import "C"

import (
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
)

type vmstatDarwinCollector struct {
	pageinsDesc  *prometheus.Desc
	pageoutsDesc *prometheus.Desc
	logger       *slog.Logger
}

func init() {
	registerCollector("vmstat", defaultEnabled, NewVmstatDarwinCollector)
}

// NewVmstatDarwinCollector returns a collector exposing Darwin VM paging counters.
// These counters are a proxy for memory-pressure-driven disk I/O — a rising
// rate(node_vmstat_pageouts_total) indicates the host is paging out to disk.
func NewVmstatDarwinCollector(logger *slog.Logger) (Collector, error) {
	return &vmstatDarwinCollector{
		pageinsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "vmstat", "pageins_total"),
			"Total number of pages paged in from disk (demand faults + swap ins).",
			nil, nil,
		),
		pageoutsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "vmstat", "pageouts_total"),
			"Total number of pages paged out to disk.",
			nil, nil,
		),
		logger: logger,
	}, nil
}

func (c *vmstatDarwinCollector) Update(ch chan<- prometheus.Metric) error {
	host := C.mach_host_self()
	infoCount := C.mach_msg_type_number_t(C.HOST_VM_INFO64_COUNT)
	vmstat := C.vm_statistics64_data_t{}
	ret := C.host_statistics64(
		C.host_t(host),
		C.HOST_VM_INFO64,
		C.host_info_t(unsafe.Pointer(&vmstat)),
		&infoCount,
	)
	if ret != C.KERN_SUCCESS {
		return fmt.Errorf("couldn't get VM statistics, host_statistics64 returned %d", ret)
	}

	ch <- prometheus.MustNewConstMetric(c.pageinsDesc, prometheus.CounterValue, float64(vmstat.pageins))
	ch <- prometheus.MustNewConstMetric(c.pageoutsDesc, prometheus.CounterValue, float64(vmstat.pageouts))
	return nil
}
