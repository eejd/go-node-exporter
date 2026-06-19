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

//go:build freebsd && !nozfs

package collector

// updateDatasetStats emits per-dataset ZFS metrics on FreeBSD by walking the
// kstat.zfs.<pool>.dataset.objset-* sysctl subtree. The emitted metrics use the
// same fully-qualified names as the Linux path (node_zfs_zpool_dataset_*) with
// the same {zpool, dataset} labels, so dashboards and alerts stay portable.
//
// Implements: https://github.com/prometheus/node_exporter/issues/2693

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// updateDatasetStats is the FreeBSD-specific per-dataset ZFS metric collection.
// It is called from the shared zfs_bsd.go Update() method after the scalar sysctls
// have been emitted.
func (c *zfsCollector) updateDatasetStats(ch chan<- prometheus.Metric) error {
	// Walk the entire kstat.zfs sysctl subtree and filter for dataset entries.
	// The subtree is typically small (a few hundred leaves per pool) so a full
	// walk is not expensive.
	names, err := sysctlWalkPrefix("kstat.zfs")
	if err != nil || names == nil {
		// ZFS not loaded or no pools present — not an error.
		c.logger.Debug("kstat.zfs sysctl subtree not available", "err", err)
		return nil
	}

	type objsetEntry struct {
		pool    string
		dataset string // resolved from the dataset_name leaf
		fields  map[string]uint64
	}

	// Key: "kstat.zfs.<pool>.dataset.<objset-handle>"
	objsets := map[string]*objsetEntry{}

	for _, name := range names {
		// We are interested in entries of the form:
		//   kstat.zfs.<pool>.dataset.objset-<hex>.<field>
		// where field is one of: nread, nwritten, reads, writes,
		//   nunlinked, nunlinks, dataset_name (string).
		parts := strings.Split(name, ".")
		if len(parts) != 6 {
			continue
		}
		// parts: [kstat, zfs, <pool>, dataset, objset-<hex>, <field>]
		if parts[0] != "kstat" || parts[1] != "zfs" ||
			parts[3] != "dataset" || !strings.HasPrefix(parts[4], "objset-") {
			continue
		}
		pool := parts[2]
		objsetHandle := parts[4]
		field := parts[5]
		key := "kstat.zfs." + pool + ".dataset." + objsetHandle

		entry, ok := objsets[key]
		if !ok {
			entry = &objsetEntry{pool: pool, fields: make(map[string]uint64)}
			objsets[key] = entry
		}

		if field == "dataset_name" {
			// String sysctl — read via unix.Sysctl which allocates the right buffer.
			if dsName, err := unix.Sysctl(name); err == nil {
				entry.dataset = dsName
			}
			continue
		}

		// Numeric leaf — read as uint64.
		if val, err := unix.SysctlUint64(name); err == nil {
			entry.fields[field] = val
		} else {
			c.logger.Debug("cannot read ZFS dataset sysctl", "mib", name, "err", err)
		}
	}

	// Emit a metric for each (pool, dataset, field) triple where the dataset
	// name is known. Use the same metric naming as the Linux objset path so
	// dashboards built for Linux work unchanged on FreeBSD.
	for _, entry := range objsets {
		if entry.dataset == "" {
			continue // skip objset handles where dataset_name was not readable
		}
		for field, val := range entry.fields {
			// The Linux path produces:
			//   prometheus.BuildFQName(namespace, "zfs_zpool_dataset", field)
			// where field is e.g. "nread", "nwritten", "reads", "writes".
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, "zfs_zpool_dataset", field),
					"kstat.zfs.misc.objset."+field,
					[]string{"zpool", "dataset"},
					nil,
				),
				prometheus.UntypedValue,
				float64(val),
				entry.pool,
				entry.dataset,
			)
		}
	}
	return nil
}
