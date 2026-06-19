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

//go:build darwin && !nozfs

package collector

import "github.com/prometheus/client_golang/prometheus"

// updateDatasetStats is a no-op on Darwin. OpenZFS on macOS does not expose
// per-dataset metrics via the kstat.zfs.<pool>.dataset sysctl tree that FreeBSD
// uses. Dataset metrics are therefore not available on this platform.
func (c *zfsCollector) updateDatasetStats(_ chan<- prometheus.Metric) error {
	return nil
}
