// Copyright 2026 The Prometheus Authors
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

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
)

const zpoolCommandTimeout = 5 * time.Second

var zpoolCommand = kingpin.Flag("collector.zpool.command", "Path of the zpool executable used by the zpool collector.").Default("/usr/local/zfs/bin/zpool").String()

type zpoolSample struct {
	name string
	size uint64
	free uint64
}

type zpoolCollector struct {
	command string
	timeout time.Duration
	size    *prometheus.Desc
	free    *prometheus.Desc
	logger  *slog.Logger
}

func init() {
	registerCollector("zpool", defaultDisabled, NewZpoolCollector)
}

// NewZpoolCollector returns a collector exposing native ZFS pool capacity as
// reported by `zpool list`. It is separate from the ARC/dataset collector so a
// pool command failure cannot suppress those metrics.
func NewZpoolCollector(logger *slog.Logger) (Collector, error) {
	return &zpoolCollector{
		command: *zpoolCommand,
		timeout: zpoolCommandTimeout,
		size: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "zfs_zpool", "size_bytes"),
			"Total size of the ZFS pool in bytes, as reported by zpool list.",
			[]string{"zpool"}, nil,
		),
		free: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "zfs_zpool", "free_bytes"),
			"Free space of the ZFS pool in bytes, as reported by zpool list.",
			[]string{"zpool"}, nil,
		),
		logger: logger,
	}, nil
}

func (c *zpoolCollector) Update(ch chan<- prometheus.Metric) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.command, "list", "-H", "-p", "-o", "name,size,free")
	cmd.WaitDelay = time.Second
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("zpool list timed out after %s: %w", c.timeout, ctx.Err())
		}
		return fmt.Errorf("zpool list failed: %w", err)
	}

	pools, err := parseZpoolList(stdout.String())
	if err != nil {
		return err
	}
	for _, p := range pools {
		ch <- prometheus.MustNewConstMetric(c.size, prometheus.GaugeValue, float64(p.size), p.name)
		ch <- prometheus.MustNewConstMetric(c.free, prometheus.GaugeValue, float64(p.free), p.name)
	}
	return nil
}

// parseZpoolList parses the complete `zpool list -H -p -o name,size,free`
// output. Any malformed row fails the whole parse so no partial facts leak.
func parseZpoolList(out string) ([]zpoolSample, error) {
	var pools []zpoolSample
	seen := map[string]struct{}{}
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, fmt.Errorf("zpool list line %d: expected 3 tab-separated fields, got %d", i+1, len(fields))
		}
		name := fields[0]
		if name == "" {
			return nil, fmt.Errorf("zpool list line %d: empty pool name", i+1)
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("zpool list line %d: duplicate pool name %q", i+1, name)
		}
		size, err := parseZpoolUint(fields[1])
		if err != nil {
			return nil, fmt.Errorf("zpool list line %d: size: %w", i+1, err)
		}
		free, err := parseZpoolUint(fields[2])
		if err != nil {
			return nil, fmt.Errorf("zpool list line %d: free: %w", i+1, err)
		}
		if size == 0 {
			return nil, fmt.Errorf("zpool list line %d: pool size is zero", i+1)
		}
		if free > size {
			return nil, fmt.Errorf("zpool list line %d: free exceeds size", i+1)
		}
		seen[name] = struct{}{}
		pools = append(pools, zpoolSample{name: name, size: size, free: free})
	}
	return pools, nil
}

func parseZpoolUint(s string) (uint64, error) {
	if s == "" {
		return 0, errors.New("empty value")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not an unsigned decimal integer: %q", s)
		}
	}
	return strconv.ParseUint(s, 10, 64)
}
