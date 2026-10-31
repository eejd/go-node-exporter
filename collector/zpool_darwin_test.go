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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/common/promslog"
)

func TestParseZpoolList(t *testing.T) {
	pools, err := parseZpoolList("zlagoa\t43980465111040\t1528321162609\nfull\t100\t0\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 2 || pools[0] != (zpoolSample{"zlagoa", 43980465111040, 1528321162609}) || pools[1].free != 0 {
		t.Fatalf("unexpected pools: %+v", pools)
	}
	if pools, err := parseZpoolList(""); err != nil || len(pools) != 0 {
		t.Fatalf("empty list: %v %v", pools, err)
	}
	bad := map[string]string{
		"duplicate": "a\t10\t5\na\t10\t5\n",
		"units":     "a\t10T\t5\n",
		"dash":      "a\t10\t-\n",
		"sign":      "a\t+10\t5\n",
		"negative":  "a\t10\t-5\n",
		"overflow":  "a\t99999999999999999999999\t5\n",
		"columns":   "a\t10\n",
		"extra":     "a\t10\t5\tx\n",
		"emptyname": "\t10\t5\n",
		"zerosize":  "a\t0\t0\n",
		"freebig":   "a\t10\t11\n",
		"partial":   "a\t10\t5\nb\t10\t-\n",
	}
	for name, in := range bad {
		if pools, err := parseZpoolList(in); err == nil || pools != nil {
			t.Errorf("%s: expected error and no pools, got %v %v", name, pools, err)
		}
	}
}

func fixtureZpool(t *testing.T, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "zpool")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func newTestZpoolCollector(t *testing.T, cmd string, timeout time.Duration) *zpoolCollector {
	c, _ := NewZpoolCollector(promslog.NewNopLogger())
	zc := c.(*zpoolCollector)
	zc.command, zc.timeout = cmd, timeout
	return zc
}

func collectZpool(c *zpoolCollector) (int, error) {
	ch := make(chan prometheus.Metric, 16)
	err := c.Update(ch)
	close(ch)
	n := 0
	for range ch {
		n++
	}
	return n, err
}

func TestZpoolCollectorUpdate(t *testing.T) {
	ok := fixtureZpool(t, `[ "$*" = "list -H -p -o name,size,free" ] || exit 9
printf 'zlagoa\t43980465111040\t1528321162609\n'`)
	c := newTestZpoolCollector(t, ok, 5*time.Second)
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(collectorFunc(func(ch chan<- prometheus.Metric) { _ = c.Update(ch) }))
	want := `# HELP node_zfs_zpool_free_bytes Free space of the ZFS pool in bytes, as reported by zpool list.
# TYPE node_zfs_zpool_free_bytes gauge
node_zfs_zpool_free_bytes{zpool="zlagoa"} 1.528321162609e+12
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "node_zfs_zpool_free_bytes"); err != nil {
		t.Fatal(err)
	}

	empty := newTestZpoolCollector(t, fixtureZpool(t, "exit 0\n"), 5*time.Second)
	if n, err := collectZpool(empty); err != nil || n != 0 {
		t.Fatalf("empty success: n=%d err=%v", n, err)
	}

	failures := map[string]*zpoolCollector{
		"missing":   newTestZpoolCollector(t, filepath.Join(t.TempDir(), "nope"), 5*time.Second),
		"nonzero":   newTestZpoolCollector(t, fixtureZpool(t, "printf 'a\\t10\\t5\\n'; exit 1\n"), 5*time.Second),
		"malformed": newTestZpoolCollector(t, fixtureZpool(t, "printf 'a\\t10\\t5\\nb\\t10\\t-\\n'\n"), 5*time.Second),
		"timeout":   newTestZpoolCollector(t, fixtureZpool(t, "sleep 30\n"), 200*time.Millisecond),
	}
	for name, fc := range failures {
		start := time.Now()
		n, err := collectZpool(fc)
		if err == nil || n != 0 {
			t.Errorf("%s: expected error with no samples, got n=%d err=%v", name, n, err)
		}
		if name == "timeout" && time.Since(start) > 5*time.Second {
			t.Errorf("timeout not enforced: %s", time.Since(start))
		}
	}
}

type collectorFunc func(ch chan<- prometheus.Metric)

func (f collectorFunc) Describe(chan<- *prometheus.Desc)    {}
func (f collectorFunc) Collect(ch chan<- prometheus.Metric) { f(ch) }
