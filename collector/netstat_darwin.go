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

//go:build darwin

package collector

// #include <netinet/tcp_var.h>
// #include <netinet/udp_var.h>
import "C"

import (
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

// Minimum sysctl payload sizes we require before trusting the pointer cast.
// The actual running-kernel struct is smaller than the SDK header (which grows
// across OS releases with MPTCP/ECN extensions). We only read early fields
// whose offsets are stable, so a conservative lower bound is sufficient.
const (
	tcpStatMinBytes = 512 // well above the ~260-byte offset of the last field used
	udpStatMinBytes = 64  // udpstat fields used are all in the first 52 bytes
)

// netstat_darwin.go emits a Darwin-native subset of node_netstat_* metrics using
// binary sysctl structs (net.inet.tcp.stats, net.inet.udp.stats).  Metric names
// match the Linux netstat collector so cross-platform dashboards work unchanged.
//
// Out of scope (no clean Darwin counter exists):
//   - Tcp_CurrEstab   — gauge; needs live pcblist enumeration
//   - Tcp_OutRsts     — tcps_sndctrl mixes SYN+FIN+RST; no RST-only field
//   - TcpExt_TCPSynRetrans / ListenOverflows — not separately counted
//   - node_sockstat_* — requires pcblist; separate task

type netStatCollector struct {
	logger *slog.Logger

	tcpActiveOpens    *prometheus.Desc
	tcpPassiveOpens   *prometheus.Desc
	tcpInSegs         *prometheus.Desc
	tcpOutSegs        *prometheus.Desc
	tcpRetransSegs    *prometheus.Desc
	tcpInErrs         *prometheus.Desc
	tcpExtListenDrops *prometheus.Desc
	tcpExtTCPTimeouts *prometheus.Desc

	udpInDatagrams  *prometheus.Desc
	udpOutDatagrams *prometheus.Desc
	udpInErrors     *prometheus.Desc
	udpNoPorts      *prometheus.Desc
}

func init() {
	registerCollector("netstat", defaultEnabled, NewNetStatCollector)
}

func netstatDesc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "netstat", name),
		help,
		nil, nil,
	)
}

// NewNetStatCollector returns a Collector exposing TCP and UDP statistics from
// Darwin's net.inet.{tcp,udp}.stats sysctl MIBs.  See eejd/node-exporter#5.
func NewNetStatCollector(logger *slog.Logger) (Collector, error) {
	return &netStatCollector{
		logger: logger,

		// TCP — names match Linux /proc/net/snmp "Tcp:" section.
		tcpActiveOpens:    netstatDesc("Tcp_ActiveOpens", "Number of active TCP open connections."),
		tcpPassiveOpens:   netstatDesc("Tcp_PassiveOpens", "Number of passive TCP open connections."),
		tcpInSegs:         netstatDesc("Tcp_InSegs", "Total number of TCP segments received."),
		tcpOutSegs:        netstatDesc("Tcp_OutSegs", "Total number of TCP segments sent."),
		tcpRetransSegs:    netstatDesc("Tcp_RetransSegs", "Total number of TCP segments retransmitted."),
		tcpInErrs:         netstatDesc("Tcp_InErrs", "Total number of bad TCP segments received (checksum, offset, truncated)."),
		tcpExtListenDrops: netstatDesc("TcpExt_ListenDrops", "Number of connections dropped from the TCP listen queue."),
		tcpExtTCPTimeouts: netstatDesc("TcpExt_TCPTimeouts", "Number of TCP retransmit timeouts."),

		// UDP — names match Linux /proc/net/snmp "Udp:" section.
		udpInDatagrams:  netstatDesc("Udp_InDatagrams", "Total number of UDP datagrams received."),
		udpOutDatagrams: netstatDesc("Udp_OutDatagrams", "Total number of UDP datagrams sent."),
		udpInErrors:     netstatDesc("Udp_InErrors", "Total number of UDP datagrams received with errors (truncated, bad checksum, short header)."),
		udpNoPorts:      netstatDesc("Udp_NoPorts", "Total number of UDP datagrams received with no application on destination port."),
	}, nil
}

func (c *netStatCollector) Update(ch chan<- prometheus.Metric) error {
	if err := c.updateTCP(ch); err != nil {
		return err
	}
	return c.updateUDP(ch)
}

func (c *netStatCollector) updateTCP(ch chan<- prometheus.Metric) error {
	raw, err := unix.SysctlRaw("net.inet.tcp.stats")
	if err != nil {
		return fmt.Errorf("sysctl net.inet.tcp.stats: %w", err)
	}
	if len(raw) < tcpStatMinBytes {
		return fmt.Errorf("sysctl net.inet.tcp.stats returned %d bytes, need at least %d", len(raw), tcpStatMinBytes)
	}

	s := (*C.struct_tcpstat)(unsafe.Pointer(&raw[0]))

	emit := func(desc *prometheus.Desc, v C.u_int32_t) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, float64(v))
	}

	emit(c.tcpActiveOpens, s.tcps_connattempt)
	emit(c.tcpPassiveOpens, s.tcps_accepts)
	emit(c.tcpInSegs, s.tcps_rcvpack)
	emit(c.tcpOutSegs, s.tcps_sndpack)
	emit(c.tcpRetransSegs, s.tcps_sndrexmitpack)
	// InErrs: sum of checksum errors, bad header offset, and truncated segments.
	inErrs := uint64(s.tcps_rcvbadsum) + uint64(s.tcps_rcvbadoff) + uint64(s.tcps_rcvshort)
	ch <- prometheus.MustNewConstMetric(c.tcpInErrs, prometheus.UntypedValue, float64(inErrs))
	emit(c.tcpExtListenDrops, s.tcps_listendrop)
	emit(c.tcpExtTCPTimeouts, s.tcps_rexmttimeo)

	return nil
}

func (c *netStatCollector) updateUDP(ch chan<- prometheus.Metric) error {
	raw, err := unix.SysctlRaw("net.inet.udp.stats")
	if err != nil {
		return fmt.Errorf("sysctl net.inet.udp.stats: %w", err)
	}
	if len(raw) < udpStatMinBytes {
		return fmt.Errorf("sysctl net.inet.udp.stats returned %d bytes, need at least %d", len(raw), udpStatMinBytes)
	}

	s := (*C.struct_udpstat)(unsafe.Pointer(&raw[0]))

	emit := func(desc *prometheus.Desc, v C.u_int32_t) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, float64(v))
	}

	emit(c.udpInDatagrams, s.udps_ipackets)
	emit(c.udpOutDatagrams, s.udps_opackets)
	// InErrors: header too short, bad checksum, data too large.
	inErrs := uint64(s.udps_hdrops) + uint64(s.udps_badsum) + uint64(s.udps_badlen)
	ch <- prometheus.MustNewConstMetric(c.udpInErrors, prometheus.UntypedValue, float64(inErrs))
	emit(c.udpNoPorts, s.udps_noport)

	return nil
}
