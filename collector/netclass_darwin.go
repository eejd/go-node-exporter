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

//go:build !nonetclass

package collector

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/prometheus/client_golang/prometheus"
)

const networkSubsystem = "network"

type netClassDarwinCollector struct {
	mtuDesc    *prometheus.Desc
	speedDesc  *prometheus.Desc
	upDesc     *prometheus.Desc
	carrierDesc *prometheus.Desc
	infoDesc   *prometheus.Desc
	logger     *slog.Logger
}

func init() {
	registerCollector("netclass", defaultEnabled, NewNetClassDarwinCollector)
}

// NewNetClassDarwinCollector returns a Collector emitting per-interface metadata
// metrics that mirror the Linux netclass collector: node_network_{mtu_bytes,
// speed_bytes, up, carrier, info}.  Data is sourced from net.Interfaces() and
// the same NET_RT_IFLIST2 sysctl used by the netdev collector (getIfaceData).
// See eejd/node-exporter#7.
func NewNetClassDarwinCollector(logger *slog.Logger) (Collector, error) {
	return &netClassDarwinCollector{
		mtuDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, networkSubsystem, "mtu_bytes"),
			"Network device property: mtu_bytes",
			[]string{"device"}, nil,
		),
		speedDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, networkSubsystem, "speed_bytes"),
			"Network device property: speed_bytes",
			[]string{"device"}, nil,
		),
		upDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, networkSubsystem, "up"),
			"Value is 1 if operstate is 'up', 0 otherwise.",
			[]string{"device"}, nil,
		),
		carrierDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, networkSubsystem, "carrier"),
			"Value is 1 if the link is in running state (carrier detected), 0 otherwise.",
			[]string{"device"}, nil,
		),
		infoDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, networkSubsystem, "info"),
			"Non-numeric data from /proc/net/dev_snmp6, value is always 1.",
			[]string{"device", "address", "broadcast", "duplex", "operstate", "adminstate"}, nil,
		),
		logger: logger,
	}, nil
}

func (c *netClassDarwinCollector) Update(ch chan<- prometheus.Metric) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("net.Interfaces() failed: %w", err)
	}

	for _, iface := range ifaces {
		name := iface.Name

		ifaceData, err := getIfaceData(iface.Index)
		if err != nil {
			c.logger.Debug("failed to load interface data", "device", name, "err", err)
			continue
		}

		// MTU: prefer the sysctl value; fall back to net.Interface.MTU.
		mtu := float64(ifaceData.Data.Mtu)
		if mtu == 0 {
			mtu = float64(iface.MTU)
		}
		ch <- prometheus.MustNewConstMetric(c.mtuDesc, prometheus.GaugeValue, mtu, name)

		// Speed: Baudrate is in bits/s; emit bytes/s to match Linux.
		// Skip zero-speed entries (loopback, synthetic interfaces with no link).
		if ifaceData.Data.Baudrate > 0 {
			ch <- prometheus.MustNewConstMetric(c.speedDesc, prometheus.GaugeValue,
				float64(ifaceData.Data.Baudrate)/8.0, name)
		}

		// Up: administratively enabled (IFF_UP).
		up := 0.0
		if iface.Flags&net.FlagUp != 0 {
			up = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.upDesc, prometheus.GaugeValue, up, name)

		// Carrier: link is running (IFF_RUNNING).  This is the best signal
		// available without SIOCGIFMEDIA — synthetic ifaces may set IFF_RUNNING
		// unconditionally, but that mirrors Linux behaviour for virtual devices.
		carrier := 0.0
		if iface.Flags&net.FlagRunning != 0 {
			carrier = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.carrierDesc, prometheus.GaugeValue, carrier, name)

		// Info: constant-1 gauge carrying string metadata.
		mac := iface.HardwareAddr.String()
		operstate := "down"
		if carrier == 1.0 {
			operstate = "up"
		}
		adminstate := "down"
		if up == 1.0 {
			adminstate = "up"
		}
		ch <- prometheus.MustNewConstMetric(c.infoDesc, prometheus.GaugeValue, 1.0,
			name, mac, "", "unknown", operstate, adminstate)
	}
	return nil
}
