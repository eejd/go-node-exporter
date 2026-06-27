// Copyright 2015 The Prometheus Authors
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

//go:build !nonetdev

package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// darwinNetCounterSanityMax is the upper bound used to detect uninitialized
// kernel counter fields on synthetic interfaces. The if_fake / vmnet drivers
// never write the error and drop fields of if_data64, leaving them as stale
// heap memory that can reach values like 3.7e15. A legitimately-busy interface
// cannot accumulate 1e12 drops or errors, so anything above this ceiling is
// treated as garbage. See eejd/node-exporter#8.
const darwinNetCounterSanityMax = 1_000_000_000_000 // 1e12

// isSyntheticDarwinIface reports whether the interface name indicates a macOS
// synthetic/virtual driver whose error and drop counters are known to contain
// uninitialized memory (the driver never calls ifnet_stat_increment for those
// fields). Byte and packet counters from these interfaces are valid.
//
// Name prefixes and their drivers:
//   - feth   — if_fake (kernel test/virtual ethernet)
//   - vmenet — vmnet (Virtualization.framework guest NIC host-side)
//   - bridge — if_bridge
//   - utun   — if_utun (VPN/tunnel)
//   - awdl   — Apple Wireless Direct Link
//   - llw    — Low-latency WLAN
//   - anpi   — Apple Network Protocol Interface
//   - gif    — generic tunnel (RFC 2893)
//   - stf    — 6to4 tunnel
//   - ap     — Wi-Fi Access Point mode
func isSyntheticDarwinIface(name string) bool {
	for _, prefix := range []string{
		"feth", "vmenet", "bridge", "utun", "awdl", "llw", "anpi", "gif", "stf", "ap",
	} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func getNetDevStats(filter *deviceFilter, logger *slog.Logger) (netDevStats, error) {
	netDev := netDevStats{}

	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("net.Interfaces() failed: %w", err)
	}

	for _, iface := range ifs {
		if filter.ignored(iface.Name) {
			logger.Debug("Ignoring device", "device", iface.Name)
			continue
		}

		ifaceData, err := getIfaceData(iface.Index)
		if err != nil {
			logger.Debug("failed to load data for interface", "device", iface.Name, "err", err)
			continue
		}

		// Byte and packet counters are reliable on all interfaces, including
		// synthetic ones (vmenet, feth, bridge, etc.) whose traffic is real.
		stats := map[string]uint64{
			"receive_packets":    ifaceData.Data.Ipackets,
			"transmit_packets":   ifaceData.Data.Opackets,
			"receive_bytes":      ifaceData.Data.Ibytes,
			"transmit_bytes":     ifaceData.Data.Obytes,
			"receive_multicast":  ifaceData.Data.Imcasts,
			"transmit_multicast": ifaceData.Data.Omcasts,
			"collisions":         ifaceData.Data.Collisions,
			"noproto":            ifaceData.Data.Noproto,
		}
		// Error and drop counters are NOT maintained by synthetic interface
		// drivers; those if_data64 fields remain as uninitialized heap memory.
		// Only emit them for interfaces that are not known-synthetic AND whose
		// values are below the sanity ceiling (backstop for any un-enumerated
		// synthetic prefix). See eejd/node-exporter#8.
		synthetic := isSyntheticDarwinIface(iface.Name)
		if !synthetic && ifaceData.Data.Ierrors <= darwinNetCounterSanityMax {
			stats["receive_errors"] = ifaceData.Data.Ierrors
		}
		if !synthetic && ifaceData.Data.Oerrors <= darwinNetCounterSanityMax {
			stats["transmit_errors"] = ifaceData.Data.Oerrors
		}
		if !synthetic && ifaceData.Data.Iqdrops <= darwinNetCounterSanityMax {
			stats["receive_dropped"] = ifaceData.Data.Iqdrops
		}
		netDev[iface.Name] = stats
	}

	return netDev, nil
}

func getIfaceData(index int) (*ifMsghdr2, error) {
	var data ifMsghdr2
	rawData, err := unix.SysctlRaw("net", unix.AF_ROUTE, 0, 0, unix.NET_RT_IFLIST2, index)
	if err != nil {
		return nil, err
	}
	err = binary.Read(bytes.NewReader(rawData), binary.LittleEndian, &data)
	if err != nil {
		return &data, err
	}

	/*
		As of macOS Ventura 13.2.1, there’s a kernel bug which truncates traffic values at the 4GiB mark.
		This is a workaround to fetch the interface traffic metrics using a sysctl call.
		Apple wants to prevent fingerprinting by 3rdparty apps and might fix this bug in future which would break this implementation.
	*/
	mib := []int32{
		unix.CTL_NET,
		unix.AF_LINK,
		0, // NETLINK_GENERIC: functions not specific to a type of iface
		2, //IFMIB_IFDATA: per-interface data table
		int32(index),
		1, // IFDATA_GENERAL: generic stats for all kinds of ifaces
	}

	var mibData ifMibData
	size := unsafe.Sizeof(mibData)

	if _, _, errno := unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&mibData)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(nil)),
		0,
	); errno != 0 {
		return &data, err
	}

	var ifdata ifData64
	err = binary.Read(bytes.NewReader(mibData.Data[:]), binary.LittleEndian, &ifdata)
	if err != nil {
		return &data, err
	}

	data.Data.Ibytes = ifdata.Ibytes
	data.Data.Obytes = ifdata.Obytes
	return &data, err
}

// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if.h#L220-L232
type ifMsghdr2 struct {
	Msglen    uint16   // to skip over non-understood messages
	Version   uint8    // future binary compatabilit
	Type      uint8    // message type
	Addrs     int32    // like rtm_addrs
	Flags     int32    // value of if_flags
	Index     uint16   // index for associated ifp
	_         [2]byte  // padding for alignment
	SndLen    int32    // instantaneous length of send queue
	SndMaxlen int32    // maximum length of send queue
	SndDrops  int32    // number of drops in send queue
	Timer     int32    // time until if_watchdog called
	Data      ifData64 // statistics and other data
}

// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_var.h#L207-L235
type ifData64 struct {
	Type      uint8  // ethernet, tokenring, etc
	Typelen   uint8  // Length of frame type id
	Physical  uint8  // e.g., AUI, Thinnet, 10base-T, etc
	Addrlen   uint8  // media address length
	Hdrlen    uint8  // media header length
	Recvquota uint8  // polling quota for receive intrs
	Xmitquota uint8  // polling quota for xmit intrs
	Unused1   uint8  // for future use
	Mtu       uint32 // maximum transmission unit
	Metric    uint32 // routing metric (external only)
	Baudrate  uint64 // linespeed

	// volatile statistics
	Ipackets   uint64         // packets received on interface
	Ierrors    uint64         // input errors on interface
	Opackets   uint64         // packets sent on interface
	Oerrors    uint64         // output errors on interface
	Collisions uint64         // collisions on csma interfaces
	Ibytes     uint64         // total number of octets received
	Obytes     uint64         // total number of octets sent
	Imcasts    uint64         // packets received via multicast
	Omcasts    uint64         // packets sent via multicast
	Iqdrops    uint64         // dropped on input, this interface
	Noproto    uint64         // destined for unsupported protocol
	Recvtiming uint32         // usec spent receiving when timing
	Xmittiming uint32         // usec spent xmitting when timing
	Lastchange unix.Timeval32 // time of last administrative change
}

// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_mib.h#L65-L74
type ifMibData struct {
	Name          [16]byte  // name of interface
	PCount        uint32    // number of promiscuous listeners
	Flags         uint32    // interface flags
	SendLength    uint32    // instantaneous length of send queue
	MaxSendLength uint32    // maximum length of send queue
	SendDrops     uint32    // number of drops in send queue
	_             [4]uint32 // for future expansion
	Data          [128]byte // generic information and statistics
}

func getNetDevLabels() (map[string]map[string]string, error) {
	// to be implemented if needed
	return nil, nil
}
