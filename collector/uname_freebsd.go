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

//go:build !nouname

package collector

import (
	"strings"

	"golang.org/x/sys/unix"
)

// getUname reads uname fields on FreeBSD via individual sysctl calls rather
// than unix.Uname. On FreeBSD 14+, kern.version contains a long multi-line
// string that overflows the fixed-size field in unix.Utsname, causing
// unix.Uname to return ENOMEM. Reading each sysctl separately avoids the
// fixed-buffer constraint. See https://github.com/prometheus/node_exporter/issues/2809.
func getUname() (uname, error) {
	sysname, err := unix.Sysctl("kern.ostype")
	if err != nil {
		return uname{}, err
	}
	release, err := unix.Sysctl("kern.osrelease")
	if err != nil {
		return uname{}, err
	}
	version, err := unix.Sysctl("kern.version")
	if err != nil {
		return uname{}, err
	}
	machine, err := unix.Sysctl("hw.machine")
	if err != nil {
		return uname{}, err
	}
	nodename, err := unix.Sysctl("kern.hostname")
	if err != nil {
		return uname{}, err
	}

	hostname, domainname := parseFreeBSDHostNameAndDomainName(nodename)

	// kern.version is multi-line on FreeBSD; collapse to the first line so the
	// metric label stays consistent with the single-line format on other OSes.
	version = strings.SplitN(version, "\n", 2)[0]

	return uname{
		SysName:    sysname,
		Release:    release,
		Version:    version,
		Machine:    machine,
		NodeName:   hostname,
		DomainName: domainname,
	}, nil
}

// parseFreeBSDHostNameAndDomainName splits a nodename into hostname and
// domainname components, matching the behaviour of parseHostNameAndDomainName
// in uname_bsd.go.
func parseFreeBSDHostNameAndDomainName(nodename string) (hostname, domainname string) {
	split := strings.SplitN(nodename, ".", 2)
	hostname = split[0]
	domainname = "(none)"
	if len(split) > 1 {
		domainname = split[1]
	}
	return hostname, domainname
}
