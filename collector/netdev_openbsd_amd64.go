// Copyright 2020 The Prometheus Authors
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

// This file previously contained an OpenBSD/amd64-specific netdev collector
// that used golang.org/x/sys/unix sysctl/route-table parsing with fixed struct
// layouts (unix.RtMsghdr, unix.IfMsghdr). OpenBSD periodically revisions its
// syscall ABI, causing "function not implemented" (ENOSYS) errors at runtime
// when struct layouts in x/sys/unix drift from the running kernel's definitions.
// The cgo implementation in netdev_openbsd.go (getifaddrs(3), compiles against
// the running kernel's headers) is now used for all architectures including amd64.
// See https://github.com/prometheus/node_exporter/issues/3084.

//go:build ignore

package collector
