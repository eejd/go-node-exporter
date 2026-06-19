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

// This file previously contained an OpenBSD/amd64-specific meminfo collector
// that used golang.org/x/sys/unix.SysctlRaw("vm.uvmexp") with a fixed
// unix.Uvmexp struct layout. OpenBSD 7.5 changed the struct layout and the
// syscall ABI, causing ENOSYS / struct-size mismatch at runtime. The cgo
// implementation in meminfo_openbsd.go (which compiles against the running
// kernel's headers) is now used for all architectures including amd64.
// See https://github.com/prometheus/node_exporter/issues/3084.

//go:build ignore

package collector
