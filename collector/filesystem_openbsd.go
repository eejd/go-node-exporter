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

// This implementation uses getmntinfo(3) via cgo rather than the pure-Go
// golang.org/x/sys/unix.Getfsstat wrapper. OpenBSD periodically changes the
// struct statfs layout (e.g. OpenBSD 7.0 added f_mount_tid), which causes
// the unix.Statfs_t struct in x/sys/unix to diverge from the running kernel,
// resulting in "function not implemented" (ENOSYS) errors. Compiling via cgo
// against the running kernel's own headers is always correct regardless of
// release. See https://github.com/prometheus/node_exporter/issues/3084.

//go:build !nofilesystem

package collector

/*
#include <sys/param.h>
#include <sys/mount.h>
#include <string.h>
#include <stdlib.h>

// getmntinfo_all calls getmntinfo(3) with MNT_NOWAIT and returns the entries.
// On success *mntbufp points to the statfs array and the function returns the
// count; on error it returns -1.
static int getmntinfo_nowait(struct statfs **mntbufp) {
    return getmntinfo(mntbufp, MNT_NOWAIT);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	defMountPointsExcluded = "^/(dev)($|/)"
	defFSTypesExcluded     = "^devfs$"
)

// GetStats exposes filesystem fullness using getmntinfo(3) compiled against the
// running kernel's struct statfs definition.
func (c *filesystemCollector) GetStats() (stats []filesystemStats, err error) {
	var mntbuf *C.struct_statfs
	count := C.getmntinfo_nowait(&mntbuf)
	if count < 0 {
		return nil, fmt.Errorf("getmntinfo: failed")
	}
	if count == 0 {
		return []filesystemStats{}, nil
	}

	// Slice the C array. mntbuf is valid until the next getmntinfo call on
	// this goroutine, and we consume it before returning.
	entries := (*[1 << 20]C.struct_statfs)(unsafe.Pointer(mntbuf))[:count:count]

	stats = make([]filesystemStats, 0, int(count))
	for _, v := range entries {
		mountpoint := C.GoString(&v.f_mntonname[0])
		if c.mountPointFilter.ignored(mountpoint) {
			c.logger.Debug("Ignoring mount point", "mountpoint", mountpoint)
			continue
		}

		device := C.GoString(&v.f_mntfromname[0])
		fstype := C.GoString(&v.f_fstypename[0])
		if c.fsTypeFilter.ignored(fstype) {
			c.logger.Debug("Ignoring fs type", "type", fstype)
			continue
		}

		var ro float64
		if v.f_flags&C.MNT_RDONLY != 0 {
			ro = 1
		}

		stats = append(stats, filesystemStats{
			labels: filesystemLabels{
				device:     device,
				mountPoint: mountpoint,
				fsType:     fstype,
			},
			size:      float64(v.f_blocks) * float64(v.f_bsize),
			free:      float64(v.f_bfree) * float64(v.f_bsize),
			avail:     float64(v.f_bavail) * float64(v.f_bsize),
			files:     float64(v.f_files),
			filesFree: float64(v.f_ffree),
			ro:        ro,
		})
	}
	return stats, nil
}
