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

//go:build freebsd && cgo

package collector

/*
#include <sys/types.h>
#include <sys/sysctl.h>
#include <string.h>
#include <stdlib.h>

// c_name2oid converts a dotted sysctl name to its OID array.
// Stores the OID in oid[] and returns the OID length on success, -1 on error.
static int c_name2oid(const char *name, int *oid, int max_oid_len) {
    int qoid[2] = {0, 3}; // CTL_SYSCTL, CTL_SYSCTL_NAME2OID
    size_t len = (size_t)max_oid_len * sizeof(int);
    if (sysctl(qoid, 2, oid, &len, (void *)name, strlen(name)) == -1)
        return -1;
    return (int)(len / sizeof(int));
}

// c_next_oid returns the next OID in the MIB tree after oid[0..oid_len-1].
// The successor is written to out_oid[]. Returns its length on success, -1 on error.
static int c_next_oid(const int *oid, int oid_len, int *out_oid, int max_out_len) {
    int qoid[2 + CTL_MAXNAME];
    qoid[0] = 0; // CTL_SYSCTL
    qoid[1] = 2; // CTL_SYSCTL_NEXT
    memcpy(&qoid[2], oid, (size_t)oid_len * sizeof(int));
    size_t out_len = (size_t)max_out_len * sizeof(int);
    if (sysctl(qoid, 2 + oid_len, out_oid, &out_len, NULL, 0) == -1)
        return -1;
    return (int)(out_len / sizeof(int));
}

// c_oid2name converts an OID array to its dotted string name.
// The name is written to namebuf (at most namebuf_len bytes, NUL-terminated).
// Returns 0 on success, -1 on error.
static int c_oid2name(const int *oid, int oid_len, char *namebuf, size_t namebuf_len) {
    int qoid[2 + CTL_MAXNAME];
    qoid[0] = 0; // CTL_SYSCTL
    qoid[1] = 1; // CTL_SYSCTL_NAME
    memcpy(&qoid[2], oid, (size_t)oid_len * sizeof(int));
    if (sysctl(qoid, 2 + oid_len, namebuf, &namebuf_len, NULL, 0) == -1)
        return -1;
    return 0;
}

// c_oid_ctltype returns the CTLTYPE_* value for the given OID.
// CTLTYPE_NODE (1) means the OID is an internal node (subtree), not a leaf.
// Returns 0 on error.
static unsigned int c_oid_ctltype(const int *oid, int oid_len) {
    int qoid[2 + CTL_MAXNAME];
    unsigned int kind = 0;
    size_t klen = sizeof(kind);
    qoid[0] = 0; // CTL_SYSCTL
    qoid[1] = 4; // CTL_SYSCTL_OIDFMT
    memcpy(&qoid[2], oid, (size_t)oid_len * sizeof(int));
    if (sysctl(qoid, 2 + oid_len, &kind, &klen, NULL, 0) == -1)
        return 0;
    return kind & 0xFU; // CTLTYPE_* occupies the low nibble
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

// sysctlMaxName is the maximum number of integers in a FreeBSD OID (CTL_MAXNAME).
const sysctlMaxName = 24

// sysctlWalkPrefix returns the dotted string names of all leaf sysctl entries
// that fall under the given prefix (i.e. whose name starts with prefix + ".").
// Leaf entries have a CTLTYPE other than CTLTYPE_NODE (1), meaning they hold an
// actual value (uint64, string, …) rather than a sub-tree.
//
// The walk uses the CTL_SYSCTL_NEXT / CTL_SYSCTL_NAME mechanism — the same
// mechanism sysctl(8) uses internally — so it correctly enumerates
// dynamically-created entries such as kstat.zfs.<pool>.dataset.objset-0xNNN.*.
//
// Returns nil, nil when the prefix does not exist (e.g. ZFS not loaded).
func sysctlWalkPrefix(prefix string) ([]string, error) {
	cname := C.CString(prefix)
	defer C.free(unsafe.Pointer(cname))

	var oid [sysctlMaxName]C.int
	oidLen := C.c_name2oid(cname, &oid[0], C.int(sysctlMaxName))
	if oidLen < 0 {
		return nil, nil // prefix does not exist
	}

	prefixDot := prefix + "."
	var results []string

	for {
		var next [sysctlMaxName]C.int
		nextLen := C.c_next_oid(&oid[0], oidLen, &next[0], C.int(sysctlMaxName))
		if nextLen < 0 {
			break // end of tree or past the subtree
		}

		var namebuf [512]C.char
		if C.c_oid2name(&next[0], nextLen, &namebuf[0], 512) < 0 {
			break
		}
		name := C.GoString(&namebuf[0])

		if !strings.HasPrefix(name, prefixDot) {
			break // walked past the prefix subtree
		}

		// Only collect leaf nodes; skip internal CTLTYPE_NODE (1) entries.
		if ctltype := C.c_oid_ctltype(&next[0], nextLen); ctltype != 1 {
			results = append(results, name)
		}

		oid = next
		oidLen = nextLen
	}

	return results, nil
}
