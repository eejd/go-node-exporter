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

//go:build !nodiskstats

package collector

// #cgo LDFLAGS: -framework CoreFoundation -framework IOKit
// #include <CoreFoundation/CoreFoundation.h>
// #include <IOKit/IOKitLib.h>
// #include <IOKit/storage/IOBlockStorageDriver.h>
// #include <IOKit/storage/IOMedia.h>
// #include <IOKit/IOBSD.h>
// #include <IOKit/storage/IOStorageDeviceCharacteristics.h>
// #include <string.h>
//
// #define NE_DISK_NAME_LEN 64
// #define NE_DISK_INFO_LEN 256
// #define NE_MAX_DISKS     128
//
// typedef struct {
//     char name[NE_DISK_NAME_LEN];     // BSD name, e.g. "disk0"
//     char model[NE_DISK_INFO_LEN];    // kIOPropertyProductNameKey
//     char serial[NE_DISK_INFO_LEN];   // kIOPropertyProductSerialNumberKey
//     char revision[NE_DISK_INFO_LEN]; // kIOPropertyProductRevisionLevelKey
// } NEDiskInfoEntry;
//
// // cfstr_to_buf copies a CFStringRef into buf (up to len bytes) if non-NULL.
// static void cfstr_to_buf(CFTypeRef val, char *buf, int len) {
//     if (!val || CFGetTypeID(val) != CFStringGetTypeID()) return;
//     CFStringGetCString((CFStringRef)val, buf, len, CFStringGetSystemEncoding());
// }
//
// // ne_get_disk_info enumerates whole IOMedia objects and for each one walks up
// // to the IOBlockStorageDevice ancestor to read device characteristics
// // (model name, serial number, firmware revision).  Returns the number of
// // entries written into `out`, or -1 on a fatal IOKit error.
// int ne_get_disk_info(NEDiskInfoEntry *out, int max) {
//     mach_port_t port;
//     IOMainPort(bootstrap_port, &port);
//
//     CFMutableDictionaryRef match = IOServiceMatching("IOMedia");
//     CFDictionaryAddValue(match, CFSTR(kIOMediaWholeKey), kCFBooleanTrue);
//
//     io_iterator_t it;
//     if (IOServiceGetMatchingServices(port, match, &it) != KERN_SUCCESS) {
//         return -1;
//     }
//
//     int n = 0;
//     io_registry_entry_t media;
//     while (n < max && (media = IOIteratorNext(it)) != 0) {
//         // Step 1: get the BSD name from the IOMedia properties.
//         CFMutableDictionaryRef mediaProps = NULL;
//         if (IORegistryEntryCreateCFProperties(media, &mediaProps,
//                                               kCFAllocatorDefault, kNilOptions) != KERN_SUCCESS) {
//             IOObjectRelease(media);
//             continue;
//         }
//         CFTypeRef bsdRef = CFDictionaryGetValue(mediaProps, CFSTR(kIOBSDNameKey));
//         if (!bsdRef || CFGetTypeID(bsdRef) != CFStringGetTypeID()) {
//             CFRelease(mediaProps);
//             IOObjectRelease(media);
//             continue;
//         }
//         CFStringGetCString((CFStringRef)bsdRef, out[n].name, NE_DISK_NAME_LEN,
//                            CFStringGetSystemEncoding());
//         CFRelease(mediaProps);
//
//         // Step 2: parent must be IOBlockStorageDriver.
//         io_registry_entry_t driver;
//         if (IORegistryEntryGetParentEntry(media, kIOServicePlane, &driver) != KERN_SUCCESS) {
//             IOObjectRelease(media);
//             continue;
//         }
//         IOObjectRelease(media);
//         if (!IOObjectConformsTo(driver, "IOBlockStorageDriver")) {
//             IOObjectRelease(driver);
//             continue;
//         }
//
//         // Step 3: walk up from the driver looking for kIOPropertyDeviceCharacteristicsKey
//         // (typically on the IOBlockStorageDevice one level up, but the hierarchy varies by
//         // transport — NVMe, AHCI, USB — so we search up to 4 more levels).
//         io_registry_entry_t cur = driver;
//         CFDictionaryRef charDict = NULL;
//         for (int depth = 0; depth < 4 && cur != 0 && !charDict; depth++) {
//             io_registry_entry_t parent;
//             if (IORegistryEntryGetParentEntry(cur, kIOServicePlane, &parent) != KERN_SUCCESS) {
//                 if (cur != driver) IOObjectRelease(cur);
//                 break;
//             }
//             if (cur != driver) IOObjectRelease(cur);
//             cur = parent;
//
//             CFMutableDictionaryRef props = NULL;
//             if (IORegistryEntryCreateCFProperties(cur, &props,
//                                                   kCFAllocatorDefault, kNilOptions) != KERN_SUCCESS) {
//                 continue;
//             }
//             CFTypeRef chars = CFDictionaryGetValue(props, CFSTR(kIOPropertyDeviceCharacteristicsKey));
//             if (chars && CFGetTypeID(chars) == CFDictionaryGetTypeID()) {
//                 CFRetain(chars);
//                 charDict = (CFDictionaryRef)chars;
//             }
//             CFRelease(props);
//         }
//         if (cur && cur != driver) IOObjectRelease(cur);
//         IOObjectRelease(driver);
//
//         if (charDict) {
//             cfstr_to_buf(CFDictionaryGetValue(charDict, CFSTR(kIOPropertyProductNameKey)),
//                          out[n].model, NE_DISK_INFO_LEN);
//             cfstr_to_buf(CFDictionaryGetValue(charDict, CFSTR(kIOPropertyProductSerialNumberKey)),
//                          out[n].serial, NE_DISK_INFO_LEN);
//             cfstr_to_buf(CFDictionaryGetValue(charDict, CFSTR(kIOPropertyProductRevisionLevelKey)),
//                          out[n].revision, NE_DISK_INFO_LEN);
//             CFRelease(charDict);
//         }
//         n++;
//     }
//     IOObjectRelease(it);
//     return n;
// }
import "C"

import "fmt"

// diskInfoEntry holds model/serial/revision strings for one disk.
type diskInfoEntry struct {
	model, serial, revision string
}

// getDiskInfo returns a map from BSD device name (e.g. "disk0") to its IOKit
// device characteristics (model name, serial number, firmware revision).
// It returns a non-nil error only when the IOKit enumeration itself fails;
// individual devices with missing characteristics are silently omitted.
func getDiskInfo() (map[string]diskInfoEntry, error) {
	const maxDisks = C.NE_MAX_DISKS
	var entries [maxDisks]C.NEDiskInfoEntry

	n := C.ne_get_disk_info(&entries[0], maxDisks)
	if n < 0 {
		return nil, fmt.Errorf("IOServiceGetMatchingServices failed for IOMedia enumeration")
	}

	result := make(map[string]diskInfoEntry, int(n))
	for i := 0; i < int(n); i++ {
		name := C.GoString(&entries[i].name[0])
		if name == "" {
			continue
		}
		result[name] = diskInfoEntry{
			model:    C.GoString(&entries[i].model[0]),
			serial:   C.GoString(&entries[i].serial[0]),
			revision: C.GoString(&entries[i].revision[0]),
		}
	}
	return result, nil
}
