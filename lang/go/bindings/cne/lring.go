/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2022 Intel Corporation
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <stdint.h>
#include <cne_ring.h>

#define RING_DEFAULT_ELEM_SZ	sizeof(void *)
*/
import "C"

import (
	"fmt"
	"unsafe"
)

var (
	RingFlagSingleProducer = "SP_ENQ"     // Single producer string
	RingFlagSingleConsumer = "SC_DEQ"     // Single consumer string
	RingFlagExactSize      = "EXACT_SIZE" // Exact size string

	RingFlagSingleProducerValue uint = C.RING_F_SP_ENQ   // Single producer value
	RingFlagSingleConsumerValue uint = C.RING_F_SC_DEQ   // Single consumer value
	RingFlagExactSizeValue      uint = C.RING_F_EXACT_SZ // Exact Size value
)

type ringFlagsMap map[string]uint
type stringFlagsMap map[uint]string

var ringFlags ringFlagsMap
var stringFlags stringFlagsMap

// LocklessRing structure contains internal information for a lockless ring.
type LocklessRing struct {
	flags      uint           // Ring flags
	name       string         // Name of the ring
	elementSz  uint           // The size of the element in the ring.
	elementCnt uint           // The number of elements in the ring.
	ring       unsafe.Pointer // The private ring pointer
}

func init() {
	// Create a map of flags and flag values.
	ringFlags = make(map[string]uint)
	ringFlags[RingFlagSingleProducer] = C.RING_F_SP_ENQ
	ringFlags[RingFlagSingleConsumer] = C.RING_F_SC_DEQ
	ringFlags[RingFlagExactSize] = C.RING_F_EXACT_SZ

	stringFlags = make(map[uint]string)
	stringFlags[C.RING_F_SP_ENQ] = RingFlagSingleProducer
	stringFlags[C.RING_F_SC_DEQ] = RingFlagSingleConsumer
	stringFlags[C.RING_F_EXACT_SZ] = RingFlagExactSize
}

// Convert the ring options from strings to a flag value
func convertRingOptions(strFlags []string) uint {

	var flags uint = 0

	if strFlags == nil {
		return flags
	}

	for _, s := range strFlags {
		f, ok := ringFlags[s]
		if ok {
			flags |= f
		}
	}

	return flags
}

// Convert the ring option value to a set of option strings
func ringOptionsToStrings(flags uint) []string {

	str := make([]string, 0)

	for v, s := range stringFlags {
		if (v & flags) != 0 {
			str = append(str, s)
		}
	}

	return str
}

// LRingCreateElem creates the lockless ring given the specified arguments and element size.
//
// The name is used to give the ring a name.
// The elementSz is the element size of each element in the ring.
// The count is used to set the max number of elements in the ring.
// strFlags are used in creating the lockless ring.
//
// Returns the internal lockless ring object or error value is set
func LRingCreateElem(name string, elementSz, count uint, strFlags []string) (*LocklessRing, error) {

	if count == 0 {
		return nil, fmt.Errorf("Count is zero")
	}

	if elementSz == 0 {
		elementSz = C.RING_DEFAULT_ELEM_SZ
	}

	flags := convertRingOptions(strFlags)

	lr := &LocklessRing{name: name, elementSz: elementSz, elementCnt: count, flags: flags}

	n := C.CString(name)
	defer C.free(unsafe.Pointer(n))

	lr.ring = C.cne_ring_create(n, C.uint(elementSz), C.uint(count), C.uint(flags))

	if lr.ring == nil {
		return nil, fmt.Errorf("failed to create lockless ring")
	}

	return lr, nil
}

// NewLRing create a lockless ring using default element size of 8 bytes.
//
// The name is used to give the ring a name.
// The count is used to set the max number of elements in the ring.
// strFlags are used in creating the lockless ring.
//
// Returns the internal lockless ring object or error value is set
func NewLRing(name string, count uint, strFlags []string) (*LocklessRing, error) {

	if count == 0 {
		return nil, fmt.Errorf("Count is zero")
	}
	return LRingCreateElem(name, C.RING_DEFAULT_ELEM_SZ, count, strFlags)
}

// Destroy a lockless ring object given the valid LocklessRing structure pointer.
func (lr *LocklessRing) Destroy() {

	if lr != nil {
		C.cne_ring_free(lr.ring)
	}
}

// EnqueueN enqueues N number of elements into a lockless ring.
func (lr *LocklessRing) EnqueueN(values []uintptr, cnt int) int {

	if lr.ring != nil {
		val := (*unsafe.Pointer)(unsafe.Pointer(&values[0]))

		n := C.cne_ring_enqueue_burst(lr.ring, val, C.uint(cnt), nil)
		return int(n)
	}

	return 0
}

// DequeueN dequeue a number of elements from the ring defined by the specified count
func (lr *LocklessRing) DequeueN(values []uintptr, cnt int) int {

	if lr.ring != nil {
		val := (*unsafe.Pointer)(unsafe.Pointer(&values[0]))

		n := C.cne_ring_dequeue_burst(lr.ring, val, C.uint(cnt), nil)

		return int(n)
	}

	return 0
}

// Dump the lockless ring information to the console.
func (lr *LocklessRing) Dump() {

	if lr != nil {
		C.cne_ring_dump(nil, lr.ring)
	}
}

// Name returns the name of the lockless ring.
func (lr *LocklessRing) Name() string {
	if lr == nil {
		return ""
	}
	return lr.name
}

// Flags returns the flags of the lockless ring.
func (lr *LocklessRing) Flags() []string {
	if lr == nil {
		return nil
	}
	strFlags := ringOptionsToStrings(lr.flags)

	return strFlags
}

// RawFlags returns the flags of the lockless ring.
func (lr *LocklessRing) RawFlags() uint {
	if lr == nil {
		return 0
	}

	return lr.flags
}

// Size returns the size of the lockless ring.
func (lr *LocklessRing) Size() uint {

	if lr == nil {
		return 0
	}
	return lr.elementCnt
}

// ElemSize returns the size of each element in the ring.
func (lr *LocklessRing) ElemSize() uint {

	if lr == nil {
		return 0
	}
	return lr.elementSz
}

// Count returns the number of elements currently in the ring
func (lr *LocklessRing) Count() uint {

	if lr == nil {
		return 0
	}
	return uint(C.cne_ring_count(lr.ring))
}

// FreeCount returns the number of elements currently free in the ring
func (lr *LocklessRing) FreeCount() uint {

	if lr == nil {
		return 0
	}
	return uint(C.cne_ring_free_count(lr.ring))
}

// Full returns true if the ring is full.
func (lr *LocklessRing) Full() bool {

	if lr == nil {
		return true
	}
	return C.cne_ring_full(lr.ring) > 0
}

// Empty returns true if the ring is empty.
func (lr *LocklessRing) Empty() bool {

	if lr == nil {
		return true
	}
	return C.cne_ring_empty(lr.ring) > 0
}

// Pointer returns the pointer to the C ring struct.
func (lr *LocklessRing) Pointer() unsafe.Pointer {
	if lr == nil {
		return nil
	}
	return lr.ring
}
