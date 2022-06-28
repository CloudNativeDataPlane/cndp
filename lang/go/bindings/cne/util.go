/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cne

import (
	"reflect"
	"unsafe"
)

// SwapUint16 swaps a uint16 in place for Big/Little Endian
func SwapUint16(x uint16) uint16 {

	return x<<8 | x>>8
}

// MakeByteSlice creates a byte slice of the given size using the array starting address
func MakeByteSlice(start uintptr, length int) (data []byte) {

	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length

	return
}

// MakeUint16Slice creates a uint16 slice of the given size using the array starting address
func MakeUint16Slice(start uintptr, length int) (data []uint16) {

	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length

	return
}
