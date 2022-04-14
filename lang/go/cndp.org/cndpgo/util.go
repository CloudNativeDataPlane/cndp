/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

package cndpgo

import (
	"reflect"
	"unsafe"
)

func SwapBytesUint16(x uint16) uint16 {
	return x<<8 | x>>8
}

func makeByteSlice(start uintptr, length int) (data []byte) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}
