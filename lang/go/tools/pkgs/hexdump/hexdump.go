// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation

package hexdump

import (
	"fmt"
)

// HexDump the data buffer for the given length
// msg is a message to print at the top of the hexdump
// data is the data to dump
// off is the offset into the byte array to start
// num is the number of bytes to dump
func HexDump(msg string, data []byte, off int, num int) string {

	str := ""

	if off > len(data) {
		str += "Invalid length or offset\n"
		return str
	}
	if (off + num) > len(data) {
		num = len(data) - off
	}

	if len(msg) > 0 {
		str += fmt.Sprintf("\n*** %s (offset: %d) ***:\n", msg, off)
	} else {
		str += fmt.Sprintf("\n*** Data (offset: %d) ***:\n", off)
	}

	for i := 0; i < (off + num); i += 16 {
		if i < off {
			continue
		}
		str += fmt.Sprintf("%4d: ", i)
		for j := 0; j < 16; j++ {
			str += fmt.Sprintf("%02x ", data[i+j])
		}
		str += "\n"
	}
	str += "\n"

	return str
}
