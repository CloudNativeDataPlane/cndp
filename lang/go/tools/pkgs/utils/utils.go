// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package utils

import (
	"fmt"
	"os"
	"sync"

	"github.com/shirou/gopsutil/cpu"
)

var numCPUs int

// NumCPUs is the number of CPUs in the system (logical cores)
func NumCPUs() int {
	var once sync.Once

	once.Do(func() {
		num, err := cpu.Counts(true)
		if err != nil {
			fmt.Printf("Unable to get number of CPUs: %v", err)
			os.Exit(1)
		}
		numCPUs = num
	})

	return numCPUs
}

// Format the bytes into human readable format
func Format(units []string, v uint64, w ...interface{}) string {
	var index int

	bytes := float64(v)
	for index = 0; index < len(units); index++ {
		if bytes < 1024.0 {
			break
		}
		bytes = bytes / 1024.0
	}

	precision := uint64(0)
	for _, v := range w {
		precision = v.(uint64)
	}

	return fmt.Sprintf("%.*f %s", precision, bytes, units[index])
}

// FormatBytes into KB, MB, GB, ...
func FormatBytes(v uint64, w ...interface{}) string {

	return Format([]string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}, v, w...)
}

// FormatUnits into KB, MB, GB, ...
func FormatUnits(v uint64, w ...interface{}) string {

	return Format([]string{" ", "K", "M", "G", "T", "P", "E", "Z", "Y"}, v, w...)
}

// BitRate - return the network bit rate
func BitRate(ioPkts, ioBytes uint64) float64 {
	return float64(((ioPkts * PktOverheadSize) + ioBytes) * 8)
}
