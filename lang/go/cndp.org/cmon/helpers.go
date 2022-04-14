// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package main

import (
	"fmt"
	"os"

	cz "cndp.org/colorize"
	tlog "cndp.org/ttylog"
)

// CloudMonInfo returning the basic information string
func CloudMonInfo(color bool) string {
	if !color {
		return fmt.Sprintf("%s, Version: %s Pid: %d %s",
			"CNDP Monitor Tool", Version(), os.Getpid(),
			"Copyright © 2019-2021 Intel Corporation")
	}

	return fmt.Sprintf("[%s, Version: %s Pid: %s %s]",
		cz.Yellow("CNDP Monitor Tool"), cz.Green(Version()),
		cz.Red(os.Getpid()),
		cz.SkyBlue("Copyright © 2019-2021 Intel Corporation"))
}

func sprintf(msg string, w ...interface{}) string {
	if len(w) > 1 {
		return fmt.Sprintf("%-36s: %6d, %6d\n", msg, w[0].(uintptr), w[1].(uintptr))
	} else if len(w) == 1 {
		return fmt.Sprintf("%-36s: %6d\n", msg, w[0].(uintptr))
	} else {
		return fmt.Sprintf("%s args is zero\n", msg)
	}
}

func dprintf(msg string, w ...interface{}) {

	tlog.DoPrintf(sprintf(msg, w...))
}
