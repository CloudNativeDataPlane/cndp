/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

var handle *System
var err error
var configStr = flag.String("config", "", "path to configuration file")
var lPortName = flag.String("port", "", "port identifier as configured")

func TestMain(m *testing.M) {
	flag.Parse()
	handle, err = Open(*configStr)
	if err != nil {
		fmt.Printf("error in initialization %s\n", err.Error())
		return
	}

	exitVal := m.Run()
	handle.Close()
	os.Exit(exitVal)

}
