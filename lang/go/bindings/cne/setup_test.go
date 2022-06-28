/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

import (
	"flag"
	"log"
	"os"

	"testing"
)

var cneSys *System
var configStr = flag.String("config", "", "path to configuration file")

func TestMain(m *testing.M) {

	flag.Parse()

	if configStr == nil || len(*configStr) == 0 {
		log.Fatalf("configuration path string is missing")
	}

	os.Exit(m.Run())
}
