// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation

package metrics

import (
	"testing"
)

var pi *MetricInfo

func TestOpen(t *testing.T) {

	pi = NewMetricInfo("/var/run/cndp", "metric.")

	if err := pi.Open(); err != nil {
		t.Errorf("Open() failed: %v", err)
	}

	t.Log("Metrics  Open: OK")
}

func TestInfo(t *testing.T) {

	for _, a := range pi.AppsList() {
		cmds, err := pi.Commands(a)
		if err != nil {
			t.Logf("Info for %s\n", a.Path)
			continue
		}

		t.Logf("Info    : %+v\n", cmds)
	}
}

func TestCommands(t *testing.T) {

	for _, a := range pi.AppsList() {
		cmds, err := pi.Commands(a)
		if err != nil {
			t.Errorf("unable to retrieve commands: %v", err)
		} else {
			t.Logf("Commands     : %v\n", cmds)
		}
	}
}

func TestFiles(t *testing.T) {

	files := pi.Files()
	if len(files) > 0 {
		t.Logf("Files        : %v\n", files)
	}
}

func TestClose(t *testing.T) {

	if pi == nil {
		t.Errorf("MetricsInfo pointer is nil")
	} else {
		pi.Close()
	}
	t.Log("Metrics Close: OK")
}
