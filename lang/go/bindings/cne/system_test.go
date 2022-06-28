/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

import (
	"io"
	"os"
	"strconv"
	"time"

	"testing"

	"github.com/tidwall/jsonc"
)

func TestSystem(t *testing.T) {
	t.Run("OpenWithString", func(t *testing.T) {
		if configFile, err := os.Open(*configStr); err != nil {
			t.Errorf("unable to open config file: %#v: %v", configStr, err)
		} else {
			defer configFile.Close()

			var bytes []byte

			// Read the JSON-C file into a single byte slice for later parsing
			if bytes, err = io.ReadAll(configFile); err != nil {
				t.Errorf("unable to load config file: %#v: %v", configStr, err)
			}

			// Open with a JSON-C string
			if cneSys, err := OpenWithString(string(bytes)); err != nil {
				t.Errorf("error parsing JSON string: %v", err)
			} else {
				cneSys.Close()
				time.Sleep(time.Second)
			}
		}
	})

	t.Run("OpenWithFile", func(t *testing.T) {
		// Open with a JSON-C filename
		if cneSys, err := OpenWithFile(*configStr); err != nil {
			t.Errorf("error parsing JSON string %#v: %v", configStr, err)
		} else {
			cneSys.Close()
		}
	})

	t.Run("OpenWithConfig", func(t *testing.T) {
		if configFile, err := os.Open(*configStr); err != nil {
			t.Errorf("unable to open config file: %#v: %v", configStr, err)
		} else {
			defer configFile.Close()

			var bytes []byte

			// Read the JSON-C file into a single byte slice for later parsing
			if bytes, err = io.ReadAll(configFile); err != nil {
				t.Errorf("unable to load config file: %#v: %v", configStr, err)
			}

			if jcfg, err := processConfig(jsonc.ToJSON(bytes)); err != nil {
				t.Errorf("unable to process config file: %#v: %v", configStr, err)
			} else {
				jcfg.valuesToUnitMultipliers()

				// Open with a cne.Config structure
				if cneSys, err := OpenWithConfig(jcfg); err != nil {
					t.Errorf("error parsing JSON string %#v: %v", configStr, err)
				} else {
					cneSys.Close()
				}
			}
		}
	})
}

func TestGetPort(t *testing.T) {
	t.Run("TestGetPortValid", func(t *testing.T) {
		lport := cneSys.LPortList()[0]
		if lport == nil {
			t.Errorf("error getting port information\n")
			return
		}
	})
	t.Run("TestGetPortInValid", func(t *testing.T) {

	})
}

func BenchmarkGetPortSerial(b *testing.B) {
	for i := 0; i < b.N; i++ {
		lport := cneSys.LPortList()[0]
		if lport == nil {
			b.Errorf("error getting port information\n")
			return
		}
	}
}

func BenchmarkGetPortParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			lport := cneSys.LPortList()[0]
			if lport == nil {
				b.Errorf("error getting port information\n")
				return
			}
		}
	})
}

func BenchmarkRegisterThreadParallel(b *testing.B) {
	i := 0
	b.RunParallel(func(pb *testing.PB) {
		str := strconv.Itoa(i)
		i++
		tid := cneSys.RegisterThread("register_thread" + str)
		if tid <= 0 {
			return
		}
		defer cneSys.UnregisterThread(tid)

		for pb.Next() {

		}
	})
}
