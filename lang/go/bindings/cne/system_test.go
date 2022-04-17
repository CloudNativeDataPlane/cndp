/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

import (
	"strconv"
	"testing"
)

func TestGetPort(t *testing.T) {
	t.Run("TestGetPortValid", func(t *testing.T) {
		_, err := handle.GetPort(*lPortName)
		if err != nil {
			t.Errorf("error getting port %s: %s\n", *lPortName, err.Error())
			return
		}
	})
	t.Run("TestGetPortInValid", func(t *testing.T) {

	})
}

func BenchmarkGetPortSerial(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := handle.GetPort(*lPortName)
		if err != nil {
			b.Errorf("error getting port %s: %s\n", *lPortName, err.Error())
			return
		}
	}
}

func BenchmarkGetPortParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := handle.GetPort(*lPortName)
			if err != nil {
				b.Errorf("error getting port %s: %s\n", *lPortName, err.Error())
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
		tid := handle.RegisterThread("register_thread" + str)
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		for pb.Next() {

		}
	})
}
