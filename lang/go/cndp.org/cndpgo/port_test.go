/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestRxBurst(t *testing.T) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		t.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	rxPackets := make([]*Packet, 256)

	t.Run("TestRxBurst", func(t *testing.T) {
		tid := handle.RegisterThread("rx" + time.Now().String())
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		size := port.RxBurst(rxPackets)
		if size > 0 {
			FreePacketBuffer(rxPackets[:size])
		}
	})
}

func TestPrepareTxPackets(t *testing.T) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		t.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	txPackets := make([]*Packet, 256)

	t.Run("TestPrepareTxPackets", func(t *testing.T) {
		tid := handle.RegisterThread("prepare_tx" + time.Now().String())
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		size := port.PrepareTxPackets(txPackets)
		if size > 0 {
			FreePacketBuffer(txPackets[:size])
		}
	})
}

func TestTxBurst(t *testing.T) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		t.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	txPackets := make([]*Packet, 256)

	t.Run("TestTxBurst", func(t *testing.T) {
		tid := handle.RegisterThread("tx" + time.Now().String())
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		size := port.PrepareTxPackets(txPackets)
		if size <= 0 {
			return
		}
		for j := 0; j < size; j++ {
			pMData := txPackets[j].GetHeaderMetaData()
			pMData.SetData(data)
		}

		port.TxBurst(txPackets)
	})
}

func TestLoopback(t *testing.T) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		t.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	rxPackets := make([]*Packet, 256)

	t.Run("TestLoopback", func(t *testing.T) {
		tid := handle.RegisterThread("lb" + time.Now().String())
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		size := port.RxBurst(rxPackets)
		if size > 0 {
			for j := 0; j < size; j++ {
				pMData := rxPackets[j].GetHeaderMetaData()
				pMData.SwapMacAddress()
			}

			sent := 0
			for sent < size {
				n_tx := port.TxBurst(rxPackets[sent:size])
				sent += n_tx
			}
		}
	})
}

func BenchmarkRxBurstSerial(b *testing.B) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		b.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	rxPackets := make([]*Packet, 256)

	tid := handle.RegisterThread("rx_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := port.RxBurst(rxPackets)
		if size > 0 {
			FreePacketBuffer(rxPackets[:size])
		}
	}
}

func BenchmarkPrepareTxPacketsSerial(b *testing.B) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		b.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	txPackets := make([]*Packet, 256)

	tid := handle.RegisterThread("prepare_tx_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := port.PrepareTxPackets(txPackets)
		if size > 0 {
			FreePacketBuffer(txPackets[:size])
		}
	}
}

/*
func BenchmarkPrepareTxPacketsParallel(b *testing.B) {
	port,err := handle.GetPort(*lPortName)
	if err != nil {
		b.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}
	b.RunParallel(func(pb *testing.PB) {

		tid := handle.RegisterThread("prepare_tx_parallel" + time.Now().String())
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		txPackets := make([]*Packet, 256)
		size := port.PrepareTxPackets(txPackets)
		if size > 0 {
			FreePacketBuffer(txPackets[:size])
		}

		for pb.Next() {

		}
	})
}
*/

func BenchmarkLoopbackSerial(b *testing.B) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		b.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	rxPackets := make([]*Packet, 256)

	tid := handle.RegisterThread("tx_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := port.RxBurst(rxPackets)
		if size > 0 {
			for j := 0; j < size; j++ {
				pMData := rxPackets[j].GetHeaderMetaData()
				pMData.SwapMacAddress()
			}

			sent := 0
			for sent < size {
				n_tx := port.TxBurst(rxPackets[sent:size])
				sent += n_tx
			}
		}
	}
}

func BenchmarkTxBurstSerial(b *testing.B) {
	port, err := handle.GetPort(*lPortName)
	if err != nil {
		b.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	txPackets := make([]*Packet, 256)
	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	tid := handle.RegisterThread("tx_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := port.PrepareTxPackets(txPackets)
		for j := 0; j < size; j++ {
			pMData := txPackets[j].GetHeaderMetaData()
			pMData.SetData(data)
		}
		sent := 0
		for sent < size {
			n_tx := port.TxBurst(txPackets[sent:size])
			sent += n_tx
		}
	}
}

/*
func BenchmarkTxBurstParallel(b *testing.B) {
	port,err := handle.GetPort(*lPortName)
	if err != nil {
		b.Fatalf("error getting port %s: %s\n", *lPortName, err.Error())
		return
	}

	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	b.RunParallel(func(pb *testing.PB) {
		tid := handle.RegisterThread("tx_parallel" + time.Now().String())
		if tid <= 0 {
			return
		}
		defer handle.UnregisterThread(tid)

		txPackets := make([]*Packet, 256)
		size := port.PrepareTxPackets(txPackets)
		for j := 0; j < size; j++ {
			pMData := txPackets[j].GetHeaderMetaData()
			pMData.SetData(data)
		}

		sent := 0
		for sent < size {
			n_tx := port.TxBurst(txPackets[sent:size])
			sent += n_tx
		}

		for pb.Next() {

		}
	})
}
*/
