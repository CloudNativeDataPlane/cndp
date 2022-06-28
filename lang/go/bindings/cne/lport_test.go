/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

import (
	"encoding/hex"
	"log"
	"os"
	"testing"
	"time"
)

func TestStarting(t *testing.T) {

	if configFile, err := os.Open(*configStr); err != nil {
		log.Fatalf("unable to open config file: %#v: %v", configStr, err)
	} else {
		defer configFile.Close()

		// Open with a JSON-C string
		cneSys, err = OpenWithFile(*configStr)
		if err != nil {
			log.Fatalf("error parsing JSON string: %v", err)
		}
	}
}

func TestGetChannel(t *testing.T) {

	for _, lport := range cneSys.LPortList() {

		t.Run("TestLoopback", func(t *testing.T) {
			if cnt, err := lport.GetLPortChannels(); err != nil {
				t.Fatalf("error getting channels %v\n", err)
			} else if cnt == 0 {
				t.Fatalf("error getting channels is zero: %v\n", err)
			}
		})
	}
}

func TestRxBurst(t *testing.T) {

	for _, lport := range cneSys.LPortList() {

		rxPackets := make([]*Packet, 256)

		t.Run("TestRxBurst", func(t *testing.T) {
			tid := cneSys.RegisterThread("rx" + time.Now().String())
			if tid <= 0 {
				return
			}
			defer cneSys.UnregisterThread(tid)

			size := RxBurst(lport.LPortID(), rxPackets)
			if size > 0 {
				PktBufferFree(rxPackets[:size])
			}
		})
	}
}

func TestPktBufferAlloc(t *testing.T) {

	for _, lport := range cneSys.LPortList() {

		txPackets := make([]*Packet, 256)

		t.Run("TestPktBufferAlloc", func(t *testing.T) {
			tid := cneSys.RegisterThread("prepare_tx" + time.Now().String())
			if tid <= 0 {
				return
			}
			defer cneSys.UnregisterThread(tid)

			size := PktBufferAlloc(lport.LPortID(), txPackets)
			if size > 0 {
				PktBufferFree(txPackets[:size])
			}
		})
	}
}

func TestTxBurst(t *testing.T) {

	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	for _, lport := range cneSys.LPortList() {
		txPackets := make([]*Packet, 256)

		t.Run("TestTxBurst", func(t *testing.T) {
			tid := cneSys.RegisterThread("tx" + time.Now().String())
			if tid <= 0 {
				return
			}
			defer cneSys.UnregisterThread(tid)

			size := PktBufferAlloc(lport.LPortID(), txPackets)
			if size <= 0 {
				return
			}
			WritePktDataList(txPackets[:size], 0, data)

			TxBurst(lport.LPortID(), txPackets[:size], true)
		})
	}
}

func TestLoopback(t *testing.T) {

	for _, lport := range cneSys.LPortList() {
		rxPackets := make([]*Packet, 256)

		t.Run("TestLoopback", func(t *testing.T) {
			tid := cneSys.RegisterThread("lb" + time.Now().String())
			if tid <= 0 {
				return
			}
			defer cneSys.UnregisterThread(tid)

			size := RxBurst(lport.LPortID(), rxPackets)
			if size > 0 {
				SwapMacAddrs(rxPackets[:size])

				TxBurst(lport.LPortID(), rxPackets[:size], true)
			}
		})
	}
}

func TestEnding(t *testing.T) {

	defer cneSys.Close()
}

func BenchmarkRxBurstSerial(b *testing.B) {
	var lport *LPort

	if lport = cneSys.LPortList()[0]; lport == nil {
		b.Fatalf("error getting lport information\n")
		return
	}

	rxPackets := make([]*Packet, 256)

	tid := cneSys.RegisterThread("rx_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer cneSys.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := RxBurst(lport.LPortID(), rxPackets)
		if size > 0 {
			PktBufferFree(rxPackets[:size])
		}
	}
}

func BenchmarkPktBufferAllocSerial(b *testing.B) {
	var lport *LPort

	if lport = cneSys.LPortList()[0]; lport == nil {
		b.Fatalf("error getting lport information\n")
		return
	}

	txPackets := make([]*Packet, 256)

	tid := cneSys.RegisterThread("pktbuffer_alloc_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer cneSys.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := PktBufferAlloc(lport.LPortID(), txPackets)
		if size > 0 {
			PktBufferFree(txPackets[:size])
		}
	}
}

func BenchmarkLoopbackSerial(b *testing.B) {
	var lport *LPort

	if lport = cneSys.LPortList()[0]; lport == nil {
		b.Fatalf("error getting lport information\n")
		return
	}

	rxPackets := make([]*Packet, 256)

	tid := cneSys.RegisterThread("loopback_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer cneSys.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := RxBurst(lport.LPortID(), rxPackets)
		if size > 0 {
			SwapMacAddrs(rxPackets[:size])

			TxBurst(lport.LPortID(), rxPackets[:size], true)
		}
	}
}

func BenchmarkTxBurstSerial(b *testing.B) {
	var lport *LPort

	if lport = cneSys.LPortList()[0]; lport == nil {
		b.Fatalf("error getting lport information\n")
		return
	}

	txPackets := make([]*Packet, 256)
	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	tid := cneSys.RegisterThread("tx_serial" + time.Now().String())
	if tid <= 0 {
		return
	}
	defer cneSys.UnregisterThread(tid)

	for i := 0; i < b.N; i++ {
		size := PktBufferAlloc(lport.LPortID(), txPackets)

		WritePktDataList(txPackets[:size], 0, data)
		TxBurst(lport.LPortID(), txPackets[:size], true)
	}
}
