/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

import (
	"encoding/hex"
	"log"
	"os"
	"testing"
)

func TestStarting(t *testing.T) {

	if configFile, err := os.Open(*configStr); err != nil {
		log.Fatalf("unable to open config file: %#v: %v", configStr, err)
	} else {
		defer configFile.Close()

		// Open with a JSON-C file
		cneSys, err = OpenWithFile(*configStr)
		if err != nil {
			log.Fatalf("error parsing JSON string: %v", err)
		}
	}
}

func TestGetChannel(t *testing.T) {

	t.Run("TestGetChannel", func(t *testing.T) {
		for _, lport := range cneSys.LPortList() {

			if cnt, err := lport.GetLPortChannels(); err != nil {
				t.Fatalf("error getting channels %v\n", err)
			} else if cnt == 0 {
				t.Fatalf("error getting channels is zero: %v\n", err)
			}
		}
	})
}

func TestRxBurst(t *testing.T) {

	t.Run("TestRxBurst", func(t *testing.T) {
		err := cneSys.RegisterThread("RxBurst")
		if err != nil {
			t.Fatalf("error registering thread: %v", err)
		}

		for _, lport := range cneSys.LPortList() {

			rxPackets := make([]*Packet, 256)

			size := RxBurst(lport.LPortID(), rxPackets)
			if size > 0 {
				PktBufferFree(rxPackets[:size])
			}
		}

		err = cneSys.UnregisterThread("RxBurst")
		if err != nil {
			t.Fatalf("error unregistering thread: %v", err)
		}
	})
}

func TestPktBufferAlloc(t *testing.T) {

	t.Run("TestPktBufferAlloc", func(t *testing.T) {
		err := cneSys.RegisterThread("PktBufferAlloc")
		if err != nil {
			t.Fatalf("error registering thread: %v", err)
		}

		for _, lport := range cneSys.LPortList() {

			txPackets := make([]*Packet, 256)

			size := PktBufferAlloc(lport.LPortID(), txPackets)
			if size > 0 {
				PktBufferFree(txPackets[:size])
			}
		}

		err = cneSys.UnregisterThread("PktBufferAlloc")
		if err != nil {
			t.Fatalf("error unregistering thread: %v", err)
		}
	})
}

func TestTxBurst(t *testing.T) {

	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	t.Run("TestTxBurst", func(t *testing.T) {
		err := cneSys.RegisterThread("TxBurst")
		if err != nil {
			t.Fatalf("error registering thread: %v", err)
		}

		for _, lport := range cneSys.LPortList() {
			txPackets := make([]*Packet, 256)

			size := PktBufferAlloc(lport.LPortID(), txPackets)
			if size <= 0 {
				break
			}
			WritePktDataList(txPackets[:size], 0, data)

			TxBurst(lport.LPortID(), txPackets[:size], true)
		}

		err = cneSys.UnregisterThread("TxBurst")
		if err != nil {
			t.Fatalf("error unregistering thread: %v", err)
		}
	})
}

func TestLoopback(t *testing.T) {

	t.Run("TestLoopback", func(t *testing.T) {
		err := cneSys.RegisterThread("Loopback")
		if err != nil {
			t.Fatalf("error registering thread: %v", err)
		}

		for _, lport := range cneSys.LPortList() {
			rxPackets := make([]*Packet, 256)

			size := RxBurst(lport.LPortID(), rxPackets)
			if size > 0 {
				SwapMacAddrs(rxPackets[:size])

				TxBurst(lport.LPortID(), rxPackets[:size], true)
			}
		}

		err = cneSys.UnregisterThread("Loopback")
		if err != nil {
			t.Fatalf("error unregistering thread: %v", err)
		}
	})
}

func TestEnding(t *testing.T) {

	defer cneSys.Close()
}
