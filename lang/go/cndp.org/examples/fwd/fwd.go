/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	cndp "github.com/intel/cndp"

	flags "github.com/jessevdk/go-flags"
)

type Options struct {
	Config    string `short:"c" long:"config" description:"path to configuration file"`
	Test      string `short:"t" long:"test" description:"run tests - rx|tx|lb"`
	LPortName string `short:"p" long:"lport name" description:"port identifier as configured"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)

func collectStats(handle *cndp.System, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	port, err := handle.GetPort(options.LPortName)
	if err != nil {
		fmt.Printf("error getting port %s: %s\n", options.LPortName, err.Error())
		return
	}

	ps := cndp.NewPortStats()
	if ps == nil {
		return
	}
	defer ps.FreePortStats()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			lastIPackets := ps.GetIPackets()
			lastOPackets := ps.GetOPackets()

			port.GetPortStats(ps)
			//ps.PrintPortStats()
			//Printing PPS as difference in packets rx/tx in 1 second interval
			fmt.Printf("\nRX PPS:%f\n", ps.GetIPackets()-lastIPackets)
			fmt.Printf("TX PPS:%f\n", ps.GetOPackets()-lastOPackets)

			time.Sleep(1 * time.Second)
		}
	}
}

func receivePackets(handle *cndp.System, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("rx")
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(options.LPortName)
	if err != nil {
		fmt.Printf("error getting port %s: %s\n", options.LPortName, err.Error())
		return
	}

	packets := make([]*cndp.Packet, 256)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			size := port.RxBurst(packets)
			if size > 0 {
				cndp.FreePacketBuffer(packets[:size])
			}
		}
	}
}

func transmitPackets(handle *cndp.System, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("tx")
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(options.LPortName)
	if err != nil {
		fmt.Printf("error getting port %s: %s\n", options.LPortName, err.Error())
		return
	}

	txPackets := make([]*cndp.Packet, 256)

	data, err := hex.DecodeString("fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79")
	if err != nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			size := port.PrepareTxPackets(txPackets)

			if size > 0 {
				for j := 0; j < size; j++ {
					/* poor cgo performance
					txPackets[j].SetData(data)
					*/
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
	}
}

func reTransmitPackets(handle *cndp.System, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("lb")
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(options.LPortName)
	if err != nil {
		fmt.Printf("error getting port %s: %s\n", options.LPortName, err.Error())
		return
	}

	packets := make([]*cndp.Packet, 256)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			size := port.RxBurst(packets)
			if size > 0 {
				for j := 0; j < size; j++ {
					pMData := packets[j].GetHeaderMetaData()
					pMData.SwapMacAddress()
				}

				sent := 0
				for sent < size {
					n_tx := port.TxBurst(packets[sent:size])
					sent += n_tx
				}
			}
		}
	}
}

func startCNDP(configStr string) (handle *cndp.System) {
	handle, err := cndp.Open(configStr)
	if err != nil {
		fmt.Printf("error in initialization %s\n", err.Error())
		return nil
	}
	return handle
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, err := parser.Parse()
	if err != nil {
		fmt.Printf("*** invalid arguments %v\n", err)
		os.Exit(1)
	}

	handle := startCNDP(options.Config)
	if handle == nil {
		return
	}

	wg := &sync.WaitGroup{}

	wg.Add(2)

	switch options.Test {
	case "rx":
		go receivePackets(handle, ctx, wg)
	case "tx":
		go transmitPackets(handle, ctx, wg)
	case "lb":
		go reTransmitPackets(handle, ctx, wg)
	default:
		fmt.Println("*** invalid test option")
		os.Exit(1)
	}

	go collectStats(handle, ctx, wg)
	wg.Wait()

	fmt.Println("All workers done, stopping CNDP!")
	handle.Close()
}
