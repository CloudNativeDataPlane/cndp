/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2022 Intel Corporation.
 */

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	cndp "github.com/CloudNativeDataPlane/cndp/cndpgo"
	flags "github.com/jessevdk/go-flags"
)

type Options struct {
	Config     string   `short:"c" long:"config" description:"path to configuration file"`
	Test       string   `short:"t" long:"test" description:"run tests - rx|tx|lb|chksum"`
	LPortNames []string `short:"p" long:"lport names" description:"list of lport names comma-seperated"`
}

var options Options
var parser = flags.NewParser(&options, flags.Default)

func collectStats(handle *cndp.System, lportName string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	port, err := handle.GetPort(lportName)
	if err != nil {
		log.Fatalf("error getting port %s: %s\n", lportName, err.Error())
		return
	}
	var pInPackets uint64 = 0
	var pOutPackets uint64 = 0

	for {
		select {
		case <-ctx.Done():
			return
		default:

			ps, err := port.GetPortStats()
			if err != nil {
				log.Fatalf("unable to fetch port %s stats: %s\n", lportName, err.Error())
				return
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("\nPort %s stats:\n", lportName))
			sb.WriteString(fmt.Sprintf("RX Pkts:%d\n", ps.InPackets))
			sb.WriteString(fmt.Sprintf("RX MBs:%d\n", ps.InBytes))
			sb.WriteString(fmt.Sprintf("RX Errors:%d\n", ps.InErrors))
			sb.WriteString(fmt.Sprintf("RX Missed:%d\n", ps.InMissed))
			sb.WriteString(fmt.Sprintf("RX Invalid:%d\n", ps.RxInvalid))
			sb.WriteString(fmt.Sprintf("RX PPS:%d\n", ps.InPackets-pInPackets))
			sb.WriteString(fmt.Sprintf("TX Pkts:%d\n", ps.OutPackets))
			sb.WriteString(fmt.Sprintf("TX MBs:%d\n", ps.OutBytes))
			sb.WriteString(fmt.Sprintf("TX Errors:%d\n", ps.OutErrors))
			sb.WriteString(fmt.Sprintf("TX Missed:%d\n", ps.OutDropped))
			sb.WriteString(fmt.Sprintf("TX Invalid:%d\n", ps.TxInvalid))
			sb.WriteString(fmt.Sprintf("TX PPS:%d\n\n", ps.OutPackets-pOutPackets))

			log.Printf(sb.String())

			pInPackets = ps.InPackets
			pOutPackets = ps.OutPackets

			time.Sleep(1 * time.Second)
		}
	}
}

func receivePackets(handle *cndp.System, lportName string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("rx_" + lportName)
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(lportName)
	if err != nil {
		log.Fatalf("error getting port %s: %s\n", lportName, err.Error())
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

func makeUint16Slice(start uintptr, length int) (data []uint16) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}

func getWords(ptr unsafe.Pointer, length, offset int) (data []uint16) {
	uptr := uintptr(ptr) + uintptr(offset)
	data = makeUint16Slice(uptr, length/2)

	if length&1 != 0 {
		v := uint16(uintptr(ptr)+uintptr(length-1)) << 8
		data = append(data, v)
	}
	return
}

func verifyIPv4(l2 unsafe.Pointer) bool {
	if l2 == nil {
		return false
	}
	ethWords := getWords(l2, cndp.EtherLen, 0)
	if !(len(ethWords) < cndp.EtherLen/2) {
		if cndp.SwapBytesUint16(ethWords[6]) == cndp.ETHER_TYPE_IPV4 {
			return true
		}
	}

	return false
}

func reduceChecksum(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

func calculateDataChecksum(data []uint16) uint32 {
	var sum uint32
	for i := range data {
		sum += uint32(cndp.SwapBytesUint16(data[i]))
	}
	return sum
}

func verifyIPv4Checksum(l3 unsafe.Pointer) bool {
	if l3 == nil {
		return false
	}
	ipv4Words := getWords(l3, cndp.IPv4Len, 0)
	if !(len(ipv4Words) < cndp.IPv4Len/2) {
		temp := ipv4Words[5]
		ipv4Words[5] = 0
		checksum := ^reduceChecksum(calculateDataChecksum(ipv4Words))
		ipv4Words[5] = temp
		if checksum == cndp.SwapBytesUint16(ipv4Words[5]) {
			return true
		}
	}
	return false
}

func verifyIPv4ChecksumPackets(handle *cndp.System, lportName string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("chksum_" + lportName)
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(lportName)
	if err != nil {
		log.Fatalf("error getting port %s: %s\n", lportName, err.Error())
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
					if verifyIPv4(pMData.L2) && !verifyIPv4Checksum(pMData.L3) {
						log.Println("packet ipv4Hdr checksum validation failed")
					}
				}
			}
			cndp.FreePacketBuffer(packets[:size])
		}
	}
}

func transmitPackets(handle *cndp.System, lportName string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("tx_" + lportName)
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(lportName)
	if err != nil {
		log.Fatalf("error getting port %s: %s\n", lportName, err.Error())
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

func reTransmitPackets(handle *cndp.System, lportName string, ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tid := handle.RegisterThread("lb_" + lportName)
	if tid <= 0 {
		return
	}
	defer handle.UnregisterThread(tid)

	port, err := handle.GetPort(lportName)
	if err != nil {
		log.Fatalf("error getting port %s: %s\n", lportName, err.Error())
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
		log.Fatalf("error in initialization %s\n", err.Error())
		return nil
	}
	return handle
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	_, err := parser.Parse()
	if err != nil {
		log.Fatalf("*** invalid arguments %v\n", err)
		os.Exit(1)
	}

	handle := startCNDP(options.Config)
	if handle == nil {
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(2 * len(options.LPortNames))

	for _, lportName := range options.LPortNames {
		switch options.Test {
		case "rx":
			go receivePackets(handle, lportName, ctx, wg)
		case "tx":
			go transmitPackets(handle, lportName, ctx, wg)
		case "lb":
			go reTransmitPackets(handle, lportName, ctx, wg)
		case "chksum":
			go verifyIPv4ChecksumPackets(handle, lportName, ctx, wg)
		default:
			log.Fatalf("*** invalid test option")
			os.Exit(1)
		}

		go collectStats(handle, lportName, ctx, wg)
	}

	wg.Wait()
	log.Println("All workers done, stopping CNDP!")
	handle.Close()
}
