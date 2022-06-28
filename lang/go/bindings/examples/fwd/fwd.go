/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2022 Intel Corporation.
 */

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"

	"github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne"
	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"
	"github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/etimers"
	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"
	tcell "github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	fwdLogID   = "FwdLogID"
	timerSteps = 2
)

type fwdInfo struct {
	handle *cne.System
	ctx    context.Context
	stop   context.CancelFunc
	app    *tview.Application
	flex0  *tview.Flex
	table  *tview.Table
	sigs   chan os.Signal
	timers *etimers.EventTimers
	stats  []*cne.LPortStats
	redraw bool
}

var (
	ConfigFlag string
	TestFlag   string
	PttyFlag   string
	twirl      int
	twirlStr   string = "|/-\\"
)

func init() {
	tlog.Register(fwdLogID, true)

	flag.StringVar(&ConfigFlag, "c", "", "path to configuration file")
	flag.StringVar(&ConfigFlag, "config", "", "path to configuration file")

	flag.StringVar(&TestFlag, "t", "rx", "run tests - rx|tx|lb|chksum")
	flag.StringVar(&TestFlag, "test", "rx", "run tests - rx|tx|lb|chksum")

	flag.StringVar(&PttyFlag, "ptty", "", "pseudo tty index value or path to /dev/pts/X")
}

// collect the stats for each lport and store them in the fwdInfo structure
func (f *fwdInfo) collectStats() {

	for i, lport := range f.handle.LPortList() {
		ps, err := lport.LPortStats()
		if err != nil {
			log.Fatalf("unable to fetch port %s stats\n", lport.Name())
		}

		f.stats[i] = ps
	}
}

// display the stats for all lports into a table
func (f *fwdInfo) displayStats() {

	row, col := 0, 0
	f.table.SetCell(row, col, tview.NewTableCell(fmt.Sprintf("Ports %c", twirlStr[twirl&3])).SetTextColor(tcell.ColorCornsilk))
	twirl++
	f.table.SetCell(row, col+1, tview.NewTableCell(":").SetTextColor(tcell.ColorOrange))
	col += 2

	for i, s := range f.handle.LPortList() {
		f.table.SetCell(row, col+i, tview.NewTableCell(fmt.Sprintf("%14s", s.Name())).SetTextColor(tcell.ColorCornsilk))
	}
	row++
	col = 0
	for _, t := range []string{"Rx Pkts/s", "   TotalPkts", "   MBytes", "   Errors", "   Missed", "   Invalid"} {
		f.table.SetCell(row, col, tview.NewTableCell(fmt.Sprintf("%-12s", t)).SetTextColor(tcell.ColorOrange))
		f.table.SetCell(row, col+1, tview.NewTableCell(":").SetTextColor(tcell.ColorOrange))
		row++
	}
	row++
	for _, t := range []string{"Tx Pkts/s", "   TotalPkts", "   MBytes", "   Errors", "   Dropped", "   Invalid"} {
		f.table.SetCell(row, col, tview.NewTableCell(fmt.Sprintf("%-12s", t)).SetTextColor(tcell.ColorOrange))
		f.table.SetCell(row, col+1, tview.NewTableCell(":").SetTextColor(tcell.ColorOrange))
		row++
	}

	prt := message.NewPrinter(language.English)
	for i, s := range f.stats {
		row = 1
		col = 2 + i

		if s == nil {
			continue
		}
		f.table.SetCell(row+0, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.InPacketRate)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+1, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.InPackets)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+2, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.InBytes/(1024*1024))).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+3, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.InErrors)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+4, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.InMissed)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+5, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.RxInvalid)).SetTextColor(tcell.ColorLightCyan))

		f.table.SetCell(row+7, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.OutPacketRate)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+8, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.OutPackets)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+9, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.OutBytes/(1024*1024))).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+10, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.OutErrors)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+11, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.OutDropped)).SetTextColor(tcell.ColorLightCyan))
		f.table.SetCell(row+12, col, tview.NewTableCell(prt.Sprintf("%14v",
			s.TxInvalid)).SetTextColor(tcell.ColorLightCyan))
	}
}

// receive test routinue and drop the packets on all lport attached to this thread
func (f *fwdInfo) receivePackets(thdName string, lportNames []string) {

	lports := f.handle.LPortsByName(lportNames)
	if len(lports) == 0 {
		return
	}

	tid := f.handle.RegisterThread(thdName)
	if tid <= 0 {
		return
	}
	defer f.handle.UnregisterThread(tid)

	packets := make([]*cne.Packet, 256)

	var lportIds []int
	for _, lport := range lports {
		lportIds = append(lportIds, lport.LPortID())
	}

	for {
		for _, pid := range lportIds {
			select {
			case <-f.ctx.Done():
				return
			default:
				size := cne.RxBurst(pid, packets)
				if size > 0 {
					cne.PktBufferFree(packets[:size])
				}
			}
		}
	}
}

// transmit a fixed packet buffer for all lports on this thread.
func (f *fwdInfo) transmitPackets(thdName string, lportNames []string) {

	lports := f.handle.LPortsByName(lportNames)
	if len(lports) == 0 {
		return
	}

	tid := f.handle.RegisterThread(thdName)
	if tid <= 0 {
		return
	}
	defer f.handle.UnregisterThread(tid)

	txPackets := make([]*cne.Packet, 256)

	// IPv4/UDP 64 byte packet
	// TTL/Port Src/Dest   :       64/ 1234/ 5678
	// Pkt Type:VLAN ID    :      IPv4 / UDP:0001
	// 802.1p CoS/DSCP/IPP :            0/  0/  0
	// VxLAN Flg/Grp/vid   :     0000/    0/    0
	// IP  Destination     :           198.18.1.1
	// 	   Source          :        198.18.0.1/24
	// MAC Destination     :    3c:fd:fe:e4:34:c0
	// 	   Source          :    3c:fd:fe:e4:38:40
	//
	// 0000   3cfd fee4 34c0 3cfd fee4 3840 0800 4500
	// 0010   002e 60ac 0000 4011 8cec c612 0001 c612
	// 0020   0101 04d2 162e 001a 93c6 6b6c 6d6e 6f70
	// 0030   7172 7374 7576 7778 797a 3031

	data, err := hex.DecodeString(
		"3cfdfee434c03cfdfee4384008004500" +
			"002e60ac000040118cecc6120001c612" +
			"010104d2162e001a93c66b6c6d6e6f70" +
			"7172737475767778797a3031")
	if err != nil {
		return
	}

	var lportIds []int
	for _, lport := range lports {
		lportIds = append(lportIds, lport.LPortID())
	}

	for {
		for _, pid := range lportIds {
			select {
			case <-f.ctx.Done():
				return
			default:
				size := cne.PktBufferAlloc(pid, txPackets)

				if size > 0 {
					pkts := txPackets[:size]

					if err := cne.WritePktDataList(pkts, 0, data); err != nil {
						log.Fatalf("Error writing packet data list: %s\n", err.Error())
					}
					cne.TxBurst(pid, pkts, true)
				}
			}
		}
	}
}

// retransmit the received packet on the same lport after swapping the MAC addresses
func (f *fwdInfo) reTransmitPackets(thdName string, lportNames []string) {

	lports := f.handle.LPortsByName(lportNames)
	if len(lports) == 0 {
		return
	}

	tid := f.handle.RegisterThread(thdName)
	if tid <= 0 {
		return
	}
	defer f.handle.UnregisterThread(tid)

	packets := make([]*cne.Packet, 256)

	var lportIds []int
	for _, lport := range lports {
		lportIds = append(lportIds, lport.LPortID())
	}

	for {
		for _, pid := range lportIds {
			select {
			case <-f.ctx.Done():
				return
			default:
				size := cne.RxBurst(pid, packets)
				if size > 0 {
					pkts := packets[:size]

					cne.SwapMacAddrs(pkts)

					cne.TxBurst(pid, pkts, true)
				}
			}
		}
	}
}

// verify IPv4 checksum for each packet for each lport then free the packet.
func (f *fwdInfo) verifyIPv4ChecksumPackets(thdName string, lportNames []string) {

	lports := f.handle.LPortsByName(lportNames)
	if len(lports) == 0 {
		return
	}

	tid := f.handle.RegisterThread(thdName)
	if tid <= 0 {
		return
	}
	defer f.handle.UnregisterThread(tid)

	packets := make([]*cne.Packet, 256)

	var lportIds []int
	for _, lport := range lports {
		lportIds = append(lportIds, lport.LPortID())
	}

	for {
		for _, pid := range lportIds {
			select {
			case <-f.ctx.Done():
				return
			default:
				size := cne.RxBurst(pid, packets)
				if size > 0 {
					for j := 0; j < size; j++ {
						ethHdr := cne.GetEtherHdr(packets[j])
						if ethHdr.EtherType != cne.SwapUint16(cne.EtherTypeIPV4) &&
							cne.IPv4Checksum(cne.GetIPv4(packets[j])) != 0 {
							log.Println("packet ipv4Hdr checksum validation failed")
						}
					}
				}
				cne.PktBufferFree(packets[:size])
			}
		}
	}
}

// setup the system signals to trap and handle shutdown
func (f *fwdInfo) setupSignals(signals ...os.Signal) {

	sigs := make(chan os.Signal, 1)

	f.sigs = sigs

	signal.Notify(sigs, signals...)
	go func() {
		sig := <-sigs

		fmt.Printf("Signal: %v\n", sig)
		f.stop()

		time.Sleep(time.Second)

		f.app.Stop()
		os.Exit(1)
	}()
}

// setup the application fwdInfo structure and allocate the table, etimers, ...
func fwdSetup() *fwdInfo {

	f := &fwdInfo{}

	handle, err := cne.OpenWithFile(ConfigFlag)
	if err != nil {
		log.Fatalf("error in initialization %s\n", err.Error())
	}
	f.handle = handle

	f.app = tview.NewApplication()

	f.flex0 = tview.NewFlex().SetDirection(tview.FlexRow)

	f.table = tview.NewTable().SetBorders(false).SetFixed(1, 1)
	f.table.SetTitleAlign(tview.AlignLeft)
	f.table.SetBorder(true).
		SetTitle(fmt.Sprintf(" %s  TestMode: %s ", cz.Cyan("Press Esc or Q/q or Ctrl-C to quit"),
			cz.Orange(TestFlag)))

	f.flex0.AddItem(f.table, 16, 1, true)

	// Shortcuts to stop application
	f.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch {
		case event.Rune() == 'q' || event.Rune() == 'Q' || event.Key() == tcell.KeyEscape:
			f.stop()
			f.app.Stop()
		default:
		}
		return event
	})

	f.timers = etimers.New(time.Second/timerSteps, timerSteps)

	f.timers.Add("FWD stats", func(step int, ticks uint64) {
		switch step {
		case 0:
			f.collectStats()

		case 1:
			f.app.QueueUpdateDraw(func() {
				f.displayStats()
			})
		}
	})
	f.timers.Start()

	f.ctx, f.stop = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	f.setupSignals(syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV)

	f.stats = make([]*cne.LPortStats, len(f.handle.LPortList()))

	return f
}

func main() {
	flag.Parse()

	if len(ConfigFlag) == 0 {
		flag.PrintDefaults()
		log.Fatalf("-c option must be present\n")
	}

	if len(TestFlag) == 0 {
		flag.PrintDefaults()
		log.Fatalf("-t option must be present\n")
	}

	if len(PttyFlag) > 0 {
		err := tlog.Open(PttyFlag)
		if err != nil {
			fmt.Printf("ttylog open failed: %s\n", err)
			os.Exit(1)
		}
	}

	f := fwdSetup()

	defer f.handle.Close()
	defer f.stop()

	// For each JSON configuration thread create a Go thread and pass
	// the list of LPorts attached to the thread to the test function.
	for thdName, thd := range f.handle.JsonCfg().ThreadInfoMap {
		if len(thd.LPorts) == 0 {
			continue
		}

		switch TestFlag {
		case "rx":
			go f.receivePackets(thdName, thd.LPorts)
		case "tx":
			go f.transmitPackets(thdName, thd.LPorts)
		case "lb":
			go f.reTransmitPackets(thdName, thd.LPorts)
		case "chksum":
			go f.verifyIPv4ChecksumPackets(thdName, thd.LPorts)
		default:
			log.Fatalf("*** invalid test option")
			os.Exit(1)
		}
	}

	// Wait for the user to stop the process
	if err := f.app.SetRoot(f.flex0, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
