// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	cz "cndp.org/colorize"
	tab "cndp.org/taborder"
	tlog "cndp.org/ttylog"
	u "cndp.org/utils"
	"github.com/rivo/tview"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

// PageSysInfo - Data for main page information
type PageSysInfo struct {
	topFlex         *tview.Flex
	host            *tview.TextView
	mem             *tview.TextView
	cpuInfo         *tview.TextView
	cpuLayout       *tview.Table
	hostNet         *tview.Table
	cpuLoad1        *tview.TextView
	cpuLoad2        *tview.TextView
	cpuLoad3        *tview.TextView
	tabOrder        *tab.Tab
	numLogical      int16
	numPhysical     int16
	numSockets      int16
	numHyperThreads int16
	info            []cpu.InfoStat
	Cores           []uint16
	Sockets         []uint16
	CoreMap         map[uint16][]uint16
	percent         []float64
	redraw          bool
}

const (
	sysinfoPanelName string = "SysInfo"
)

func init() {
	tlog.Register("SysInfoLogID")
}

// Printf - send message to the ttylog interface
func (pg *PageSysInfo) Printf(format string, a ...interface{}) {
	tlog.Log("SysInfoLogID", fmt.Sprintf("%T.", pg)+format, a...)
}

// locate the cpu id or physical id in the slice
func uint16InSlice(b uint16, lst []uint16) bool {

	for _, v := range lst {
		if v == b {
			return true
		}
	}
	return false
}

// setupSysInfo - setup and init the sysInfo page
func setupSysInfo() *PageSysInfo {

	pg := &PageSysInfo{}

	info, err := cpu.Info()
	if err != nil {
		pg.Printf("cpu.Info() returned %s\n", err)
		return nil
	}
	pg.info = info

	pg.CoreMap = make(map[uint16][]uint16)
	pg.Cores = []uint16{}
	pg.Sockets = []uint16{}
	pg.redraw = true

	for lcore, c := range info {
		core, _ := strconv.Atoi(c.CoreID)

		// If the core is found in the list of cores then append that core to
		// a list for cores
		if !uint16InSlice(uint16(core), pg.Cores) {
			pg.Cores = append(pg.Cores, uint16(core))
		}

		// If the socket id is found in the list of sockets then append that socket to
		// a list for sockets
		socket, _ := strconv.Atoi(c.PhysicalID)
		if !uint16InSlice(uint16(socket), pg.Sockets) {
			pg.Sockets = append(pg.Sockets, uint16(socket))
		}

		key := uint16((socket << 8) | core)

		// Add the core to the coremap
		_, ok := pg.CoreMap[key]
		if !ok {
			pg.CoreMap[key] = []uint16{}
		}
		pg.CoreMap[key] = append(pg.CoreMap[key], uint16(lcore))
	}

	// Calculate the cores, sockets and logical cores in the system
	numLogical, _ := cpu.Counts(true)
	numPhysical, _ := cpu.Counts(false)
	pg.Printf("numLogical %d, numPhysical %d\n", numLogical, numPhysical)

	pg.numSockets = int16(len(pg.Sockets))
	pg.numLogical = int16(numLogical)
	pg.numPhysical = (int16(numPhysical) / pg.numSockets)
	pg.numHyperThreads = (pg.numLogical / (pg.numPhysical * pg.numSockets))

	return pg
}

// SysInfoPanelSetup setup the main cpu page
func SysInfoPanelSetup(nextSlide func()) (pageName string, content tview.Primitive) {

	pg := setupSysInfo()

	to := tab.New(sysinfoPanelName, cmon.app)
	pg.tabOrder = to

	flex0 := tview.NewFlex().SetDirection(tview.FlexRow)
	flex1 := tview.NewFlex().SetDirection(tview.FlexRow)
	flex2 := tview.NewFlex().SetDirection(tview.FlexColumn)
	flex3 := tview.NewFlex().SetDirection(tview.FlexColumn)

	TitleBox(flex0)

	pg.host = CreateTextView(flex2, "Host (h)", tview.AlignLeft, 0, 5, true)
	pg.mem = CreateTextView(flex2, "Memory (m)", tview.AlignLeft, 0, 4, false)
	pg.cpuLayout = CreateTableView(flex2, "CPU Layout (l)", tview.AlignLeft, 0, 3, false)
	flex1.AddItem(flex2, 0, 2, true)

	pg.cpuInfo = CreateTextView(flex1, "CPU (c)", tview.AlignLeft, 0, 1, true)
	pg.hostNet = CreateTableView(flex1, "Host Network Stats (n)", tview.AlignLeft, 0, 2, false)
	flex0.AddItem(flex1, 0, 1, true)

	pg.cpuLoad1 = CreateTextView(flex3, "CPU Load (1)", tview.AlignLeft, 0, 1, true)
	pg.cpuLoad2 = CreateTextView(flex3, "CPU Load (2)", tview.AlignLeft, 0, 1, false)
	pg.cpuLoad3 = CreateTextView(flex3, "CPU Load (3)", tview.AlignLeft, 0, 1, false)
	flex1.AddItem(flex3, 0, 4, true)

	to.Add(pg.host, 'h')
	to.Add(pg.mem, 'm')
	to.Add(pg.cpuLayout, 'l')
	to.Add(pg.cpuInfo, 'c')
	to.Add(pg.hostNet, 'n')

	to.Add(pg.cpuLoad1, '1')
	to.Add(pg.cpuLoad2, '2')
	to.Add(pg.cpuLoad3, '3')

	to.SetInputDone()

	pg.topFlex = flex0

	// Setup static pages
	pg.displayHost(pg.host)
	pg.displayCPU(pg.cpuInfo)
	pg.displayLayout(pg.cpuLayout)
	pg.displayHostNet(pg.hostNet)
	pg.hostNet.ScrollToBeginning()

	percent, err := cpu.Percent(0, true)
	if err != nil {
		tlog.DoPrintf("Percent: %v\n", err)
	}
	pg.percent = percent

	cmon.timers.Add(sysinfoPanelName, func(step int, ticks uint64) {
		if pg.topFlex.HasFocus() {
			cmon.app.QueueUpdateDraw(func() {
				pg.displaySysInfo(step, ticks)
			})
		} else {
			pg.redraw = true
		}
	})

	return sysinfoPanelName, pg.topFlex
}

// Callback timer routine to display the sysinfo panel
func (pg *PageSysInfo) displaySysInfo(step int, ticks uint64) {

	switch step {
	case 0:
		pg.displayMem(pg.mem)

	case 1:
		percent, err := cpu.Percent(0, true)
		if err != nil {
			tlog.DoPrintf("Percent: %v\n", err)
		}
		pg.percent = percent

	case 2:
		pg.displayHostNet(pg.hostNet)
		pg.displayLoadData(pg.cpuLoad1, 1)
		pg.displayLoadData(pg.cpuLoad2, 2)
		pg.displayLoadData(pg.cpuLoad3, 3)
	}
}

// Display the Host information
func (pg *PageSysInfo) displayHost(view *tview.TextView) {

	str := ""
	info, _ := host.Info()
	str += fmt.Sprintf("Hostname: %s\n", cz.Yellow(info.Hostname))
	str += fmt.Sprintf("Host ID : %s\n", cz.Green(info.HostID))
	str += fmt.Sprintf("OS      : %s-%s\n",
		cz.GoldenRod(strings.Title(info.OS)), cz.Orange(info.KernelVersion))
	str += fmt.Sprintf("Platform: %s %s, Family: %s\n",
		cz.MediumSpringGreen(strings.Title(info.Platform)),
		cz.LightSkyBlue(info.PlatformVersion),
		cz.Green(strings.Title(info.PlatformFamily)))

	days := info.Uptime / (60 * 60 * 24)
	hours := (info.Uptime - (days * 60 * 60 * 24)) / (60 * 60)
	minutes := ((info.Uptime - (days * 60 * 60 * 24)) - (hours * 60 * 60)) / 60
	s := fmt.Sprintf("%d days, %d hours, %d minutes", days, hours, minutes)
	str += fmt.Sprintf("Uptime  : %s\n", cz.DeepPink(s))

	str += fmt.Sprintf("Virtual : Role: %s, System: %s",
		cz.Orange(info.VirtualizationRole),
		cz.Red(info.VirtualizationSystem))

	view.SetText(str)
}

// Display the information about the memory in the system
func (pg *PageSysInfo) displayMem(view *tview.TextView) {

	str := ""

	v, _ := mem.VirtualMemory()

	str += fmt.Sprintf("Memory  Total: %s MiB\n", cz.LightBlue(v.Total/u.MegaBytes, 6))
	str += fmt.Sprintf("         Free: %s MiB\n", cz.Green(v.Free/u.MegaBytes, 6))
	str += fmt.Sprintf("         Used: %s Percent\n\n", cz.Orange(v.UsedPercent, 6, 1))

	//	for i := 0; i < int(pg.numSockets); i++ {
	//		v, _ := mem.VirtualMemoryPerSocket(i)
	//		str += fmt.Sprintf("%s:\n", cz.MediumSpringGreen(fmt.Sprintf("NUMA Node %d Hugepage Info", i)))
	//		str += fmt.Sprintf("   Free/Total: %s/%s pages\n", cz.LightBlue(v.HugePagesFree, 6), cz.LightBlue(v.HugePagesTotal, 6))
	//		str += fmt.Sprintf("      Surplus: %s pages\n\n", cz.LightBlue(v.HugePagesSurp, 6))
	//	}

	str += fmt.Sprintf("%s:\n", cz.MediumSpringGreen("Total Hugepage Info"))
	str += fmt.Sprintf("   Free/Total: %s/%s pages\n", cz.LightBlue(v.HugePagesFree, 6), cz.LightBlue(v.HugePagesTotal, 6))
	//	str += fmt.Sprintf(" Rsvd/Surplus: %s/%s pages\n", cz.LightBlue(v.HugePagesRsvd, 6), cz.LightBlue(v.HugePagesSurp, 6))
	str += fmt.Sprintf("Hugepage Size: %s Kb\n", cz.LightBlue(v.HugePageSize/u.KiloBytes, 6))

	view.SetText(str)
}

// clamp the data to a fixed set of ranges
func clamp(x, low, high float64) float64 {

	if x > high {
		return high
	}
	if x < low {
		return low
	}
	return x
}

// Display the CPU information
func (pg *PageSysInfo) displayCPU(view *tview.TextView) {
	str := ""

	v := pg.info
	str += fmt.Sprintf("Vendor         : %s", cz.GoldenRod(v[0].VendorID, -14))
	str += fmt.Sprintf(" %s\n", cz.MediumSpringGreen(v[0].ModelName))
	str += fmt.Sprintf("Cores Logical  : %s ", cz.LightBlue(pg.numLogical, -6))
	str += fmt.Sprintf("Physical : %s ", cz.LightBlue(pg.numPhysical, -6))
	str += fmt.Sprintf("Hyper-Thread : %s ", cz.MediumSpringGreen(pg.numHyperThreads, -6))
	str += fmt.Sprintf("Sockets : %s\n", cz.Orange(pg.numSockets))

	view.SetText(str)
	view.ScrollToBeginning()
}

// Build up a string for displaying the CPU layout window
func buildStr(a []uint16, width int) string {

	str := "{"

	for k, v := range a {
		str += fmt.Sprintf("%s", cz.Green(v, width))
		if k < (len(a) - 1) {
			str += " /"
		}
	}

	return str + " }"
}

// Display the CPU layout data
func (pg *PageSysInfo) displayLayout(view *tview.Table) {

	str := fmt.Sprintf("%s", cz.LightBlue(" Core", -5))
	tableCell := tview.NewTableCell(cz.YellowGreen(str)).
		SetAlign(tview.AlignLeft).
		SetSelectable(false)
	view.SetCell(0, 0, tableCell)

	for k, s := range pg.Sockets {
		str = fmt.Sprintf("%s", cz.LightBlue(fmt.Sprintf("Socket %d", s)))
		tableCell := tview.NewTableCell(cz.YellowGreen(str)).
			SetAlign(tview.AlignCenter).
			SetSelectable(false)
		view.SetCell(0, k+1, tableCell)
	}

	row := int16(1)

	pg.Printf("numPhysical %d, numSockets %d\n", pg.numPhysical, pg.numSockets)
	pg.Printf("pg.Cores = %v\n", pg.Cores)
	for _, cid := range pg.Cores {
		col := int16(0)

		tableCell := tview.NewTableCell(cz.Red(cid, 4)).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		view.SetCell(int(row), int(col), tableCell)

		pg.Printf("cid %d\n", cid)
		for sid := int16(0); sid < pg.numSockets; sid++ {
			pg.Printf("  sid %d\n", sid)
			key := uint16(sid<<uint16(8)) | cid
			v, ok := pg.CoreMap[key]
			if ok {
				str = fmt.Sprintf(" %s", buildStr(v, 3))
			} else {
				str = fmt.Sprintf(" %s", strings.Repeat(".", 10))
			}
			tableCell := tview.NewTableCell(cz.YellowGreen(str)).
				SetAlign(tview.AlignLeft).
				SetSelectable(false)
			view.SetCell(int(row), int(col+1), tableCell)
			col++
		}
		row++
	}
	view.ScrollToBeginning()
}

// Grab the percent load dat and display the meters
func (pg *PageSysInfo) displayLoadData(view *tview.TextView, flg int) {

	num := int16(pg.numLogical/3) + 1

	switch flg {
	case 1:
		pg.displayLoad(pg.percent, 0, num, view)
	case 2:
		pg.displayLoad(pg.percent, num, num*int16(2), view)
	case 3:
		pg.displayLoad(pg.percent, num*int16(2), pg.numLogical, view)
	}
	if pg.redraw {
		view.ScrollToBeginning()
		pg.redraw = false
	}
}

// Display the load meters
func (pg *PageSysInfo) displayLoad(percent []float64, start, end int16, view *tview.TextView) {

	_, _, width, _ := view.GetInnerRect()

	width -= 14
	if width <= 0 {
		return
	}
	str := ""

	str += fmt.Sprintf("%s\n", cz.Orange("Core Percent          Load Meter"))

	for i := start; i < end; i++ {
		str += pg.drawMeter(i, percent[i], width)
	}

	view.SetText(str)
}

// Draw the meter for the load
func (pg *PageSysInfo) drawMeter(id int16, percent float64, width int) string {

	total := 100.0

	p := clamp(percent, 0.0, total)
	if p > 0 {
		p = math.Ceil((p / total) * float64(width))
	}

	bar := make([]byte, width)

	for i := 0; i < width; i++ {
		if i <= int(p) {
			bar[i] = '|'
		} else {
			bar[i] = ' '
		}
	}
	str := fmt.Sprintf(" %3d:%s%% [%s]\n",
		id, cz.Red(percent, 5, 1), cz.Yellow(string(bar)))

	return str
}

// Display the Host network information
func (pg *PageSysInfo) displayHostNet(view *tview.Table) {

	row := 0
	col := 0

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("network interfaces: %s\n", err)
		return
	}

	setTitle := func(title string, col int) int {
		tableCell := tview.NewTableCell(title).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		pg.hostNet.SetCell(0, col, tableCell)
		col++

		return col
	}

	titles := []string{"Name", "Flags", "MTU", "IP Addr",
		"RX Pkts", "TX Pkts", "RX Err", "TX Err",
		"RX Drop", "Tx Drop", "MAC"}

	for _, v := range titles {
		col = setTitle(cz.Green(v), col)
	}

	setCell := func(row, col int, value string) int {
		tableCell := tview.NewTableCell(value).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		pg.hostNet.SetCell(row, col, tableCell)
		col++

		return col
	}

	ioCount, err := net.IOCounters(true)
	if err != nil {
		pg.Printf("network IO Count: %s\n", err)
		return
	}

	row++ // Skip the headers row
	for _, f := range ifaces {
		if f.Name == "lo" {
			continue
		}
		col = setCell(row, 0, cz.LightBlue(f.Name))
		col = setCell(row, col, cz.LightSkyBlue(f.Flags))
		col = setCell(row, col, cz.LightYellow(f.MTU))
		if len(f.Addrs) > 0 {
			col = setCell(row, col, cz.Orange(f.Addrs[0].Addr))
		} else {
			col++
		}

		for _, k := range ioCount {
			if k.Name != f.Name {
				continue
			}
			col = setCell(row, col, cz.Wheat(k.PacketsRecv))
			col = setCell(row, col, cz.Wheat(k.PacketsSent))
			col = setCell(row, col, cz.Wheat(k.Errin))
			col = setCell(row, col, cz.Wheat(k.Errout))
			col = setCell(row, col, cz.Wheat(k.Dropin))
			col = setCell(row, col, cz.Wheat(k.Dropout))
			break
		}
		col = setCell(row, col, cz.Wheat(f.HardwareAddr))

		row++
	}

	for ; row < view.GetRowCount(); row++ {
		view.RemoveRow(row)
	}
}
