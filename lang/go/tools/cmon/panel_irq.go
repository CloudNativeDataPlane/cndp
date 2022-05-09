// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"

	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"
	"github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/irq"
	tab "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/taborder"

	gd "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/graphdata"
	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"
	u "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils"
	"github.com/rivo/tview"
)

type selectData struct {
	window   *SelectWindow
	selected int
	changed  bool
}

// PageIRQ - System IRQ
type PageIRQ struct {
	tabOrder     *tab.Tab
	topFlex      *tview.Flex
	title        *tview.Box
	selectNetdev selectData
	irqData      *tview.Table
	form         *tview.Form
	lcore        *tview.Table
	chart        *tview.TextView
	charts       *gd.GraphInfo
	irqInfo      *irq.Info
	dataRow      int
	lcoreRow     int
	irqNumList   []int
	redraw       bool
	prevCounters []uint64
	rateCounters []uint64
}

const (
	irqPanelName string = "IRQ"
	irqModalName string = "IRQ Modal"
	maxIRQPoints int    = 120
)

// Setup and create the IRQ page structure
func setupIRQ() *PageIRQ {

	pg := &PageIRQ{}

	info := irq.New("/proc/interrupts")
	if info == nil {
		return nil
	}
	info.Collect()

	pg.irqInfo = info
	pg.lcoreRow = 1
	pg.dataRow = 1

	pg.selectNetdev.changed = true
	pg.irqNumList = nil
	pg.redraw = true

	pg.charts = gd.NewGraph(1).SetPrecision(0).SetFieldWidth(9)
	pg.charts.WithIndex(0).SetMaxPoints(128).SetName("CPU Interrupts").AddPoint(0.0)

	return pg
}

func (pg *PageIRQ) resetData() {

	pg.charts.WithIndex(0).Reset()
	pg.charts.WithIndex(0).AddPoint(0.0)
	pg.prevCounters = nil
	pg.rateCounters = nil
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (pg *PageIRQ) affinityMaskToCores(coreMask string) string {

	masks := strings.Split(coreMask, ",")
	lcores := ""
	for j := len(masks) - 1; j >= 0; j-- {
		masks[j] = strings.Trim(masks[j], " ")
		n, _ := strconv.ParseUint(masks[j], 16, 32)

		k := len(masks[j]) * 4
		r := reverse(fmt.Sprintf("%0*b", k, n))

		lcores += r
	}

	lcoreList := ""
	for i, v := range lcores {
		if v == rune('1') {
			lcoreList += fmt.Sprintf("%d ", i)
		}
	}
	return strings.TrimSpace(lcoreList)
}

func (pg *PageIRQ) coresToAffinityMask(coreList string) string {
	var coreValues []int

	coreList = strings.ReplaceAll(coreList, " ", "") // Remove spaces

	// Break done the core list string into cores values
	// The corelist string can be
	for _, v := range strings.Split(coreList, ",") {
		v = strings.TrimSpace(v)
		if strings.Contains(v, "-") {
			c := strings.Split(v, "-")
			if len(c) != 2 {
				return ""
			}
			s, _ := strconv.Atoi(c[0])
			e, _ := strconv.Atoi(c[1])
			if s > e { // Flip start and end if in wrong order
				s, e = e, s
			}
			for ; s <= e; s++ {
				coreValues = append(coreValues, s)
			}
		} else {
			s, _ := strconv.Atoi(v)
			coreValues = append(coreValues, s)
		}
	}
	sort.Ints(coreValues)

	n := (u.NumCPUs() + 31) / 32 // Round up to next 32 bit value
	cores := make([]uint32, n)
	for _, v := range coreValues {
		d := v / 32
		cores[d] |= cores[d] | (1 << (v % 32))
	}

	str := ""
	for i, v := range cores {
		if i < (n - 1) {
			str += reverse(fmt.Sprintf("%08x", v))
			str += ","
		} else {
			str += reverse(fmt.Sprintf("%0*x", (u.NumCPUs()-(i*32))/4, v))
		}
	}

	return reverse(str)
}

// IRQPanelSetup setup the main event page
func IRQPanelSetup(nextSlide func()) (pageName string, content tview.Primitive) {

	pg := setupIRQ()

	to := tab.New(irqPanelName, cmon.app)
	pg.tabOrder = to

	// Flex boxes used to hold tview window types
	flex0 := tview.NewFlex().SetDirection(tview.FlexRow)
	flex1 := tview.NewFlex().SetDirection(tview.FlexColumn)
	flex2 := tview.NewFlex().SetDirection(tview.FlexRow)

	// Create the top window for basic information about tool and panel
	TitleBox(flex0)
	pg.topFlex = flex0

	// Core selection window to be able to select a core to view
	table := CreateTableView(flex1, "Netdev (n)", tview.AlignLeft, 18, 1, true)
	table.SetFixed(0, 0)

	names := pg.irqInfo.NetdevList()
	lst := make([]interface{}, len(names))
	for i, v := range names {
		lst[i] = v
	}
	// Select window setup and callback function when selection changes. Skip first row
	pg.selectNetdev.window = NewSelectWindow(table, "Netdev", 0, func(row, col int) {
		if row != pg.selectNetdev.selected {
			pg.selectNetdev.window.UpdateItem(row, col)

			pg.selectNetdev.changed = true

			pg.selectNetdev.selected = row
			pg.resetData()
		}
	}).AddColumn(1, lst, cz.SkyBlueColor)

	pg.irqData = CreateTableView(flex2, "Data (d)", tview.AlignLeft, 0, 1, true).
		Select(1, 0).
		SetSelectedStyle(tcell.StyleDefault.Foreground(tcell.ColorBlack).Background(tcell.ColorLightYellow).Reverse(false)).
		SetSelectionChangedFunc(func(row, col int) {
			if row == 0 {
				row = 1
				pg.irqData.Select(row, 0)
			}
			pg.dataRow = row

			info := pg.irqData.GetCell(row, 0).GetReference().(*irq.InfoIRQ)

			s := fmt.Sprintf("SMP Affinity %d:%d", info.Device.QueueID, info.IRQNum)
			pg.form.SetTitle(TitleColor(s))

			pg.resetData()
		}).SetSelectedFunc(func(row, col int) {
		info := pg.irqData.GetCell(row, 0).GetReference().(*irq.InfoIRQ)

		tlog.DoPrintf("Enter pressed on %d, %d, irqNum %d, %s\n", row, col, info.IRQNum, info.SMPAffinity)

		pg.form.SetFocus(0) // Start at the first field in the form
		item := pg.form.GetFormItem(0).(*tview.InputField)
		item.SetText(pg.affinityMaskToCores(info.SMPAffinity)).SetDoneFunc(func(key tcell.Key) {
			switch key {
			case tcell.KeyEscape:
				item.SetText(pg.affinityMaskToCores(info.SMPAffinity))
			case tcell.KeyEnter:
				smp := pg.coresToAffinityMask(item.GetText())
				tlog.DoPrintf("Affinity: %s\n", smp)
				pg.irqInfo.SetAffinity(info, smp)
			}
		})
		to.SetFocus(pg.form)
	})

	pg.form = CreateForm(flex2, "SMP Affinity 0:0", tview.AlignLeft, 5, 0, true).
		AddInputField(cz.ColorWithName("Green", "Core List:"), "", 60, nil, nil).
		SetCancelFunc(func() {
			tlog.DoPrintf("Cancel\n")
			cmon.app.SetFocus(pg.irqData)
		}).
		SetHorizontal(true)
	pg.form.SetBorder(true)
	flex1.AddItem(flex2, 0, 3, true)

	pg.lcore = CreateTableView(flex1, "Cores (c)", tview.AlignLeft, 24, 2, true).Select(1, 0).
		SetFixed(1, 0).
		SetSelectedStyle(tcell.StyleDefault.Foreground(tcell.ColorBlack).Background(tcell.ColorLightYellow).Reverse(false)).
		SetSeparator(tview.Borders.Vertical).
		SetSelectionChangedFunc(func(row, col int) {
			if row == 0 {
				row = 1
				pg.lcore.Select(row, 0)
			}
			pg.lcoreRow = row
			pg.resetData()
		})

	flex0.AddItem(flex1, 0, 3, true)

	pg.chart = CreateTextView(flex0, "CPU Interrupts", tview.AlignLeft, 0, 1, true)

	to.Add(pg.selectNetdev.window.table, 'n')
	to.Add(pg.irqData, 'd')
	to.Add(pg.lcore, 'c')
	to.SetInputDone()

	// Create timer and callback function to display and process IRQ data
	cmon.timers.Add(irqPanelName, func(step int, ticks uint64) {
		// up to 4 cases, done every second
		switch step {
		case 0:
			pg.irqInfo.Collect()
		case 1:
			if pg.topFlex.HasFocus() {
				pg.collectChartData()
			}
		case 2:
			if pg.topFlex.HasFocus() {
				cmon.app.QueueUpdateDraw(func() {
					pg.displayIRQPage()
				})
			} else {
				pg.redraw = true
			}
		}

	})

	return irqPanelName, pg.topFlex
}

// Display the IRQ data in the windows created
func (pg *PageIRQ) displayIRQPage() {

	pg.displayData(pg.irqData)
	pg.lcoreCounters(pg.lcore)
	pg.displayGraph(pg.chart)

	if pg.selectNetdev.changed {
		pg.selectNetdev.changed = false
		pg.irqData.ScrollToBeginning()
		pg.lcore.ScrollToBeginning()
	}
}

// Collect the graph data to be displayed in the chart window
func (pg *PageIRQ) collectChartData() {

	if pg.lcoreRow == 0 || pg.dataRow == 0 {
		return
	}
	if len(pg.rateCounters) == 0 {
		pg.rateCounters = make([]uint64, u.NumCPUs())
	}
	g := pg.charts.WithIndex(0)

	g.AddPoint(float64(pg.rateCounters[pg.lcoreRow-1]))

}

// Display the IRQ data
func (pg *PageIRQ) displayData(view *tview.Table) {

	netdev := pg.selectNetdev.window.ItemValue()

	d := pg.irqInfo.DataByNetdev(netdev)
	if d == nil {
		return
	}

	var lst []int
	for k := range d.DataIRQ {
		lst = append(lst, k)
	}
	sort.Ints(lst)

	view.SetCell(0, 0, tview.NewTableCell("QID").SetTextColor(tcell.ColorYellow))
	view.SetCell(0, 1, tview.NewTableCell("IRQ #").SetTextColor(tcell.ColorYellow))
	view.SetCell(0, 2, tview.NewTableCell("Drv-Netdev-QID").SetTextColor(tcell.ColorYellow))
	view.SetCell(0, 3, tview.NewTableCell("SMP Affinity CoreMask").SetTextColor(tcell.ColorYellow))
	view.SetCell(0, 4, tview.NewTableCell("lcore ID(s)").SetTextColor(tcell.ColorYellow))

	pg.irqNumList = make([]int, 0)
	pg.irqNumList = append(pg.irqNumList, -1)

	for i, k := range lst {
		view.SetCell(i+1, 1, tview.NewTableCell(fmt.Sprintf("%4d", k)).SetTextColor(tcell.ColorGreen))
		pg.irqNumList = append(pg.irqNumList, k)

		info := pg.irqInfo.DataByIRQ(netdev, k)
		if info != nil {
			s := fmt.Sprintf("%s-%s-%d", info.Device.Driver, info.Device.Netdev, info.Device.QueueID)
			c := tview.NewTableCell(fmt.Sprintf("%4d", info.Device.QueueID)).
				SetReference(info).
				SetTextColor(tcell.ColorSkyblue)
			view.SetCell(i+1, 0, c)
			view.SetCell(i+1, 2, tview.NewTableCell(s).SetTextColor(tcell.ColorThistle))

			view.SetCell(i+1, 3, tview.NewTableCell(info.SMPAffinity).SetTextColor(tcell.ColorDeepPink))
			view.SetCell(i+1, 4, tview.NewTableCell(pg.affinityMaskToCores(info.SMPAffinity)).SetTextColor(tcell.ColorLightSeaGreen))
		}
	}
	r, _ := view.GetSelection()
	info := view.GetCell(r, 0).GetReference().(*irq.InfoIRQ)
	s := fmt.Sprintf("SMP Affinity %d:%d", info.Device.QueueID, info.IRQNum)
	pg.form.SetTitle(TitleColor(s))
}

// Display the lcore interrupt counters
func (pg *PageIRQ) lcoreCounters(view *tview.Table) {

	counters := pg.irqInfo.CoreCounters(pg.selectNetdev.window.ItemValue(), pg.irqNumList[pg.dataRow])
	if counters == nil {
		tlog.DoPrintf("Core Counters %v, %d is empty\n", pg.selectNetdev.window.ItemValue(), pg.dataRow)
		return
	}
	if len(pg.prevCounters) == 0 {
		pg.prevCounters = counters
	}

	view.SetCell(0, 0, tview.NewTableCell("lcore ID").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))
	view.SetCell(0, 1, tview.NewTableCell("Interrupts").SetAlign(tview.AlignCenter).SetTextColor(tcell.ColorYellow))

	for i, v := range counters {
		s := fmt.Sprintf("%5d", i)
		c := tview.NewTableCell(s).
			SetAlign(tview.AlignLeft).
			SetTextColor(tcell.ColorLightSkyBlue)
		view.SetCell(i+1, 0, c)

		s = fmt.Sprintf("%12d", v)
		c = tview.NewTableCell(s).
			SetAlign(tview.AlignLeft).
			SetTextColor(tcell.ColorSeaGreen)
		if pg.prevCounters[i] != v {
			c.SetTextColor(tcell.ColorDeepPink)
		}
		view.SetCell(i+1, 1, c)
	}
	if pg.redraw {
		pg.redraw = false
		view.ScrollToBeginning()
	}
	pg.rateCounters = make([]uint64, u.NumCPUs())
	for i, v := range counters {
		pg.rateCounters[i] = v - pg.prevCounters[i]
	}
	pg.prevCounters = counters
}

func (pg *PageIRQ) displayGraph(view *tview.TextView) {

	view.SetText(pg.charts.MakeChart(view, 0, 0))
}
