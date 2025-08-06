// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2025 Intel Corporation

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"

	tab "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/taborder"
	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"

	"github.com/rivo/tview"
)

const (
	netstatPanelName string = "Netstat"
)

// NetstatData - Hold the stats name and counter data
type NetstatData struct {
	Names    []string
	Counters []uint64
}

type NetstatInfo struct {
	Data map[string]*NetstatData
}

type dInfo struct {
	filename string
	sections []string
	prev     *NetstatInfo
}

// NetstatPanel - Data for main page information
type NetstatPanel struct {
	tabOrder *tab.Tab
	topFlex  *tview.Flex

	netstat1       *tview.Table
	netstat2       *tview.Table
	changed        bool
	redraw         bool
	displaySeconds uint64

	nInfo []*dInfo
}

// Setup and create the netstat panel structure
func setupNetstatPanel() *NetstatPanel {

	pg := &NetstatPanel{changed: true, redraw: true}

	pg.nInfo = append(pg.nInfo, &dInfo{
		filename: "/proc/net/snmp",
		sections: []string{"IP", "UDP", "TCP", "ICMP", "ICMPMSG"},
		prev:     &NetstatInfo{}})
	pg.nInfo = append(pg.nInfo, &dInfo{
		filename: "/proc/net/netstat",
		sections: []string{"TCPEXT", "IPEXT", "MPTCPEXT"},
		prev:     &NetstatInfo{}})

	return pg
}

// NetstatPanelSetup setup the main event page
func NetstatPanelSetup(nextSlide func()) (pageName string, content tview.Primitive) {

	pg := setupNetstatPanel()

	to := tab.New(netstatPanelName, cmon.app)
	pg.tabOrder = to

	flex0 := tview.NewFlex().SetDirection(tview.FlexRow)
	flex1 := tview.NewFlex().SetDirection(tview.FlexRow)

	TitleBox(flex0)

	pg.netstat1 = CreateTableView(flex1, "SNMP (s) Update 3sec", tview.AlignLeft, 0, 1, true).
		SetSeparator(tview.Borders.Vertical).
		SetEvaluateAllRows(true)

	pg.netstat2 = CreateTableView(flex1, "Netstat (n) Update 3sec", tview.AlignLeft, 0, 1, true).
		SetSeparator(tview.Borders.Vertical).
		SetEvaluateAllRows(true)

	flex0.AddItem(flex1, 0, 2, true)

	to.Add(pg.netstat1, 's')
	to.Add(pg.netstat2, 'n')

	to.SetInputDone()

	pg.topFlex = flex0

	pg.displayNetstatSNMP(pg.netstat1)
	pg.displayNetstat(pg.netstat2)
	pg.netstat1.ScrollToBeginning()
	pg.netstat2.ScrollToBeginning()

	cmon.timers.Add(netstatPanelName, func(step int, ticks uint64) {
		if pg.topFlex.HasFocus() {
			cmon.app.QueueUpdateDraw(func() {
				pg.displayNetstatPanel(step, ticks)
			})
		} else {
			pg.redraw = true
		}
	})

	return netstatPanelName, pg.topFlex
}

// Display the netstat panel data
func (pg *NetstatPanel) displayNetstatPanel(step int, ticks uint64) {

	switch step {
	case 0:
		if pg.topFlex.HasFocus() {
			pg.displaySeconds++
			if pg.displaySeconds%3 == 0 {
				pg.displayNetstatSNMP(pg.netstat1)
				pg.displayNetstat(pg.netstat2)

				if pg.changed {
					pg.netstat1.ScrollToBeginning()
					pg.netstat2.ScrollToBeginning()
					pg.changed = false
				}
			}
		}
	}
}

func (pg *NetstatPanel) readData(filename string) (*NetstatInfo, error) {

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	nInfo := &NetstatInfo{}
	nInfo.Data = make(map[string]*NetstatData)

	for {
		ln, err := reader.ReadString('\n')
		if err != nil || err == io.EOF {
			break
		}
		lineData := strings.Fields(ln)

		s := lineData[0]
		s = s[0 : len(s)-1]
		s = strings.ToUpper(s)

		ni, ok := nInfo.Data[s]
		if !ok {
			ni := &NetstatData{Names: lineData[1:]}
			nInfo.Data[s] = ni
		} else {
			for _, v := range lineData[1:] {
				n, _ := strconv.ParseUint(v, 10, 64)
				ni.Counters = append(ni.Counters, n)
			}
		}
	}

	return nInfo, nil
}

// Get the netstat information
func (pg *NetstatPanel) netstatDisplay(table *tview.Table, displayType int) {

	di := pg.nInfo[displayType]
	nInfo, err := pg.readData(di.filename)
	if err != nil {
		tlog.DoPrintf("Reading %s failed\n", di.filename)
		return
	}

	row := 0
	col := 0
	for _, v := range di.sections {
		_, ok := nInfo.Data[v]
		if !ok {
			continue
		}
		SetCell(table, row, col, cz.SkyBlue(v)).SetAlign(tview.AlignCenter)
		SetCell(table, row, col+1, cz.GoldenRod("Counters")).SetAlign(tview.AlignRight)
		col += 2
	}
	row++
	col = 0
	for _, v := range di.sections {
		ni, ok := nInfo.Data[v]
		if !ok {
			continue
		}

		pni, pok := di.prev.Data[v]
		for i, s := range ni.Names {
			SetCell(table, row, col, cz.MediumSpringGreen(s)).SetAlign(tview.AlignLeft)

			n := fmt.Sprintf("%v", ni.Counters[i])
			if pok && ni.Counters[i] != pni.Counters[i] {
				SetCell(table, row, col+1, cz.Red(n)).SetAlign(tview.AlignRight)
			} else {
				SetCell(table, row, col+1, cz.CornSilk(n)).SetAlign(tview.AlignRight)
			}
			row++
		}
		col += 2
		row = 1
	}

	di.prev = nInfo

	if pg.redraw {
		table.ScrollToBeginning()
		pg.redraw = false
	}
}

// Display the netstat information
func (pg *NetstatPanel) displayNetstatSNMP(table *tview.Table) {

	pg.netstatDisplay(table, 0)
}

// Display the next set of data points for the netstat
func (pg *NetstatPanel) displayNetstat(table *tview.Table) {

	pg.netstatDisplay(table, 1)
}
