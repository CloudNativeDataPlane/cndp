// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2025 Intel Corporation

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"
	tab "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/taborder"
	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"
	u "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils"
	"github.com/rivo/tview"
	ps "github.com/shirou/gopsutil/process"
)

const (
	processPanelName string = "Process"
)

// ProcessPanel - Data for main page information
type ProcessPanel struct {
	tabOrder *tab.Tab
	topFlex  *tview.Flex

	selectApp *SelectWindow
	process1  *tview.Table
	process2  *tview.Table
	cmdline   *tview.Table
	changed   bool
	procs     []*ps.Process
}

// Setup and create the process panel structure
func setupProcessPanel() *ProcessPanel {

	pg := &ProcessPanel{changed: true}

	return pg
}

// ProcessPanelSetup setup the main event page
func ProcessPanelSetup(nextSlide func()) (pageName string, content tview.Primitive) {

	pg := setupProcessPanel()

	to := tab.New(processPanelName, cmon.app)
	pg.tabOrder = to

	flex0 := tview.NewFlex().SetDirection(tview.FlexRow)
	flex1 := tview.NewFlex().SetDirection(tview.FlexColumn)
	flex2 := tview.NewFlex().SetDirection(tview.FlexColumn)

	TitleBox(flex0)

	flex0.AddItem(flex1, 0, 5, true)
	flex0.AddItem(flex2, 0, 6, true)

	table := CreateTableView(flex1, "Process List (p)", tview.AlignLeft, 0, 1, true)
	pg.selectApp = NewSelectWindow(table, "Process", 1, func(row, col int) {
		pg.selectApp.UpdateItem(row, col)
		pg.changed = true
	})

	pg.cmdline = CreateTableView(flex1, "Cmdline (c)", tview.AlignLeft, 0, 1, false)

	pg.process1 = CreateTableView(flex2, "Process Info (1)", tview.AlignLeft, 0, 2, false)
	pg.process2 = CreateTableView(flex2, "Process Info (2)", tview.AlignLeft, 0, 2, false).
		SetSeparator(tview.Borders.Vertical)

	to.Add(pg.selectApp.table, 'p')
	to.Add(pg.cmdline, 'c')
	to.Add(pg.process1, '1')
	to.Add(pg.process2, '2')

	to.SetInputDone()

	pg.topFlex = flex0

	cmon.timers.Add(processPanelName, func(step int, ticks uint64) {
		if pg.topFlex.HasFocus() {
			cmon.app.QueueUpdateDraw(func() {
				pg.displayProcessPanel(step, ticks)
			})
		}
	})

	return processPanelName, pg.topFlex
}

// Display the process panel data
func (pg *ProcessPanel) displayProcessPanel(step int, ticks uint64) {

	switch step {
	case 0:
		if pg.topFlex.HasFocus() {
			pg.displayProcessData(pg.selectApp.table)
			pg.displayProcessCmdline(pg.cmdline)
			pg.displayProcess1Info(pg.process1)
			pg.displayProcess2Info(pg.process2)

			if pg.changed {
				pg.cmdline.ScrollToBeginning()
				pg.process1.ScrollToBeginning()
				pg.process2.ScrollToBeginning()
				pg.changed = false
			}
		}
	}
}

// Column values for alignment and the data to display
type columnValue struct {
	values []interface{}
	align  int
}

// Display the process data window information
func (pg *ProcessPanel) displayProcessData(table *tview.Table) {

	// We must find a process to display, else return
	procs, err := ps.Processes()
	if err != nil || len(procs) == 0 {
		return
	}
	pg.procs = procs

	var row, col int = 1, 0

	for _, t := range []string{"  ", "  Pid", "Percent", "Name", "% Mem"} {
		SetCell(table, 0, col, cz.Orange(t), tview.AlignLeft)
		col++
	}

	columns := make([]columnValue, col-1)

	columns[0].align = tview.AlignRight // Pid
	columns[1].align = tview.AlignRight // Percent
	columns[2].align = tview.AlignLeft  // Name
	columns[3].align = tview.AlignLeft  // Command Line

	// For each process found display the given information
	for _, p := range pg.procs {
		if p.Pid == int32(os.Getpid()) {
			continue
		}

		// CPUPersent() must be called to determine th percent load of the process
		percent, err := p.CPUPercent()
		if err != nil {
			tlog.ErrorPrintf("Process Percent error: %v\n", err)
			continue
		}

		// When the percent load is below 1% we do not display the process
		// this can be adjusted to a higher value if too many processes
		if percent < 1.0 {
			continue
		}
		col = 0

		columns[col].values = append(columns[col].values, p.Pid)
		col++

		// Attempt to colorize the percentage value to show load
		if percent >= 80.0 {
			columns[col].values = append(columns[col].values, cz.Red(percent))
		} else if percent >= 60.0 {
			columns[col].values = append(columns[col].values, cz.DeepPink(percent))
		} else if percent >= 40.0 {
			columns[col].values = append(columns[col].values, cz.Orange(percent))
		} else if percent >= 20.0 {
			columns[col].values = append(columns[col].values, cz.LightGreen(percent))
		} else {
			columns[col].values = append(columns[col].values, cz.CornSilk(percent))
		}
		col++

		name, _ := p.Name()

		// If the percent load is greater then 95% it is most likely a CNDP process
		// which we set to a different color
		if percent > 95.0 {
			name = cz.Orange(name, -30)
		} else {
			name = cz.SkyBlue(name, -30)
		}
		columns[col].values = append(columns[col].values, name)
		col++

		// Find out the percent amount of memory used by the process
		mem, err := p.MemoryPercent()
		if err == nil {
			columns[col].values = append(columns[col].values, mem)
		} else {
			columns[col].values = append(columns[col].values, 0)
		}

		row++
	}

	// for each column we use different colors to highlight the data.
	colors := []string{cz.DeepPinkColor, cz.NoColor, cz.NoColor, cz.WheatColor}
	for c, cs := range columns {
		if len(colors[c]) > 0 {
			pg.selectApp.AddColumn(c+1, cs.values, colors[c])
		} else {
			pg.selectApp.AddColumn(c+1, cs.values)
		}
	}
}

// Display the process command line information
func (pg *ProcessPanel) displayProcessCmdline(table *tview.Table) {

	v := pg.selectApp.ItemValue()
	if v == nil {
		return
	}
	pid := v.(int32)

	row := 0
	col := 0

	// Process must exist as then can die and restart
	p := pg.findProc(pid)
	if p == nil {
		return
	}

	SetCell(table, row, col, cz.Orange("Args:"))
	cmd, err := p.Cmdline()
	if err == nil {
		col++
		l := ""
		for _, s := range strings.Split(cmd, " ") {
			v := s + " "
			if len(v)+len(l) > 50 {
				SetCell(table, row, col, cz.Wheat(l), tview.AlignLeft)
				row++
				l = v
			} else {
				l += v
			}
		}
		if len(l) > 0 {
			SetCell(table, row, col, cz.Wheat(l), tview.AlignLeft)
			row++
		}
		for i := row; i < table.GetRowCount(); i++ {
			SetCell(table, i, col, "")
		}
	}

	// Remove the rows in the table if the information was reduced in rows
	for i := row; i < table.GetRowCount(); i++ {
		table.RemoveRow(i)
	}
}

// Find the process data by the Pid value
func (pg *ProcessPanel) findProc(pid int32) *ps.Process {

	for _, p := range pg.procs {
		if p.Pid == pid {
			return p
		}
	}

	return nil
}

// Display the process information
func (pg *ProcessPanel) displayProcess1Info(table *tview.Table) {

	v := pg.selectApp.ItemValue()
	if v == nil {
		return
	}
	pid := v.(int32)

	s := fmt.Sprintf("%s %s", cz.Orange("Pid:"), cz.Red(pid))
	SetCell(table, 0, 0, s)

	p := pg.findProc(pid)
	if p == nil {
		return
	}

	row := 0

	// Set the color of the name
	name, err := p.Name()
	if err == nil {
		SetCell(table, row, 1, cz.SkyBlue(name), tview.AlignLeft)
		row++
	}

	epoch, err := p.CreateTime()
	if err == nil {
		str := fmt.Sprintf("%v", time.Unix(0, (epoch*1000000)))
		SetCell(table, row, 0, cz.Orange("Create Time:"))
		SetCell(table, row, 1, cz.Wheat(str), tview.AlignLeft)
		row++
	}

	back, err := p.Background()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("Background:"))
		SetCell(table, row, 1, cz.LightBlue(back), tview.AlignLeft)
		row++
	}

	status, err := p.Status()
	if err == nil {
		s := ""
		switch status {
		case "R":
			s = "Running"
		case "S":
			s = "Sleeping"
		case "T":
			s = "Stopped"
		case "I":
			s = "Idle"
		case "Z":
			s = "Zombie"
		case "W":
			s = "Waiting"
		case "L":
			s = "Locked"
		}
		SetCell(table, row, 0, cz.Orange("Status:"))
		SetCell(table, row, 1, cz.LightBlue(s), tview.AlignLeft)
		row++
	}

	cwd, err := p.Cwd()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("CWD:"))
		SetCell(table, row, 1, cz.LightBlue(cwd), tview.AlignLeft)
		row++
	}

	uids, err := p.Uids()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("User IDs:"))
		SetCell(table, row, 1, cz.LightBlue(fmt.Sprintf("%v", uids)), tview.AlignLeft)
		row++
	}

	gids, err := p.Gids()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("Group IDs:"))
		SetCell(table, row, 1, cz.LightBlue(fmt.Sprintf("%v", gids)), tview.AlignLeft)
		row++
	}

	term, err := p.Terminal()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("Terminal:"))
		SetCell(table, row, 1, cz.LightBlue(term), tview.AlignLeft)
		row++
	}

	nice, err := p.Nice()
	ionice, _ := p.IOnice()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("Nice/IO:"))
		SetCell(table, row, 1, cz.LightBlue(fmt.Sprintf("%d/%d", nice, ionice)), tview.AlignLeft)
		row++
	}

	ctx, err := p.NumCtxSwitches()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("CTX Switches:"))
		s := fmt.Sprintf("Voluntary: %d, Involuntary: %d", ctx.Voluntary, ctx.Involuntary)
		SetCell(table, row, 1, cz.LightBlue(s), tview.AlignLeft)
		row++
	}

	numfd, err := p.NumFDs()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("# FDs:"))
		SetCell(table, row, 1, cz.LightBlue(numfd), tview.AlignLeft)
		row++
	}

	thrd, err := p.NumThreads()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("# Threads:"))
		SetCell(table, row, 1, cz.LightBlue(thrd), tview.AlignLeft)
		row++
	}
	row++
}

// Display the next set of data points for the process
func (pg *ProcessPanel) displayProcess2Info(table *tview.Table) {

	v := pg.selectApp.ItemValue()
	if v == nil {
		return
	}
	pid := v.(int32)

	s := fmt.Sprintf("%s %s", cz.Orange("Pid:"), cz.Red(pid))
	SetCell(table, 0, 0, s)

	p := pg.findProc(pid)
	if p == nil {
		return
	}

	row := 0

	// Display the rlimits for the process
	rlimit, err := p.Rlimit()
	if err == nil {
		var rlimitNames = []string{
			"Addr Space", "Core", "CPU", "Data", "FileSize", "Locks",
			"Memlock", "MsgQueue", "Nice", "# OpenFiles", "# Proc", "RSS",
			"RT-Priority", "RT-Timeout", "SigPending", "Stack",
		}
		SetCell(table, row, 0, cz.Orange("Rlimit"))
		for col, v := range []string{"Resource Name", "Soft", "Hard", "Units"} {
			SetCell(table, row, col, cz.Orange(v))
		}
		row++

		for _, v := range rlimit {
			SetCell(table, row, 0, cz.DeepPink(rlimitNames[v.Resource]), tview.AlignLeft)
			SetCell(table, row, 1, cz.LightBlue(u.FormatUnits(uint64(v.Soft)), 8))
			SetCell(table, row, 2, cz.LightBlue(u.FormatUnits(uint64(v.Hard)), 8))
			SetCell(table, row, 3, cz.LightBlue(u.FormatUnits(uint64(v.Used)), 8))
			row++
		}
	}
	row++

	// Display the IO counters for the process
	ioCounters, err := p.IOCounters()
	if err == nil {
		SetCell(table, row, 0, cz.Orange("IOCounters:"))
		SetCell(table, row, 1, cz.Orange("ReadCount"), tview.AlignLeft)
		SetCell(table, row, 2, cz.Orange("ReadBytes"), tview.AlignLeft)
		SetCell(table, row, 3, cz.Orange("WriteCount"), tview.AlignLeft)
		SetCell(table, row, 4, cz.Orange("WriteBytes"), tview.AlignLeft)
		row++
		SetCell(table, row, 1, cz.LightBlue(ioCounters.ReadCount))
		SetCell(table, row, 2, cz.LightBlue(ioCounters.ReadBytes))
		SetCell(table, row, 3, cz.LightBlue(ioCounters.WriteCount))
		SetCell(table, row, 4, cz.LightBlue(ioCounters.WriteBytes))
	}
	row += 2

	// Display the memory information about the process
	mem, err := p.MemoryInfo()
	if err == nil {
		for i, v := range []string{"Memory Info:", "RSS", "VMS", "HWM", "Data"} {
			if i == 0 {
				SetCell(table, row, i, cz.Orange(v))
			} else {
				SetCell(table, row, i, cz.DeepPink(v))
			}
		}
		row++
		SetCell(table, row, 1, cz.LightBlue(u.FormatBytes(mem.RSS)))
		SetCell(table, row, 2, cz.LightBlue(u.FormatBytes(mem.VMS)))
		SetCell(table, row, 3, cz.LightBlue(u.FormatBytes(mem.HWM)))
		SetCell(table, row, 4, cz.LightBlue(u.FormatBytes(mem.Data)))
		row++

		for i, v := range []string{"", "Stack", "Locked", "Swap"} {
			SetCell(table, row, i, cz.DeepPink(v))
		}
		row++
		SetCell(table, row, 1, cz.LightBlue(u.FormatBytes(mem.Stack)))
		SetCell(table, row, 2, cz.LightBlue(u.FormatBytes(mem.Locked)))
		SetCell(table, row, 3, cz.LightBlue(u.FormatBytes(mem.Swap)))
		row++
	}
}
