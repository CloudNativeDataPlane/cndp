// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2025 Intel Corporation

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"
	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"
	flags "github.com/jessevdk/go-flags"

	"github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/etimers"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	// cmtVersion string
	cmtVersion = "22.04.0"
	timerSteps = 4
)

// PanelInfo for title and primitive
type PanelInfo struct {
	title     string
	primitive tview.Primitive
}

// Panels is a function which returns the feature's main primitive and its title.
// It receives a "nextFeature" function which can be called to advance the
// presentation to the next slide.
type Panels func(nextPanel func()) (title string, content tview.Primitive)

// CloudMonitor for monitoring CNDP and system performance data
type CloudMonitor struct {
	version string // Version of PMDT
	pages   *tview.Pages
	app     *tview.Application // Application or top level application
	timers  *etimers.EventTimers
	panels  []PanelInfo
}

// Options command line options
type Options struct {
	Ptty        string `short:"p" long:"ptty" description:"path to ptty /dev/pts/X"`
	Dbg         bool   `short:"D" long:"debug" description:"Wait 15 seconds (default) to connect debugger"`
	WaitTime    uint   `short:"W" long:"wait-time" description:"N seconds before startup" default:"15"`
	ShowVersion bool   `short:"V" long:"version" description:"Print out version and exit"`
	Verbose     bool   `short:"v" long:"Verbose output for debugging"`
}

// Global to the main package for the tool
var cmon CloudMonitor
var options Options
var parser = flags.NewParser(&options, flags.Default)

const (
	mainLog = "MainLogID"
)

func buildPanelString(str string) string {
	// Build the panel selection string at the bottom of the xterm and
	// highlight the selected tab/panel item.
	s := ""
	for index, p := range cmon.panels {
		if p.title == str {
			s += fmt.Sprintf("F%d:[orange::r]%s[white::-]", index+1, p.title)
		} else {
			s += fmt.Sprintf("F%d:[orange::-]%s[white::-]", index+1, p.title)
		}
		if (index + 1) < len(cmon.panels) {
			s += " "
		}
	}
	return s
}

// Setup the tool's global information and startup the process info connection
func init() {
	tlog.Register(mainLog, true)

	cmon = CloudMonitor{}
	cmon.version = cmtVersion

	// Create the main tveiw application.
	cmon.app = tview.NewApplication()
}

// Version number string
func Version() string {
	return cmon.version
}

func main() {

	cz.SetDefault("ivory", "", 0, 2, "")

	_, err := parser.Parse()
	if err != nil {
		fmt.Printf("*** invalid arguments %v\n", err)
		os.Exit(1)
	}

	if len(options.Ptty) > 0 {
		err = tlog.Open(options.Ptty)
		if err != nil {
			fmt.Printf("ttylog open failed: %s\n", err)
			os.Exit(1)
		}
	}
	if options.ShowVersion {
		fmt.Printf("PME Version: %s\n", cmon.version)
		return
	}

	tlog.Log(mainLog, "\n===== %s =====\n", CloudMonInfo(false))
	fmt.Printf("\n===== %s =====\n", CloudMonInfo(false))

	app := cmon.app

	cmon.timers = etimers.New(time.Second/timerSteps, timerSteps)
	cmon.timers.Start()

	panels := []Panels{
		SysInfoPanelSetup,
		ProcessPanelSetup,
		IRQPanelSetup,
		NetstatPanelSetup,
	}

	// The bottom row has some info on where we are.
	info := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(false)

	currentPanel := 0
	info.Highlight(strconv.Itoa(currentPanel))

	pages := tview.NewPages()
	cmon.pages = pages

	previousPanel := func() {
		currentPanel = (currentPanel - 1 + len(panels)) % len(panels)
		name := cmon.panels[currentPanel].title
		info.Highlight(name).ScrollToHighlight()
		pages.SwitchToPage(name)
		info.SetText(buildPanelString(name))
	}

	nextPanel := func() {
		currentPanel = (currentPanel + 1) % len(panels)
		name := cmon.panels[currentPanel].title
		info.Highlight(name).ScrollToHighlight()
		pages.SwitchToPage(name)
		info.SetText(buildPanelString(name))
	}

	for index, f := range panels {
		title, primitive := f(nextPanel)
		pages.AddPage(title, primitive, true, index == currentPanel)
		cmon.panels = append(cmon.panels, PanelInfo{title: title, primitive: primitive})
	}
	info.SetText(buildPanelString(cmon.panels[0].title))

	// Create the main panel.
	panel := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(pages, 0, 1, true).
		AddItem(info, 1, 1, false)

	// Shortcuts to navigate the panels.
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyCtrlN {
			nextPanel()
		} else if event.Key() == tcell.KeyCtrlP {
			previousPanel()
		} else if event.Key() == tcell.KeyCtrlQ {
			app.Stop()
		} else {
			switch {
			case tcell.KeyF1 <= event.Key() && event.Key() <= tcell.KeyF19:
				idx := int(event.Key() - tcell.KeyF1)
				if idx >= 0 && idx < len(panels) {
					name := cmon.panels[idx].title
					info.Highlight(name).ScrollToHighlight()
					pages.SwitchToPage(name)
					info.SetText(buildPanelString(name))
				}
			case event.Rune() == 'q' || event.Rune() == 'Q':
				app.Stop()
			default:
			}
		}
		return event
	})

	setupSignals(syscall.SIGINT, syscall.SIGTERM, syscall.SIGSEGV)

	if options.Dbg {
		fmt.Printf("Waiting %d seconds for dlv to attach\n", options.WaitTime)
		time.Sleep(time.Second * time.Duration(options.WaitTime))
	}

	// Start the application.
	if err := app.SetRoot(panel, true).Run(); err != nil {
		panic(err)
	}

	tlog.Log(mainLog, "===== Done =====\n")
}

func setupSignals(signals ...os.Signal) {
	app := cmon.app

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, signals...)
	go func() {
		sig := <-sigs

		tlog.Log(mainLog, "Signal: %v\n", sig)
		time.Sleep(time.Second)

		app.Stop()
		os.Exit(1)
	}()
}
