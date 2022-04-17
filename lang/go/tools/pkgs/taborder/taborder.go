// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package taborder

import (
	"fmt"

	tlog "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var (
	defaultBorderColor   tcell.Color = tcell.ColorGreen
	highlightBorderColor tcell.Color = tcell.ColorBlue
)

// TabInfo for windows on the current panel
type TabInfo struct {
	Index int
	View  interface{}
	EKey  *tcell.EventKey
}

// Tab for all windows in a panel
type Tab struct {
	Name    string
	TabList []*TabInfo
	Index   int
	Prev    int
	Appl    *tview.Application
}

// New information object
func New(name string, appl *tview.Application) *Tab {
	return &Tab{Name: name, Appl: appl}
}

// Add to the given list of windows
func (to *Tab) Add(w interface{}, key interface{}) (*TabInfo, error) {
	if to == nil {
		return nil, fmt.Errorf("invalid tabOrderInfo pointer")
	}

	tab := &TabInfo{View: w}

	if key != nil {
		switch key.(type) {
		case tcell.Key:
			k := key.(tcell.Key)
			tab.EKey = tcell.NewEventKey(k, 0, tcell.ModNone)
		case rune:
			k := key.(rune)
			tab.EKey = tcell.NewEventKey(tcell.KeyRune, k, tcell.ModNone)
		}
	}

	tab.Index = len(to.TabList)

	to.TabList = append(to.TabList, tab)
	if len(to.TabList) == 1 {
		to.ColorBorder(tab.View, highlightBorderColor)
	} else {
		to.ColorBorder(tab.View, defaultBorderColor)
	}

	return tab, nil
}

// SetDefaultBorderColor to the normal non-selected border color
func (to *Tab) SetDefaultBorderColor(color tcell.Color) {
	defaultBorderColor = color
}

// SetHighlightBorderColor to the normal non-selected border color
func (to *Tab) SetHighlightBorderColor(color tcell.Color) {
	highlightBorderColor = color
}

// SetFocus to the tview primitive
func (to *Tab) SetFocus(a interface{}) {

	switch a.(type) {
	case *tview.TextView:
		t := a.(*tview.TextView)
		to.Appl.SetFocus(t)
	case *tview.Table:
		t := a.(*tview.Table)
		to.Appl.SetFocus(t)
	case *tview.Form:
		t := a.(*tview.Form)
		to.Appl.SetFocus(t)
	}
}

// ColorBorder to the tview
func (to *Tab) ColorBorder(a interface{}, color tcell.Color) {

	switch a.(type) {
	case *tview.TextView:
		t := a.(*tview.TextView)
		t.Box.SetBorderColor(color)
	case *tview.Table:
		t := a.(*tview.Table)
		t.Box.SetBorderColor(color)
	case *tview.Form:
		t := a.(*tview.Form)
		t.Box.SetBorderColor(color)
	}
}

func (to *Tab) findKey(ek *tcell.EventKey) *TabInfo {

	for _, tab := range to.TabList {
		if tab.EKey.Name() == ek.Name() {
			return tab
		}
	}
	return nil
}

// inputCapture for taborder
func (to *Tab) inputCapture(ek *tcell.EventKey) *tcell.EventKey {

	if ek.Key() != tcell.KeyBacktab && ek.Key() != tcell.KeyTab {
		if tab := to.findKey(ek); tab != nil {
			to.ColorBorder(to.TabList[to.Index].View, defaultBorderColor)
			to.SetFocus(tab.View)
			to.ColorBorder(tab.View, highlightBorderColor)
			to.Prev, to.Index = to.Index, tab.Index
		} else {
			tlog.DebugPrintf("EventKey: not found\n")
		}
	}
	return ek
}

// doDone key handling for Tab and Backtab
func (to *Tab) doDone(key tcell.Key) {

	p := to.TabList[to.Index]
	to.ColorBorder(p.View, defaultBorderColor)

	if key == tcell.KeyBacktab {
		if to.Index == 0 {
			p = to.TabList[len(to.TabList)-1]
		} else {
			p = to.TabList[to.Index-1]
		}
	} else if key == tcell.KeyTab {
		if to.Index < (len(to.TabList) - 1) {
			p = to.TabList[to.Index+1]
		} else {
			p = to.TabList[0]
		}
	}

	to.SetFocus(p.View)
	to.ColorBorder(p.View, highlightBorderColor)

	to.Prev, to.Index = to.Index, p.Index
}

// setInput for tview
func (to *Tab) setInput(a interface{}, inputFunc func(ev *tcell.EventKey) *tcell.EventKey) {

	switch a.(type) {
	case *tview.TextView:
		t := a.(*tview.TextView)
		t.SetInputCapture(inputFunc)
	case *tview.Table:
		t := a.(*tview.Table)
		t.SetInputCapture(inputFunc)
	case *tview.Form:
		t := a.(*tview.Form)
		t.SetInputCapture(inputFunc)
	}
}

// setDone function for tview
func (to *Tab) setDone(a interface{}, doneFunc func(key tcell.Key)) {

	switch a.(type) {
	case *tview.TextView:
		t := a.(*tview.TextView)
		t.SetDoneFunc(doneFunc)
	case *tview.Table:
		t := a.(*tview.Table)
		t.SetDoneFunc(doneFunc)
	case *tview.Form:
		// add support for done function in Form views
	}
}

// SetInputDone functions and data
func (to *Tab) SetInputDone() error {
	if to.TabList == nil {
		return fmt.Errorf("tab list is nil")
	}

	for _, tab := range to.TabList {
		to.setInput(tab.View, func(ek *tcell.EventKey) *tcell.EventKey {
			return to.inputCapture(ek)
		})
		to.setDone(tab.View, func(key tcell.Key) {
			to.doDone(key)
		})
	}

	return nil
}
