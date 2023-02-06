// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation

package main

import (
	"fmt"

	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	defaultColumn int = 1
)

// SelectWindow to hold the table and Application information
type SelectWindow struct {
	name   string        // Name of the selection window
	table  *tview.Table  // Table for the selection window
	values []interface{} // slice of values for the sCol column selection
	offset int           // Number of rows to offset to show selection values
	item   int           // used to select the values slice
	sRow   int           // Current row pointer value
	sCol   int           // The column to use for selection values
}

// NewSelectWindow structure
func NewSelectWindow(table *tview.Table, name string, offset int, f func(row, col int)) *SelectWindow {

	w := &SelectWindow{
		name:   name,
		table:  table,
		values: make([]interface{}, 0),
		offset: offset,
		item:   0,
		sRow:   -1,
		sCol:   defaultColumn,
	}

	table.SetSelectable(true, false)
	table.SetSelectedStyle(tcell.StyleDefault.Foreground(tcell.ColorDefault).Background(tcell.ColorBlack).Reverse(true))

	table.Select(w.offset, 0)
	w.UpdatePointer()
	table.SetSelectionChangedFunc(f)

	return w
}

// AddColumn of data if the selection column then save the slice of data
func (w *SelectWindow) AddColumn(col int, values []interface{}, color ...string) *SelectWindow {

	if values == nil || w == nil || w.table == nil {
		return nil
	}

	// when col is negative then we restore the value back to the selected column
	if col < 0 {
		col = w.sCol
	}

	// if the column to be setup matches the selection column update the slice
	// of values for the column
	if w.sCol == col {
		w.values = values
	}

	row := w.offset

	// Output all of the values for a given column
	for _, name := range values {
		s := fmt.Sprintf("%v", name)

		// Set the color if given
		if len(color) > 0 {
			s = fmt.Sprintf("%s", cz.ColorWithName(color[0], name))
		}
		tableCell := tview.NewTableCell(s).
			SetAlign(tview.AlignLeft).
			SetSelectable(false)
		w.table.SetCell(row, col, tableCell)
		row++
	}

	if w.sRow > row {
		w.item = row - w.offset
		w.UpdatePointer()
		w.table.Select(w.sRow, w.sCol)
	}

	// Scroll the window to the beginning of the list
	w.table.ScrollToBeginning()

	return w
}

// SetColumn for the value returned on selection of a row.
func (w *SelectWindow) SetColumn(col int) {

	if w == nil {
		return
	}
	w.sCol = col
}

// UpdatePointer by replacing the current select item with '->' string
func (w *SelectWindow) UpdatePointer() {

	if w.sRow >= 0 {
		SetCell(w.table, w.sRow, 0, "  ", tview.AlignLeft, true)
	}

	w.sRow = w.item + w.offset

	if w.sRow >= 0 {
		SetCell(w.table, w.sRow, 0, "->", tview.AlignLeft, true)
	}
}

// Offset value is returned
func (w *SelectWindow) Offset() int {

	return w.offset
}

// ItemIndex value is returned
func (w *SelectWindow) ItemIndex() int {

	if w.item >= len(w.values) {
		w.item = len(w.values) - 1
	}
	return w.item
}

// ItemValue returns the current selected item value
func (w *SelectWindow) ItemValue() interface{} {

	if w == nil || w.item < 0 || w.values == nil || len(w.values) == 0 {
		return nil
	}
	if w.item >= len(w.values) {
		return nil
	}

	return w.values[w.item]
}

// UpdateItem for the apps pointer
func (w *SelectWindow) UpdateItem(row, col int) {

	if w == nil || w.table == nil {
		return
	}

	if w.sRow != row {
		row -= w.offset
		if row >= 0 && row < len(w.values) {
			w.item = row
			w.UpdatePointer()
		}
	}
}
