// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package main

import (
	"fmt"

	cz "github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type chartData struct {
	points []float64
	name   string
}

// TitleColor - Set the title color to the windows
func TitleColor(msg string) string {

	return fmt.Sprintf("[%s]", cz.Orange(msg))
}

// Center returns a new primitive which shows the provided primitive in its
// center, given the provided primitive's size.
func Center(width, height int, p tview.Primitive) tview.Primitive {
	return tview.NewFlex().
		AddItem(tview.NewBox(), 0, 1, false).
		AddItem(tview.NewFlex().
			SetDirection(tview.FlexRow).
			AddItem(tview.NewBox(), 0, 1, false).
			AddItem(p, height, 1, true).
			AddItem(tview.NewBox(), 0, 1, false), width, 1, true).
		AddItem(tview.NewBox(), 0, 1, false)
}

// TitleBox to return the top title window
func TitleBox(flex *tview.Flex) *tview.Box {

	box := tview.NewBox().
		SetBorder(true).
		SetTitle(CloudMonInfo(true)).
		SetTitleAlign(tview.AlignLeft)

	flex.AddItem(box, 2, 1, false)

	return box
}

// CreateTextView - helper routine to create a TextView
func CreateTextView(flex *tview.Flex, msg string, align, fixedSize, proportion int, focus bool) *tview.TextView {

	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(true)

	textView.SetBorder(true).
		SetTitle(TitleColor(msg)).
		SetTitleAlign(align)

	flex.AddItem(textView, fixedSize, proportion, focus)

	return textView
}

// CreateTableView - Helper to create a Table
func CreateTableView(flex *tview.Flex, msg string, align, fixedSize, proportion int, focus bool) *tview.Table {
	table := tview.NewTable().
		SetFixed(1, 0).
		SetEvaluateAllRows(true)

	table.SetBorder(true).
		SetTitle(TitleColor(msg)).
		SetTitleAlign(align)

	flex.AddItem(table, fixedSize, proportion, focus)

	return table
}

// CreateForm window
func CreateForm(flex *tview.Flex, msg string, align, fixedSize, proportion int, focus bool) *tview.Form {

	form := tview.NewForm().
		SetFieldBackgroundColor(tcell.ColorDefault).
		SetFieldTextColor(tcell.ColorSlateGrey)

	form.SetBorder(true).
		SetTitleAlign(align).
		SetTitle(TitleColor(msg))

	flex.AddItem(form, fixedSize, proportion, focus)

	return form
}

// CreateList window
func CreateList(flex *tview.Flex, msg string, align, fixedSize, proportion int, focus bool) *tview.List {

	list := tview.NewList().ShowSecondaryText(false)

	list.SetBorder(true).
		SetTitleAlign(align).
		SetTitle(TitleColor(msg))

	flex.AddItem(list, fixedSize, proportion, focus)

	return list
}

// SetCell content given the information
// row, col of the cell to create and fill
// msg is the string content to insert in the cell
// a is an interface{} object list
//   object a is int then alignment tview.AlignLeft/Right/Center
//   object a is bool then set the cell as selectable or not
func SetCell(table *tview.Table, row, col int, msg string, a ...interface{}) *tview.TableCell {

	align := tview.AlignRight
	selectable := false
	for _, v := range a {
		switch v.(type) {
		case int:
			align = v.(int)
		case bool:
			selectable = v.(bool)
		}
	}
	tableCell := tview.NewTableCell(msg).
		SetAlign(align).
		SetSelectable(selectable)
	table.SetCell(row, col, tableCell)

	return tableCell
}
