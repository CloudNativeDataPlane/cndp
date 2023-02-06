// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation
//
// Modified in 2019 from https://github.com/guptarohit/asciigraph

package asciichart

import (
	"strings"
)

// PlotConfig - information about the chart
type PlotConfig struct {
	Width, Height int
	Offset        int
	FieldWidth    int
	Min, Max      float64
	Caption       string
	Precision     int
	AddColor      bool

	LabelColor   string
	LineColor    string
	CaptionColor string
	TickColor    string
}

// SetChartOptions - Set all of the chart options
func (ac *Chart) SetChartOptions(c *PlotConfig) *Chart {

	if c != nil {
		ac.config = *c
	}
	return ac
}

// Width - Get the width of the chart
func (ac *Chart) Width() int {

	return ac.config.Width
}

// SetWidth sets the graphs width. By default, the width of the graph is
// determined by the number of data points. If the value given is a
// positive number, the data points are interpolated on the x axis.
// Values <= 0 reset the width to the default value.
func (ac *Chart) SetWidth(w int) *Chart {
	c := &ac.config

	if w > 0 {
		c.Width = w
	} else {
		c.Width = 0
	}

	return ac
}

// Height - Get the height of the chart
func (ac *Chart) Height() int {

	return ac.config.Height
}

// SetHeight sets the graphs height.
func (ac *Chart) SetHeight(h int) *Chart {
	c := &ac.config

	if h > 0 {
		c.Height = h
	} else {
		c.Height = 0
	}

	return ac
}

// Min - Get the minimum of the chart
func (ac *Chart) Min() float64 {

	return ac.config.Min
}

// SetMin sets the graph's minimum value for the vertical axis. It will be ignored
// if the series contains a lower value.
func (ac *Chart) SetMin(min float64) *Chart {
	c := &ac.config

	c.Min = min

	return ac
}

// Max - Get the Max of the chart
func (ac *Chart) Max() float64 {

	return ac.config.Max
}

// SetMax sets the graph's maximum value for the vertical axis. It will be ignored
// if the series contains a bigger value.
func (ac *Chart) SetMax(max float64) *Chart {
	c := &ac.config

	c.Max = max

	return ac
}

// Offset - Get the Offset of the chart
func (ac *Chart) Offset() int {

	return ac.config.Offset
}

// SetOffset sets the graphs offset.
func (ac *Chart) SetOffset(o int) *Chart {
	c := &ac.config

	c.Offset = o

	return ac
}

// SetPrecision set the precision of the ticker
func (ac *Chart) SetPrecision(p int) *Chart {

	c := &ac.config

	c.Precision = p

	return ac
}

// FieldWidth - Get the default field width
func (ac *Chart) FieldWidth() int {

	return ac.config.FieldWidth
}

// SetFieldWidth sets the graphs field width.
func (ac *Chart) SetFieldWidth(h int) *Chart {
	c := &ac.config

	if h > 0 {
		c.FieldWidth = h
	} else {
		c.FieldWidth = 0
	}

	return ac
}

// Caption - Get the Caption of the chart
func (ac *Chart) Caption() string {

	return ac.config.Caption
}

// SetCaption sets the graphs caption.
func (ac *Chart) SetCaption(caption string) *Chart {
	c := &ac.config

	c.Caption = strings.TrimSpace(caption)

	return ac
}

func (ac *Chart) AddColor(flag bool) *Chart {
	c := &ac.config

	c.AddColor = flag

	return ac
}

func setColor(color string) string {

	return "[" + color + "]"
}

// LabelColor sets the label color.
func (ac *Chart) LabelColor() string {
	c := &ac.config

	if len(c.LabelColor) == 0 || c.LabelColor == "[]" {
		return ""
	}
	return c.LabelColor
}

// SetLabelColor sets the color for the label.
func (ac *Chart) SetLabelColor(color string) *Chart {
	c := &ac.config

	c.LabelColor = setColor(color)

	return ac
}

// LineColor sets the label color.
func (ac *Chart) LineColor() string {
	c := &ac.config

	if len(c.LineColor) == 0 || c.LineColor == "[]" {
		return ""
	}
	return c.LineColor
}

// SetLineColor sets the color for the label.
func (ac *Chart) SetLineColor(color string) *Chart {
	c := &ac.config

	c.LineColor = setColor(color)

	return ac
}

// CaptionColor sets the label color.
func (ac *Chart) CaptionColor() string {
	c := &ac.config

	if len(c.CaptionColor) == 0 || c.CaptionColor == "[]" {
		return ""
	}
	return c.CaptionColor
}

// SetCaptionColor sets the color for the label.
func (ac *Chart) SetCaptionColor(color string) *Chart {
	c := &ac.config

	c.CaptionColor = setColor(color)

	return ac
}

// TickColor sets the Tick color.
func (ac *Chart) TickColor() string {
	c := &ac.config

	if len(c.TickColor) == 0 || c.TickColor == "[]" {
		return ""
	}
	return c.TickColor
}

// SetTickColor sets the color for the Ticker.
func (ac *Chart) SetTickColor(color string) *Chart {
	c := &ac.config

	c.TickColor = setColor(color)

	return ac
}

// EndColor - change color to default value
func (ac *Chart) EndColor() string {
	c := &ac.config

	if c.AddColor {
		return setColor("white")
	} else {
		return ""
	}
}
