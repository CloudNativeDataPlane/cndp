// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation

package graphdata

import (
	"github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart"
	"github.com/rivo/tview"
)

// GraphPoints used to build the graph
type GraphPoints []float64

// GraphData contains the points and name of graph
type GraphData struct {
	index     int
	name      string
	maxPoints int
	points    GraphPoints
}

// GraphInfo information to construct the chart
type GraphInfo struct {
	labelColor   string
	lineColor    string
	captionColor string
	tickColor    string
	numGraphs    int
	fieldWidth   int
	precision    int
	graphs       []*GraphData
}

// Trim the data to fit the width
func (gd *GraphData) Trim() bool {

	if len(gd.points) > 0 {
		// Make sure the number of data points is capped at a given size
		if len(gd.points) >= gd.maxPoints {
			gd.points = gd.points[1:gd.maxPoints]
		}
		return true
	}
	return false
}

// Index of the current graph
func (gd *GraphData) Index() int {
	return gd.index
}

// AddPoint to the graph list and trim the data to fit
func (gd *GraphData) AddPoint(point float64) *GraphData {

	gd.points = append(gd.points, point)

	gd.Trim()

	return gd
}

// MaxPoints is the number of allowed points in the graph
func (gd *GraphData) MaxPoints() int {
	return gd.maxPoints
}

// SetMaxPoints of the graph in the number of points it can have
func (gd *GraphData) SetMaxPoints(maxPoints int) *GraphData {
	gd.maxPoints = maxPoints

	return gd
}

// Name returns the current name of the graph
func (gd *GraphData) Name() string {
	return gd.name
}

// SetName of the graph
func (gd *GraphData) SetName(name string) *GraphData {
	gd.name = name

	return gd
}

// SetFieldWidth of the values
func (gi *GraphInfo) SetFieldWidth(width int) *GraphInfo {
	gi.fieldWidth = width

	return gi
}

// WithIndex returns the graph at the given index value
func (gi *GraphInfo) WithIndex(index int) *GraphData {
	return gi.graphs[index]
}

// NumGraphs in the GraphInfo Structure
func (gi *GraphInfo) NumGraphs() int {
	return gi.numGraphs
}

// Graphs returns the GraphData slice of all graphs
func (gi *GraphInfo) Graphs() []*GraphData {
	return gi.graphs
}

// GraphPoints returns the GraphData slice of all points for a given graph
func (gi *GraphInfo) GraphPoints(g int) *GraphData {

	if g >= len(gi.graphs) {
		return nil
	}
	return gi.graphs[g]
}

// Reset the points in the graph to no points
func (gd *GraphData) Reset() {

	gd.points = nil
}

// NewGraphData returning a new GraphData object
// maxPoints is the number points allowed in the graph
func NewGraphData(maxPoints int) *GraphData {

	gd := &GraphData{}

	gd.SetMaxPoints(maxPoints)

	return gd
}

// NewGraph structure with default values
func NewGraph(numGraphs int) *GraphInfo {

	gi := &GraphInfo{
		labelColor:   "green",
		lineColor:    "blue",
		captionColor: "yellow",
		tickColor:    "red",
		fieldWidth:   10,
		precision:    2,
		numGraphs:    numGraphs,
	}

	for i := 0; i < numGraphs; i++ {
		gd := NewGraphData(1)
		gd.index = i
		gi.graphs = append(gi.graphs, gd)
	}

	return gi
}

// SetPrecision of the graph entries
func (gi *GraphInfo) SetPrecision(p int) *GraphInfo {
	gi.precision = p

	return gi
}

// MakeChart text string to be added to a text view window
func (gi *GraphInfo) MakeChart(view *tview.TextView, w ...interface{}) string {

	graph := ""

	if view == nil {
		return graph
	}

	start := int(0)
	end := gi.numGraphs

	switch len(w) {
	case 1:
		start = w[0].(int)
		end = gi.numGraphs
	case 2:
		start = w[0].(int)
		end = w[1].(int) + 1
	}
	cnt := end - start

	if start > end || end > gi.numGraphs {
		return graph
	}

	chart := asciichart.New()

	// Get the inside rectangle sizes
	_, _, wOrig, hOrig := view.GetInnerRect()

	// Calculate the height of the chart based on the number of charts and
	// the text view size
	height := hOrig
	if cnt > 0 {
		height = (height / cnt)
	}
	height--

	for i := start; i < end; i++ {
		gd := gi.graphs[i]

		maxPoints := wOrig - gi.fieldWidth - 2
		if gd.maxPoints != maxPoints {
			gd.maxPoints = maxPoints
		}
		if len(gd.name) > 0 {
			height--
		}

		graph += chart.SetCaption(gd.name).
			SetHeight(height).SetFieldWidth(gi.fieldWidth).
			SetLabelColor(gi.labelColor).
			SetLineColor(gi.lineColor).
			SetCaptionColor(gi.captionColor).
			SetTickColor(gi.tickColor).
			SetPrecision(gi.precision).
			Plot(gd.points)

		// Add a line to the multiple graph string if not the last graph
		if (i + 1) < end {
			graph += "\n"
		}
	}

	return graph
}
