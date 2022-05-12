// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation
//
// Modified in 2019 from https://github.com/guptarohit/asciigraph

package asciichart

import (
	"fmt"
	"strings"
	"testing"
)

type testCases struct {
	data     []float64
	opts     *PlotConfig
	expected string
}

// Equal tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
func Equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func TestPlot(t *testing.T) {
	cases := []testCases{
		{
			[]float64{1, 1, 1, 1, 1},
			&PlotConfig{},
			` 1.00 ┼──── `},
		{
			[]float64{0, 0, 0, 0, 0},
			&PlotConfig{},
			` 0.00 ┼──── `},
		{
			[]float64{2, 1, 1, 2, -2, 5, 7, 11, 3, 7, 1},
			&PlotConfig{},
			` 11.00 ┤      ╭╮
 10.00 ┤      ││
  9.00 ┼      ││
  8.00 ┤      ││
  7.00 ┤     ╭╯│╭╮
  6.00 ┤     │ │││
  5.00 ┤    ╭╯ │││
  4.00 ┤    │  │││
  3.00 ┤    │  ╰╯│
  2.00 ┼╮ ╭╮│    │
  1.00 ┤╰─╯││    ╰
  0.00 ┤   ││
 -1.00 ┤   ││
 -2.00 ┤   ╰╯      `},
		{
			[]float64{2, 1, 1, 2, -2, 5, 7, 11, 3, 7, 4, 5, 6, 9, 4, 0, 6, 1, 5, 3, 6, 2},
			&PlotConfig{Caption: "Plot using asciigraph."},
			` 11.00 ┤      ╭╮
 10.00 ┤      ││
  9.00 ┼      ││    ╭╮
  8.00 ┤      ││    ││
  7.00 ┤     ╭╯│╭╮  ││
  6.00 ┤     │ │││ ╭╯│ ╭╮  ╭╮
  5.00 ┤    ╭╯ │││╭╯ │ ││╭╮││
  4.00 ┤    │  ││╰╯  ╰╮││││││
  3.00 ┤    │  ╰╯     ││││╰╯│
  2.00 ┼╮ ╭╮│         ││││  ╰
  1.00 ┤╰─╯││         ││╰╯
  0.00 ┤   ││         ╰╯
 -1.00 ┤   ││
 -2.00 ┤   ╰╯
          Plot using asciigraph.`},
		{
			[]float64{.2, .1, .2, 2, -.9, .7, .91, .3, .7, .4, .5},
			&PlotConfig{Caption: "Plot using asciigraph."},
			`  2.00 ┤  ╭╮ ╭╮
  0.55 ┼──╯│╭╯╰───
 -0.90 ┤   ╰╯
          Plot using asciigraph.`},
		{
			[]float64{2, 1, 1, 2, -2, 5, 7, 11, 3, 7, 1},
			&PlotConfig{Height: 4, Offset: 3},
			` 11.00 ┤      ╭╮
  7.75 ┼    ╭─╯│╭╮
  4.50 ┼╮ ╭╮│  ╰╯│
  1.25 ┤╰─╯││    ╰
 -2.00 ┤   ╰╯      `},
		{
			[]float64{.453, .141, .951, .251, .223, .581, .771, .191, .393, .617, .478},
			&PlotConfig{},
			` 0.95 ┤ ╭╮
 0.85 ┤ ││  ╭╮
 0.75 ┤ ││  ││
 0.65 ┤ ││ ╭╯│ ╭╮
 0.55 ┤ ││ │ │ │╰
 0.44 ┼╮││ │ │╭╯
 0.34 ┤│││ │ ││
 0.24 ┤││╰─╯ ╰╯
 0.14 ┤╰╯         `},

		{
			[]float64{.01, .004, .003, .0042, .0083, .0033, 0.0079},
			&PlotConfig{},
			` 0.010 ┼╮
 0.009 ┤│
 0.008 ┤│  ╭╮╭
 0.007 ┤│  │││
 0.006 ┤│  │││
 0.005 ┤│  │││
 0.004 ┤╰╮╭╯││
 0.003 ┤ ╰╯ ╰╯ `},

		{
			[]float64{192, 431, 112, 449, -122, 375, 782, 123, 911, 1711, 172},
			&PlotConfig{Height: 10},
			` 1711 ┤        ╭╮
 1528 ┼        ││
 1344 ┤        ││
 1161 ┤        ││
  978 ┤       ╭╯│
  794 ┤     ╭╮│ │
  611 ┤     │││ │
  428 ┤╭╮╭╮╭╯││ │
  245 ┼╯╰╯││ ╰╯ ╰
   61 ┤   ││
 -122 ┤   ╰╯      `},
		{
			[]float64{0.3189989805, 0.149949026, 0.30142492354, 0.195129182935, 0.3142492354, 0.1674974513, 0.3142492354, 0.1474974513, 0.3047974513},
			&PlotConfig{Width: 30, Height: 5, Caption: "Plot with custom height & width."},
			` 0.32 ┼╮            ╭─╮     ╭╮     ╭
 0.29 ┤╰╮    ╭─╮   ╭╯ │    ╭╯│     │
 0.26 ┤ │   ╭╯ ╰╮ ╭╯  ╰╮  ╭╯ ╰╮   ╭╯
 0.23 ┤ ╰╮ ╭╯   ╰╮│    ╰╮╭╯   ╰╮ ╭╯
 0.20 ┤  ╰╮│     ╰╯     ╰╯     │╭╯
 0.16 ┤   ╰╯                   ╰╯
         Plot with custom height & width.`},
		{
			[]float64{
				0, 0, 0, 0, 1.5, 0, 0, -0.5, 9, -3, 0, 0, 1, 2, 1, 0, 0, 0, 0,
				0, 0, 0, 0, 1.5, 0, 0, -0.5, 8, -3, 0, 0, 1, 2, 1, 0, 0, 0, 0,
				0, 0, 0, 0, 1.5, 0, 0, -0.5, 10, -3, 0, 0, 1, 2, 1, 0, 0, 0, 0,
			},
			&PlotConfig{Offset: 10, Height: 10, Caption: "I'm a doctor, not an engineer."},
			`     10.00    ┤                                             ╭╮
      8.70    ┤       ╭╮                                    ││
      7.40    ┼       ││                 ╭╮                 ││
      6.10    ┤       ││                 ││                 ││
      4.80    ┤       ││                 ││                 ││
      3.50    ┤       ││                 ││                 ││
      2.20    ┤       ││   ╭╮            ││   ╭╮            ││   ╭╮
      0.90    ┤   ╭╮  ││  ╭╯╰╮       ╭╮  ││  ╭╯╰╮       ╭╮  ││  ╭╯╰╮
     -0.40    ┼───╯╰──╯│╭─╯  ╰───────╯╰──╯│╭─╯  ╰───────╯╰──╯│╭─╯  ╰───
     -1.70    ┤        ││                 ││                 ││
     -3.00    ┤        ╰╯                 ╰╯                 ╰╯
                 I'm a doctor, not an engineer.`},
		{
			[]float64{-5, -2, -3, -4, 0, -5, -6, -7, -8, 0, -9, -3, -5, -2, -9, -3, -1},
			&PlotConfig{},
			`  0.00 ┤   ╭╮   ╭╮
 -1.00 ┤   ││   ││     ╭
 -2.00 ┤╭╮ ││   ││  ╭╮ │
 -3.00 ┤│╰╮││   ││╭╮││╭╯
 -4.00 ┤│ ╰╯│   │││││││
 -5.00 ┼╯   ╰╮  │││╰╯││
 -6.00 ┤     ╰╮ │││  ││
 -7.00 ┤      ╰╮│││  ││
 -8.00 ┤       ╰╯││  ││
 -9.00 ┼         ╰╯  ╰╯  `},
		{
			[]float64{-0.000018527, -0.021, -.00123, .00000021312, -.0434321234, -.032413241234, .0000234234},
			&PlotConfig{Height: 5, Width: 45},
			`  0.000 ┼─╮           ╭────────╮                    ╭
 -0.008 ┤ ╰──╮     ╭──╯        ╰─╮                ╭─╯
 -0.017 ┤    ╰─────╯             ╰╮             ╭─╯
 -0.025 ┤                         ╰─╮         ╭─╯
 -0.034 ┤                           ╰╮   ╭────╯
 -0.042 ┼                            ╰───╯            `},
		{
			[]float64{57.76, 54.04, 56.31, 57.02, 59.5, 52.63, 52.97, 56.44, 56.75, 52.96, 55.54, 55.09, 58.22, 56.85, 60.61, 59.62, 59.73, 59.93, 56.3, 54.69, 55.32, 54.03, 50.98, 50.48, 54.55, 47.49, 55.3, 46.74, 46, 45.8, 49.6, 48.83, 47.64, 46.61, 54.72, 42.77, 50.3, 42.79, 41.84, 44.19, 43.36, 45.62, 45.09, 44.95, 50.36, 47.21, 47.77, 52.04, 47.46, 44.19, 47.22, 45.55, 40.65, 39.64, 37.26, 40.71, 42.15, 36.45, 39.14, 36.62},
			&PlotConfig{Width: -10, Height: -10, Offset: -1},
			` 60.61 ┤             ╭╮ ╭╮
 59.60 ┤   ╭╮        │╰─╯│
 58.60 ┤   ││      ╭╮│   │
 57.59 ┼╮ ╭╯│      │││   │
 56.58 ┤│╭╯ │ ╭─╮  │╰╯   ╰╮
 55.58 ┤││  │ │ │╭─╯      │╭╮    ╭╮
 54.57 ┤╰╯  │ │ ││        ╰╯╰╮ ╭╮││      ╭╮
 53.56 ┤    │╭╯ ╰╯           │ ││││      ││
 52.56 ┤    ╰╯               │ ││││      ││           ╭╮
 51.55 ┤                     ╰╮││││      ││           ││
 50.54 ┤                      ╰╯│││      ││╭╮      ╭╮ ││
 49.54 ┤                        │││  ╭─╮ ││││      ││ ││
 48.53 ┤                        │││  │ │ ││││      ││ ││
 47.52 ┤                        ╰╯│  │ ╰╮││││      │╰─╯╰╮╭╮
 46.52 ┤                          ╰─╮│  ╰╯│││      │    │││
 45.51 ┤                            ╰╯    │││   ╭──╯    ││╰╮
 44.50 ┤                                  │││ ╭╮│       ╰╯ │
 43.50 ┤                                  ││╰╮│╰╯          │
 42.49 ┤                                  ╰╯ ╰╯            │   ╭╮
 41.48 ┤                                                   │   ││
 40.48 ┤                                                   ╰╮ ╭╯│
 39.47 ┤                                                    ╰╮│ │╭╮
 38.46 ┤                                                     ││ │││
 37.46 ┤                                                     ╰╯ │││
 36.45 ┤                                                        ╰╯╰ `},
		{
			[]float64{2, 1, 1, 2, -2, 5, 7, 11, 3, 7, 4, 5, 6, 9, 4, 0, 6, 1, 5, 3, 6, 2},
			&PlotConfig{Min: -3, Max: 13},
			` 13.00 ┤
 12.00 ┤
 11.00 ┤      ╭╮
 10.00 ┼      ││
  9.00 ┤      ││    ╭╮
  8.00 ┤      ││    ││
  7.00 ┤     ╭╯│╭╮  ││
  6.00 ┤     │ │││ ╭╯│ ╭╮  ╭╮
  5.00 ┤    ╭╯ │││╭╯ │ ││╭╮││
  4.00 ┤    │  ││╰╯  ╰╮││││││
  3.00 ┤    │  ╰╯     ││││╰╯│
  2.00 ┼╮ ╭╮│         ││││  ╰
  1.00 ┤╰─╯││         ││╰╯
  0.00 ┤   ││         ╰╯
 -1.00 ┤   ││
 -2.00 ┤   ╰╯
 -3.00 ┤`},
		{
			[]float64{2, 1, 1, 2, -2, 5, 7, 11, 3, 7, 4, 5, 6, 9, 4, 0, 6, 1, 5, 3, 6, 2},
			&PlotConfig{Min: 0, Max: 3},
			` 11.00 ┤      ╭╮
 10.00 ┤      ││
  9.00 ┼      ││    ╭╮
  8.00 ┤      ││    ││
  7.00 ┤     ╭╯│╭╮  ││
  6.00 ┤     │ │││ ╭╯│ ╭╮  ╭╮
  5.00 ┤    ╭╯ │││╭╯ │ ││╭╮││
  4.00 ┤    │  ││╰╯  ╰╮││││││
  3.00 ┤    │  ╰╯     ││││╰╯│
  2.00 ┼╮ ╭╮│         ││││  ╰
  1.00 ┤╰─╯││         ││╰╯
  0.00 ┤   ││         ╰╯
 -1.00 ┤   ││
 -2.00 ┤   ╰╯`},
	}

	for i := range cases {
		name := fmt.Sprintf("%d", i)
		t.Run(name, func(t *testing.T) {
			var err error
			act := make([]string, 1)
			exp := make([]string, 1)
			c := cases[i]

			trimStr := func(c *testCases, str string) ([]string, error) {

				s := strings.Split(str, "\n")

				for r, v := range s {
					ln := len(c.data) + c.opts.Offset
					if len(v) >= ln {
						v = strings.TrimRight(v, " \n")
						k := (len(v) - (len(c.data) + c.opts.Offset))
						t.Logf("k: %3d, len(c.data): %3d offset: %3d: %s\n", k, len(c.data), c.opts.Offset, v)
						if k > 0 {
							v += strings.Repeat(" ", k)
						}
						v += "\n"
					}
					s[r] = v
				}

				return s, nil
			}

			newexp := c.expected
			if c.opts.Caption == "" {
				c.opts.Caption = fmt.Sprintf("%d: Chart", i)
				if c.opts.Offset > 0 {
					newexp += strings.Repeat(" ", c.opts.Offset) +
						fmt.Sprintf("%d: Chart", i)

				}
			} else {
				c.opts.Caption = fmt.Sprintf("%d: %s", i, c.opts.Caption)
				if c.opts.Offset > 0 {
					newexp += strings.Repeat(" ", c.opts.Offset) + c.opts.Caption
				}
			}
			actual := New().SetChartOptions(c.opts).Plot(c.data)

			if act, err = trimStr(&c, actual); err != nil {
				t.Logf("trimnStr: actual: %v\n", err)
				return
			}
			t.Logf("act:\n%s", strings.ReplaceAll(strings.Join(act, ""), " ", "*"))

			if exp, err = trimStr(&c, newexp); err != nil {
				t.Logf("trimnStr: expect: %v\n", err)
				return
			}
			t.Logf("exp:\n%s", strings.ReplaceAll(strings.Join(exp, ""), " ", "*"))

			if Equal(act, exp) == false {
				expout := strings.ReplaceAll(newexp, " ", ".")
				t.Logf("expected:\n%s\n", expout)
			}

			actout := strings.ReplaceAll(actual, " ", ".")
			t.Logf("act:\n%s\n", actout)
		})
	}
}
