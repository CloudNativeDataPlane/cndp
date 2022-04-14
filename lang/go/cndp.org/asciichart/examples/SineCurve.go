// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation
//
// Modified by Keith Wiles 2019 from https://github.com/guptarohit/asciigraph

package main

import (
	"fmt"
	"math"

	"cndp.org/asciichart"
)

func main() {
	var data []float64

	// sine curve
	for i := 0; i < 105; i++ {
		data = append(data, 15*math.Sin(float64(i)*((math.Pi*4)/120.0)))
	}
	graph := asciichart.NewPlot().Plot(data)

	fmt.Println(graph)
	// Output:
	//   15.00 ┤          ╭────────╮                                                  ╭────────╮
	//   12.00 ┤       ╭──╯        ╰──╮                                            ╭──╯        ╰──╮
	//    9.00 ┤    ╭──╯              ╰─╮                                       ╭──╯              ╰─╮
	//    6.00 ┤  ╭─╯                   ╰──╮                                  ╭─╯                   ╰──╮
	//    3.00 ┤╭─╯                        ╰─╮                              ╭─╯                        ╰─╮
	//    0.00 ┼╯                            ╰╮                            ╭╯                            ╰╮
	//   -3.00 ┤                              ╰─╮                        ╭─╯                              ╰─╮
	//   -6.00 ┤                                ╰─╮                   ╭──╯                                  ╰─╮
	//   -9.00 ┤                                  ╰──╮              ╭─╯                                       ╰──╮
	//  -12.00 ┤                                     ╰──╮        ╭──╯                                            ╰──╮
	//  -15.00 ┤                                        ╰────────╯                                                  ╰───
}
