module cndp.org/cmon

replace cndp.org/colorize => ../colorize

replace cndp.org/ttylog => ../ttylog

replace cndp.org/taborder => ../taborder

replace cndp.org/etimers => ../etimers

replace cndp.org/graphdata => ../graphdata

replace cndp.org/asciichart => ../asciichart

replace cndp.org/irq => ../irq

replace cndp.org/utils => ../utils

go 1.14

require (
	cndp.org/colorize v0.0.0-00010101000000-000000000000
	cndp.org/etimers v0.0.0-00010101000000-000000000000
	cndp.org/graphdata v0.0.0-00010101000000-000000000000
	cndp.org/irq v0.0.0-00010101000000-000000000000
	cndp.org/taborder v0.0.0-00010101000000-000000000000
	cndp.org/ttylog v0.0.0-00010101000000-000000000000
	cndp.org/utils v0.0.0-00010101000000-000000000000
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gdamore/tcell v1.4.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/rivo/tview v0.0.0-20200915114512-42866ecf6ca6
	github.com/shirou/gopsutil v2.20.9+incompatible
)
