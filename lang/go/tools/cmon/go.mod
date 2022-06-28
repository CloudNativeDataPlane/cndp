module github.com/CloudNativeDataPlane/cndp/lang/go/tools/cmon

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize => ../pkgs/colorize

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../pkgs/ttylog

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/taborder => ../pkgs/taborder

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/etimers => ../pkgs/etimers

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/graphdata => ../pkgs/graphdata

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart => ../pkgs/asciichart

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/irq => ../pkgs/irq

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils => ../pkgs/utils

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/etimers v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/graphdata v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/irq v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/taborder v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils v0.0.0-00010101000000-000000000000
	github.com/gdamore/tcell/v2 v2.5.1
	github.com/jessevdk/go-flags v1.5.0
	github.com/rivo/tview v0.0.0-20220307222120-9994674d60a8
	github.com/shirou/gopsutil v3.21.11+incompatible
)

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart v0.0.0-00010101000000-000000000000 // indirect
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/sys v0.0.0-20220330033206-e17cdc41300f // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	golang.org/x/text v0.3.7 // indirect
)
