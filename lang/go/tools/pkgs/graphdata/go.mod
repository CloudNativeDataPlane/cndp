module github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/graphdata

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart => ../asciichart

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../ttylog

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart v0.0.0-00010101000000-000000000000
	github.com/rivo/tview v0.0.0-20220307222120-9994674d60a8
)

require (
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/gdamore/tcell/v2 v2.4.1-0.20210905002822-f057f0a857a1 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	golang.org/x/text v0.3.8 // indirect
)
