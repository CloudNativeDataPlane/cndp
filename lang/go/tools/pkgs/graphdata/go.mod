module github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/graphdata

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart => ../asciichart

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../ttylog

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/asciichart v0.0.0-00010101000000-000000000000
	github.com/rivo/tview v0.0.0-20220307222120-9994674d60a8
)
