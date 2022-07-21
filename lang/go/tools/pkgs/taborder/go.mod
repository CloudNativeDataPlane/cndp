module github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/taborder

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../ttylog

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog v0.0.0-00010101000000-000000000000
	github.com/gdamore/tcell/v2 v2.4.1-0.20210905002822-f057f0a857a1
	github.com/rivo/tview v0.0.0-20220307222120-9994674d60a8
)
