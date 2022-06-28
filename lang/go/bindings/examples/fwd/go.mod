module github.com/CloudNativeDataPlane/cndp/lang/go/bindings/examples/fwd

replace github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne => ../../cne

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../../../tools/pkgs/ttylog

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/etimers => ../../../tools/pkgs/etimers

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize => ../../../tools/pkgs/colorize

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/colorize v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/etimers v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog v0.0.0-20220730140151-855a3ef0ebc1
	github.com/gdamore/tcell/v2 v2.5.2
	github.com/rivo/tview v0.0.0-20220731115447-9d32d269593e
	golang.org/x/text v0.3.7
)

require (
	github.com/gdamore/encoding v1.0.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/rivo/uniseg v0.3.1 // indirect
	github.com/tidwall/jsonc v0.3.2 // indirect
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
)
