module github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/irq

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils => ../utils

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../ttylog

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils v0.0.0-00010101000000-000000000000
)

require github.com/davecgh/go-spew v1.1.1 // indirect
