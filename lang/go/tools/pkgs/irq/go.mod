module github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/irq

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils => ../utils

replace github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog => ../ttylog

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/ttylog v0.0.0-00010101000000-000000000000
	github.com/CloudNativeDataPlane/cndp/lang/go/tools/pkgs/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/sys v0.0.0-20220330033206-e17cdc41300f // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
require gopkg.in/yaml.v3 v3.0.0
