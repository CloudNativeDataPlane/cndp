module github.com/CloudNativeDataPlane/cndp/lang/go/bindings/examples/distributor

go 1.20

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
)

require (
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/tidwall/jsonc v0.3.2 // indirect
	golang.org/x/sys v0.0.0-20220829200755-d48e67d00261 // indirect
)

replace github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne => ../../cne
