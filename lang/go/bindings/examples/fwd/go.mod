module github.com/CloudNativeDataPlane/cndp/lang/go/bindings/examples/fwd

replace github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne => ../../cne

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne v0.0.0-00010101000000-000000000000
	github.com/jessevdk/go-flags v1.5.0
)

require golang.org/x/sys v0.0.0-20210320140829-1e4c9ba3b0c4 // indirect
