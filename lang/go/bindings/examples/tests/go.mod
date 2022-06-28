module github.com/CloudNativeDataPlane/cndp/lang/go/bindings/example/tests

replace github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne => ../../cne

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne v0.0.0-00010101000000-000000000000
	github.com/franela/goblin v0.0.0-20211003143422-0a4f594942bf
)

require github.com/tidwall/jsonc v0.3.2 // indirect
