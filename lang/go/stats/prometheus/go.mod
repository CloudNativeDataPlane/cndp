module github.com/CloudNativeDataPlane/cndp/lang/go/stats/prometheus

replace github.com/CloudNativeDataPlane/cndp/lang/go/stats/metrics => ../metrics

go 1.18

require (
	github.com/CloudNativeDataPlane/cndp/lang/go/stats/metrics v0.0.0-00010101000000-000000000000
	github.com/prometheus/client_golang v1.12.1
)
