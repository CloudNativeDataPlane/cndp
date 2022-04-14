module cndp.org/prometheus

replace cndp.org/prometheus => ./prometheus

replace cndp.org/metrics => ../metrics

replace cndp.org/ttylog => ../ttylog

go 1.13

require (
	cndp.org/metrics v0.0.0-00010101000000-000000000000
	github.com/prometheus/client_golang v1.11.1
)
