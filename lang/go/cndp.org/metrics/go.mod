module cndp.org/metrics

replace cndp.org/metrics => ./metrics

replace cndp.org/ttylog => ../ttylog

go 1.14

require (
	cndp.org/ttylog v0.0.0-00010101000000-000000000000
	github.com/fsnotify/fsnotify v1.4.9
)
