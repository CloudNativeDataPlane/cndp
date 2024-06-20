# Install the prometheus go client library

You can install the prometheus, promauto, and promhttp libraries by running:

```sh
go get github.com/prometheus/client_golang/prometheus
go get github.com/prometheus/client_golang/prometheus/promauto
go get github.com/prometheus/client_golang/prometheus/promhttp
```

To run the cndp prometheus client just run:

```sh
go run prometheus.go
```

You can then access the metrics using:

```sh
curl http://localhost:2112/metrics
```

## Metrics naming best practices

The best practices for naming metrics with prometheus is explained here:

- <https://sysdig.com/blog/prometheus-metrics/>
- <https://prometheus.io/docs/practices/naming/>
