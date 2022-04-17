// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package main

// TODO Need to extend for multi CNDP container support as more than one
// may run in the pod

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/CloudNativeDataPlane/cndp/lang/go/stats/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PrometheusConf struct {
	Interval int `json:"interval"`
	Stats    []struct {
		Metric string  `json:"metric"`
		Value  float64 `json:"value"`
		Type   string  `json:"type"`
	}
}

type AppName struct {
	Application string `json:"name"`
}

func recordMetrics() {
	go func() {
		for {
			var _processes []*string
			//UPDATE PROCESSES list locally
			for _, f := range metricInfo.Processes() {

				i := sort.Search(len(_processes), func(i int) bool { return f == *_processes[i] })
				if i == len(_processes) {
					_processes = append(_processes, &f)
					for _, p := range _processes {
						_, err := metricInfo.DoCmd(metricInfo.ConnectionByProcessName(*p),
							"/app/appname")
						if err != nil {
							fmt.Println("ERROR RETRIEVING appname")
							metricInfo.CloseConnectionByProcessName(*p)
							os.Exit(-1)
						}
					}
				}
			}
			if len(_processes) > 0 {
				for _, p := range _processes {
					ans, err := metricInfo.DoCmd(metricInfo.ConnectionByProcessName(*p),
						"/metrics/port_stats")
					if err != nil {
						fmt.Println("ERROR RETRIEVING Stats")
					}
					var response map[string]float64

					if err := json.Unmarshal(ans, &response); err != nil {
						fmt.Println("ERROR UNMARSHALLING the json")
					}

					for key, value := range response {
						tmp := pMetrics[key]
						switch tmp.(type) {
						case prometheus.Counter:
							old_val := pMetricsValues[key]
							if value > old_val {
								tmp.(prometheus.Counter).Add(value - old_val)
								pMetricsValues[key] = value
							}
						case prometheus.Gauge:
							tmp.(prometheus.Gauge).Set(value)
						default:
							fmt.Println("Error Couldn't decode the metric type")
						}
					} // for key, value := range response
				} // for _ , p := range _processes
				time.Sleep(time.Duration(interval) * time.Second)
			} else { //(len(_processes) > 0)
				os.Exit(0)
			}
		} // for
	}()
}

var metricInfo *metrics.MetricInfo
var interval int
var pMetrics map[string]interface{}
var pMetricsValues map[string]float64

func main() {
	var processes []*string
	// Setup and locate the telemery socket connections
	metricInfo = metrics.New("/var/run/cndp", "")
	if metricInfo == nil {
		fmt.Println("unable to setup metricInfo")
		return
	}

	if err := metricInfo.StartWatching(); err != nil {
		panic(err)
	}
	defer metricInfo.StopWatching()

	// Add a callback for this watcher
	metricInfo.Add("prometheus", func(event int) {
		for _, f := range metricInfo.Processes() {

			i := sort.Search(len(processes), func(i int) bool { return f == *processes[i] })
			if i == len(processes) {
				processes = append(processes, &f)
				var ver = metricInfo.Version(metricInfo.ConnectionByProcessName(f))
				fmt.Printf("CNDP Version for process %s is %s \n", f, ver)
			}
		}
	})

	app := &AppName{}

	for _, p := range metricInfo.Processes() {
		ans, err := metricInfo.DoCmd(metricInfo.ConnectionByProcessName(p), "/app/appname")
		if err != nil {
			fmt.Println("ERROR RETRIEVING appname")
		}

		if err := json.Unmarshal(ans, &app); err != nil {
			fmt.Println("ERROR UNMARSHALLING the json")
		}
	}

	file, err := ioutil.ReadFile("prom_cfg.json")
	if err != nil {
		fmt.Println("ERROR couldn't read the json configuration")
		panic(err)
	}

	conf := PrometheusConf{}

	if err := json.Unmarshal([]byte(file), &conf); err != nil {
		fmt.Println("ERROR parsing the json configuration")
		return
	}
	mp := make(map[string]interface{})
	mv := make(map[string]float64)

	for _, p := range processes {
		ans, err := metricInfo.DoCmd(metricInfo.ConnectionByProcessName(*p),
			"/metrics/port_stats")
		if err != nil {
			fmt.Println("ERROR RETRIEVING Stats")
		}
		var response map[string]float64

		if err := json.Unmarshal(ans, &response); err != nil {
			fmt.Println("ERROR UNMARSHALLING the json")
		}

		for key := range response {
			for _, d := range conf.Stats {

				if strings.Contains(key, d.Metric) {
					switch d.Type {
					case "counter":
						mp[key] = promauto.NewCounter(prometheus.CounterOpts{
							Name: app.Application + "_" + key})
					case "gauge":
						mp[key] = promauto.NewGauge(prometheus.GaugeOpts{
							Name: app.Application + "_" + key})
					case "histogram":
						mp[key] = promauto.NewHistogram(prometheus.HistogramOpts{
							Name: app.Application + "_" + key})
					}
					mv[key] = 0
				}
			} // for _,d := range conf.Stats {
		} // for key, value := range response
	} // for _ , p := range processes

	pMetrics = mp
	pMetricsValues = mv

	interval = conf.Interval

	recordMetrics()

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
}
