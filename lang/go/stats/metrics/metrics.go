// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation

package metrics

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// ConnInfo - Information about the app
type ConnInfo struct {
	valid       bool // true if the process info data is valid
	conn        *net.UnixConn
	Pid         int64  // Pid for the process
	Path        string // Path of the metric socket file
	ProcessName string // Directory name of the telemetry file
	CNDPVersion string
	MaxOutput   int64
}

// ConnInfoMap holds all of the process info data
type ConnInfoMap map[string]*ConnInfo

// CallbackMap holds the watcher fsnotify callback information
type CallbackMap map[string]*Callback

// MetricInfo data for applications
type MetricInfo struct {
	lock     sync.Mutex
	opened   bool              // true if process info open
	basePath string            // Base path to the run directory
	baseName string            // Base file name
	connInfo ConnInfoMap       // Indexed by Pid for each application
	callback CallbackMap       // Callback routines for the fsnotify
	watcher  *fsnotify.Watcher // watcher for the directory notify
}

// Define the buffer size to be used for incoming data
const (
	maxBufferSize = (16 * 1024)
)

// New information structure
func New(bpath, bname string) *MetricInfo {

	mi := &MetricInfo{basePath: bpath, baseName: bname}

	mi.connInfo = make(ConnInfoMap)
	mi.callback = make(CallbackMap)

	mi.opened = false

	return mi
}

// doCmd information
func (mi *MetricInfo) DoCmd(a *ConnInfo, cmd string) ([]byte, error) {

	// if string is empty do not write, but continue with read
	if len(cmd) > 0 {
		if _, err := a.conn.Write([]byte(cmd)); err != nil {
			return nil, fmt.Errorf("write on socket failed: %v", err)
		}
	}

	buf := make([]byte, maxBufferSize) // big buffer

	n, err := a.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ConnectionList returns the list of ConnInfo structures
func (mi *MetricInfo) ConnectionList() []*ConnInfo {

	p := make([]*ConnInfo, 0)

	for _, a := range mi.connInfo {
		p = append(p, a)
	}
	return p
}

// Files returns a string slice of application process info data
func (mi *MetricInfo) Files() []string {

	files := []string{}
	for _, a := range mi.connInfo {
		files = append(files, a.Path)
	}

	return files
}

// Metrics returns a string slice of application process info data
func (mi *MetricInfo) Processes() []string {

	files := []string{}
	for _, a := range mi.connInfo {
		files = append(files, a.ProcessName)
	}

	return files
}

// mids returns a int64 slice of application process info data
func (mi *MetricInfo) Pids() []int64 {

	pids := make([]int64, 0)
	for _, a := range mi.connInfo {
		pids = append(pids, a.Pid)
	}

	return pids
}

// ConnectionBymid returns the ConnInfo pointer using the pid
func (mi *MetricInfo) ConnectionByPid(pid int64) *ConnInfo {

	for _, a := range mi.connInfo {
		if a.Pid == pid {
			return a
		}
	}
	return nil
}

// ConnectionByMetricName returns the ConnInfo pointer using the pid
func (mi *MetricInfo) ConnectionByProcessName(ProcessName string) *ConnInfo {

	for _, a := range mi.connInfo {
		if a.ProcessName == ProcessName {
			return a
		}
	}
	return nil
}

// ConnectionByMetricName returns the ConnInfo pointer using the pid
func (mi *MetricInfo) CloseConnectionByProcessName(ProcessName string) *ConnInfo {

	for _, a := range mi.connInfo {
		if a.ProcessName == ProcessName {
			if !a.valid {
				a.conn.Close()
				delete(mi.connInfo, a.Path)
			}
		}
	}
	return nil
}

// Unmarshal the JSON data into a structure
func (mi *MetricInfo) Unmarshal(p *ConnInfo, command string, data interface{}) error {

	if len(mi.connInfo) == 0 {
		return nil
	}
	if p == nil {
		// Get the first element of a map
		for _, m := range mi.connInfo {
			p = m
			break
		}
	}
	d, err := mi.DoCmd(p, command)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(d, data); err != nil {
		return err
	}

	return nil
}

// Marshal the structure into a JSON string
func (mi *MetricInfo) Marshal(data interface{}) ([]byte, error) {

	return json.MarshalIndent(data, "", "  ")
}

// Version takes process info version and passes back string
func (mi *MetricInfo) Version(p *ConnInfo) string {
	return p.CNDPVersion
}

// PID takes process info pid and passes back int64
func (mi *MetricInfo) PID(p *ConnInfo) int64 {
	return p.Pid
}
