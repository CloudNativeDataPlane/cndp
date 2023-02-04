// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2023 Intel Corporation

package metrics

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

// Define the events the application callback will use
const (
	AppInited  = iota
	AppCreated = iota
	AppRemoved = iota
)

// TelemetryVersion string and information
type TelemetryVersion struct {
	Pid         int64  `json: "pid"`
	MaxOutput   int64  `json:"max_output_len"`
	CNDPVersion string `json:"version"`
}

// Callback structure and data
type Callback struct {
	name string          // string name of the callback used as key
	cb   func(event int) // function to callback the application for notifies
}

func (pi *MetricInfo) watchDir(path string, fi os.FileInfo, err error) error {

	if fi != nil && fi.Mode().IsDir() {
		return pi.watcher.Add(path)
	}
	return nil
}

// exists returns whether the given file or directory exists
func exists(path string) (bool, error) {

	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func (pi *MetricInfo) callbackFunctions() {

	// Callback the user level functions on the first time
	for _, c := range pi.callback {
		c.cb(AppInited)
	}
}

// StartWatching the directory and read the first set of directories
func (pi *MetricInfo) StartWatching() error {

	// Create the watcher to watch all sub-directories
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	pi.watcher = watcher

	if ok, _ := exists(pi.basePath); !ok {
		os.MkdirAll(pi.basePath, os.ModePerm)
	}

	// Add the basepath to the watcher
	watcher.Add(pi.basePath)

	if err := filepath.Walk(pi.basePath, pi.watchDir); err != nil {
		return fmt.Errorf("%s: %v", pi.basePath, err)
	}

	pi.scan() // Scan the directory for the first time

	// Spin up a thread for watching the directory
	go func() {
		// Callback the user level functions on the first time
		pi.callbackFunctions()

		for {
			select {
			case err, ok := <-watcher.Errors:
				if !ok {
					continue
				}
				fmt.Printf("fsnotify: error %v", err)

			case event, ok := <-watcher.Events:
				if !ok {
					continue
				}

				switch {
				case (event.Op & fsnotify.Create) == fsnotify.Create:

					if fi, err := os.Stat(event.Name); err == nil {
						if fi.Mode().IsDir() {
							watcher.Add(event.Name)
						}
					}

					pi.scan() // Scan when a create event has happened

					pi.callbackFunctions()

				case (event.Op & fsnotify.Remove) == fsnotify.Remove:
					watcher.Remove(event.Name)

					pi.scan()

					pi.callbackFunctions()
				}
			}
		}
	}()

	pi.opened = true

	return nil
}

// StopWatching the directory
func (pi *MetricInfo) StopWatching() {

	if !pi.opened {
		return
	}

	pi.watcher.Close()

	pi.watcher = nil
	pi.opened = false
}

// Add callback function when directory changes
func (pi *MetricInfo) Add(name string, f func(event int)) {

	pi.callback[name] = &Callback{name: name, cb: f}
	f(AppInited) // Call it the first time it is setup
}

// Remove callback function
func (pi *MetricInfo) Remove(name string) {

	_, ok := pi.callback[name]
	if ok {
		delete(pi.callback, name)
	}
}

func (pi *MetricInfo) addFile(name, dir string) {
	if len(name) == 0 || strings.HasPrefix(filepath.Base(name), pi.baseName) == true {

		/*
			ext := filepath.Ext(name)
			pid, err := strconv.ParseInt(ext[1:], 10, 64)
			if err != nil {
				fmt.Printf("unable to parse pid from filename %s\n", name)
				return
			} */

		var path string
		if len(name) == 0 {
			path = pi.basePath + "/" + dir
		} else {
			path = pi.basePath + "/" + dir + "/" + name
		}
		if a, ok := pi.connInfo[path]; ok {
			a.valid = true
			return
		}

		// Open the connection to the application
		t := "unixpacket"
		laddr := net.UnixAddr{Name: path, Net: t}
		conn, err := net.DialUnix(t, nil, &laddr)
		if err != nil {
			return
		}

		// {"pid": 4464, "max_output_len": 16384, "version": "CNDP 20.11.0"}
		// store in connection info
		ap := &ConnInfo{valid: true, Pid: -1, Path: path, conn: conn, ProcessName: dir}

		buf := make([]byte, maxBufferSize) // big buffer

		if _, err := conn.Write([]byte("/info")); err != nil {
			fmt.Printf("Error writing to socket: %v\n", err)
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		b := buf[:n]

		tv := &TelemetryVersion{}
		if err := json.Unmarshal(b, tv); err != nil {
			// No connection data found
			fmt.Printf("Error parsing info from telemetry socket %v\n", err)
			return
		}

		ap.Pid = tv.Pid
		ap.MaxOutput = tv.MaxOutput
		ap.CNDPVersion = tv.CNDPVersion

		// Add the ConnInfo to the internal map structures
		pi.connInfo[path] = ap
	}
}

// Scan for the socket files
func (pi *MetricInfo) scan() {

	dirs, err := ioutil.ReadDir(pi.basePath)
	if err != nil {
		log.Fatalf("ReadDir failed: %v\n", err)
	}

	pi.lock.Lock()
	defer pi.lock.Unlock()

	// Set all of the current files to false, to allow for removal later
	// When we find the same one in the scan we mark it as true, then
	// remove the ones that are not valid anymore
	for _, a := range pi.connInfo {
		a.valid = false
	}

	for _, entry := range dirs {
		if entry.IsDir() {
			appFiles, err := ioutil.ReadDir(pi.basePath + "/" + entry.Name())
			if err != nil {
				log.Fatalf("Unable to open %s\n", pi.basePath+"/"+entry.Name())
			}

			for _, file := range appFiles {
				// looking for metrics.{PID} files
				if strings.HasPrefix(filepath.Base(file.Name()), pi.baseName) {
					pi.addFile(file.Name(), entry.Name())
				}
			}
		} else {
			// looking for metrics.{PID} files
			if strings.HasPrefix(filepath.Base(entry.Name()), pi.baseName) {
				pi.addFile("", entry.Name())
			}
		}
	}

	// release ConnInfo data for old process info files/pids
	for _, a := range pi.connInfo {
		if !a.valid {
			a.conn.Close()
			delete(pi.connInfo, a.Path)
		}
	}
}
