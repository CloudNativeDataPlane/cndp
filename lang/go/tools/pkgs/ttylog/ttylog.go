// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package ttylog

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// LogStates map of log id states
type LogStates map[string]bool

// TTYLog - Log tty information
type TTYLog struct {
	tty    string
	fd     *os.File
	out    chan string
	done   chan bool
	states LogStates
}

var tlog *TTYLog

const (
	// FatalLog for fatal error log message
	FatalLog string = "FatalLog"
	// ErrorLog for error log messages
	ErrorLog string = "ErrorLog"
	// WarnLog for warning log messages
	WarnLog string = "WarnLog"
	// InfoLog for normal information
	InfoLog string = "InfoLog"
	// DebugLog for normal information
	DebugLog string = "DebugLog"
)

func init() {
	tlog = new(TTYLog)
	tlog.states = make(LogStates)

	tlog.states[FatalLog] = true
	tlog.states[ErrorLog] = true
	tlog.states[WarnLog] = true
	tlog.states[InfoLog] = true
	tlog.states[DebugLog] = false
}

// logger go function to log data to tty
func logger() {

ForLoop:
	for {
		select {
		case <-tlog.done: // Quit
			break ForLoop
		case str := <-tlog.out:
			fmt.Fprintf(tlog.fd, "%s", str)
		}
	}
}

// Register is a function to register new logging type strings
func Register(id string, state ...bool) {

	flg := false
	if state != nil {
		flg = state[0]
	}

	tlog.states[id] = flg
}

// Delete a log id
func Delete(id string) error {

	_, ok := tlog.states[id]
	if ok {
		delete(tlog.states, id)
		return nil
	}

	return fmt.Errorf("log id not registered")
}

// State is a function to return the current logid state
func State(id string) (bool, error) {

	state, ok := tlog.states[id]
	if !ok {
		return false, fmt.Errorf("unknown logid %s", id)
	}
	return state, nil
}

// SetState on a logid
func SetState(id string, state bool) error {
	state, ok := tlog.states[id]
	if !ok {
		return fmt.Errorf("unknown logid %s", id)
	}
	tlog.states[id] = state
	return nil
}

// IsInited - return true if tty open and channels are active
func IsInited() bool {

	if tlog.fd == nil || tlog.out == nil || tlog.done == nil {
		return false
	}
	return true
}

// IsActive - return true if log type id is true else false
func IsActive(id string) bool {

	state, ok := tlog.states[id]
	if !ok {
		return false
	}

	return state
}

// GetList returns the list of states and log ids
func GetList() LogStates {

	return tlog.states
}

// FatalPrintf to print out fatal error messages
func FatalPrintf(format string, a ...interface{}) (err error) {
	if !IsInited() {
		return fmt.Errorf("tty or channel is not inited")
	}

	s := fmt.Sprintf("Fatal: "+format, a...)
	tlog.out <- s
	os.Exit(1)

	return nil
}

// ErrorPrintf to print out error messages
func ErrorPrintf(format string, a ...interface{}) (err error) {
	if !IsInited() {
		return fmt.Errorf("tty or channel is not inited")
	}

	if IsActive(ErrorLog) {
		s := fmt.Sprintf("Error: "+format, a...)
		tlog.out <- s
	}

	return nil
}

// WarnPrintf to print out warning messages
func WarnPrintf(format string, a ...interface{}) (err error) {
	if !IsInited() {
		return fmt.Errorf("tty or channel is not inited")
	}

	if IsActive(WarnLog) {
		s := fmt.Sprintf("Warning: "+format, a...)
		tlog.out <- s
	}

	return nil
}

// InfoPrintf to print out informational messages
func InfoPrintf(format string, a ...interface{}) (err error) {
	if !IsInited() {
		return fmt.Errorf("tty or channel is not inited")
	}

	if IsActive(InfoLog) {
		s := fmt.Sprintf("Info: "+format, a...)
		tlog.out <- s
	}

	return nil
}

// DebugPrintf to print out informational messages
func DebugPrintf(format string, a ...interface{}) (err error) {
	if !IsInited() {
		return fmt.Errorf("tty or channel is not inited")
	}

	if IsActive(DebugLog) {
		s := fmt.Sprintf("Debug: "+format, a...)
		tlog.out <- s
	}

	return nil
}

// Log - output using printf like routine
func Log(id string, format string, a ...interface{}) (n int, err error) {
	if !IsInited() {
		return 0, fmt.Errorf("tty or channel is not inited")
	}

	if IsActive(id) {
		s := fmt.Sprintf(format, a...)
		tlog.out <- s
		if id == FatalLog {
			os.Exit(1)
		}
		return len(s), nil
	}
	return 0, fmt.Errorf("tty or channel is not active")
}

// Print a fmt.Print like function for verbose output
func Print(id string, a ...interface{}) (n int, err error) {
	return Log(id, fmt.Sprint(a...))
}

// Println a fmt.Println like function for verbose output
func Println(id string, format string, a ...interface{}) (n int, err error) {
	return Log(id, fmt.Sprintf(format, a...)+"\n")
}

// Printf a fmt.Print like function for verbose output
func Printf(id string, format string, a ...interface{}) (n int, err error) {
	return Log(id, fmt.Sprintf(format, a...))
}

// DoPrintf - output using printf like format without leading text and checks
func DoPrintf(format string, a ...interface{}) (n int, err error) {
	if !IsInited() {
		return 0, fmt.Errorf("tty or channel is not inited")
	}

	s := fmt.Sprintf(format, a...)
	tlog.out <- s

	return len(s), nil
}

// Open - Open the tty and channel
func Open(w ...interface{}) error {

	tty := "0"
	if len(w) > 0 {
		tty = w[0].(string)
	}

	// Test if arg is valid or we have not set tlog.tty
	if len(tty) == 0 && len(tlog.tty) == 0 {
		tty = "0"
	}

	if !IsInited() {
		// Update tlog.tty if empty or tty has changed
		if len(tlog.tty) == 0 || tty != tlog.tty {
			tlog.tty = tty
		}
		tlog.out = make(chan string)
		tlog.done = make(chan bool)

		if strings.Contains(tty, "/dev/") == false {
			tty = "/dev/pts/" + tty
		}
		tlog.tty = tty

		fd, err := os.OpenFile(tlog.tty, os.O_RDWR, 0755)
		if err != nil {
			fmt.Printf("Unable to open tty (%v)\n", tlog.tty)
			return fmt.Errorf("unable to open tty")
		}
		tlog.fd = fd

		go logger()

		return nil
	}

	return nil
}

// Close - close the channel and fd
func Close() {

	if tlog.fd != nil {
		tlog.fd.Close()
		tlog.fd = nil
	}

	if tlog.out != nil {
		tlog.done <- true

		time.Sleep(1)

		close(tlog.out)
		tlog.out = nil

		close(tlog.done)
		tlog.done = nil
	}

	tlog.tty = ""
	tlog.states = make(LogStates)
}

// HexDump the data to the ttylog
func HexDump(msg string, b []byte, n int) {
	if len(msg) > 0 {
		DoPrintf("*** %s ***\n", msg)
	}

}
