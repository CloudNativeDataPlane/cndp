/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 * Copyright (c) 2022 Canopus Networks.
 */

package cne

/*
#include <cne.h>
#include <cne_mmap.h>
#include <pktmbuf.h>
#include <pktdev.h>
#include <uds.h>
#include <uds_connect.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/tidwall/jsonc"
	"golang.org/x/sys/unix"
)

const (
	DefaultLCoreGroup = "default" // the lcore group used if a thread if not assigned to a group
	MainThreadName    = "main"    // the thread name used to register the main CNDP thread
)

// System structure to hold internal information for binding layer to CNDP
type System struct {
	jcfg     *Config
	mu       sync.Mutex
	tidMap   map[string]*int         // map of thread name to cne uid
	groupSet map[string]*unix.CPUSet // map of lcore group name to cpu set to use when registering
	oldSet   map[string]*unix.CPUSet // map of thread name to cpu set before the thread was registered
}

// Create and setup the UMEM and LPort structures
func (sys *System) initializeSystem() error {

	if err := sys.setupUMEMs(); err != nil {
		return err
	}

	if err := sys.setupLPorts(); err != nil {
		sys.cleanupUMEM()
		return err
	}

	return nil
}

// InitCNE initializes the CNE system and returns error on failure.
//
// The cne_init() is also called from OpenWithConfig(), which means
// this routine does not need to be called if OpenWith*() routines
// are used. It is OK to call this routine multiple times as it is
// protected to only initialize once.
func InitCNE() error {

	if C.cne_init() < 0 {
		return fmt.Errorf("error initializing CNE subsystem")
	}
	return nil
}

// OpenWithConfig by passing in a initialized cne.Config structure
func OpenWithConfig(cfg *Config) (*System, error) {
	if err := cfg.validateConfig(); err != nil {
		return nil, fmt.Errorf("failed to validate configuration: %w", err)
	}

	sys := &System{jcfg: cfg}
	sys.tidMap = make(map[string]*int)
	sys.groupSet = make(map[string]*unix.CPUSet)
	sys.oldSet = make(map[string]*unix.CPUSet)

	if err := InitCNE(); err != nil {
		return nil, err
	}

	// create cpu sets for lcore groups
	for group, cores := range cfg.LCoreGroupData {
		var cs unix.CPUSet
		for _, n := range cores {
			cs.Set(n)
		}
		sys.groupSet[group] = &cs
	}

	err := sys.RegisterThread(MainThreadName)
	if err != nil {
		return nil, err
	}

	err = sys.initializeSystem()
	if err != nil {
		sys.UnregisterThread(MainThreadName)
		return nil, err
	}
	return sys, nil
}

func openWithBytes(b []byte) (*System, error) {
	jcfg, err := processConfig(jsonc.ToJSON(b))
	if err != nil {
		return nil, fmt.Errorf("failed to process configuration: %w", err)
	}
	return OpenWithConfig(jcfg)
}

// OpenWithString by passing in a string containing JSON-C or JSON text
func OpenWithString(s string) (*System, error) {
	return openWithBytes([]byte(s))
}

// OpenWithFile by passing in a filename or path to a JSON-C or JSON configuration
func OpenWithFile(path string) (*System, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return openWithBytes(b)
}

// Close the binding layer and cleanup UMEM and LPorts
func (sys *System) Close() error {
	sys.mu.Lock()
	defer sys.mu.Unlock()

	if sys.tidMap[MainThreadName] == nil {
		return errors.New("system not initialized")
	}
	defer sys.unregister(MainThreadName)

	if err := sys.cleanupUMEM(); err != nil {
		return fmt.Errorf("error cleaning up mempool %w", err)
	}

	if err := sys.cleanupLPorts(); err != nil {
		return fmt.Errorf("error cleaning up lports %w", err)
	}

	return nil
}

// JsonCfg returns the JSON configuration structure pointer
func (sys *System) JsonCfg() *Config {

	return sys.jcfg
}

// RegisterThread locks a thread and registers it to CNDP to get the CNE UID value
func (sys *System) RegisterThread(name string) error {
	sys.mu.Lock()
	defer sys.mu.Unlock()

	if sys.tidMap[name] != nil {
		return fmt.Errorf("thread %s already registered", name)
	}

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	runtime.LockOSThread()
	tid := int(C.cne_register(cName))
	if tid < 0 {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to register %s thread", name)
	}
	sys.tidMap[name] = &tid

	// get cpu set from thread lcore group
	var newSet *unix.CPUSet
	if threadInfo := sys.jcfg.ThreadInfoMap[name]; threadInfo != nil {
		newSet = sys.groupSet[threadInfo.Group]
	}
	if newSet == nil {
		newSet = sys.groupSet[DefaultLCoreGroup]
		if newSet == nil {
			return nil
		}
	}

	// save current cpu affinity settings
	var oldSet unix.CPUSet
	err := unix.SchedGetaffinity(0, &oldSet)
	if err != nil {
		sys.unregister(name)
		return err
	}
	sys.oldSet[name] = &oldSet

	// set new cpu affinity settings
	err = unix.SchedSetaffinity(0, newSet)
	if err != nil {
		sys.unregister(name)
		return err
	}
	return nil
}

func (sys *System) unregister(name string) error {
	tid := sys.tidMap[name]
	if tid == nil {
		return fmt.Errorf("thread %s not registered", name)
	}

	if ret := int(C.cne_unregister(C.int(*tid))); ret < 0 {
		return fmt.Errorf("cne_unregister(%v) failed", tid)
	}
	delete(sys.tidMap, name)

	runtime.UnlockOSThread()

	oldSet := sys.oldSet[name]
	if oldSet != nil {
		delete(sys.oldSet, name)
		return unix.SchedSetaffinity(0, oldSet)
	}
	return nil
}

// UnregisterThread unregister the thread from CNDP
func (sys *System) UnregisterThread(name string) error {
	sys.mu.Lock()
	defer sys.mu.Unlock()

	return sys.unregister(name)
}
