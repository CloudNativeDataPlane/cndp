/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp -lbsd

#include <cne.h>
#include <cne_mmap.h>
#include <pktmbuf.h>
#include <pktdev.h>
#include <uds.h>
#include <uds_connect.h>
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/tidwall/jsonc"
)

// System structure to hold internal information for binding layer to CNDP
type System struct {
	tid  int
	jcfg *Config
}

// Create and setup the UMEM and LPort structures
func (sys *System) initializeSystem() error {

	if err := sys.setupUMEMs(); err != nil {
		return err
	}

	if err := sys.setupLPorts(); err != nil {
		return err
	}

	return nil
}

// open processes the JSON-C configuration and initializes the binding layer
//
// The cfg argument can be a JSON string, path to JSON file or pointer to cne.Config structure
// Returns an error or the binding layer System structure pointer
func open(cfg interface{}) (*System, error) {

	sys := &System{}

	sys.tid = RegisterThread("main")
	if sys.tid < 0 {
		return nil, fmt.Errorf("failed to register main thread")
	}

	switch v := cfg.(type) {
	case *Config: //  Initialize the binding layer with a cne.Config structure
		jcfg := v

		if err := jcfg.validateConfig(); err != nil {
			UnregisterThread(sys.tid)
			return nil, fmt.Errorf("failed to validate configuration")
		}
		sys.jcfg = jcfg

	case []byte: // Initialize the binding layer with a JSON byte array
		if jcfg, err := processConfig(v); err != nil {
			UnregisterThread(sys.tid)
			return nil, fmt.Errorf("failed to process configuration")
		} else {
			sys.jcfg = jcfg
		}

	default:
		UnregisterThread(sys.tid)
		return nil, fmt.Errorf("invalid argument type not *Config or []byte, %T", v)
	}

	return sys, sys.initializeSystem()
}

// OpenWithConfig by passing in a initialized cne.Config structure
func OpenWithConfig(cfg *Config) (*System, error) {

	return open(cfg)
}

// OpenWithString by passing in a string containing JSON-C or JSON text
func OpenWithString(cfgStr string) (*System, error) {

	str := strings.TrimSpace(cfgStr)

	// test for a JSON-C or JSON string, which must start with a '{'
	if !strings.HasPrefix(str, "{") {
		return nil, fmt.Errorf("string does not appear to be a valid JSON text missing starting '{'")
	}

	return open(jsonc.ToJSON([]byte(str)))
}

// OpenWithFile by passing in a filename or path to a JSON-C or JSON configuration
func OpenWithFile(path string) (*System, error) {

	var err error

	str := strings.TrimSpace(path)

	// test for a JSON-C or JSON string, which must start with a '{'
	if strings.HasPrefix(str, "{") {
		err = fmt.Errorf("path does not appear to be a valid filepath")
	} else {
		var configFile *os.File

		if configFile, err = os.Open(str); err == nil {
			var bytes []byte

			defer configFile.Close()

			// Read the JSON-C file into a single byte array for later parsing
			if bytes, err = io.ReadAll(configFile); err == nil {
				return open(jsonc.ToJSON(bytes))
			}
		}
	}

	return nil, err
}

// Close the binding layer and cleanup UMEM and LPorts
func (sys *System) Close() error {

	if sys.tid < 0 {
		return fmt.Errorf("system not initialized")
	}
	defer UnregisterThread(sys.tid)

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
func RegisterThread(name string) int {

	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	runtime.LockOSThread()

	return int(C.cne_register(cName))
}

// UnregisterThread unregister the thread from CNDP
func UnregisterThread(tid int) {

	if ret := int(C.cne_unregister(C.int(tid))); ret < 0 {
		fmt.Printf("cne_unregister(%v) failed", tid)
	}
	runtime.UnlockOSThread()
}
