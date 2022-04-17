/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp -lbsd

#include <cne.h>
*/
import "C"
import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

type System struct {
	tid int
	mu  sync.Mutex
	cfg *Config
}

func Open(configStr string) (*System, error) {
	handle := &System{}
	handle.tid = handle.RegisterThread("main")

	cfg, err := loadConfig(configStr)
	if err != nil {
		return nil, fmt.Errorf("error loading config file at %s: %w", configStr, err)
	}

	err = cfg.validate()
	if err != nil {
		return nil, fmt.Errorf("error validating config file at %s: %w", configStr, err)
	}

	err = cfg.process()
	if err != nil {
		return nil, fmt.Errorf("error processing config file at %s: %w", configStr, err)
	}

	handle.cfg = cfg

	return handle, nil
}

func (sys *System) GetPort(name string) (*Port, error) {
	return sys.cfg.getPortByName(name)
}

func (sys *System) RegisterThread(name string) int {
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	runtime.LockOSThread()

	sys.mu.Lock()
	defer sys.mu.Unlock()

	tid := int(C.cne_id())
	if tid < 0 {
		tid = int(C.cne_register(cName))
	}

	return tid
}

func (sys *System) UnregisterThread(tid int) int {
	sys.mu.Lock()
	defer sys.mu.Unlock()

	ret := int(C.cne_unregister(C.int(tid)))
	runtime.UnlockOSThread()

	return ret
}

func (sys *System) Close() error {
	if sys.cfg == nil {
		return fmt.Errorf("system handle or config is nil")
	}

	err := sys.cfg.cleanup()
	if err != nil {
		return fmt.Errorf("error cleaning up config %w", err)
	}

	sys.UnregisterThread(sys.tid)
	return nil
}
