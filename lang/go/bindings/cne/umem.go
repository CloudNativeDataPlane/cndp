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
	"strconv"
	"unsafe"
)

type regionData struct {
	addr   *C.char
	pool   *C.pktmbuf_info_t
	bufCnt uint
}

// UmemData is the primary structure for UMEM information and data
type UmemData struct {
	name  string        // Name of the UMEM
	mm    *C.mmap_t     // Memory mmap information pointer
	rInfo []*regionData // Region data information
}

var umemDataList []*UmemData
var umemDataMap map[string]*UmemData

func init() {
	umemDataMap = make(map[string]*UmemData)
}

// setupUMEM initializes the given data structure for AF_XDP UMEM
func (sys *System) setupUMEM(umemName string, umem *UmemInfo) error {

	cMmapType := C.CString(umem.MemType)
	defer C.free(unsafe.Pointer(cMmapType))

	mmapType := (C.mmap_type_t)(C.mmap_type_by_name(cMmapType))

	ud := &UmemData{name: umemName}

	mmapPtr := (*C.mmap_t)(C.mmap_alloc(C.uint(umem.BufCnt), C.uint(umem.BufSize), mmapType))
	if mmapPtr == nil {
		return fmt.Errorf("failed to allocate mmap memory %d for umem %s", umem.BufCnt*umem.BufSize, umemName)
	}
	ud.mm = mmapPtr

	umemAddr := C.mmap_addr(unsafe.Pointer(ud.mm))
	ud.rInfo = make([]*regionData, len(umem.Regions))

	for i := 0; i < len(umem.Regions); i++ {
		ud.rInfo[i] = &regionData{}
		ri := ud.rInfo[i]
		ri.bufCnt = umem.Regions[i]
		ri.addr = (*C.char)(umemAddr)
		umemAddr = (unsafe.Pointer)((uintptr(umemAddr) + uintptr(ri.bufCnt*umem.BufSize)))

		bufcnt := C.uint(ri.bufCnt)
		bufsz := C.uint(umem.BufSize)
		cache := C.uint(sys.jcfg.DefaultData.Cache)

		pi := (*C.pktmbuf_info_t)(C.pktmbuf_pool_create(ri.addr, bufcnt, bufsz, cache, nil))
		if pi == nil {
			if C.mmap_free(unsafe.Pointer(mmapPtr)) < 0 {
				return fmt.Errorf("failed to free mmap memory after pktmbuf creation failed, region %d %v", i, umemName)
			}
			return fmt.Errorf("pktmbuf pool creation failed for region %d in umem %s", i, umemName)
		}

		name := umemName + "-" + strconv.Itoa(i)

		cName := C.CString(name)
		defer C.free(unsafe.Pointer(cName))

		C.pktmbuf_info_name_set(pi, cName)
		ri.pool = pi
	}

	umemDataList = append(umemDataList, ud)
	umemDataMap[umemName] = ud

	return nil
}

// Name returns the UMEM name string
func (ud *UmemData) Name() string {

	return ud.name
}

// setupUMEMs initializes the list of UMEMs
func (sys *System) setupUMEMs() error {

	umemMap := sys.jcfg.UmemInfoMap
	if umemMap == nil {
		return fmt.Errorf("failed to setup UMEM, jcfg.UmemInfoMap is nil")
	}

	for umemName, umem := range umemMap {
		if err := sys.setupUMEM(umemName, umem); err != nil {
			return err
		}
	}

	return nil
}

// UmemMap returns the map structure of all UMEMs
func (sys *System) UmemMap() map[string]*UmemData {

	return umemDataMap
}

// UmemData returns the information about a UMEM for the given name
func (sys *System) UmemData(umemName string) *UmemData {

	umemData, ok := umemDataMap[umemName]
	if !ok {
		fmt.Printf("UmemData %v not found\n", umemName)
		return nil
	}
	return umemData
}

// cleanupUMEM frees resources associated with all UMEMs
func (sys *System) cleanupUMEM() error {

	for _, ud := range umemDataList {
		for i := 0; i < len(ud.rInfo); i++ {
			if ud.rInfo[i] != nil {
				C.pktmbuf_destroy(ud.rInfo[i].pool)
			}
		}
		ret := C.mmap_free(unsafe.Pointer(ud.mm))
		if ret < 0 {
			return fmt.Errorf("error mmap_free for umem %s", ud.name)
		}
		delete(umemDataMap, ud.name)
	}
	umemDataList = nil

	return nil
}
