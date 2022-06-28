/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp -lbsd

#include <cne.h>
#include <pktmbuf.h>
#include <pktdev.h>
#include <cne_lport.h>
#include <uds.h>
#include <uds_connect.h>
*/
import "C"

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"unsafe"
)

// LPort is the logical port data structure to hold information for accessing
// the logical port or netdev/queue ID.
type LPort struct {
	name           string   // Name of the logical port
	netdev         string   // Name of the netdev interface for the logical port
	lportId        C.ushort // The LPort ID value
	prevInPackets  uint64   // Previous number of input packets
	prevOutPackets uint64   // Previous number of output packets
}

var lportList []*LPort         // list of logical port structures for a fixed order
var lportMap map[string]*LPort // A map of LPort structures using lport name as index

// LPortStats is the Go structure for LPort statistics
type LPortStats struct {
	InPackets     uint64 // Number of input packets
	InBytes       uint64 // Number of input bytes
	InErrors      uint64 // Number of input errors
	InMissed      uint64 // Number of missed input packets
	RxInvalid     uint64 // Number of invalid Rx packets
	OutPackets    uint64 // Number of output packets
	OutBytes      uint64 // Number of output bytes
	OutErrors     uint64 // Number of output errors
	OutDropped    uint64 // Number of dropped output packets
	TxInvalid     uint64 // Number of invalid Tx packets
	InPacketRate  uint64 // Packet rate for input
	OutPacketRate uint64 // Packet rate for output
}

func init() {
	lportMap = make(map[string]*LPort)
}

// Create a new LPort structure pointer
func newLPort(name, netdev string, lportId int) *LPort {

	return &LPort{name: name, netdev: netdev, lportId: C.ushort(lportId)}
}

// setupLPort creates a new LPort structure pointer and initializes the port
func (sys *System) setupLPort(lportName string, lportInfo *LPortInfo) error {
	jcfg := sys.jcfg

	lportUmem, ok := jcfg.UmemInfoMap[lportInfo.Umem]
	if !ok {
		return fmt.Errorf("unable to get umem map")
	}
	ud := sys.UmemData(lportInfo.Umem)

	var pcfg *C.lport_cfg_t
	pcfg = (*C.lport_cfg_t)(C.calloc(1, C.ulong(unsafe.Sizeof(*pcfg))))
	if pcfg == nil {
		return fmt.Errorf("unable to allocate C.lport_cfg_t structure")
	}

	pcfg.qid = C.ushort(lportInfo.Qid)
	pcfg.bufsz = C.uint(lportUmem.BufSize)
	pcfg.rx_nb_desc = C.uint(lportUmem.RxDesc)
	pcfg.tx_nb_desc = C.uint(lportUmem.TxDesc)

	lportNameArr := strings.Split(lportName, ":")
	netdevName := lportNameArr[0]

	for i := 0; i < len(netdevName) && i < C.LPORT_NAME_LEN; i++ {
		pcfg.ifname[i] = C.char(netdevName[i])
		pcfg.name[i] = C.char(lportName[i])
	}

	lportPmdArr := strings.Split(lportInfo.Pmd, ":")
	lportPmd := lportPmdArr[0]

	for i := 0; i < len(lportPmd) && i < C.LPORT_NAME_LEN; i++ {
		pcfg.pmd_name[i] = C.char(lportPmd[i])
	}

	if len(lportNameArr) > 1 {
		cPmdOpts := C.CString(lportNameArr[1])
		defer C.free(unsafe.Pointer(cPmdOpts))

		pcfg.pmd_opts = cPmdOpts
	}

	pcfg.umem_addr = (*C.char)(C.mmap_addr(unsafe.Pointer(ud.mm)))
	pcfg.umem_size = C.ulong(C.mmap_size(unsafe.Pointer(ud.mm), nil, nil))
	pcfg.busy_timeout = C.ushort(lportInfo.BusyTimeout)
	pcfg.busy_budget = C.ushort(lportInfo.BusyBudget)
	pcfg.flags = C.ushort(lportInfo.LPortFlags())

	if lportInfo.Region >= len(ud.rInfo) {
		return fmt.Errorf("lport region %d in umem %s for lport %s is not configured",
			lportInfo.Region, lportInfo.Umem, lportName)
	}

	pcfg.addr = unsafe.Pointer(ud.rInfo[lportInfo.Region].addr)
	if pcfg.addr == nil {
		return fmt.Errorf("lport %s umem %s region index %d >= %d or not configured correctly",
			lportName, lportInfo.Umem, lportInfo.Region, len(ud.rInfo))
	}

	pcfg.bufcnt = C.uint(ud.rInfo[lportInfo.Region].bufCnt)

	pcfg.pi = ud.rInfo[lportInfo.Region].pool

	lportId := int(C.pktdev_port_setup(pcfg))
	if lportId < 0 {
		return fmt.Errorf("pktdev_port_setup() failed for lport %s", lportName)
	}

	// Build up the LPort structure only once per LPortInfo structure
	lport := newLPort(lportName, netdevName, lportId)

	// Add the Lport to the LPort slice and map
	lportList[lportId] = lport
	lportMap[lportName] = lport

	return nil
}

// setupLPorts sets up all LPorts and initializes them
func (sys *System) setupLPorts() error {

	var lportNames []string

	lportList = make([]*LPort, len(sys.jcfg.LPortInfoMap))

	// Force the LPort names to be sorted to force order on the LPortInfo structures
	for lportName := range sys.jcfg.LPortInfoMap {
		lportNames = append(lportNames, lportName)
	}

	sort.Slice(lportNames, func(i, j int) bool { return lportNames[i] < lportNames[j] })

	for _, lportName := range lportNames {

		lportInfo, ok := sys.jcfg.LPortInfoMap[lportName]
		if !ok {
			return fmt.Errorf("LPort %s not found in LPortMap", lportName)
		}

		if err := sys.setupLPort(lportName, lportInfo); err != nil {
			return err
		}
	}

	return nil
}

// cleanupLPorts will cleanup all of the LPorts
func (sys *System) cleanupLPorts() error {

	for _, lport := range lportList {
		if lport.lportId < 0xFFFF {
			ret := C.pktdev_close(C.ushort(lport.lportId))
			if ret < 0 {
				return fmt.Errorf("error pktdev_close for lport %s", lport.name)
			}
		}
	}
	return nil
}

// LPortMap returns the MAP of LPorts
func (sys *System) LPortMap() map[string]*LPort {

	return lportMap
}

// LPortList returns the List of LPorts
func (sys *System) LPortList() []*LPort {

	return lportList
}

// LPortByName returns the LPort for the given name
func (sys *System) LPortByName(name string) *LPort {

	lport, ok := lportMap[name]
	if !ok {
		log.Printf("LPort %#v not found\n", name)
		return nil
	}
	return lport
}

// LPortsByName return a list of LPort structure pointers
func (sys *System) LPortsByName(names []string) []*LPort {

	var lports []*LPort

	for _, name := range names {
		lport := sys.LPortByName(name)
		if lport == nil {
			return nil
		}
		lports = append(lports, lport)
	}
	return lports
}

// Name returns the netdev name of the given LPort
func (p *LPort) Name() string {

	return p.name
}

// NetdevName returns the name of the given LPort
func (p *LPort) NetdevName() string {

	return p.netdev
}

// LPortID returns the lport ID value for the given LPort
func (p *LPort) LPortID() int {

	return int(p.lportId)
}

// LPortStats returns the lport statistics structure for the given LPort
func (p *LPort) LPortStats() (*LPortStats, error) {

	var stats C.lport_stats_t

	if ret := C.pktdev_stats_get(p.lportId, &stats); ret < 0 {
		return nil, fmt.Errorf("LPortStats failed with error code %d", ret)
	}

	ps := &LPortStats{}
	ps.InPackets = uint64(stats.ipackets)
	ps.InBytes = uint64(stats.ibytes)
	ps.InErrors = uint64(stats.ierrors)
	ps.InMissed = uint64(stats.imissed)
	ps.RxInvalid = uint64(stats.rx_invalid)
	ps.OutPackets = uint64(stats.opackets)
	ps.OutBytes = uint64(stats.obytes)
	ps.OutErrors = uint64(stats.oerrors)
	ps.OutDropped = uint64(stats.odropped)
	ps.TxInvalid = uint64(stats.tx_invalid)

	ps.InPacketRate = ps.InPackets - p.prevInPackets
	ps.OutPacketRate = ps.OutPackets - p.prevOutPackets

	p.prevInPackets = ps.InPackets
	p.prevOutPackets = ps.OutPackets

	return ps, nil
}

// ResetLPortStats resets the LPort statistics
func (p *LPort) ResetLPortStats() error {

	if ret := C.pktdev_stats_reset(p.lportId); ret < 0 {
		return fmt.Errorf("ResetLPortStats failed with error code %d", ret)
	}
	p.prevInPackets = 0
	p.prevOutPackets = 0

	return nil
}

// GetChannels returns the number of channels enabled for the given netdev device name
func GetChannels(name string) (int, error) {

	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	cnt := C.netdev_get_channels(cname)
	if cnt < 0 {
		return 0, fmt.Errorf("failed to get channel count for %s", name)
	}

	return int(cnt), nil
}

// GetLPortChannels using an LPort structure return the number of channels of a netdev device.
func (p *LPort) GetLPortChannels() (int, error) {

	return GetChannels(p.netdev)
}
