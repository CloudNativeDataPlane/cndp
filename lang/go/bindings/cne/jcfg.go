/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -lcndp -lbsd

#include <cne_mmap.h>
#include <pktmbuf.h>
#include <pktdev.h>
#include <uds.h>
#include <uds_connect.h>

*/
import "C"

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	LPortInhibitProgLoad      = (1 << 0) // Inhibit Loading the BPF program & config of busy poll
	LPortForceWakeup          = (1 << 1) // Force a wakeup, for CVL NICs
	LPortSkbMode              = (1 << 2) // Force the SKB_MODE or copy mode
	LPortBusyPolling          = (1 << 3) // Enable busy polling
	LPortSharedUmem           = (1 << 4) // Enable UMEM Shared mode if available
	LPortUserManagedBuffers   = (1 << 5) // Enable Buffer Manager outside of CNDP
	LPortUmemUnalignedBuffers = (1 << 6) // Enable unaligned frame UMEM support
)

const (
	UmemMaxRegions = 16   // Maximum number of regions allowed
	UnitMultiplier = 1024 // Multiplier number for each unit or count value
)

// ApplicationInfo is the JSON Application data structure
type ApplicationInfo struct {
	Name        string `json:"name"`        // Name of the application
	Description string `json:"description"` // Description of the application
}

// DefaultInfo is the JSON Default data structure
type DefaultInfo struct {
	BufCnt  uint   `json:"bufcnt"` // Default number of buffers
	BufSize uint   `json:"bufsz"`  // Default size of the buffer
	RxDesc  uint   `json:"rxdesc"` // Default size of RX ring
	TxDesc  uint   `json:"txdesc"` // Default size of TX ring
	Cache   uint   `json:"cache"`  // Default size of cache entries, can be 0
	MemType string `json:"mtype"`  // Default memory allocation type
}

// UmemInfo is the JSON UMEM data structure(s)
type UmemInfo struct {
	BufCnt      uint   `json:"bufcnt"`      // Number of buffers in 1024 increments
	BufSize     uint   `json:"bufsz"`       // Size of each buffer in 1024 increments
	MemType     string `json:"mtype"`       // Memory type for buffer allocation
	Regions     []uint `json:"regions"`     // Region array for size of each region in 1024 increments
	RxDesc      uint   `json:"rxdesc"`      // Rx Descriptor ring size in 1024 increments
	TxDesc      uint   `json:"txdesc"`      // Tx Descriptor ring size in 1024 increments
	SharedUmem  bool   `json:"shared_umem"` // Use Shared UMEM flag
	Description string `json:"description"` // UMEM description
}

// LPortInfo is the JSON LPort information data structure(s)
type LPortInfo struct {
	Pmd             string `json:"pmd"`               // PMD name
	Qid             uint16 `json:"qid"`               // QID number
	Umem            string `json:"umem"`              // UMEM name string for this LPort to use
	Region          int    `json:"region"`            // The UMEM region index value
	Description     string `json:"description"`       // Description of the LPort
	BusyPolling     bool   `json:"busy_polling"`      // "busy_poll" enable busy polling if true
	BusyTimeout     uint16 `json:"busy_timeout"`      // Busy timeout value in seconds
	BusyBudget      uint16 `json:"busy_budget"`       // Busy budget value
	InhibitProgLoad bool   `json:"inhibit_prog_load"` // Inhibit eBPD program load flag
	ForceWakeup     bool   `json:"force_wakeup"`      // Force wakeup calls for AF_XDP
	SkbMode         bool   `json:"skb_mode"`          // Force SKB_MODE or copy mode flag
	flags           int
}

// LCoreGroupInfo is the JSON LCoreGroup information structure
type LCoreGroupInfo struct {
	Initial      []int    `json:"initial"`
	Group0       []int    `json:"group0"`
	Group1       []int    `json:"group1"`
	DefaultGroup []string `json:"default"`
}

// OptionInfo is the JSON Option information structure
type OptionInfo struct {
	PktApi    string `json:"pkt_api"`    // Define the packet device API pktdev or xskdev
	NoMetrics bool   `json:"no-metrics"` // Disable Metrics collecting
	NoRestapi bool   `json:"no-restapi"` // Disable RestAPI support
	Cli       bool   `json:"cli"`        // Enable CLI mode or command line mode
	Mode      string `json:"mode"`       // Type of mode to use rx-only, tx-only, loopback, ...
	UdsPath   string `json:"uds_path"`   // UDS path string
}

// ThreadInfo is the JSON Thread structure(s)
type ThreadInfo struct {
	Group       string   `json:"group"`       // LCoreGroup string name
	LPorts      []string `json:"lports"`      // List of LPorts for this thread to manage
	Description string   `json:"description"` // Description of the thread
}

// Config is the top level JSON configuration structure
type Config struct {
	ApplicationData *ApplicationInfo       `json:"application"`  // Application data
	DefaultData     *DefaultInfo           `json:"defaults"`     // Default data
	UmemInfoMap     map[string]*UmemInfo   `json:"umems"`        // UMEM data
	LPortInfoMap    map[string]*LPortInfo  `json:"lports"`       // LPort data
	LCoreGroupData  *LCoreGroupInfo        `json:"lcore-groups"` // LCoreGroup data
	OptionData      *OptionInfo            `json:"options"`      // Option data
	ThreadInfoMap   map[string]*ThreadInfo `json:"threads"`      // Thread data
}

func (jcfg *Config) validateRegions() error {

	for umemName, umem := range jcfg.UmemInfoMap {
		if len(umem.Regions) >= UmemMaxRegions {
			return fmt.Errorf("invalid number of regions %d with umem %s", len(umem.Regions), umemName)
		}
	}

	return nil
}

func (jcfg *Config) unitMultipliersToValues() {

	// Convert count or size numbers by multiplying them by UnitMultiplier (1024)
	def := jcfg.DefaultData
	def.BufCnt *= UnitMultiplier
	def.BufSize *= UnitMultiplier
	def.RxDesc *= UnitMultiplier
	def.TxDesc *= UnitMultiplier

	for _, umem := range jcfg.UmemInfoMap {
		umem.BufCnt *= UnitMultiplier
		umem.BufSize *= UnitMultiplier
		umem.RxDesc *= UnitMultiplier
		umem.TxDesc *= UnitMultiplier

		for i := 0; i < len(umem.Regions); i++ {
			umem.Regions[i] *= UnitMultiplier
		}
	}
}

func (jcfg *Config) valuesToUnitMultipliers() {

	convert := func(v uint) uint {
		if v > UnitMultiplier {
			return v / UnitMultiplier
		}
		return v
	}

	// Convert count or size numbers by multiplying them by UnitMultiplier (1024)
	def := jcfg.DefaultData

	def.BufCnt = convert(def.BufCnt)
	def.BufSize = convert(def.BufSize)
	def.RxDesc = convert(def.RxDesc)
	def.TxDesc = convert(def.TxDesc)

	for _, umem := range jcfg.UmemInfoMap {
		umem.BufCnt = convert(umem.BufCnt)
		umem.BufSize = convert(umem.BufSize)
		umem.RxDesc = convert(umem.RxDesc)
		umem.TxDesc = convert(umem.TxDesc)

		for i := 0; i < len(umem.Regions); i++ {
			umem.Regions[i] = convert(umem.Regions[i])
		}
	}
}

func (jcfg *Config) validateConfig() error {

	// Must have UMEM data structure(s)
	if jcfg.UmemInfoMap == nil {
		return fmt.Errorf("no UMEMs configured")
	}

	// Validate the region numbers for each UmemData
	if err := jcfg.validateRegions(); err != nil {
		return err
	}

	// Must have LPortData structure(s)
	if jcfg.LPortInfoMap == nil {
		return fmt.Errorf("no lports configured")
	}

	// Must have ThreadData structure(s)
	if jcfg.ThreadInfoMap == nil {
		fmt.Printf("validateConfig(): Warning no thread configuration\n")
	}

	jcfg.unitMultipliersToValues()

	// Convert the LPort Flags to a single flag bitwise ORed variable
	for _, lport := range jcfg.LPortInfoMap {
		var flags int

		flags = 0
		if lport.ForceWakeup {
			flags = flags | LPortForceWakeup
		}
		if lport.SkbMode {
			flags = flags | LPortSkbMode
		}
		if lport.BusyPolling {
			flags = flags | LPortBusyPolling
		}

		umemInfo := jcfg.UmemByName(lport.Umem)
		if umemInfo != nil {
			if umemInfo.SharedUmem {
				flags = flags | LPortSharedUmem
			}
		}
		lport.flags = flags
	}

	return nil
}

func processConfig(jsonText []byte) (*Config, error) {

	if len(jsonText) == 0 {
		return nil, fmt.Errorf("empty json text string")
	}

	jcfg := &Config{}

	// Convert JSON-C to JSON format and then unmarshal the data
	if err := json.Unmarshal(jsonText, jcfg); err != nil {
		return nil, err
	}

	if err := jcfg.validateConfig(); err != nil {
		return nil, err
	}

	return jcfg, nil
}

func (jcfg *Config) String() string {

	if data, err := json.MarshalIndent(jcfg, "", "  "); err != nil {
		return fmt.Sprintf("error marshalling config: %v", err)
	} else {
		return string(data)
	}
}

// UmemByName returns the UmemInfo structure for the UMEM name
func (jcfg *Config) UmemByName(umemName string) *UmemInfo {

	if jcfg.UmemInfoMap != nil {
		if umem, ok := jcfg.UmemInfoMap[umemName]; ok {
			return umem
		}
	}
	return nil
}

// UmemNames returns a slice of strings for each UMEM structure
func (jcfg *Config) UmemNames() []string {

	var umemNames []string

	for name := range jcfg.UmemInfoMap {
		umemNames = append(umemNames, name)
	}
	sort.Strings(umemNames)
	return umemNames
}

// LPortByName returns the LPortInfo pointer for the given LPort name
func (jcfg *Config) LPortByName(lportName string) *LPortInfo {

	if jcfg.LPortInfoMap != nil {
		if lport, ok := jcfg.LPortInfoMap[lportName]; ok {
			return lport
		}
	}
	return nil
}

// LPortName returns a array of strings giving the list of LPorts
func (jcfg *Config) LPortNames() []string {

	var lportNames []string

	for name := range jcfg.LPortInfoMap {
		lportNames = append(lportNames, name)
	}
	sort.Strings(lportNames)
	return lportNames
}

// LPortFlags returns the LPort configuration flags
func (lport *LPortInfo) LPortFlags() int {

	return lport.flags
}

// ThreadByName returns the ThreadInfo structure for the given thread name
func (jcfg *Config) ThreadByName(threadName string) *ThreadInfo {

	if jcfg.ThreadInfoMap != nil {
		if thd, ok := jcfg.ThreadInfoMap[threadName]; ok {
			return thd
		}
	}
	return nil
}

// ThreadNames returns the array of thread names
func (jcfg *Config) ThreadNames() []string {

	var threadNames []string

	for name := range jcfg.ThreadInfoMap {
		threadNames = append(threadNames, name)
	}
	sort.Strings(threadNames)
	return threadNames
}
