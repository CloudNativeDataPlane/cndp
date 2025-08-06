/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2025 Intel Corporation.
 * Copyright (c) 2022 Canopus Networks.
 */

package cne

/*
#include <cne_mmap.h>
#include <pktmbuf.h>
#include <pktdev.h>
#include <uds.h>
#include <uds_connect.h>

*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
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

// sortUnique sorts a list of ints, removing duplicates
func sortUnique(l []int) []int {
	if len(l) <= 1 {
		return l
	}
	sort.Ints(l)

	i := 0
	for j := 1; j < len(l); j++ {
		if l[i] == l[j] {
			continue
		}
		i++
		l[i] = l[j]
	}
	i++
	l = l[:i]
	return l
}

// LCoreInfo is the list of lcores for a JSON LCoreGroup
type LCoreInfo []int

// MarshalJSON implements the json.Marshaler interface.
// The output is sorted by core number with duplicates removed.
// Contiguous ranges will be unmashalled as a string of the form "x-y".
func (lc LCoreInfo) MarshalJSON() ([]byte, error) {
	b := []byte{'['}
	sl := append([]int{}, lc...)
	sl = sortUnique(sl)

	i := 0
	for i < len(sl) {
		j := i + 1
		// find contiguous range
		for j < len(sl) && sl[j] == sl[j-1]+1 {
			j++
		}
		if len(b) != 1 {
			b = append(b, ',')
		}
		if i == j-1 {
			b = strconv.AppendInt(b, int64(sl[i]), 10)
		} else {
			b = append(b, '"')
			b = strconv.AppendInt(b, int64(sl[i]), 10)
			b = append(b, '-')
			b = strconv.AppendInt(b, int64(sl[j-1]), 10)
			b = append(b, '"')
		}
		i = j
	}
	b = append(b, ']')
	return b, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// The marshalled LCoreInfo is sorted by core number with duplicates removed.
func (lc *LCoreInfo) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	cores := []int{}

	if len(data) < 2 {
		return errors.New("json unmarshall lcore group: string too short")
	}
	if data[0] != '[' || data[len(data)-1] != ']' {
		return errors.New("json unmarshall lcore group: bracket(s) not found")
	}
	// remove brackets
	data = data[1 : len(data)-1]

	fields := bytes.Split(data, []byte{','})
	for _, field := range fields {
		field = bytes.TrimSpace(field)
		// remove quotes
		if len(field) >= 2 && field[0] == '"' && field[len(field)-1] == '"' {
			field = field[1 : len(field)-1]
		}
		if len(field) == 0 {
			continue
		}
		if field[0] == '-' {
			return errors.New("json unmarshall lcore group: negative core number not allowed")
		}
		nums := bytes.Split(field, []byte{'-'})
		if len(nums) > 2 {
			return errors.New("json unmarshall lcore group: too many fields in core range")
		}
		lo, err := strconv.Atoi(string(nums[0]))
		if err != nil {
			return fmt.Errorf("json unmarshall lcore group: invalid core number '%s'", string(nums[0]))
		}
		if len(nums) == 1 {
			cores = append(cores, lo)
			continue
		}
		hi, err := strconv.Atoi(string(nums[1]))
		if err != nil {
			return fmt.Errorf("json unmarshall lcore group: invalid core number '%s'", string(nums[0]))
		}
		if lo > hi {
			return fmt.Errorf("json unmarshall lcore group: core range low (%d) > high (%d)", lo, hi)
		} else if hi == lo {
			cores = append(cores, lo)
			continue
		}
		for i := lo; i <= hi; i++ {
			cores = append(cores, i)
		}
	}
	cores = sortUnique(cores)

	*lc = []int(cores)
	return nil
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
	LCoreGroupData  map[string]LCoreInfo   `json:"lcore-groups"` // LCoreGroup data
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

func (jcfg *Config) validateLCoreGroups() error {
	for group, cores := range jcfg.LCoreGroupData {
		for _, core := range cores {
			if core < 0 {
				return fmt.Errorf("core %d in lcore group %s is < 0", core, group)
			}
		}
	}
	return nil
}

func (jcfg *Config) validateThreadInfoMap() error {
	for threadName, info := range jcfg.ThreadInfoMap {
		if info.Group != "" && len(jcfg.LCoreGroupData[info.Group]) == 0 {
			return fmt.Errorf("lcore group %s for thread %s is missing or empty", info.Group, threadName)
		}
		for _, lport := range info.LPorts {
			if jcfg.LPortInfoMap[lport] == nil {
				return fmt.Errorf("invalid lport %s for thread %s", lport, threadName)
			}
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

func (jcfg *Config) validateConfig() error {

	// Must have UMEM data structure(s)
	if jcfg.UmemInfoMap == nil {
		return fmt.Errorf("no UMEMs configured")
	}

	// Validate the region numbers for each UmemData
	if err := jcfg.validateRegions(); err != nil {
		return err
	}

	// Validate the lcore groups
	if err := jcfg.validateLCoreGroups(); err != nil {
		return err
	}

	// Validate the threads
	if err := jcfg.validateThreadInfoMap(); err != nil {
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
	jsonText = bytes.TrimSpace(jsonText)

	if len(jsonText) == 0 {
		return nil, fmt.Errorf("empty json text string")
	}

	// test for a JSON-C or JSON string, which must start with a '{'
	if jsonText[0] != '{' {
		return nil, fmt.Errorf("string does not appear to be a valid JSON text missing starting '{'")
	}

	jcfg := &Config{}

	// Convert JSON-C to JSON format and then unmarshal the data
	if err := json.Unmarshal(jsonText, jcfg); err != nil {
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
