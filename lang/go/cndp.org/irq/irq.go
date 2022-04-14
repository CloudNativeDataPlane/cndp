// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package irq

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"

	tlog "cndp.org/ttylog"
	u "cndp.org/utils"
)

// Index values into the interrupt line array
const (
	IntrTypeIdx int = iota
	EdgeTypeIdx
	DeviceInfoIdx
	MaxIntrIdx
)

// Misc constants
const (
	SMPAffinityFormat string = "/proc/irq/%d/smp_affinity"
)

// NetdevName - is the name of each netdev available
type NetdevName string

// DeviceInfo is the decoded IRQDevice string
type DeviceInfo struct {
	DevStr  string
	Driver  string
	Netdev  string
	QType   string
	QueueID int
}

// InfoIRQ - information per IRQ
type InfoIRQ struct {
	IRQNum      int
	Device      *DeviceInfo
	Counters    []uint64
	IntrType    string
	EdgeType    string
	SMPAffinity string
}

// NetdevInfo - is the information about each netdev including queue id, IRQ, ...
type NetdevInfo struct {
	DataIRQ map[int]*InfoIRQ
}

// Info - data structure
type Info struct {
	path        string
	lcoreCount  int
	netdevNames []NetdevName
	netdev      map[NetdevName]*NetdevInfo
}

// Convert the IRQDevice string into its component parts, returning a DeviceInfo structure
// The components are driver-netdev-QType-QueueID
//     driver : i40e, ... can be unknown
//     netdev : eth0, eth1, ens0, ...
//     QType  : TxRx or something else
//     QueueID: The queue ID number
func (irq *Info) parseDeviceStr(devStr string) (*DeviceInfo, error) {
	var err error

	if strings.Contains(devStr, ":") {
		return nil, fmt.Errorf("Invalid device string")
	}

	dev := &DeviceInfo{DevStr: devStr}

	desc := strings.Split(devStr, "-")

	switch len(desc) {
	case 4:
		dev.Driver = desc[0]
		dev.Netdev = desc[1]
		dev.QType = desc[2]
		dev.QueueID, err = strconv.Atoi(desc[3])
		if err != nil {
			return nil, err
		}
	case 3:
		dev.Driver = "Unkn"
		dev.Netdev = desc[0]
		dev.QType = desc[1]
		dev.QueueID, err = strconv.Atoi(desc[2])
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("length of device string is not correct")
	}

	return dev, nil
}

// Get the IRQ Number which is the first field in the lineArr, convert to int
func (irq *Info) getIRQNum(lineArr []string) int {
	var irqNum int = -1

	if len(lineArr) > 0 {
		irqNum, _ = strconv.Atoi(strings.TrimSuffix(lineArr[0], ":")) // Get the IRQ number
	}
	return irqNum
}

// NetdevList is the list of known netdev names
func (irq *Info) NetdevList() []NetdevName {
	return irq.netdevNames
}

// DataByNetdev returns the data structure pointer based on index
func (irq *Info) DataByNetdev(netdev interface{}) *NetdevInfo {

	d, ok := irq.netdev[netdev.(NetdevName)]
	if ok {
		return d
	}
	return nil
}

// DataByIRQ returns the data structure pointer based on index
func (irq *Info) DataByIRQ(netdev interface{}, irqNum int) *InfoIRQ {

	d, ok := irq.netdev[netdev.(NetdevName)]
	if !ok {
		return nil
	}

	info, ok := d.DataIRQ[irqNum]
	if ok {
		return info
	}
	return nil
}

// CoreCounters returns the slice of core counter values
func (irq *Info) CoreCounters(netdev interface{}, irqNum int) []uint64 {

	d, ok := irq.netdev[netdev.(NetdevName)]
	if !ok {
		return nil
	}

	info, ok := d.DataIRQ[irqNum]
	if ok {
		return info.Counters
	}
	return nil
}

// List - return the list of IRQs
func (irq *Info) List(netdev NetdevName) []int {
	var list []int

	net, ok := irq.netdev[netdev]
	if !ok {
		return nil
	}

	for n := range net.DataIRQ {
		list = append(list, n)
	}

	sort.Ints(list)

	return list
}

// SetAffinity for the given IRQ and cores
func (irq *Info) SetAffinity(info *InfoIRQ, smp string) error {

	s := fmt.Sprintf(SMPAffinityFormat, info.IRQNum)
	f, err := os.OpenFile(s, os.O_WRONLY, 0664)
	if err != nil {
		tlog.DoPrintf("OpenFile: error %v\n", err)
		return err
	}
	defer f.Close()

	if n, err := fmt.Fprintf(f, smp); err != nil {
		tlog.DoPrintf("Wrote %d bytes, %s\n", n, smp)
	} else {
		tlog.DoPrintf("Number of bytes written %d\n", n)
	}

	return nil
}

// New - IRQ information routine
func New(filename string) *Info {

	irq := &Info{path: filename}

	irq.netdev = make(map[NetdevName]*NetdevInfo)
	irq.netdevNames = nil
	irq.lcoreCount = u.NumCPUs()

	return irq
}

// Collect the data for all IRQs and interrupts
func (irq *Info) Collect() error {

	if err := irq.parseLines(); err != nil {
		return err
	}
	return nil
}

func (irq *Info) parseLines() error {

	file, err := os.Open(irq.path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)

	// Skip the first line or the column header strings
	_, err = reader.ReadString('\n')
	if err != nil || err == io.EOF {
		return err
	}

	// Clear the data and rebuild information
	irq.netdev = make(map[NetdevName]*NetdevInfo)
	irq.netdevNames = nil

	for {
		ln, err := reader.ReadString('\n')
		if err != nil || err == io.EOF {
			break
		}

		// Skip this line if does not contain 'TxRx' in Device components
		lineData := strings.Fields(ln)

		n := len(lineData)
		if n-MaxIntrIdx <= 0 { // Skip line if not valid length lcoreCount + extra fields
			continue
		}

		// Create a new slice of the last IRQMaxIdx fields
		desc := lineData[n-MaxIntrIdx:]
		if len(desc) <= 0 {
			continue
		}

		// Convert the Device string into its component parts
		dev, err := irq.parseDeviceStr(desc[DeviceInfoIdx])
		if err != nil {
			continue
		}

		// Test to see of the netdev in the map is valid, if not create the new entry
		net, ok := irq.netdev[NetdevName(dev.Netdev)]
		if !ok {
			net = &NetdevInfo{}
			net.DataIRQ = make(map[int]*InfoIRQ)

			irq.netdev[NetdevName(dev.Netdev)] = net

			irq.netdevNames = append(irq.netdevNames, NetdevName(dev.Netdev))
		}

		// The IRQ number is the first field in the lineData
		irqNum := irq.getIRQNum(lineData)
		if irqNum < 0 {
			break
		}

		// Check to see if the IRQ exists in the map table, if not create the new entry
		info, ok := net.DataIRQ[irqNum]
		if !ok {
			info = &InfoIRQ{IRQNum: irqNum}
			net.DataIRQ[irqNum] = info
		}
		info.Device, err = irq.parseDeviceStr(desc[DeviceInfoIdx])
		if err != nil {
			continue
		}
		info.EdgeType = desc[EdgeTypeIdx]
		info.IntrType = desc[IntrTypeIdx]

		b, err := ioutil.ReadFile(fmt.Sprintf(SMPAffinityFormat, irqNum))
		if err != nil {
			continue
		}
		info.SMPAffinity = strings.TrimSpace(string(b))

		lineData = lineData[1 : irq.lcoreCount+1] // Trim off the IRQ Number and the non-CPU counters

		// Convert the lcore interrupt counter strings to integer values
		for _, f := range lineData {
			v, _ := strconv.ParseUint(f, 10, 64)
			info.Counters = append(info.Counters, v)
		}
	}

	return nil
}
