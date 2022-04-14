/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

package cndpgo

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
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

const (
	LPORT_UNPRIVILEGED           = (1 << 0) /**< Inhibit Loading the BPF program & config of busy poll */
	LPORT_FORCE_WAKEUP           = (1 << 1) /**< Force a wakeup, for CVL NICs */
	LPORT_SKB_MODE               = (1 << 2) /**< Force the SKB_MODE or copy mode */
	LPORT_BUSY_POLLING           = (1 << 3) /**< Enable busy polling */
	LPORT_SHARED_UMEM            = (1 << 4) /**< Enable UMEM Shared mode if available */
	LPORT_USER_MANAGED_BUFFERS   = (1 << 5) /**< Enable Buffer Manager outside of CNDP */
	LPORT_UMEM_UNALIGNED_BUFFERS = (1 << 6) /**< Enable unaligned frame UMEM support */
)

const (
	UMEM_MAX_REGIONS = 16
)

type Application struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Defaults struct {
	Bufcnt uint   `json:"bufcnt"`
	Bufsz  uint   `json:"bufsz"`
	Rxdesc int    `json:"rxdesc"`
	Txdesc int    `json:"txdesc"`
	Cache  uint   `json:"cache"`
	Mtype  string `json:"mtype"`
}

type RegionInfo struct {
	addr   *C.char
	pool   *C.pktmbuf_info_t
	bufcnt uint
}

type UmemData struct {
	Bufcnt      uint          `json:"bufcnt"`
	Bufsz       uint          `json:"bufsz"`
	Mtype       string        `json:"mtype"`
	Regions     []uint        `json:"regions"`
	Rxdesc      uint          `json:"rxdesc"`
	Txdesc      uint          `json:"txdesc"`
	Sharedumem  bool          `json:"shared_umem"`
	Description string        `json:"description"`
	name        string        `json:"-"`
	mm          *C.mmap_t     `json:"-"`
	rinfo       []*RegionInfo `json:"-"`
}

type Lport struct {
	Netdev       string         `json:"netdev"`
	Pmd          string         `json:"pmd"`
	Qid          uint16         `json:"qid"`
	Umem         string         `json:"umem"`
	Region       int            `json:"region"`
	Busy_polling bool           `json:"busy_polling"`
	Busy_timeout uint16         `json:"busy_timeout"`
	Busy_budget  uint16         `json:"busy_budget"`
	Unprivileged bool           `json:"unprivileged"`
	Force_wakeup bool           `json:"force_wakeup"`
	Skb_mode     bool           `json:"skb_mode"`
	Description  string         `json:"description"`
	xdp_uds      unsafe.Pointer `json:"-"`
	lportId      C.int          `json:"-"`
}

type Lcoregroups struct {
	Initial []int    `json:"initial"`
	Group0  []int    `json:"group0"`
	Group1  []int    `json:"group1"`
	Default []string `json:"default"`
}

type Options struct {
	Pktapi    string `json:"pkt_api"`
	Nometrics bool   `json:"no-metrics"`
	Norestapi bool   `json:"no-restapi"`
	Cli       bool   `json:"cli"`
	Mode      string `json:"mode"`
	Udspath   string `json:"uds_path"`
}

type Thread struct {
	Group       string   `json:"group"`
	Lports      []string `json:"lports"`
	Description string   `json:"description"`
}

type Config struct {
	Application *Application          `json:"application"`
	Defaults    *Defaults             `json:"defaults"`
	Umems       *map[string]*UmemData `json:"umems"`
	Lports      *map[string]*Lport    `json:"lports"`
	Lcoregroups *Lcoregroups          `json:"lcore-groups"`
	Options     *Options              `json:"options"`
	Threads     *map[string]*Thread   `json:"-"`
}

func loadConfig(configPath string) (*Config, error) {
	configFile, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	bytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	err = json.Unmarshal([]byte(bytes), &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func (cfg *Config) validateMemPool() error {
	for umemName, umem := range *cfg.Umems {
		if len(umem.Regions) >= UMEM_MAX_REGIONS {
			return fmt.Errorf("Invalid number of regions %d with umem %s", len(umem.Regions), umemName)
		}
	}

	return nil
}

func (cfg *Config) setupMemPool() error {
	for umemName, umem := range *cfg.Umems {
		cMmapType := C.CString(umem.Mtype)
		defer C.free(unsafe.Pointer(cMmapType))
		mmapType := (C.mmap_type_t)(C.mmap_type_by_name(cMmapType))

		umem.name = umemName
		umem.Bufcnt *= 1024
		umem.Bufsz *= 1024
		umem.Rxdesc *= 1024
		umem.Txdesc *= 1024

		mmapPtr := (*C.mmap_t)(C.mmap_alloc(C.uint(umem.Bufcnt), C.uint(umem.Bufsz), mmapType))
		if mmapPtr == nil {
			return fmt.Errorf("Failed to allocate mmap memory %d for umem %s", umem.Bufcnt*umem.Bufsz, umemName)
		}
		umem.mm = mmapPtr

		umemAddr := C.mmap_addr(unsafe.Pointer(umem.mm))
		umem.rinfo = make([]*RegionInfo, len(umem.Regions))

		for i := 0; i < len(umem.Regions); i++ {
			umem.rinfo[i] = &RegionInfo{}
			ri := umem.rinfo[i]
			ri.bufcnt = umem.Regions[i] * 1024
			ri.addr = (*C.char)(umemAddr)
			umemAddr = (unsafe.Pointer)((uintptr(umemAddr) + uintptr(ri.bufcnt*umem.Bufsz)))

			pi := (*C.pktmbuf_info_t)(C.pktmbuf_pool_create(ri.addr, C.uint(ri.bufcnt), C.uint(umem.Bufsz), C.uint(cfg.Defaults.Cache), nil))
			if pi == nil {
				return fmt.Errorf("pktmbuf_pool_init() failed for region %d in umem %s", i, umemName)
			}

			name := umemName + "-" + strconv.Itoa(i)

			cName := C.CString(name)
			defer C.free(unsafe.Pointer(cName))
			C.pktmbuf_info_name_set(pi, cName)
			ri.pool = pi
		}
	}
	return nil
}

func (cfg *Config) setupLPorts() error {
	for lportName, lport := range *cfg.Lports {
		var pcfg *C.lport_cfg_t
		pcfg = (*C.lport_cfg_t)(C.calloc(1, C.ulong(unsafe.Sizeof(*pcfg))))

		var lportUmem *UmemData
		for umemName, umem := range *cfg.Umems {
			if umemName == lport.Umem {
				lportUmem = umem
				break
			}
		}

		if lportUmem == nil {
			return fmt.Errorf("umem %s for lport %s is not configured", lport.Umem, lportName)
		}

		pcfg.qid = C.ushort(lport.Qid)
		pcfg.bufsz = C.uint(lportUmem.Bufsz)
		pcfg.rx_nb_desc = C.uint(lportUmem.Rxdesc)
		pcfg.tx_nb_desc = C.uint(lportUmem.Txdesc)

		lportNameArr := strings.Split(lportName, ":")
		lport.Netdev = lportNameArr[0]
		for i := 0; i < len(lport.Netdev) && i < C.LPORT_NAME_LEN; i++ {
			pcfg.ifname[i] = C.char(lport.Netdev[i])
		}

		for i := 0; i < len(lportName) && i < C.LPORT_NAME_LEN; i++ {
			pcfg.name[i] = C.char(lportName[i])
		}

		lportPmdArr := strings.Split(lport.Pmd, ":")
		for i := 0; i < len(lportPmdArr[0]) && i < C.LPORT_NAME_LEN; i++ {
			pcfg.pmd_name[i] = C.char(lportPmdArr[0][i])
		}

		if len(lportNameArr) > 1 {
			cPmdOpts := C.CString(lportNameArr[1])
			defer C.free(unsafe.Pointer(cPmdOpts))
			pcfg.pmd_opts = cPmdOpts
		}

		pcfg.umem_addr = (*C.char)(C.mmap_addr(unsafe.Pointer(lportUmem.mm)))
		pcfg.umem_size = C.ulong(C.mmap_size(unsafe.Pointer(lportUmem.mm), nil, nil))
		pcfg.busy_timeout = C.ushort(lport.Busy_timeout)
		pcfg.busy_budget = C.ushort(lport.Busy_budget)

		flags := 0
		if lport.Unprivileged {
			flags = flags | LPORT_UNPRIVILEGED
		}
		if lport.Force_wakeup {
			flags = flags | LPORT_FORCE_WAKEUP
		}
		if lport.Skb_mode {
			flags = flags | LPORT_SKB_MODE
		}
		if lport.Busy_polling {
			flags = flags | LPORT_BUSY_POLLING
		}
		if lportUmem.Sharedumem {
			flags = flags | LPORT_SHARED_UMEM
		}
		pcfg.flags = C.ushort(flags)

		if lport.Region >= len(lportUmem.rinfo) {
			return fmt.Errorf("lport region %d in umem %s for lport %s is not configured", lport.Region, lport.Umem, lportName)
		}

		pcfg.addr = unsafe.Pointer(lportUmem.rinfo[lport.Region].addr)
		if pcfg.addr == nil {
			return fmt.Errorf("lport %s umem %s region index %d >= %d or not configured correctly",
				lportName, lport.Umem, lport.Region, len(lportUmem.rinfo))
		}

		pcfg.bufcnt = C.uint(lportUmem.rinfo[lport.Region].bufcnt)

		pcfg.pi = lportUmem.rinfo[lport.Region].pool
		if (pcfg.flags & LPORT_UNPRIVILEGED) != 0 {
			if cfg.Options != nil && cfg.Options.Udspath != "" {
				cUdspath := C.CString(cfg.Options.Udspath)
				pcfg.xsk_uds = unsafe.Pointer(C.udsc_handshake(cUdspath))
				if pcfg.xsk_uds == nil {
					return fmt.Errorf("UDS handshake failed for lport %s", lportName)
				}
			}
		}

		lportId := C.pktdev_port_setup(pcfg)
		if lportId < 0 {
			return fmt.Errorf("pktdev_port_setup() failed for lport %s", lportName)
		}
		lport.lportId = lportId
	}
	return nil
}

func (cfg *Config) cleanupMemPool() error {
	for umemName, umem := range *cfg.Umems {
		for i := 0; i < len(umem.rinfo); i++ {
			if umem.rinfo[i] != nil {
				C.pktmbuf_destroy(umem.rinfo[i].pool)
			}
		}
		ret := C.mmap_free(unsafe.Pointer(umem.mm))
		if ret < 0 {
			return fmt.Errorf("error mmap_free for umem %s", umemName)
		}
	}

	return nil
}

func (cfg *Config) cleanupLPorts() error {
	for lportName, lport := range *cfg.Lports {
		if lport.xdp_uds != nil {
			ret := C.udsc_close((*C.uds_info_t)(lport.xdp_uds))
			if ret < 0 {
				return fmt.Errorf("error udsc_close for lport %s", lportName)
			}
		}
		if lport.lportId >= 0 {
			ret := C.pktdev_close(C.ushort(lport.lportId))
			if ret < 0 {
				return fmt.Errorf("error pktdev_close for lport %s", lportName)
			}
		}
	}
	return nil
}

func (cfg *Config) getPortByName(name string) (*Port, error) {
	if *cfg.Lports == nil {
		return nil, fmt.Errorf("no lports configured")
	}

	lport, ok := (*cfg.Lports)[name]
	if !ok {
		return nil, fmt.Errorf("lport %s is not configured", name)
	}

	return newPort(lport.lportId), nil
}

func (cfg *Config) validate() error {
	err := cfg.validateMemPool()
	if err != nil {
		return fmt.Errorf("error validating mempool %w", err)
	}

	return nil
}

func (cfg *Config) process() error {
	err := cfg.setupMemPool()
	if err != nil {
		return fmt.Errorf("error setting up mempool %w", err)
	}

	err = cfg.setupLPorts()
	if err != nil {
		return fmt.Errorf("error setting up lports %w", err)
	}
	return nil
}

func (cfg *Config) cleanup() error {
	err := cfg.cleanupMemPool()
	if err != nil {
		return fmt.Errorf("error cleaning up mempool %w", err)
	}
	err = cfg.cleanupLPorts()
	if err != nil {
		return fmt.Errorf("error cleaning up lports %w", err)
	}
	return nil
}
