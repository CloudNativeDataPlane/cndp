/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use indexmap::IndexMap;
use json_comments::StripComments;
use nix::sched::{sched_setaffinity, CpuSet};
use nix::unistd::Pid;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::raw::c_void;
use std::result::Result;

use cne_sys::bindings::{
    _pktmbuf_info_name_set, lport_cfg_t, mmap_addr, mmap_alloc, mmap_free, mmap_size, mmap_t,
    mmap_type_by_name, pktdev_close, pktdev_port_setup, pktmbuf_destroy, pktmbuf_info_t,
    pktmbuf_pool_create, uds_info_t, udsc_close, udsc_handshake, xskdev_info_t,
    xskdev_socket_create, xskdev_socket_destroy, LPORT_BUSY_POLLING, LPORT_FORCE_WAKEUP,
    LPORT_SHARED_UMEM, LPORT_SKB_MODE, LPORT_UNPRIVILEGED, MEMPOOL_CACHE_MAX_SIZE,
};

use super::error::*;
use super::port::*;
use super::util::*;

#[derive(Serialize, Deserialize)]
struct Application {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Defaults {
    bufcnt: Option<u32>,
    bufsz: Option<u32>,
    #[serde(default)]
    rxdesc: u32,
    #[serde(default)]
    txdesc: u32,
    cache: Option<u32>,
    mtype: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct UmemData {
    bufcnt: u32,
    bufsz: u32,
    mtype: Option<String>,
    regions: Vec<u32>,
    #[serde(default)]
    rxdesc: u32,
    #[serde(default)]
    txdesc: u32,
    #[serde(default)]
    shared_umem: bool,
    description: Option<String>,
    #[serde(skip_deserializing, skip_serializing)]
    name: String,
    #[serde(skip_deserializing, skip_serializing)]
    mm: Option<*mut mmap_t>,
    #[serde(skip_deserializing, skip_serializing)]
    rinfo: Vec<RegionInfo>,
}
#[derive(Clone, Debug)]
struct RegionInfo {
    addr: *mut i8,
    pool: *mut pktmbuf_info_t,
    bufcnt: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Lport {
    netdev: Option<String>,
    pmd: String,
    qid: u16,
    umem: String,
    #[serde(default)]
    region: usize,
    #[serde(default)]
    busy_polling: bool,
    #[serde(default)]
    busy_timeout: u16,
    #[serde(default)]
    busy_budget: u16,
    #[serde(default)]
    unprivileged: bool,
    #[serde(default)]
    force_wakeup: bool,
    #[serde(default)]
    skb_mode: bool,
    description: Option<String>,
    #[serde(skip_deserializing, skip_serializing)]
    xdp_uds: Option<*mut uds_info_t>,
    #[serde(skip_deserializing, skip_serializing)]
    pkt_api: Option<PktApi>,
}

#[derive(Serialize, Deserialize)]
struct Options {
    pkt_api: Option<String>,
    #[serde(default, rename = "no-metrics")]
    no_metrics: bool,
    #[serde(default, rename = "no-restapi")]
    no_restapi: bool,
    #[serde(default)]
    cli: bool,
    mode: Option<String>,
    uds_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Thread {
    pub group: Option<String>,
    pub lports: Option<Vec<String>>,
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Config {
    application: Application,
    defaults: Option<Defaults>,
    umems: HashMap<String, UmemData>,
    // Use IndexMap to maintain order of lports entries in JSON file.
    lports: IndexMap<String, Lport>,
    #[serde(rename = "lcore-groups")]
    lcore_groups: Option<HashMap<String, Vec<Value>>>,
    #[serde(skip_deserializing, skip_serializing)]
    cpu_sets: HashMap<String, CpuSet>,
    options: Option<Options>,
    threads: Option<HashMap<String, Thread>>,
}

#[derive(Copy, Clone, Debug)]
pub(crate) enum PktApi {
    PktDev(u16),
    XskDev(*mut xskdev_info_t),
}

impl Config {
    pub(crate) fn load_config(jsonc_file: &str) -> Result<Config, CneError> {
        // Read JSONC file.
        let contents =
            fs::read_to_string(jsonc_file).map_err(|e| CneError::ConfigError(e.to_string()))?;

        // Strip comments in JSONC file.
        let mut stripped = String::new();
        StripComments::new(contents.as_bytes())
            .read_to_string(&mut stripped)
            .map_err(|e| CneError::ConfigError(e.to_string()))?;

        // Deserialize.
        let mut cfg = serde_json::from_str::<Config>(&stripped)
            .map_err(|e| CneError::ConfigError(e.to_string()))?;

        // Populate CPU sets in lcore groups. This can be (optionally) used by application
        // to affinitize threads to CPU cores based on JSONC configuration.
        cfg.parse_lcore_groups()?;

        Ok(cfg)
    }

    #[cfg(test)]
    pub(crate) fn get_config(cfg: &Config) -> Result<String, CneError> {
        serde_json::to_string(cfg).map_err(|e| CneError::ConfigError(e.to_string()))
    }

    pub(crate) fn setup(&mut self) -> Result<(), CneError> {
        self.setup_mem_pool()?;

        self.setup_lports()?;

        Ok(())
    }

    pub(crate) fn cleanup(&mut self) -> Result<(), CneError> {
        self.cleanup_lports()?;

        self.cleanup_mem_pool()?;

        Ok(())
    }

    pub(crate) fn get_num_ports(&self) -> u16 {
        self.lports.len() as u16
    }

    pub(crate) fn get_port_by_index(&self, port_index: u16) -> Result<Port, CneError> {
        self.validate_port_index(port_index)?;

        let (_, lport) = self.lports.get_index(port_index as usize).ok_or_else(|| {
            CneError::ConfigError(format!("Port {} is not configured", port_index))
        })?;

        let port = match lport.pkt_api {
            Some(pkt_api) => Ok(Port::new(port_index, pkt_api)),
            None => {
                let err_msg = format!("Port {} is not configured", port_index);
                Err(CneError::PortError(err_msg))
            }
        };
        port
    }

    #[allow(dead_code)]
    // Keep this for future use.
    pub(crate) fn get_port_by_name(&self, port_name: &str) -> Result<Port, CneError> {
        let port_index = self.get_port_index_from_name(port_name)?;

        self.get_port_by_index(port_index)
    }

    pub(crate) fn get_port_index_from_name(&self, port_name: &str) -> Result<u16, CneError> {
        let port_index = self.lports.get_index_of(port_name).ok_or_else(|| {
            CneError::ConfigError(format!("Port name {} is not present in config", port_name))
        })?;

        Ok(port_index as u16)
    }

    pub(crate) fn get_port_details(&self, port_index: u16) -> Result<PortDetails, CneError> {
        self.validate_port_index(port_index)?;

        let (name, lport) = self.lports.get_index(port_index as usize).ok_or_else(|| {
            CneError::ConfigError(format!("Port {} is not configured", port_index))
        })?;

        let port_info = PortDetails {
            name: Some(name.to_owned()),
            netdev: lport.netdev.to_owned(),
            qid: lport.qid,
            description: lport.description.to_owned(),
        };
        Ok(port_info)
    }

    pub(crate) fn get_port_pktmbuf_pool(
        &self,
        port_index: u16,
    ) -> Result<*mut pktmbuf_info_t, CneError> {
        self.validate_port_index(port_index)?;

        let (_, lport) = self.lports.get_index(port_index as usize).ok_or_else(|| {
            CneError::ConfigError(format!("Port {} is not configured", port_index))
        })?;
        let lport_umem = match self.umems.get(&lport.umem) {
            Some(umem) => umem,
            None => {
                let err_msg = format!(
                    "umem {} for port index {} is not configured",
                    lport.umem, port_index
                );
                return Err(CneError::ConfigError(err_msg));
            }
        };
        let pool = lport_umem.rinfo[lport.region].pool;
        Ok(pool)
    }

    pub(crate) fn get_thread_details(&self) -> Result<HashMap<String, Thread>, CneError> {
        let thread_details = self
            .threads
            .clone()
            .ok_or_else(|| CneError::ConfigError("No threads present".to_string()))?;

        Ok(thread_details)
    }

    pub(crate) fn set_current_thread_affinity(&self, group: &str) -> Result<(), CneError> {
        let cpu_set = self.cpu_sets.get(group).ok_or_else(|| {
            CneError::ConfigError(format!("{} is not present in lcore-groups", group))
        })?;

        // Set current thread's CPU affinity. Pid 0 corresponds to calling thread.
        sched_setaffinity(Pid::from_raw(0), cpu_set)
            .map_err(|e| CneError::ConfigError(e.to_string()))?;

        Ok(())
    }

    fn validate_port_index(&self, port_index: u16) -> Result<(), CneError> {
        if port_index >= self.lports.len() as u16 {
            let err_msg = format!("Invalid port index {}", port_index);
            Err(CneError::PortError(err_msg))
        } else {
            Ok(())
        }
    }

    fn setup_mem_pool(&mut self) -> Result<(), CneError> {
        for (umem_name, umem) in &mut self.umems {
            umem.name = umem_name.clone();
            umem.bufcnt *= 1024;
            umem.bufsz *= 1024;

            if umem.rxdesc == 0 {
                umem.rxdesc = self.defaults.as_ref().map(|d| d.rxdesc).unwrap_or(0);
            }
            umem.rxdesc *= 1024;

            if umem.txdesc == 0 {
                umem.txdesc = self.defaults.as_ref().map(|d| d.txdesc).unwrap_or(0);
            }
            umem.txdesc *= 1024;

            unsafe {
                let default_mmap_type = String::from("4KB");
                let mmap_type = mmap_type_by_name(
                    get_cstring_from_str(
                        umem.mtype.as_ref().unwrap_or(&default_mmap_type).as_str(),
                    )
                    .as_ptr(),
                );
                let mmap_ptr = mmap_alloc(umem.bufcnt, umem.bufsz, mmap_type);
                if mmap_ptr.is_null() {
                    let err_msg = format!(
                        "Failed to allocate mmap memory {} for umem {}",
                        umem.bufcnt * umem.bufsz,
                        umem.name
                    );
                    return Err(CneError::ConfigError(err_msg));
                }
                umem.mm = Some(mmap_ptr);
                let mut umem_addr = mmap_addr(mmap_ptr);
                if umem_addr.is_null() {
                    let err_msg = format!(
                        "Failed to get virtual address for mmap memory for umem {}",
                        umem.name
                    );
                    return Err(CneError::ConfigError(err_msg));
                }

                umem.rinfo = vec![
                    RegionInfo {
                        addr: std::ptr::null_mut(),
                        bufcnt: 0,
                        pool: std::ptr::null_mut()
                    };
                    umem.regions.len()
                ];

                for i in 0..umem.regions.len() {
                    umem.rinfo[i].bufcnt = umem.regions[i] * 1024;
                    umem.rinfo[i].addr = umem_addr as *mut i8;
                    umem_addr = umem_addr.offset((umem.rinfo[i].bufcnt * umem.bufsz) as isize);

                    let cache_sz = self
                        .defaults
                        .as_ref()
                        .map(|d| d.cache.unwrap_or(MEMPOOL_CACHE_MAX_SIZE));

                    let pi = pktmbuf_pool_create(
                        umem.rinfo[i].addr,
                        umem.rinfo[i].bufcnt,
                        umem.bufsz,
                        cache_sz.unwrap(),
                        std::ptr::null_mut(),
                    );
                    if pi.is_null() {
                        let err_msg = format!(
                            "pktmbuf_pool_init() failed for region {} in umem {}",
                            i, umem.name
                        );
                        mmap_free(mmap_ptr);
                        return Err(CneError::ConfigError(err_msg));
                    }

                    let name = umem.name.clone() + "-" + &(i as u32).to_string();
                    _pktmbuf_info_name_set(pi, get_cstring_from_str(&name.to_owned()).as_ptr());
                    umem.rinfo[i].pool = pi;
                }
            }
        }

        Ok(())
    }

    fn setup_lports(&mut self) -> Result<(), CneError> {
        for (lport_name, lport) in &mut self.lports {
            let lport_umem = match self.umems.get_mut(&lport.umem) {
                Some(umem) => umem,
                None => {
                    let err_msg = format!(
                        "umem {} for lport {} is not configured",
                        lport.umem, lport_name
                    );
                    return Err(CneError::ConfigError(err_msg));
                }
            };

            unsafe {
                let mut pcfg_uninit = MaybeUninit::<lport_cfg_t>::zeroed();
                let pcfg = pcfg_uninit.assume_init_mut();

                pcfg.qid = lport.qid;
                pcfg.bufsz = lport_umem.bufsz;
                pcfg.rx_nb_desc = lport_umem.rxdesc;
                pcfg.tx_nb_desc = lport_umem.rxdesc;

                let mm = lport_umem
                    .mm
                    .ok_or_else(|| CneError::ConfigError("mmap not allocated".to_string()))?;

                pcfg.umem_addr = mmap_addr(mm) as *mut i8;
                pcfg.umem_size = mmap_size(mm, std::ptr::null_mut(), std::ptr::null_mut());

                pcfg.busy_timeout = lport.busy_timeout;
                pcfg.busy_budget = lport.busy_budget;

                let mut flags = 0;
                if lport.unprivileged {
                    flags |= LPORT_UNPRIVILEGED;
                }
                if lport.force_wakeup {
                    flags |= LPORT_FORCE_WAKEUP
                }
                if lport.skb_mode {
                    flags |= LPORT_SKB_MODE
                }
                if lport.busy_polling {
                    flags |= LPORT_BUSY_POLLING
                }
                if lport_umem.shared_umem {
                    flags |= LPORT_SHARED_UMEM
                }

                pcfg.flags = flags as u16;

                if lport.region >= lport_umem.rinfo.len() {
                    let err_msg = format!(
                        "lport region {} in umem {} for lport {} is not configured",
                        lport.region, lport.umem, lport_name
                    );
                    return Err(CneError::ConfigError(err_msg));
                }

                pcfg.addr = lport_umem.rinfo[lport.region].addr as *mut c_void;

                if pcfg.addr.is_null() {
                    let err_msg = format!(
                        "lport {} umem {} region index {} >= {} or not configured correctly",
                        lport_name,
                        lport.umem,
                        lport.region,
                        lport_umem.rinfo.len()
                    );
                    return Err(CneError::ConfigError(err_msg));
                }

                pcfg.bufcnt = lport_umem.rinfo[lport.region].bufcnt;

                pcfg.pi = lport_umem.rinfo[lport.region].pool;

                // UDS handshake.
                if pcfg.flags & LPORT_UNPRIVILEGED as u16 != 0 {
                    if let Some(options) = &self.options {
                        if let Some(uds_path) = &options.uds_path {
                            if !uds_path.is_empty() {
                                let c_uds_path = get_cstring_from_str(uds_path).as_ptr();
                                let xsk_uds = udsc_handshake(c_uds_path);

                                if xsk_uds.is_null() {
                                    let err_msg =
                                        format!("UDS handshake failed for lport {}", lport_name);
                                    return Err(CneError::ConfigError(err_msg));
                                }
                                pcfg.xsk_uds = xsk_uds as *mut c_void;
                                lport.xdp_uds = Some(xsk_uds);
                            }
                        }
                    }
                }

                lport.netdev = lport_name.split(':').next().map(String::from);
                if lport.netdev.is_none() {
                    let err_msg = format!("Netdev is not present for lport {}", lport_name);
                    return Err(CneError::ConfigError(err_msg));
                }
                // Copy lport.netdev.
                copy_string_to_c_array(lport.netdev.as_ref().unwrap(), &mut pcfg.ifname);

                // Copy lport_name.
                copy_string_to_c_array(lport_name, &mut pcfg.name);

                // Copy pmd name.
                let mut pmd_split = lport.pmd.split(':');
                let pmd = pmd_split.next().map(String::from);
                copy_string_to_c_array(&pmd.unwrap(), &mut pcfg.pmd_name);

                // Copy pmd_opts.
                let cstring_pmd_opts = get_cstring_from_str(pmd_split.next().unwrap_or(""));
                pcfg.pmd_opts = cstring_pmd_opts.into_bytes_with_nul().as_mut_ptr() as *mut i8;

                // Setup lport.
                Self::setup_lport(&self.options, pcfg, lport_name, lport)?;
            }
        }

        Ok(())
    }

    fn setup_lport(
        options: &Option<Options>,
        pcfg: &mut lport_cfg_t,
        lport_name: &String,
        lport: &mut Lport,
    ) -> Result<(), CneError> {
        // Use pktdev or xskdev. pktdev is used as default.
        let pktdev = options
            .as_ref()
            .and_then(|options| options.pkt_api.as_ref())
            .and_then(|pkt_api| match pkt_api.as_str() {
                "xskdev" => Some(false),
                "pktdev" => Some(true),
                _ => None,
            })
            .unwrap_or(true);

        if pktdev {
            let lport_id = Self::setup_pktdev(pcfg, lport_name)
                .map_err(|e| CneError::ConfigError(e.to_string()))?;
            lport.pkt_api = Some(PktApi::PktDev(lport_id));
        } else {
            let xsk_dev = Self::setup_xskdev(pcfg, lport_name)
                .map_err(|e| CneError::ConfigError(e.to_string()))?;
            lport.pkt_api = Some(PktApi::XskDev(xsk_dev));
        }

        Ok(())
    }

    fn setup_pktdev(pcfg: &mut lport_cfg_t, lport_name: &String) -> Result<u16, CneError> {
        let lport_id = unsafe { pktdev_port_setup(pcfg) };
        if lport_id < 0 {
            let err_msg = format!("pktdev_port_setup() failed for lport {}", lport_name);
            Err(CneError::ConfigError(err_msg))
        } else {
            Ok(lport_id as u16)
        }
    }

    fn setup_xskdev(
        pcfg: &mut lport_cfg_t,
        lport_name: &String,
    ) -> Result<*mut xskdev_info_t, CneError> {
        let xsk_dev = unsafe { xskdev_socket_create(pcfg) };
        if xsk_dev.is_null() {
            let err_msg = format!("xskdev_socket_create() failed for lport {}", lport_name);
            Err(CneError::ConfigError(err_msg))
        } else {
            Ok(xsk_dev)
        }
    }

    fn cleanup_mem_pool(&mut self) -> Result<(), CneError> {
        for (umem_name, umem) in &mut self.umems {
            for rinfo in umem.rinfo.iter() {
                unsafe {
                    pktmbuf_destroy(rinfo.pool);
                }
            }

            let mm = umem
                .mm
                .ok_or_else(|| CneError::ConfigError("Mempool not configured".to_string()))?;

            let ret = unsafe { mmap_free(mm) };
            if ret < 0 {
                let err_msg = format!("mmap_free() failed for umem {}", umem_name);
                return Err(CneError::ConfigError(err_msg));
            }
        }

        Ok(())
    }

    fn cleanup_lports(&mut self) -> Result<(), CneError> {
        for (lport_name, lport) in &mut self.lports {
            if let Some(xdp_uds) = lport.xdp_uds {
                if !xdp_uds.is_null() {
                    let ret = unsafe { udsc_close(xdp_uds) };
                    if ret < 0 {
                        let err_msg = format!("udsc_close() failed for lport {}", lport_name);
                        return Err(CneError::ConfigError(err_msg));
                    }
                }
            }

            if let Some(pkt_api) = lport.pkt_api {
                match pkt_api {
                    PktApi::PktDev(lport_id) => {
                        let ret = unsafe { pktdev_close(lport_id) };
                        if ret < 0 {
                            let err_msg = format!("pktdev_close() failed for lport {}", lport_name);
                            return Err(CneError::ConfigError(err_msg));
                        }
                    }
                    PktApi::XskDev(xskdev) => {
                        unsafe { xskdev_socket_destroy(xskdev) };
                    }
                }
            }
        }
        Ok(())
    }

    fn parse_lcore_groups(&mut self) -> Result<(), CneError> {
        if self.lcore_groups.is_none() {
            return Ok(());
        }
        let lcore_groups = self.lcore_groups.as_ref().unwrap();
        let cpu_sets = &mut self.cpu_sets;
        let num_cores = num_cpus::get();

        for (group_name, values) in lcore_groups {
            let mut cpu_set = CpuSet::new();
            for item in values {
                if item.is_number() {
                    let cpu_id = item
                        .to_string()
                        .parse::<usize>()
                        .map_err(|e| CneError::ConfigError(e.to_string()))
                        .and_then(|cpu_id| Self::validate_cpu_id(cpu_id, num_cores))?;

                    cpu_set
                        .set(cpu_id)
                        .map_err(|e| CneError::ConfigError(e.to_string()))?;
                } else if item.is_string() {
                    let cpu_id_str = item.as_str().unwrap_or("");
                    if cpu_id_str.contains('-') {
                        let v: Vec<&str> = cpu_id_str.split('-').collect();
                        // There should be exactly two items - start and end core id.
                        if v.len() == 2 && !v[0].is_empty() && !v[1].is_empty() {
                            let start = v[0]
                                .parse::<usize>()
                                .map_err(|e| CneError::ConfigError(e.to_string()))
                                .and_then(|cpu_id| Self::validate_cpu_id(cpu_id, num_cores))?;

                            let end = v[1]
                                .parse::<usize>()
                                .map_err(|e| CneError::ConfigError(e.to_string()))
                                .and_then(|cpu_id| Self::validate_cpu_id(cpu_id, num_cores))?;

                            for cpu_id in start..end + 1 {
                                cpu_set
                                    .set(cpu_id as usize)
                                    .map_err(|e| CneError::ConfigError(e.to_string()))?;
                            }
                        }
                    } else {
                        let cpu_id = cpu_id_str
                            .parse::<usize>()
                            .map_err(|e| CneError::ConfigError(e.to_string()))
                            .and_then(|cpu_id| Self::validate_cpu_id(cpu_id, num_cores))?;

                        cpu_set
                            .set(cpu_id)
                            .map_err(|e| CneError::ConfigError(e.to_string()))?;
                    }
                }
            }
            cpu_sets.insert(group_name.to_string(), cpu_set);
        }

        Ok(())
    }

    fn validate_cpu_id(cpu_id: usize, num_cores: usize) -> Result<usize, CneError> {
        if cpu_id >= num_cores {
            let err_msg = format!("Invalid CPU ID {} in lcore-groups", cpu_id);
            Err(CneError::ConfigError(err_msg))
        } else {
            Ok(cpu_id)
        }
    }
}
