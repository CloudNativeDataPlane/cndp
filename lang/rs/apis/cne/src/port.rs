/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use std::mem::MaybeUninit;
use std::os::raw::c_void;
use std::sync::{Arc, Mutex, MutexGuard};

use cne_sys::bindings::{
    _pktdev_rx_burst, _pktdev_tx_burst, _pktmbuf_alloc_bulk, _xskdev_rx_burst, _xskdev_tx_burst,
    lport_stats_t, pktdev_buf_alloc, pktdev_stats_get, xskdev_stats_get,
};

use super::config::*;
use super::error::*;
use super::instance::*;
use super::packet::*;

/// CNE Port.
/// Get the Port instance using [CneInstance::get_port].
#[derive(Clone)]
pub struct Port {
    inner: Arc<Mutex<PortInner>>,
}

struct PortInner {
    // Port index of port in lports section in JSONC file.
    port_index: u16,
    // Pkt API - PktDev or XskDev.
    pkt_api: PktApi,
}

unsafe impl Send for PortInner {}

/// Port statistics.
#[derive(Default, Debug)]
pub struct PortStats {
    /// Total number of successfully received packets.
    pub in_packets: u64,
    /// Total number of successfully received bytes.
    pub in_bytes: u64,
    /// Total number of erroneous received packets.
    pub in_errors: u64,
    /// Total number of packets missed to be read.
    pub in_missed: u64,
    /// Total number of invalid RX descriptors.
    pub rx_invalid: u64,
    /// Total number of successfully transmitted packets.
    pub out_packets: u64,
    /// Total number of successfully transmitted bytes.
    pub out_bytes: u64,
    /// Total number of failed transmitted packets.
    pub out_errors: u64,
    /// Total number of packets dropped during transmission.
    pub out_dropped: u64,
    /// Total number of invalid TX descriptors.
    pub tx_invalid: u64,
}

/// Port details in lports section of JSONC configuration file.
#[derive(Debug)]
pub struct PortDetails {
    /// Port name.
    pub name: Option<String>,
    /// Network device name for this port.
    pub netdev: Option<String>,
    /// The queue id for this port.
    pub qid: u16,
    /// Port description.
    pub description: Option<String>,
}

impl Port {
    pub(crate) fn new(port_index: u16, pkt_api: PktApi) -> Port {
        let inner = PortInner {
            port_index,
            pkt_api,
        };
        Port {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// Receives burst of [packets](Packet) from the port.
    ///
    /// Returns number of packets read or error.
    ///
    /// # Arguments
    /// * `pkts` - mutable slice of packets to be filled with data.
    ///
    /// # Errors
    ///
    /// Returns [CneError::RxBurstError] if an error is encountered.
    ///
    pub fn rx_burst(&self, pkts: &mut [Packet]) -> Result<u16, CneError> {
        let port = self.lock()?;

        if pkts.is_empty() {
            let err_msg = "Packet array is empty".to_string();
            return Err(CneError::RxBurstError(err_msg));
        }

        let pkts_read = match port.pkt_api {
            PktApi::PktDev(lport_id) => unsafe {
                let rx_pkts = &mut pkts[0].0 as *mut *mut _;
                _pktdev_rx_burst(lport_id, rx_pkts, pkts.len() as u16)
            },
            PktApi::XskDev(xskdev) => unsafe {
                let rx_pkts = &mut pkts[0].0 as *mut _ as *mut *mut c_void;
                _xskdev_rx_burst(xskdev, rx_pkts, pkts.len() as u16)
            },
        };

        Ok(pkts_read)
    }

    /// Prepares burst of [packets](Packet) to be sent from the port.
    ///
    /// This function allocates underlying buffers for the packets in the slice.
    /// The buffers allocated are transparent to the caller of this function.
    /// Also check out [txburst()](Port::tx_burst)
    ///
    /// Returns number of packets for which underlying buffers are allocated or an error.
    ///
    /// # Arguments
    /// * `pkts` - mutable slice of packets for which underlying buffers will be allocated.
    ///
    /// # Errors
    ///
    /// Returns [CneError::BufferAllocError] if an error is encountered.
    ///
    pub fn prepare_tx_packets(&self, pkts: &mut [Packet]) -> Result<u16, CneError> {
        let port = self.lock()?;

        if pkts.is_empty() {
            let err_msg = "Packet array is empty".to_string();
            return Err(CneError::BufferAllocError(err_msg));
        }

        let pkts_alloc = match port.pkt_api {
            PktApi::PktDev(lport_id) => unsafe {
                let tx_pkts = &mut pkts[0].0 as *mut *mut _;
                pktdev_buf_alloc(lport_id as i32, tx_pkts, pkts.len() as u16)
            },
            PktApi::XskDev(_xskdev) => unsafe {
                let tx_pkts = &mut pkts[0].0 as *mut *mut _;
                let cne = CneInstance::get_instance();
                // xskdev buffer management support not yet added in Rust library. Use pktmbuf pool for now.
                let pool = cne.get_port_pktmbuf_pool(port.port_index)?;
                _pktmbuf_alloc_bulk(pool, tx_pkts, pkts.len() as u32)
            },
        };

        if pkts_alloc < 0 {
            let err_msg = "Error allocating buffers".to_string();
            return Err(CneError::BufferAllocError(err_msg));
        }

        Ok(pkts_alloc as u16)
    }

    /// Transmits burst of [packets](Packet) from the port.
    ///
    /// Applications can check the return value of the function to check the number of packets
    /// sent. A return value equal to `pkts.size()` means that all packets have been sent, and
    /// this is likely to signify that other output packets could be immediately transmitted
    /// again. Applications that implement a "send as many packets to transmit as possible"
    /// policy can check this specific case and keep invoking this function until a value less
    /// than `pkts.size()` is returned.
    ///
    /// This function transparently frees the underlying buffers of packets previously sent.
    /// Applications can also call [PacketInterface::free_packet_buffer] to free the
    /// packets which are not sent.
    ///
    /// Call [prepare_tx_packets()](Port::prepare_tx_packets) before calling this function.
    /// Also check out [PacketInterface::set_data] to set some valid data in packet.
    ///
    /// Returns number of packets that will be send or an error.
    ///
    /// # Arguments
    /// * `pkts` - mutable slice of packets.
    ///
    /// # Errors
    ///
    /// Returns [CneError::TxBurstError] if an error is encountered.
    ///
    pub fn tx_burst(&self, pkts: &mut [Packet]) -> Result<u16, CneError> {
        let port = self.lock()?;

        if pkts.is_empty() {
            let err_msg = "Packet array is empty".to_string();
            return Err(CneError::TxBurstError(err_msg));
        }

        let pkts_sent = match port.pkt_api {
            PktApi::PktDev(lport_id) => unsafe {
                let tx_pkts = &mut pkts[0].0 as *mut *mut _;
                _pktdev_tx_burst(lport_id, tx_pkts, pkts.len() as u16)
            },

            PktApi::XskDev(xskdev) => unsafe {
                let tx_pkts = &mut pkts[0].0 as *mut _ as *mut *mut c_void;
                _xskdev_tx_burst(xskdev, tx_pkts, pkts.len() as u16)
            },
        };

        Ok(pkts_sent)
    }

    /// Get port statistics.
    ///
    /// Returns [port statistics](PortStats) or error.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortStatsError] if an error is encountered.
    ///
    pub fn get_port_stats(&self) -> Result<PortStats, CneError> {
        let port = self.lock()?;

        let mut port_stats = PortStats::default();

        let mut c_port_stats = MaybeUninit::<lport_stats_t>::zeroed();
        let c_port_stats = unsafe { c_port_stats.assume_init_mut() };

        let ret = match port.pkt_api {
            PktApi::PktDev(lport_id) => unsafe { pktdev_stats_get(lport_id, c_port_stats) },
            PktApi::XskDev(xskdev) => unsafe { xskdev_stats_get(xskdev, c_port_stats) },
        };

        if ret < 0 {
            let err_msg = format!("Getting ports stats failed for port {}", port.port_index);
            return Err(CneError::PortStatsError(err_msg));
        }

        port_stats.in_packets = c_port_stats.ipackets;
        port_stats.in_bytes = c_port_stats.ibytes;
        port_stats.in_errors = c_port_stats.ierrors;
        port_stats.in_missed = c_port_stats.imissed;
        port_stats.rx_invalid = c_port_stats.rx_invalid;
        port_stats.out_packets = c_port_stats.opackets;
        port_stats.out_bytes = c_port_stats.obytes;
        port_stats.out_errors = c_port_stats.oerrors;
        port_stats.out_dropped = c_port_stats.odropped;
        port_stats.tx_invalid = c_port_stats.tx_invalid;

        Ok(port_stats)
    }

    /// Get port details.
    ///
    /// Returns [port details](PortDetails) or error.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortError] if an error is encountered.
    ///
    pub fn get_port_details(&self) -> Result<PortDetails, CneError> {
        let port = self.lock()?;

        let cne = CneInstance::get_instance();
        cne.get_port_details(port.port_index)
    }

    fn lock(&self) -> Result<MutexGuard<PortInner>, CneError> {
        self.inner
            .lock()
            .map_err(|e| CneError::PortError(e.to_string()))
    }
}
