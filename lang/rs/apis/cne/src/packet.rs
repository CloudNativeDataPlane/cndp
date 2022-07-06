/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use super::error::*;
use cne_sys::bindings::{_pktmbuf_free_bulk, _pktmbuf_write, pktmbuf_t};
use std::os::raw::c_void;
use std::slice;

/// CNE abstract Packet type.
#[derive(Clone, Copy)]
pub struct Packet(pub(crate) *mut pktmbuf_t);

impl Default for Packet {
    /// Default function to initialize Packet.
    fn default() -> Self {
        Self(std::ptr::null_mut::<pktmbuf_t>())
    }
}

unsafe impl Send for Packet {}
unsafe impl Sync for Packet {}

// Interface functions to be implemented for [`crate::packet::Packet`].
pub trait PacketInterface<'a> {
    /// A constant for max packet burst.
    const MAX_BURST: usize = 256;

    /// Gets packet data length.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PacketError] if an error is encountered.
    ///
    fn get_data_len(&self) -> Result<u16, CneError>;

    /// Sets packet data length.
    ///
    /// # Arguments
    /// * `data_len` - data length to be set in packet.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PacketError] if an error is encountered.
    ///
    fn set_data_len(&mut self, data_len: u16) -> Result<(), CneError>;

    /// Gets data in the packet.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PacketError] if an error is encountered.
    ///
    fn get_data(&self) -> Result<&'a [u8], CneError>;

    /// Gets mutable data in the packet.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PacketError] if an error is encountered.
    ///
    fn get_data_mut(&mut self) -> Result<&'a mut [u8], CneError>;

    /// Sets packet data.
    ///
    /// # Arguments
    /// * `data` - data slice to be set in packet.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PacketError] if an error is encountered.
    ///
    fn set_data(&mut self, data: &[u8]) -> Result<(), CneError>;

    /// Frees underlying buffers in the packet slice.
    ///
    /// # Arguments
    /// * `pkts` - slice of packets.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PacketError] if an error is encountered.
    ///
    fn free_packet_buffer(pkts: &mut [Packet]) -> Result<(), CneError>;
}

impl<'a> PacketInterface<'a> for Packet {
    fn get_data_len(&self) -> Result<u16, CneError> {
        let pkt = self.0 as *const pktmbuf_t;
        if pkt.is_null() {
            let err_msg = "Packet data is null".to_string();
            Err(CneError::PacketError(err_msg))
        } else {
            unsafe { Ok((*pkt).data_len) }
        }
    }

    fn set_data_len(&mut self, data_len: u16) -> Result<(), CneError> {
        let pkt = self.0 as *mut pktmbuf_t;
        if pkt.is_null() {
            let err_msg = "Packet data is null".to_string();
            Err(CneError::PacketError(err_msg))
        } else {
            unsafe {
                (*pkt).data_len = data_len;
            }
            Ok(())
        }
    }

    fn get_data(&self) -> Result<&'a [u8], CneError> {
        unsafe {
            let data_len = self.get_data_len()?;
            let data_addr = self.get_data_addr()?;
            if data_addr.is_null() {
                let err_msg = "Packet data is null".to_string();
                Err(CneError::PacketError(err_msg))
            } else {
                let p: &'a [u8] = slice::from_raw_parts(data_addr, data_len as usize);
                Ok(p)
            }
        }
    }

    fn get_data_mut(&mut self) -> Result<&'a mut [u8], CneError> {
        unsafe {
            let data_len = self.get_data_len()?;
            let data_addr = self.get_data_addr_mut()?;
            if data_addr.is_null() {
                let err_msg = "Packet data is null".to_string();
                Err(CneError::PacketError(err_msg))
            } else {
                let p: &'a mut [u8] = slice::from_raw_parts_mut(data_addr, data_len as usize);
                Ok(p)
            }
        }
    }

    fn set_data(&mut self, data: &[u8]) -> Result<(), CneError> {
        let pkt = self.0 as *mut pktmbuf_t;
        unsafe {
            if pkt.is_null() {
                let err_msg = "Packet data is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            if data.is_empty() {
                let err_msg = "Data passed is empty".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            let data_ptr = &data[0] as *const u8;
            let addr = _pktmbuf_write(data_ptr as *const c_void, data.len() as u32, pkt, 0);
            if addr.is_null() {
                let err_msg = "Set data failed".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            Ok(())
        }
    }

    fn free_packet_buffer(pkts: &mut [Packet]) -> Result<(), CneError> {
        if !pkts.is_empty() {
            let rx_pkts = &mut pkts[0].0 as *mut *mut _;
            unsafe {
                _pktmbuf_free_bulk(rx_pkts, pkts.len() as u32);
            }
        }
        Ok(())
    }
}

impl Packet {
    fn get_data_addr(&self) -> Result<*const u8, CneError> {
        let pkt = self.0 as *const pktmbuf_t;
        unsafe {
            if pkt.is_null() {
                let err_msg = "Packet data is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            let buff_addr = (*pkt).buf_addr as *const u8;
            if buff_addr.is_null() {
                let err_msg = "Packet buffer address is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            let data_off = (*pkt).data_off;
            let data_addr = buff_addr.offset(data_off as isize);
            if data_addr.is_null() {
                let err_msg = "Packet data address is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }

            Ok(data_addr)
        }
    }

    fn get_data_addr_mut(&mut self) -> Result<*mut u8, CneError> {
        let pkt = self.0 as *const pktmbuf_t;
        unsafe {
            if pkt.is_null() {
                let err_msg = "Packet data is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            let buff_addr = (*pkt).buf_addr as *mut u8;
            if buff_addr.is_null() {
                let err_msg = "Packet buffer address is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }
            let data_off = (*pkt).data_off;
            let data_addr = buff_addr.offset(data_off as isize);
            if data_addr.is_null() {
                let err_msg = "Packet data address is null".to_string();
                return Err(CneError::PacketError(err_msg));
            }

            Ok(data_addr)
        }
    }
}
