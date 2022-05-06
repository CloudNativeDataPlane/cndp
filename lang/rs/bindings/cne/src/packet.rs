/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use cne_sys::bindings::{_pktmbuf_free_bulk, _pktmbuf_write, pktmbuf_t};
use std::os::raw::c_void;
use std::slice;

#[derive(Clone, Copy)]
pub struct Packet(pub(crate) *mut pktmbuf_t);

impl Default for Packet {
    fn default() -> Self {
        Self(std::ptr::null_mut::<pktmbuf_t>())
    }
}

pub trait PacketInterface<'a> {
    const MAX_BURST: usize = 256;
    fn get_data_len(&self) -> Option<u16>;
    fn set_data_len(&mut self, data_len: u16);
    fn get_data(&self) -> Option<&'a [u8]>;
    fn get_data_mut(&self) -> Option<&'a mut [u8]>;
    fn set_data(&mut self, data: &[u8]) -> Option<&'a [u8]>;
    fn free_packet_buffer(pkts: &mut [Packet]);
}

impl<'a> PacketInterface<'a> for Packet {
    fn get_data_len(&self) -> Option<u16> {
        let pkt = self.0 as *const pktmbuf_t;
        if pkt.is_null() {
            None
        } else {
            unsafe { Some((*pkt).data_len) }
        }
    }

    fn set_data_len(&mut self, data_len: u16) {
        let pkt = self.0 as *mut pktmbuf_t;
        unsafe {
            (*pkt).data_len = data_len;
        }
    }

    fn get_data(&self) -> Option<&'a [u8]> {
        unsafe {
            let (data_addr, data_len) = self.get_data_addr_and_len();
            if data_addr.is_none() || data_len.is_none() {
                return None;
            }

            let p: &'a [u8] = slice::from_raw_parts(data_addr.unwrap(), data_len.unwrap() as usize);
            Some(p)
        }
    }

    fn get_data_mut(&self) -> Option<&'a mut [u8]> {
        unsafe {
            let (data_addr, data_len) = self.get_data_addr_and_len();
            if data_addr.is_none() || data_len.is_none() {
                return None;
            }
            let p: &'a mut [u8] =
                slice::from_raw_parts_mut(data_addr.unwrap(), data_len.unwrap() as usize);
            Some(p)
        }
    }

    fn set_data(&mut self, data: &[u8]) -> Option<&'a [u8]> {
        let pkt = self.0 as *mut pktmbuf_t;
        unsafe {
            if pkt.is_null() {
                return None;
            }
            if data.is_empty() {
                return None;
            }
            let data_ptr = &data[0] as *const u8;
            let addr = _pktmbuf_write(data_ptr as *const c_void, data.len() as u32, pkt, 0);
            if addr.is_null() {
                return None;
            }
            let p: &'a [u8] = slice::from_raw_parts(addr as *const u8, data.len() as usize);
            Some(p)
        }
    }

    fn free_packet_buffer(pkts: &mut [Packet]) {
        if pkts.is_empty() {
            return;
        }

        let rx_pkts = &mut pkts[0].0 as *mut *mut _;
        unsafe { _pktmbuf_free_bulk(rx_pkts, pkts.len() as u32) }
    }
}

impl Packet {
    fn get_data_addr_and_len(&self) -> (Option<*mut u8>, Option<u16>) {
        let pkt = self.0 as *const pktmbuf_t;
        unsafe {
            if pkt.is_null() {
                return (None, None);
            }
            let buff_addr = (*pkt).buf_addr as *mut u8;
            if buff_addr.is_null() {
                return (None, None);
            }
            let data_len = self.get_data_len();
            if data_len.is_none() {
                return (None, None);
            }
            let data_off = (*pkt).data_off;
            let data_addr = buff_addr.offset(data_off as isize);
            if data_addr.is_null() {
                return (None, None);
            }

            (Some(data_addr), data_len)
        }
    }
}
