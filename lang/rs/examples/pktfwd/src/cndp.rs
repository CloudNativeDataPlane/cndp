/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::env;

// Include Rust bindings for C code.
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));

pub fn get_tx_buffers(fport: &fwd_port) -> Option<*mut *mut txbuff_t> {
    // Check if fwd_port processing thread is valid.
    if fport.thd.is_null() {
        return None;
    }
    let fwd_port_thd = unsafe { &mut *(fport.thd as *mut jcfg_thd_t) };
    // Check if fwd port thread private data (txbuff**) is valid.
    if fwd_port_thd.priv_.is_null() {
        return None;
    }
    // Get TX buffers -> txbuff** pointer
    let txbuff_pptr = fwd_port_thd.priv_ as *mut *mut txbuff_t;
    return Some(txbuff_pptr);
}

pub fn get_rx_mbufs(fport: &fwd_port) -> Option<*mut *mut pktmbuf_s> {
    // Get RX mbufs -> pktmbuf** pointer
    let mut rx_mbufs = fport.rx_mbufs;
    let rx_mbufs = &mut rx_mbufs[0] as *mut *mut _;
    return Some(rx_mbufs);
}

pub fn get_item_at_index<T>(index: u16, item_pptr: *mut *mut T) -> Option<*mut T> {
    if item_pptr.is_null() {
        return None;
    }
    let item = unsafe { *item_pptr.offset(index as isize) };
    return Some(item);
}

pub fn get_pktmbuf_data(pkt_mbuf: *const pktmbuf_s) -> Option<*mut u8> {
    if pkt_mbuf.is_null() {
        return None;
    } else {
        unsafe {
            let buff_addr = (*pkt_mbuf).buf_addr as *mut u8;
            let data_off = (*pkt_mbuf).data_off;
            let data_addr = buff_addr.offset(data_off as isize);
            return Some(data_addr);
        }
    }
}

pub fn set_pktmbuf_data_len(pkt_mbuf: *mut pktmbuf_s, data_len: u16) {
    if pkt_mbuf.is_null() {
        return;
    } else {
        unsafe {
            (*pkt_mbuf).data_len = data_len;
        }
    }
}

pub fn get_pktmbuf_data_len(pkt_mbuf: *const pktmbuf_s) -> u16 {
    if pkt_mbuf.is_null() {
        return 0;
    } else {
        let data_len = unsafe { (*pkt_mbuf).data_len };
        return data_len;
    }
}

pub fn get_fwd_port<'a>(lport: *const jcfg_lport_t) -> Option<&'a fwd_port> {
    // Check if lport is valid.
    if lport.is_null() {
        return None;
    }
    let lport: &jcfg_lport_t = unsafe { & *(lport as *const jcfg_lport_t) };
    // Check if lport private data (fwd_port) is valid.
    if lport.priv_.is_null() {
        return None;
    }
    let fport: &fwd_port = unsafe { & *(lport.priv_ as *const fwd_port) };
    return Some(fport);
}
