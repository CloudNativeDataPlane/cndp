/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

use libc::c_char;
use libc::c_int;
use std::ffi::CString;
use std::os::raw::c_void;
use std::slice;

mod util;
use util::*;

mod cndp;
use cndp::*;

mod packet;
use packet::*;

// static fwd_info structure.
static mut FINFO: fwd_info = fwd_info {
    jinfo: std::ptr::null_mut(),
    flags: 0,
    test: test_t_FWD_TEST,
    test_arr: [fwd_test {
        test: test_t_UNKNOWN_TEST,
        cb_func: None,
    }; 5],
    timer_quit: 0,
    barrier: pthread_barrier_t { __align: 0 },
    opts: app_options {
        no_metrics: false,
        no_restapi: true,
        cli: true,
        mode: std::ptr::null_mut(),
    },
};

#[no_mangle]
pub unsafe extern "C" fn r_pkt_drop_cb(lport: *mut jcfg_lport_t) -> i32 {
    // Get fwd_port structure from lport.
    if let Some(fport) = get_fwd_port(lport) {
        // Get RX pktmbuf buffers -> pktmbuf** pointer
        let rx_pktmbufs_pptr = get_rx_mbufs(&fport).unwrap();
        // Get burst of RX packets.
        let n_pkts = pktdev_rx_burst_fn(fport.lport as u16, rx_pktmbufs_pptr, MAX_BURST as u16);
        if n_pkts > 0 {
            pktmbuf_free_bulk_fn(rx_pktmbufs_pptr, n_pkts as u32);
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn r_pkt_fwd_cb(lport: *mut jcfg_lport_t) -> i32 {
    // Get fwd_port structure from lport.
    if let Some(fport) = get_fwd_port(lport) {
        // Get TX buffers  -> txbuff** pointer.
        let txbuff_pptr = get_tx_buffers(&fport);
        if txbuff_pptr.is_none() {
            return 0;
        }
        let txbuff_pptr = txbuff_pptr.unwrap();
        // Get RX pktmbuf buffers -> pktmbuf** pointer
        let rx_pktmbufs_pptr = get_rx_mbufs(&fport).unwrap();
        // Get burst of RX packets.
        let n_pkts = pktdev_rx_burst_fn(fport.lport as u16, rx_pktmbufs_pptr, MAX_BURST as u16);
        // Get RX packets, swap mac address and sent TX on incoming interface.
        for i in 0..n_pkts {
            /* let's echo back on incoming interface.*/
            let dst_lport = &mut *lport;
            let dst_lport_index = dst_lport.lpid;
            // Get a single RX pktmbuf.
            let pkt_mbuf = get_item_at_index(i, rx_pktmbufs_pptr).unwrap();
            // Get pktmbuf data pointer.
            let pkt_data_addr = get_pktmbuf_data(pkt_mbuf).unwrap();
            // Get pktmbut data length.
            let data_len = get_pktmbuf_data_len(pkt_mbuf);
            // Create CNDP packet structre.
            let mut cndp_ethernet_packet =
                CndpPacket::new(pkt_data_addr, data_len as usize).unwrap();
            // Swap mac/ip/port address using Rust pnet library or use direct byte swap.
            let pnet_swap = false;
            cndp_ethernet_packet.swap_mac_addresses_eth(pnet_swap);
            // Keep below lines commented for now.
            //cndp_ethernet_packet.swap_ip_addresses(pnet_swap);
            //cndp_ethernet_packet.swap_ports(pnet_swap);
            // Parse eth packet.
            //cndp_ethernet_packet.parse_eth_packet();
            //log::debug!("cndp_ethernet_packet = {}",cndp_ethernet_packet );
            //swap_mac_addresses(pkt_data_addr);
            // Get a single TX buffer
            let tx_buffer = get_item_at_index(dst_lport_index, txbuff_pptr).unwrap();
            // Buffer TX packet for future trasmission.
            txbuff_add(tx_buffer, pkt_mbuf);
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn r_pkt_lb_cb(lport: *mut jcfg_lport_t) -> i32 {
    // Get fwd_port structure from lport.
    if let Some(fport) = get_fwd_port(lport) {
        // Get RX pktmbuf buffers -> pktmbuf** pointer
        let rx_pktmbufs_pptr = get_rx_mbufs(&fport).unwrap();
        // Get burst of RX packets.
        let mut n_pkts = pktdev_rx_burst_fn(fport.lport as u16, rx_pktmbufs_pptr, MAX_BURST as u16);
        // Get RX packets, swap mac address.
        for i in 0..n_pkts {
            // Get a single RX pktmbuf.
            let pkt_mbuf = get_item_at_index(i, rx_pktmbufs_pptr).unwrap();
            // Get pktmbuf data pointer.
            let pkt_data_addr = get_pktmbuf_data(pkt_mbuf).unwrap();
            // Swap mac address.
            swap_mac_addresses(pkt_data_addr);
        }
        // Send packets (with swapped mac address) on same lport (loopback).
        loop {
            let n = pktdev_tx_burst_fn(fport.lport as u16, rx_pktmbufs_pptr, n_pkts);
            if n_pkts <= n {
                break;
            }
            n_pkts -= n;
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn r_pkt_txonly_cb(lport: *mut jcfg_lport_t) -> i32 {
    // Get fwd_port structure from lport.
    if let Some(fport) = get_fwd_port(lport) {
        // Get RX pktmbuf buffers -> pktmbuf** pointer.
        let rx_pktmbufs_pptr = get_rx_mbufs(&fport).unwrap();
        let mut n_pkts =
            pktdev_buf_alloc(fport.lport as i32, rx_pktmbufs_pptr, MAX_BURST as u16) as u16;
        if n_pkts > 0 {
            for i in 0..n_pkts {
                // Get a single RX pktmbuf.
                let pkt_mbuf = get_item_at_index(i as u16, rx_pktmbufs_pptr).unwrap();
                // Get pktmbuf data pointer.
                let pkt_data_addr = get_pktmbuf_data(pkt_mbuf).unwrap();
                // Cast the pointer as u64.
                let pkt_data_addr = pkt_data_addr as *mut u64;
                // Cast raw pointer to slice.
                let p: &mut [u64] = slice::from_raw_parts_mut(pkt_data_addr, 8 as usize);
                // Fill packets with some data.
                p[0] = 0xfd3c78299efefd3c;
                p[1] = 0x00450008b82c9efe;
                p[2] = 0x110400004f122e00;
                p[3] = 0xa8c00100a8c01e22;
                p[4] = 0x1a002e16d2040101;
                p[5] = 0x706f6e6d6c6b9a9e;
                p[6] = 0x7877767574737271;
                p[7] = 0x31307a79;
                // Set packet length.
                set_pktmbuf_data_len(pkt_mbuf, 60);
            }
            let mut n = 0 as u16;
            loop {
                // RX buffers (pktmbufs) starting at index n.
                let rx_buffers = get_rx_mbufs(&fport).unwrap();
                let rx_buffers = rx_buffers.offset(n as isize);
                n = pktdev_tx_burst_fn(fport.lport as u16, rx_buffers, n_pkts);
                if n_pkts <= n {
                    break;
                }
                n_pkts -= n;
            }
        }
        // NOTE: the RX burst is needed to prevent lockups on CVL.
        n_pkts = pktdev_rx_burst_fn(fport.lport as u16, rx_pktmbufs_pptr, MAX_BURST as u16);
        if n_pkts > 0 {
            pktmbuf_free_bulk_fn(rx_pktmbufs_pptr, n_pkts as u32);
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn r_on_exit(sig: i32, arg: *mut c_void, exit_type: i32) {
    if arg.is_null() {
        return;
    }
    let finfo_arg: &mut fwd_info = &mut *(arg as *mut fwd_info);
    let terminate_cstring =
        get_cstring_from_str("\n>>> [cyan]Terminating with signal [green]%d[]\n");
    if exit_type == CNE_CAUGHT_SIGNAL as i32 {
        if sig == SIGUSR1 as i32 {
            return;
        }
        cne_printf_pos(99, 1, terminate_cstring.as_ptr(), sig);
        finfo_arg.timer_quit = 1;
    } else if exit_type == CNE_CALLED_EXIT as i32 {
        if sig > 0 {
            cne_printf_pos(99, 1, terminate_cstring.as_ptr(), sig);
        }
        cne_printf(get_cstring_from_str(">>> [blue]Closing lport(s)[]\n").as_ptr());
        jcfg_object_foreach(
            finfo_arg.jinfo,
            jcfg_cb_type_t_JCFG_THREAD_TYPE,
            Some(r_thread_quit),
            arg,
        );
        cne_printf(get_cstring_from_str(">>> [blue]Done[]\n").as_ptr());
        // Destroy metrics.
        metrics_destroy();
        finfo_arg.timer_quit = 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn r_thread_quit(
    _jinfo: *mut jcfg_info_t,
    obj: *mut c_void,
    _arg: *mut c_void,
    _index: i32,
) -> i32 {
    if obj.is_null() {
        return 0;
    }
    let thd = &mut *(obj as *mut jcfg_thd_t);
    thd.quit = 1;
    // Get lport count and thread name
    let lport_cnt = thd.lport_cnt;
    let thd_name = get_str_from_raw_ptr(thd.name);
    // Close lports
    if thd.lports.is_null() || lport_cnt == 0 {
        log::debug!("No lports attached to thread {} ", thd_name);
        return 0;
    } else {
        log::debug!("Close {} lports attached to thread {}", lport_cnt, thd_name);
        for i in 0..lport_cnt {
            let lport = get_item_at_index(i, thd.lports).unwrap();
            if lport.is_null() {
                break;
            }
            let cstring = get_cstring_from_str(">>>    [blue]lport [red]%d[] - '[cyan]%s[]'\n");
            let port_index = (*lport).lpid;
            let port_name = (*lport).name;
            cne_printf(cstring.as_ptr(), port_index as i32, port_name);
            if pktdev_close(port_index) < 0 {
                log::debug!("pktdev_close() returned error");
            }
            free_lport(lport);
        }
    }
    return 0;
}

fn test_pkt_fwd(args: std::env::Args) -> i32 {
    let tests = ["Unknown", "Drop", "Loopback", "Tx Only", "Forward"];
    unsafe {
        let ftests: [fwd_test; 5] = [
            fwd_test {
                test: test_t_UNKNOWN_TEST,
                cb_func: None,
            },
            fwd_test {
                test: test_t_DROP_TEST,
                cb_func: Some(r_pkt_drop_cb),
            },
            fwd_test {
                test: test_t_LOOPBACK_TEST,
                cb_func: Some(r_pkt_lb_cb),
            },
            fwd_test {
                test: test_t_TXONLY_TEST,
                cb_func: Some(r_pkt_txonly_cb),
            },
            fwd_test {
                test: test_t_FWD_TEST,
                cb_func: Some(r_pkt_fwd_cb),
            },
        ];
        FINFO.test_arr = ftests;
        // Create a vector of zero terminated strings
        let args = args
            .map(|arg| CString::new(arg).unwrap())
            .collect::<Vec<CString>>();
        // Convert the strings to raw pointers
        //let mut c_args = rargs.iter().map(|arg| arg.as_ptr()).collect::<Vec<*const c_char>>();
        let c_args = args
            .iter()
            .map(|arg| arg.clone().into_raw())
            .collect::<Vec<*mut c_char>>();
        let finfo_ptr = &mut FINFO as *mut _;
        let ret = parse_args(c_args.len() as c_int, c_args.as_ptr(), finfo_ptr);
        if ret < 0 {
            return ret;
        }
        // Signals
        let mut signals = [SIGINT as i32, SIGUSR1 as i32];
        let signals_ptr = &mut signals[0] as *mut i32;
        // Register function exit callback.
        let finfo_cvoid_ptr: *mut c_void = &mut FINFO as *mut _ as *mut c_void;
        cne_on_exit(
            Some(r_on_exit),
            finfo_cvoid_ptr,
            signals_ptr,
            signals.len() as i32,
        );

        let barrier = &mut FINFO.barrier as *mut pthread_barrier_t;
        if pthread_barrier_wait(barrier) > 0 {
            log::error!("Failed to wait on barrier");
            return 0;
        }

        let stat_string = "\n[yellow]*** [cyan:-:italic]Rust PKTDEV Forward Application[], \
                       [blue]PID[]: [red]%d[] \
                       [blue]lcore \
                       [red]%d[] [blue]Mode[]: [red:-:italic]%s[]\n";
        let stat_cstring = get_cstring_from_str(stat_string);
        let test_cstring = get_cstring_from_str(tests[FINFO.test as usize]);
        cne_printf(
            stat_cstring.as_ptr(),
            getpid(),
            cne_lcore_id(),
            test_cstring.as_ptr(),
        );
        let locale_cstring = get_cstring_from_str("");
        setlocale(LC_ALL as i32, locale_cstring.as_ptr());
        FINFO.timer_quit = 0;
        loop {
            sleep(1);

            /* Test for quiting after sleep to avoid calling print_port_stats() */
            if FINFO.timer_quit == 1 {
                break;
            }
            print_port_stats_all(finfo_ptr);
        }
        if pthread_barrier_destroy(barrier) > 0 {
            log::error!("Failed to destroy barrier");
        }

        let exit_string = ">>> [cyan]Rust Main Application Exiting[]: [green]Bye![]\n";
        cne_printf(get_cstring_from_str(exit_string).as_ptr());
    }
    return 0;
}

fn main() {
    unsafe {
        let x = cne_init();
        if x < 0 {
            log::debug!("Unable to initalize cne");
            return;
        }
        let args = std::env::args();
        // Test packet forward.
        test_pkt_fwd(args);
    }
}
