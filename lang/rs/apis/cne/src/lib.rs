/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

//! # High level Rust API for CNDP CNE
//!
//! The project provides high-level Rust APIs (crate `cne`) for CNDP CNE.
//! It depends on low-level Rust bindings (crate `cne-sys`) for CNDP CNE C library. It is expected that most
//! Rust applications using CNDP would only need high-level CNDP CNE Rust APIs.
//!
//! This project is hosted on [GitHub](https://github.com/CloudNativeDataPlane/cndp/tree/main/lang/rs/apis/cne)
//!
//! ## Getting Started
//!
//! Refer [README.md](https://github.com/CloudNativeDataPlane/cndp/blob/main/lang/rs/apis/cne/README.md)
//!
//! ## Examples and Usage
//!
//! Checkout [examples](https://github.com/CloudNativeDataPlane/cndp/tree/main/lang/rs/apis/cne/examples)
//! Also see the crate documentation.

pub mod config;
pub mod error;
pub mod instance;
pub mod packet;
pub mod port;
pub mod port_tx_buff;
mod util;

#[cfg(test)]
mod tests {
    use super::config;
    use super::instance::*;
    use super::packet::*;
    use etherparse::Ethernet2Header;
    use hex;
    use std::env;
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    fn init() {
        // This will enable logs for test.
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn get_jsonc_file() -> String {
        let path_manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let jsonc_file = path_manifest
            .join("fwd.jsonc")
            .as_path()
            .display()
            .to_string();

        jsonc_file
    }

    fn swap_mac_address(p: &mut [u8]) {
        match Ethernet2Header::from_slice(p) {
            Ok((mut eth_hdr, _)) => {
                let tmp = eth_hdr.source;
                eth_hdr.source = eth_hdr.destination;
                eth_hdr.destination = tmp;
                eth_hdr.write_to_slice(p).unwrap();
            }
            Err(e) => {
                log::error!("Error parsing ethernet packet : {}", e);
            }
        }
    }

    #[test]
    fn test_load_config() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        let cfg = config::Config::load_config(&jsonc_file);
        assert!(cfg.is_ok());

        let cfg = cfg.unwrap();
        let ser_string = config::Config::get_config(&cfg);
        assert!(ser_string.is_ok());
    }

    #[test]
    fn test_cne_instance() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Configure CNE.
        let ret = cne.configure(&jsonc_file);
        assert!(ret.is_ok());

        // Cleanup CNE.
        let ret = cne.cleanup();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_get_port() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Configure CNE.
        let ret = cne.configure(&jsonc_file);
        assert!(ret.is_ok());

        // Get num ports.
        let num_ports = cne.get_num_ports();
        assert!(num_ports.is_ok());

        // Get valid port. Should return success.
        let port = cne.get_port(0);
        assert!(port.is_ok());

        // Get invalid port. Should return error.
        let port = cne.get_port(100);
        assert!(port.is_err());
        if let Err(e) = port {
            log::debug!("{}", e.to_string());
        }

        // Cleanup CNE.
        let ret = cne.cleanup();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_get_port_details() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Configure CNE.
        let ret = cne.configure(&jsonc_file);
        assert!(ret.is_ok());

        // Get valid port. Should return success.
        let port = cne.get_port(0);
        assert!(port.is_ok());

        // Get port details
        let port = port.unwrap();
        let port_details = port.get_port_details();
        assert!(port_details.is_ok());

        // Cleanup CNE.
        let ret = cne.cleanup();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_rx_burst() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Configure CNE.
        let ret = cne.configure(&jsonc_file);
        assert!(ret.is_ok());

        // Get valid port. Should return success.
        let port = cne.get_port(0);
        assert!(port.is_ok());

        let port = port.unwrap();

        let mut rx_pkts = [Packet::default(); Packet::MAX_BURST];

        // Try reading packets.
        let num_tries = 10;
        for _i in 0..num_tries {
            let pkts_read = port.rx_burst(&mut rx_pkts[..]);
            assert!(pkts_read.is_ok());
            let pkts_read = pkts_read.unwrap();

            if pkts_read > 0 {
                log::debug!("Number of packets read = {}", pkts_read);
                let pkt = &rx_pkts[0];

                let data_len = pkt.get_data_len();
                assert!(data_len.is_ok());
                log::debug!("packet data length = {}", data_len.unwrap());

                let ret = Packet::free_packet_buffer(&mut rx_pkts[..pkts_read as usize]);
                assert!(ret.is_ok());
                break;
            } else {
                // If there are no packets read then thread can (optionally) sleep for sometime.
                // This will reduce CPU utilization instead of reading in tight loop
                // and keeping CPU busy at 100%.
                thread::sleep(Duration::from_micros(20));
            }
        }

        // Cleanup CNE.
        let ret = cne.cleanup();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_tx_burst() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Configure CNE.
        let ret = cne.configure(&jsonc_file);
        assert!(ret.is_ok());

        // Get valid port. Should return success.
        let port = cne.get_port(0);
        assert!(port.is_ok());

        let port = port.unwrap();

        let mut tx_pkts = [Packet::default(); Packet::MAX_BURST];

        let alloc_pkts = port.prepare_tx_packets(&mut tx_pkts[..]);
        assert!(alloc_pkts.is_ok());
        let alloc_pkts = alloc_pkts.unwrap();

        // Fill a byte array with some values.
        let input = "fd3c78299efefd3c00450008b82c9efe110400004f122e00a8c00100a8c01e221a002e16d2040101706f6e6d6c6b9a9e787776757473727131307a79";
        let ret = hex::decode(input);
        assert!(ret.is_ok());
        let p = ret.unwrap();

        // Fill packets with data.
        for i in 0..alloc_pkts {
            let pkt = &mut tx_pkts[i as usize];

            let ret = pkt.set_data(&p);
            assert!(ret.is_ok());
        }

        let pkts_sent = port.tx_burst(&mut tx_pkts[..]);
        assert!(pkts_sent.is_ok());
        log::debug!("Number of packets sent = {}", pkts_sent.unwrap());

        // Cleanup CNE.
        let ret = cne.cleanup();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_loopback() {
        init();

        // Get jsonc file path.
        let jsonc_file = get_jsonc_file();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Configure CNE.
        let ret = cne.configure(&jsonc_file);
        assert!(ret.is_ok());

        // Get valid port. Should return success.
        let port = cne.get_port(0);
        assert!(port.is_ok());

        let port = port.unwrap();

        let mut rx_pkts = [Packet::default(); Packet::MAX_BURST];

        let mut pkts_read = 0;

        // Try reading some packets.
        let num_tries = 10;
        for _i in 0..num_tries {
            pkts_read = port.rx_burst(&mut rx_pkts[..]).unwrap() as usize;
            if pkts_read == 0 {
                // If there are no packets read then thread can (optionally) sleep for sometime.
                // This will reduce CPU utilization instead of reading in tight loop
                // and keeping CPU busy at 100%.
                thread::sleep(Duration::from_micros(20));
            } else {
                break;
            }
        }

        log::debug!("Number of packets read = {}", pkts_read);

        if pkts_read > 0 {
            for i in 0..pkts_read {
                let pkt = &mut rx_pkts[i];

                let p = pkt.get_data_mut();
                assert!(p.is_ok());

                let p = p.unwrap();

                // Swap mac address.
                swap_mac_address(p);
            }

            let mut pkts_sent = 0;
            let mut max_tries = 10;
            // Try sending back all the packets in a loop with threshold on number of tries.
            while pkts_sent < pkts_read && max_tries > 0 {
                let n_pkts = port.tx_burst(&mut rx_pkts[pkts_sent..pkts_read]).unwrap() as usize;
                pkts_sent += n_pkts;
                max_tries -= 1;
            }
            log::debug!("Number of packets sent = {}", pkts_sent);
            // Free packets which are not sent.
            if pkts_sent < pkts_read {
                let ret = Packet::free_packet_buffer(&mut rx_pkts[pkts_sent..pkts_read]);
                assert!(ret.is_ok());
            }
        }

        // Cleanup CNE.
        let ret = cne.cleanup();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_register() {
        init();

        // Get CNE instance.
        let cne = CneInstance::get_instance();

        // Register thread with CNE.
        let tid = cne.register_thread("main");
        assert!(tid.is_ok());

        // Re-register thread with CNE. It should return same tid.
        let tid1 = cne.register_thread("main");
        assert!(tid1.is_ok());
        assert!(tid1.as_ref().unwrap() == tid.as_ref().unwrap());

        // Unregister thread.
        let ret = cne.unregister_thread(tid.unwrap());
        assert!(ret.is_ok());
    }
}
