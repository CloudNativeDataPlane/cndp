/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use clap::{App, Arg};
use crossbeam_channel::{bounded, select, tick, Receiver};
use etherparse::Ethernet2Header;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use cne::error::*;
use cne::instance::*;
use cne::packet::*;
use cne::port::*;

fn main() {
    // Parse command line arguments.
    let matches = App::new("loopback")
        .version("0.1.0")
        .about("CNE loopback example application.")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .required(true)
                .takes_value(true)
                .help("CNE JSON config file"),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .required(true)
                .takes_value(true)
                .help("port number (lport index) in JSON file"),
        )
        .arg(
            Arg::with_name("affinity")
                .short("a")
                .long("affinity")
                .required(false) // optional parameter
                .takes_value(true)
                .allow_hyphen_values(true) // allow negative values
                .help("Core affinity for loopback thread. If provided, can help to improve performance"),
        )
        .get_matches();

    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    log::info!("CNE loopback application. Press ctrl-c to exit");

    // Parse config file.
    let jsonc_file = matches
        .value_of("config")
        .unwrap()
        .parse::<String>()
        .expect("Invalid CNE JSON file name");

    // Parse port id.
    let port_id = matches
        .value_of("port")
        .unwrap()
        .parse::<u16>()
        .expect("Invalid port number");

    let mut core_id = -1;
    if matches.is_present("affinity") {
        core_id = matches
            .value_of("affinity")
            .unwrap()
            .parse::<i16>()
            .expect("Invalid core id");
    }

    // Get CNE instance.
    let cne = CneInstance::get_instance();

    // Configure CNE.
    if let Err(e) = cne.configure(&jsonc_file) {
        log::error!("Error configuring CNE: {}", e.to_string());
        return;
    }

    // Get CNE port to recv/send packets.
    let port = cne.get_port(port_id);

    // Check if port is valid.
    if let Err(ref e) = port {
        log::error!("{}", e.to_string());
        // Cleanup and exit.
        if let Err(e) = cne.cleanup() {
            log::error!("{}", e.to_string());
        }
        return;
    }
    let port = port.unwrap();

    // Create ctrl-c channel to check for ctrl-c event.
    let ctrl_c_events = ctrl_channel().unwrap();

    // Create channel for periodic logging.
    let ticks = tick(Duration::from_secs(1));

    // Variable to check if application is running.
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Spawn loopback thread to recv/send packets.
    let port_clone = port.clone();
    let handle = thread::spawn(move || {
        // Affinitize thread to core.
        if core_id >= 0 {
            core_affinity::set_for_current(core_affinity::CoreId {
                id: core_id as usize,
            });
        }
        // Register loopback thread with CNE.
        let cne = CneInstance::get_instance();
        let tid = cne.register_thread("loopback").unwrap();

        while r.load(Ordering::SeqCst) {
            if let Err(e) = loopback(&port_clone) {
                log::error!("loopback error: {}", e.to_string());
                break;
            }
        }
        // Unregister thread.
        cne.unregister_thread(tid).unwrap();
    });

    // log port stats. Wait for ctrl-c event from user.
    loop {
        select! {
            recv(ticks) -> _ => {
                if running.load(Ordering::SeqCst) {
                    let port_stats = port.get_port_stats().unwrap();
                    log::info!("Port Stats = {:?}", port_stats);
                }
            }
            recv(ctrl_c_events) -> _ => {
                log::info!("Got ctrl-c event");
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    // Wait for loopback thread to finish.
    handle.join().unwrap();

    // Cleanup CNE.
    let ret = cne.cleanup();
    if let Err(e) = ret {
        log::error!("{}", e.to_string());
    }

    log::info!("Application exited");
}

fn ctrl_channel() -> Result<Receiver<()>, ctrlc::Error> {
    let (sender, receiver) = bounded(16);
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;

    Ok(receiver)
}

fn loopback(port: &Port) -> Result<(), CneError> {
    let mut rx_pkts = [Packet::default(); Packet::MAX_BURST];

    let pkts_read = port.rx_burst(&mut rx_pkts[..])?;
    log::debug!("Number of packets read = {}", pkts_read);

    if pkts_read > 0 {
        for i in 0..pkts_read {
            let pkt = &rx_pkts[i as usize];
            let data = pkt.get_data_mut();
            if let Some(data) = data {
                // Swap mac address.
                swap_mac_address(data);
            }
        }

        let mut pkts_sent = 0;
        while pkts_sent < pkts_read {
            let tx_sent = port.tx_burst(&mut rx_pkts[pkts_sent as usize..pkts_read as usize])?;
            pkts_sent += tx_sent;
        }
        log::debug!("Number of packets sent = {}", pkts_sent);
    }

    Ok(())
}

fn swap_mac_address(p: &mut [u8]) {
    match Ethernet2Header::from_slice(p) {
        Ok((mut eth_hdr, _)) => {
            std::mem::swap(&mut eth_hdr.source, &mut eth_hdr.destination);
            eth_hdr.write_to_slice(p).unwrap();
        }
        Err(e) => {
            log::error!("Error parsing ethernet packet : {}", e);
        }
    }
}
