/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use clap::{App, Arg};
use crossbeam_channel::{bounded, select, tick, Receiver};

use cne::error::CneError;
use cne::instance::CneInstance;
use cne::packet::PacketInterface;
use cne::port::Port;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::MutableEthernetPacket;

// Example echo server implementation using cne and libpnet library.
// CNE based echo server receives and sends layer 2 packets using AF-XDP socket.
// libpnet based echo server receives and sends layer 2 packets using AF_PACKET.
// This application requires an external load generator (s/w or h/w) to send packets
// to required n/w interface. The performance of CNE/libpnet echo server can be checked
// at load generator end by observing packets per sec (pps) of echoed packets.
// An example script run.sh is provided to build and run the application. Please refer
// the script for descrption on how to run the application with command line parameters.
fn main() {
    // Parse command line arguments.
    let matches = App::new("echo_server")
        .version("0.1.0")
        .about("Echo server application using pnet and cne.")
        .subcommand(
            App::new("pnet").about("pnet based echo server").arg(
                Arg::with_name("interface")
                    .short('i')
                    .long("interface")
                    .required(true)
                    .takes_value(true)
                    .help("Network interface name"),
            ),
        )
        .subcommand(
            App::new("cne")
                .about("cne based echo server")
                .arg(
                    Arg::with_name("config")
                        .short('c')
                        .long("config")
                        .required(true)
                        .takes_value(true)
                        .help("CNE JSONC config file"),
                )
                .arg(
                    Arg::with_name("port")
                        .short('p')
                        .long("port")
                        .required(true)
                        .takes_value(true)
                        .help("port index in JSON file"),
                )
                .arg(
                    Arg::with_name("burst")
                        .short('b')
                        .long("burst")
                        .required(false)
                        .takes_value(true)
                        .help("packet burst size. Default is 256"),
                )
                .arg(
                    Arg::with_name("affinity")
                        .short('a')
                        .long("affinity")
                        .required(false) // optional parameter
                        .default_value("")
                        .takes_value(true)
                        .help(
                            "Cpu set affinity group for loopback thread. Group name should match with JSONC
                             file lcore-groups section. If provided, can help to improve performance",
                        ),
                ),
        )
        .get_matches();

    // Start logging.
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    log::info!("Echo server example application. Press ctrl-c to exit");

    // Parse sub command parameters.
    match matches.subcommand() {
        Some(("pnet", pnet_matches)) => {
            // Parse interface name.
            let interface_name = pnet_matches
                .value_of("interface")
                .unwrap()
                .parse::<String>()
                .expect("Invalid interface name");

            pnet_echo_server(&interface_name);
        }
        Some(("cne", cne_matches)) => {
            // Parse CNE JSONC config file.
            let jsonc_file = cne_matches
                .value_of("config")
                .unwrap()
                .parse::<String>()
                .expect("Invalid CNE JSON file name");

            // Parse port id.
            let port_id = cne_matches
                .value_of("port")
                .unwrap()
                .parse::<u16>()
                .expect("Invalid port number");

            // Burst size.
            let mut burst_size = cne::packet::Packet::MAX_BURST;
            if cne_matches.is_present("burst") {
                burst_size = cne_matches
                    .value_of("burst")
                    .unwrap()
                    .parse::<usize>()
                    .expect("Invalid burst size");
            }

            // Parse lcore core group.
            let mut lcore_group = String::from("");
            if cne_matches.is_present("affinity") {
                lcore_group = cne_matches
                    .value_of("affinity")
                    .unwrap()
                    .parse::<String>()
                    .expect("Invalid lcore group");
            }

            cne_echo_server(&jsonc_file, port_id, burst_size, &lcore_group);
        }
        _ => {
            log::error!("Invalid mode. Mode should be either pnet or cne");
        }
    }
}

// Echo server based on libpnet library.
// Uses AF_PACKET to receive/send layer 2 packets. It receives/sends only one packet at a time.
fn pnet_echo_server(interface_name: &str) {
    // Find the network interface matching the iface name.
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .unwrap();

    // Create datalink channel. Sends and receives data link layer packets using Linux's AF_PACKET.
    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            panic!("channel type not supported")
        }
        Err(e) => panic!("Error creating the datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                // Constructs a packet of same length as the the one received, using the provided closure.
                // The packet is sent once the closure has finished executing.
                tx.build_and_send(1, packet.len(), &mut |new_packet| {
                    // Create a clone of the original packet.
                    new_packet.clone_from_slice(packet);
                    // Swap the source and destination mac addresses.
                    swap_mac_address(new_packet);
                });
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                log::error!("An error occurred while reading: {}", e);
                return;
            }
        }
    }
}

// Echo server based on CNE library.
// Uses AF_XDP socket to receive/send layer 2 packets. It receives/sends packets in burst.
// Burst size is configurable.
fn cne_echo_server(jsonc_file: &str, port_id: u16, burst_size: usize, lcore_group: &str) {
    // Get CNE instance.
    let cne = CneInstance::get_instance();

    // Configure CNE.
    if let Err(e) = cne.configure(jsonc_file) {
        log::error!("Error configuring CNE: {}", e.to_string());
        return;
    }

    // Get CNE port to receive/send packets.
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

    // Spawn thread to receive/send packets.
    let port_clone = port.clone();
    let lcore_group = String::from(lcore_group);
    let handle = thread::spawn(move || {
        // Register thread with CNE.
        let cne = CneInstance::get_instance();
        let tid = cne.register_thread("echo").unwrap();

        // Affinitize current thread to lcore group.
        if !lcore_group.is_empty() {
            if let Err(e) = cne.set_current_thread_affinity(&lcore_group) {
                log::warn!("Thread affinity cannot be set: {}", e.to_string());
            }
        }

        while r.load(Ordering::SeqCst) {
            if let Err(e) = cne_macswap_and_send(&port_clone, burst_size) {
                log::error!("cne echo server error: {}", e.to_string());
                break;
            }
        }
        // Unregister thread.
        cne.unregister_thread(tid).unwrap();
    });

    // Get port stats. Wait for ctrl-c event from user.
    loop {
        select! {
            recv(ticks) -> _ => {
                if running.load(Ordering::SeqCst) {
                    let port_stats = port.get_port_stats().unwrap();
                    log::debug!("CNE Port Stats = {:?}", port_stats);
                }
            }
            recv(ctrl_c_events) -> _ => {
                log::info!("Got ctrl-c event");
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    // Wait for echo thread to finish.
    handle.join().unwrap();

    // Cleanup CNE.
    let ret = cne.cleanup();
    if let Err(e) = ret {
        log::error!("{}", e.to_string());
    }
}

// Channel to handle ctrl-c input from user.
fn ctrl_channel() -> Result<Receiver<()>, ctrlc::Error> {
    let (sender, receiver) = bounded(16);
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;

    Ok(receiver)
}

// Receives burst of packets from port, swaps mac addresses and send packets on same port.
fn cne_macswap_and_send(port: &Port, burst_size: usize) -> Result<(), CneError> {
    let mut rx_pkts = vec![cne::packet::Packet::default(); burst_size];

    let pkts_read = port.rx_burst(&mut rx_pkts[..burst_size])? as usize;
    log::debug!("Number of packets read = {}", pkts_read);

    if pkts_read > 0 {
        for i in 0..pkts_read {
            let pkt = &mut rx_pkts[i as usize];
            let data = pkt.get_data_mut()?;
            // Swap mac address.
            swap_mac_address(data);
        }

        let mut pkts_sent = 0;
        let mut max_tries = 10;
        // Try sending back all the packets in a loop with threshold on number of tries.
        while pkts_sent < pkts_read && max_tries > 0 {
            let tx_sent = port.tx_burst(&mut rx_pkts[pkts_sent..pkts_read])? as usize;
            pkts_sent += tx_sent;
            max_tries -= 1;
        }
        log::debug!("Number of packets sent = {}", pkts_sent);
        // Free packets which are not sent.
        if pkts_sent < pkts_read {
            cne::packet::Packet::free_packet_buffer(&mut rx_pkts[pkts_sent..pkts_read])?;
        }
    }

    Ok(())
}

fn swap_mac_address(p: &mut [u8]) {
    let mut packet = MutableEthernetPacket::new(p).unwrap();
    let src = packet.get_source();
    packet.set_source(packet.get_destination());
    packet.set_destination(src);
}
