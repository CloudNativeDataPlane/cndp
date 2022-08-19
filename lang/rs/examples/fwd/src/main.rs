/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use clap::{arg, value_parser, App, Arg, ValueEnum};
use cne::config::Thread;
use cne::error::CneError;
use cne::instance::CneInstance;
use cne::packet::{Packet, PacketInterface};
use cne::port::{Port, PortStats};
use cne::port_tx_buff::BufferedTxPort;
use crossbeam_channel::{bounded, select, tick, Receiver};
use etherparse::Ethernet2Header;
use etherparse::Ethernet2HeaderSlice;
use prettytable::{Cell, Row, Table};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Clone, Debug, ValueEnum, Eq, PartialEq)]
enum Mode {
    Drop,
    RxOnly,
    TxOnly,
    #[clap(alias = "loopback")]
    Lb,
    #[clap(alias = "forward")]
    Fwd,
}

fn main() {
    // Parse command line arguments.
    let matches = App::new("fwd")
        .version("0.1.0")
        .about("CNE fwd example application.")
        .arg(
            Arg::with_name("config")
                .short('c')
                .long("config")
                .required(true)
                .takes_value(true)
                .help("CNE JSONC config file"),
        )
        .arg(
            arg!(<MODE>)
                .help("Mode to run the program")
                .required(true)
                .value_parser(value_parser!(Mode)),
        )
        .get_matches();

    // start logging
    env_logger::builder()
        .try_init()
        .expect("Failed to initialize event logger");

    log::info!("CNE fwd application. Press ctrl-c to exit");

    // Parse config file.
    let jsonc_file = matches
        .value_of("config")
        .unwrap()
        .parse::<String>()
        .expect("Invalid CNE JSONC file name");

    // Parse mode.
    let mode = matches.get_one::<Mode>("MODE").unwrap();
    log::info!("Mode is {:?}", mode);

    // Get CNE instance.
    let cne = CneInstance::get_instance();

    // Configure CNE.
    if let Err(e) = cne.configure(&jsonc_file) {
        log::error!("Error configuring CNE: {}", e.to_string());
        return;
    }

    // Get number of ports.
    let num_ports = cne.get_num_ports().unwrap() as usize;

    // Create port list.
    let ports = create_port_list(num_ports);

    // Create Tx buffered ports. Used for "fwd" mode.
    let buff_tx_ports = create_tx_buff_ports(&ports, Packet::MAX_BURST);

    // Get threads.
    let threads = cne.get_thread_details().unwrap();
    let mut handles = Vec::new();

    // Create ctrl-c channel to check for ctrl-c event.
    let ctrl_c_events = ctrl_channel().unwrap();

    // Create channel for periodic logging.
    let ticks = tick(Duration::from_secs(1));

    // Variable to check if application is running.
    let running = Arc::new(AtomicBool::new(true));

    // Create threads to run tests.
    for (name, thd) in threads {
        if name == "main" {
            continue;
        }
        let handle = run_thread(
            name,
            thd,
            mode.clone(),
            num_ports,
            buff_tx_ports.clone(),
            &running,
        );
        handles.push(handle);
    }

    // Print port stats every sec. Wait for ctrl-c event from user.
    let mut prev_port_stats = vec![PortStats::default(); num_ports];
    let mut port_stats = vec![PortStats::default(); num_ports];
    let mut table_height: usize = 0;

    loop {
        select! {
            recv(ticks) -> _ => {
                if running.load(Ordering::SeqCst) {
                    // Get port stats.
                    for (i,port) in ports.iter().enumerate() {
                        port_stats[i] = port.get_port_stats().unwrap();
                    }
                    print_port_stats(num_ports, &port_stats, &mut prev_port_stats, &mut table_height);
                }
            }
            recv(ctrl_c_events) -> _ => {
                log::info!("Got ctrl-c event");
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    // Wait for threads to quit.
    for handle in handles {
        handle.join().unwrap();
    }

    // Cleanup CNE.
    let ret = cne.cleanup();
    if let Err(e) = ret {
        log::error!("{}", e.to_string());
    }
}

fn create_tx_buff_ports(ports: &[Port], buffer_size: usize) -> Vec<BufferedTxPort> {
    let mut tx_buff_port_list = Vec::new();
    for port in ports {
        tx_buff_port_list.push(BufferedTxPort::new(port.clone(), buffer_size));
    }
    tx_buff_port_list
}

fn create_port_list(num_ports: usize) -> Vec<Port> {
    let cne = CneInstance::get_instance();
    let mut ports = Vec::with_capacity(num_ports);
    for i in 0..num_ports {
        let port = cne.get_port(i as u16);
        // Check if port is valid.
        if let Err(ref e) = port {
            log::error!("{}", e.to_string());
            continue;
        }
        ports.push(port.unwrap());
    }
    ports
}

fn run_thread(
    thd_name: String,
    thd: Thread,
    mode: Mode,
    num_ports: usize,
    buff_tx_ports: Vec<BufferedTxPort>,
    running: &Arc<AtomicBool>,
) -> JoinHandle<()> {
    let builder = thread::Builder::new().name(thd_name.clone());
    let running = running.clone();
    builder
        .spawn(move || {
            // Register thread with CNE.
            let cne = CneInstance::get_instance();
            let tid = cne.register_thread(&thd_name).unwrap();

            // Affinitize current thread to lcore group.
            match &thd.group {
                Some(lcore_group) => {
                    if let Err(e) = cne.set_current_thread_affinity(lcore_group) {
                        log::warn!("Thread affinity cannot be set: {}", e.to_string());
                    }
                }
                None => {}
            };

            // List of ports in this thread section in JSONC file.
            let mut thd_ports = Vec::new();
            match &thd.lports {
                Some(port_names) => {
                    for port_name in port_names {
                        let port = cne.get_port_by_name(port_name);
                        // Check if port is valid.
                        if let Err(ref e) = port {
                            log::error!("{}", e.to_string());
                            continue;
                        }
                        log::info!("Add port with name {}", port_name);
                        thd_ports.push(port.unwrap());
                    }
                }
                None => {}
            };

            let mut pkts = vec![Packet::default(); Packet::MAX_BURST];
            while running.load(Ordering::SeqCst) {
                for port in &thd_ports {
                    if let Err(e) = run_test(&mode, port, num_ports, &buff_tx_ports, &mut pkts) {
                        log::error!("run test error: {}", e.to_string());
                        break;
                    }
                }
            }
            if mode == Mode::Fwd {
                if let Err(e) = flush_tx_buff_pkts(&buff_tx_ports) {
                    log::error!("Error flushing Tx packets: {}", e.to_string());
                }
            }
            // Unregister thread.
            cne.unregister_thread(tid).unwrap();
        })
        .unwrap()
}

// Channel to handle ctrl-c input from user.
fn ctrl_channel() -> Result<Receiver<()>, ctrlc::Error> {
    let (sender, receiver) = bounded(16);
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;

    Ok(receiver)
}

fn run_test(
    mode: &Mode,
    port: &Port,
    num_ports: usize,
    buff_tx_ports: &[BufferedTxPort],
    pkts: &mut [Packet],
) -> Result<(), CneError> {
    match mode {
        Mode::Drop | Mode::RxOnly => drop(port, pkts),
        Mode::TxOnly => tx_only(port, pkts),
        Mode::Lb => loopback(port, pkts),
        Mode::Fwd => forward(port, num_ports, buff_tx_ports, pkts),
    }
}

fn drop(port: &Port, pkts: &mut [Packet]) -> Result<(), CneError> {
    let pkts_read = port.rx_burst(pkts)? as usize;
    if pkts_read > 0 {
        cne::packet::Packet::free_packet_buffer(&mut pkts[0..pkts_read])?;
    }

    Ok(())
}

fn tx_only(port: &Port, pkts: &mut [Packet]) -> Result<(), CneError> {
    let alloc_pkts = port.prepare_tx_packets(pkts)? as usize;

    // Fill a byte array with some values.
    // IPv4/UDP 64 byte packet
    // Port Src/Dest       :           1234/ 5678
    // Pkt Type            :           IPv4 / UDP
    // IP  Destination     :           198.18.1.1
    //     Source          :        198.18.0.1/24
    // MAC Destination     :    3c:fd:fe:e4:34:c0
    //     Source          :    3c:fd:fe:e4:38:40
    //
    // 0000   3cfd fee4 34c0 3cfd fee4 3840 0800 4500
    // 0010   002e 60ac 0000 4011 8cec c612 0001 c612
    // 0020   0101 04d2 162e 001a 93c6 6b6c 6d6e 6f70
    // 0030   7172 7374 7576 7778 797a 3031
    let input = "3cfdfee434c03cfdfee4384008004500002e60ac000040118cecc6120001c612010104d2162e001a93c66b6c6d6e6f707172737475767778797a3031";
    let ret = hex::decode(input);
    assert!(ret.is_ok());
    let p = ret.unwrap();

    // Fill packets with data.
    for pkt in pkts.iter_mut() {
        let ret = pkt.set_data(&p);
        assert!(ret.is_ok());
    }

    let pkts_sent = port.tx_burst(&mut pkts[..alloc_pkts])? as usize;

    // Free packets which are not sent.
    if pkts_sent < alloc_pkts {
        cne::packet::Packet::free_packet_buffer(&mut pkts[pkts_sent..alloc_pkts])?;
    }

    Ok(())
}

fn loopback(port: &Port, pkts: &mut [Packet]) -> Result<(), CneError> {
    // Read burst of packets.
    let pkts_read = port.rx_burst(pkts)? as usize;

    if pkts_read > 0 {
        log::debug!("Number of packets read = {}", pkts_read);
        for i in 0..pkts_read {
            let pkt = &mut pkts[i as usize];
            let data = pkt.get_data_mut()?;
            // Swap mac address.
            let mut eth_hdr = Ethernet2HeaderSlice::from_slice(data)
                .map_err(|e| CneError::PacketError(e.to_string()))?
                .to_header();
            swap_mac_address(data, &mut eth_hdr);
        }

        let mut pkts_sent = 0;
        let mut max_tries = 10;
        // Try sending back all the packets in a loop with threshold on number of tries.
        while pkts_sent < pkts_read && max_tries > 0 {
            let tx_sent = port.tx_burst(&mut pkts[pkts_sent..pkts_read])? as usize;
            pkts_sent += tx_sent;
            max_tries -= 1;
        }
        log::debug!("Number of packets sent = {}", pkts_sent);
        // Free packets which are not sent.
        if pkts_sent < pkts_read {
            Packet::free_packet_buffer(&mut pkts[pkts_sent..pkts_read])?;
        }
    }

    Ok(())
}

fn forward(
    port: &Port,
    num_ports: usize,
    buff_tx_ports: &[BufferedTxPort],
    pkts: &mut [Packet],
) -> Result<(), CneError> {
    // Read burst of packets.
    let pkts_read = port.rx_burst(pkts)? as usize;

    if pkts_read > 0 {
        log::debug!("Number of packets read = {}", pkts_read);
        for i in 0..pkts_read {
            let pkt = &mut pkts[i as usize];
            let data = pkt.get_data_mut()?;
            // Get destination port.
            // Look at the lowest byte of the destination mac address to determine
            // the output port on which packet should be transmitted.
            // For example, if dest mac is 00:01:02:03:04:05, the packet is transmitted
            // on the logical port with port id 5. If no such port exists, packet is
            // transmitted on the same port on which it was received.
            let mut eth_hdr = Ethernet2HeaderSlice::from_slice(data)
                .map_err(|e| CneError::PacketError(e.to_string()))?
                .to_header();
            let dst_port_index = eth_hdr.destination[5] as usize;

            let buff_tx_port = if is_valid_port(dst_port_index, num_ports) {
                &buff_tx_ports[dst_port_index]
            } else {
                let port_index = port.get_port_index()? as usize;
                &buff_tx_ports[port_index]
            };
            // Swap mac address.
            swap_mac_address(data, &mut eth_hdr);

            // Add packet to buffered Tx port.
            // Packet will be transmitted from the port later once buffer is full.
            let pkts_sent = buff_tx_port.tx_buff_add(*pkt)?;
            if pkts_sent > 0 {
                let port_index = buff_tx_port.tx_buff_port_index()?;
                log::debug!(
                    "tx_buff_add: Number of packets sent from port {} = {}",
                    port_index,
                    pkts_sent
                );
            }
        }
    }

    Ok(())
}

fn flush_tx_buff_pkts(buff_tx_ports: &[BufferedTxPort]) -> Result<(), CneError> {
    // Flush buffered Tx packets from ports.
    for (port_index, buff_tx_port) in buff_tx_ports.iter().enumerate() {
        let pkts_sent = buff_tx_port.tx_buff_flush()?;
        if pkts_sent > 0 {
            log::debug!(
                "Flush: Number of packets sent from port {} = {}",
                port_index,
                pkts_sent
            );
        }
    }

    Ok(())
}

fn is_valid_port(index: usize, num_ports: usize) -> bool {
    index <= num_ports
}

fn swap_mac_address(data: &mut [u8], eth_hdr: &mut Ethernet2Header) {
    std::mem::swap(&mut eth_hdr.source, &mut eth_hdr.destination);
    data[..eth_hdr.header_len()].copy_from_slice(&eth_hdr.to_bytes());
}

enum PrintStats {
    RxPPS,
    RxTotalPkts,
    RxTotalMBs,
    RxErrors,
    RxMissed,
    RxInvalid,
    TxPPS,
    TxTotalPkts,
    TxTotalMBs,
    TxErrors,
    TxDropped,
    TxInvalid,
}

impl fmt::Display for PrintStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrintStats::RxPPS => write!(f, "Rx Pkts/s"),
            PrintStats::RxTotalPkts => write!(f, "Rx Total Pkts"),
            PrintStats::RxTotalMBs => write!(f, "Rx Total MBs"),
            PrintStats::RxErrors => write!(f, "Rx Errors"),
            PrintStats::RxMissed => write!(f, "Rx Missed"),
            PrintStats::RxInvalid => write!(f, "Rx Invalid"),
            PrintStats::TxPPS => write!(f, "Tx Pkts/s"),
            PrintStats::TxTotalPkts => write!(f, "Tx Total Pkts"),
            PrintStats::TxTotalMBs => write!(f, "Tx Total MBs"),
            PrintStats::TxErrors => write!(f, "Tx Errors"),
            PrintStats::TxDropped => write!(f, "Tx Dropped"),
            PrintStats::TxInvalid => write!(f, "Tx Invalid"),
        }
    }
}

fn print_port_stats(
    num_ports: usize,
    port_stats: &[PortStats],
    prev_port_stats: &mut [PortStats],
    height: &mut usize,
) {
    let mut table = Table::new();
    let mut row = Row::empty();
    row.add_cell(Cell::new("Stats"));
    for i in 0..num_ports {
        let port_str = format!("Port {}", i).to_string();
        row.add_cell(Cell::new(&port_str));
    }
    table.add_row(row);

    let print_stats = vec![
        PrintStats::RxPPS,
        PrintStats::RxTotalPkts,
        PrintStats::RxTotalMBs,
        PrintStats::RxErrors,
        PrintStats::RxMissed,
        PrintStats::RxInvalid,
        PrintStats::TxPPS,
        PrintStats::TxTotalPkts,
        PrintStats::TxTotalMBs,
        PrintStats::TxErrors,
        PrintStats::TxDropped,
        PrintStats::TxInvalid,
    ];

    for stat in print_stats {
        let mut row = Row::empty();
        row.add_cell(Cell::new(&stat.to_string()));
        for i in 0..num_ports {
            let value = match stat {
                PrintStats::RxPPS => port_stats[i].in_packets - prev_port_stats[i].in_packets,
                PrintStats::RxTotalPkts => port_stats[i].in_packets,
                PrintStats::RxTotalMBs => port_stats[i].in_bytes / (1024 * 1024),
                PrintStats::RxErrors => port_stats[i].in_errors,
                PrintStats::RxMissed => port_stats[i].in_missed,
                PrintStats::RxInvalid => port_stats[i].rx_invalid,
                PrintStats::TxPPS => port_stats[i].out_packets - prev_port_stats[i].out_packets,
                PrintStats::TxTotalPkts => port_stats[i].out_packets,
                PrintStats::TxTotalMBs => port_stats[i].out_bytes / (1024 * 1024),
                PrintStats::TxErrors => port_stats[i].out_errors,
                PrintStats::TxDropped => port_stats[i].out_dropped,
                PrintStats::TxInvalid => port_stats[i].tx_invalid,
            };
            row.add_cell(Cell::new(&value.to_string()));
        }
        table.add_row(row);
    }

    // Update previous port stats to current port stats.
    prev_port_stats.clone_from_slice(port_stats);

    // Clear the terminal by deleting the printed lines in previous table.
    let mut terminal = term::stdout().unwrap();
    for _ in 0..*height {
        terminal.cursor_up().unwrap();
        terminal.delete_line().unwrap();
    }

    // Print updated table and update height (number of lines) of table.
    *height = table.print_tty(false);
}
