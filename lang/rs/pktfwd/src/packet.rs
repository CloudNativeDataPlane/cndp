/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
use pnet::datalink::{channel, Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations};
use pnet::packet::arp::{ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;
use std::net::{IpAddr, Ipv4Addr};
use std::slice;

pub struct CndpPacket<'p> {
    eth_packet: MutableEthernetPacket<'p>,
    pub src_mac: Option<MacAddr>,
    pub dst_mac: Option<MacAddr>,
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl CndpPacket<'_> {
    const IPV4_HEADER_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;
}

impl<'p> Display for CndpPacket<'p> {
    fn fmt(&self, fmt: &mut Formatter) -> Result {
        write!(
            fmt,
            "CndpPacket [
                            src_mac: {:?}, dst_mac: {:?},
                            src_ip: {:?}, dst_ip: {:?},
                            src_port: {:?}, dst_port: {:?}
                           ]",
            self.src_mac, self.dst_mac, self.src_ip, self.dst_ip, self.src_port, self.dst_port
        )
    }
}

impl<'p> CndpPacket<'p> {
    pub fn new<'a>(pkt_data_addr: *mut u8, data_len: usize) -> Option<CndpPacket<'a>> {
        if pkt_data_addr.is_null() {
            None
        } else {
            let p: &'a mut [u8] = unsafe { slice::from_raw_parts_mut(pkt_data_addr, data_len) };
            let ethernet_packet = MutableEthernetPacket::new(&mut p[..]).unwrap();
            Some(CndpPacket {
                eth_packet: ethernet_packet,
                src_mac: None,
                dst_mac: None,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
            })
        }
    }

    pub fn parse_eth_udp_packet(&mut self) -> i32 {
        self.src_mac = Some(self.eth_packet.get_source());
        self.dst_mac = Some(self.eth_packet.get_destination());
        let ret = match self.eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => self.parse_ipv4_packet(),
            EtherTypes::Ipv6 => self.parse_ipv6_packet(),
            _ => {
                log::debug!(
                    "Unknown packet: {} > {}; ethertype: {:?} length: {}",
                    self.eth_packet.get_source(),
                    self.eth_packet.get_destination(),
                    self.eth_packet.get_ethertype(),
                    self.eth_packet.packet().len()
                );
                -1
            }
        };
        ret
    }

    fn parse_ipv4_packet(&mut self) -> i32 {
        let ip = Ipv4Packet::new(self.eth_packet.payload());
        if let Some(ip) = ip {
            self.src_ip = Some(IpAddr::V4(ip.get_source()));
            self.dst_ip = Some(IpAddr::V4(ip.get_destination()));
            let (src_port, dst_port, status) = self.parse_transport_packet(
                self.src_ip.unwrap(),
                self.dst_ip.unwrap(),
                ip.get_next_level_protocol(),
                ip.payload(),
            );
            self.src_port = src_port;
            self.dst_port = dst_port;
            status
        } else {
            log::debug!("Malformed IPv4 Packet");
            -1
        }
    }

    fn parse_ipv6_packet(&mut self) -> i32 {
        let ip = Ipv6Packet::new(self.eth_packet.payload());
        if let Some(ip) = ip {
            self.src_ip = Some(IpAddr::V6(ip.get_source()));
            self.dst_ip = Some(IpAddr::V6(ip.get_destination()));
            let (src_port, dst_port, status) = self.parse_transport_packet(
                self.src_ip.unwrap(),
                self.dst_ip.unwrap(),
                ip.get_next_header(),
                ip.payload(),
            );
            self.src_port = src_port;
            self.dst_port = dst_port;
            status
        } else {
            log::debug!("Malformed IPv6 Packet");
            -1
        }
    }

    fn parse_transport_packet(
        &self,
        source: IpAddr,
        destination: IpAddr,
        protocol: IpNextHeaderProtocol,
        packet: &[u8],
    ) -> (Option<u16>, Option<u16>, i32) {
        let ret = match protocol {
            IpNextHeaderProtocols::Udp => self.parse_udp_packet(packet),
            IpNextHeaderProtocols::Tcp => self.parse_tcp_packet(packet),
            _ => {
                log::debug!(
                    "Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                    match source {
                        IpAddr::V4(..) => "IPv4",
                        _ => "IPv6",
                    },
                    source,
                    destination,
                    protocol,
                    packet.len()
                );
                (None, None, -1)
            }
        };
        ret
    }

    fn parse_udp_packet(&self, packet: &[u8]) -> (Option<u16>, Option<u16>, i32) {
        let udp = UdpPacket::new(packet);
        let ret = if let Some(udp) = udp {
            (Some(udp.get_source()), Some(udp.get_destination()), 0)
        } else {
            log::debug!("Malformed UDP Packet");
            (None, None, -1)
        };
        ret
    }

    fn parse_tcp_packet(&self, packet: &[u8]) -> (Option<u16>, Option<u16>, i32) {
        let tcp = TcpPacket::new(packet);
        let ret = if let Some(tcp) = tcp {
            (Some(tcp.get_source()), Some(tcp.get_destination()), 0)
        } else {
            log::debug!("Malformed TCP Packet");
            (None, None, -1)
        };
        ret
    }

    pub fn swap_mac_addresses_eth(&mut self, pnet_swap: bool) {
        // Swap src and dst mac address.
        if pnet_swap {
            let src = self.eth_packet.get_source();
            let dst = self.eth_packet.get_destination();
            self.eth_packet.set_source(dst);
            self.eth_packet.set_destination(src);
        } else {
            let mac_addr_len = 6;
            let mut p = self.eth_packet.packet_mut();
            // Get src and dst mac address.
            p = &mut p[0..mac_addr_len * 2];
            let (left, right) = p.split_at_mut(mac_addr_len);
            // Swap src and dst mac address.
            left.swap_with_slice(&mut right[0..left.len()]);
        }
    }

    pub fn swap_ip_addresses(&mut self, pnet_swap: bool) {
        // Swap source and dst UDP port.
        match self.eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.swap_ipv4_addresses(pnet_swap);
            }
            EtherTypes::Ipv6 => {
                self.swap_ipv6_addresses(pnet_swap);
            }
            _ => log::debug!("Malformed IP Packet"),
        }
    }
    pub fn swap_ipv4_addresses(&mut self, pnet_swap: bool) {
        // Swap source and dst IP address.
        let ip = MutableIpv4Packet::new(self.eth_packet.payload_mut());
        if let Some(mut ip) = ip {
            if pnet_swap {
                let src = ip.get_source();
                let dst = ip.get_destination();
                ip.set_source(dst);
                ip.set_destination(src);
            } else {
                // src ipv4: ip_packet[12-15], dst ipv4: ip_packet[16-19]
                let ipv4_addr_len = 4;
                let ipv4_offset = 12;
                // Get src and dst ipv4 address.
                let p = &mut ip.packet_mut()[ipv4_offset..(ipv4_offset + ipv4_addr_len * 2)];
                let (left, right) = p.split_at_mut(ipv4_addr_len);
                // Swap src and dst ipv4 address.
                left.swap_with_slice(&mut right[0..left.len()]);
            }
        }
    }

    pub fn swap_ipv6_addresses(&mut self, pnet_swap: bool) {
        // Swap source and dst IP address.
        let ip = MutableIpv6Packet::new(self.eth_packet.payload_mut());
        if let Some(mut ip) = ip {
            if pnet_swap {
                let src = ip.get_source();
                let dst = ip.get_destination();
                ip.set_source(dst);
                ip.set_destination(src);
            } else {
                // src ipv6: ip_packet[8-23], dst ipv6: ip_packet[24-39]
                let ipv6_addr_len = 16;
                let ipv6_offset = 8;
                // Get src and dst ipv6 address.
                let p = &mut ip.packet_mut()[ipv6_offset..(ipv6_offset + ipv6_addr_len * 2)];
                let (left, right) = p.split_at_mut(ipv6_offset);
                // Swap src and dst ipv6 address.
                left.swap_with_slice(&mut right[0..left.len()]);
            }
        }
    }

    pub fn swap_ports(&mut self, pnet_swap: bool) {
        // Swap source and dst UDP port.
        match self.eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip = MutableIpv4Packet::new(self.eth_packet.payload_mut());
                if let Some(mut ip) = ip {
                    let protocol = ip.get_next_level_protocol();
                    swap_transport_ports(protocol, ip.payload_mut(), pnet_swap);
                }
            }
            EtherTypes::Ipv6 => {
                let ip = MutableIpv6Packet::new(self.eth_packet.payload_mut());
                if let Some(mut ip) = ip {
                    let protocol = ip.get_next_header();
                    swap_transport_ports(protocol, ip.payload_mut(), pnet_swap);
                }
            }
            _ => log::debug!("Malformed IP Packet"),
        }

        fn swap_transport_ports(
            protocol: IpNextHeaderProtocol,
            payload: &mut [u8],
            pnet_swap: bool,
        ) {
            match protocol {
                IpNextHeaderProtocols::Udp => {
                    let udp = MutableUdpPacket::new(payload);
                    swap_udp_ports(udp, pnet_swap);
                }
                IpNextHeaderProtocols::Tcp => {
                    let tcp = MutableTcpPacket::new(payload);
                    swap_tcp_ports(tcp, pnet_swap);
                }
                _ => {
                    log::debug!("Unknown protocol: {}", protocol);
                }
            }
        }

        fn swap_udp_ports(udp: Option<MutableUdpPacket>, pnet_swap: bool) {
            if let Some(mut udp) = udp {
                if pnet_swap {
                    let tmp = udp.get_source();
                    let dst = udp.get_destination();
                    udp.set_source(dst);
                    udp.set_destination(tmp);
                } else {
                    // src port: packet[0-1], dst port: packet[2-3]
                    let port_len = 2;
                    // Get src and dst port.
                    let p = &mut udp.packet_mut()[0..port_len * 2];
                    let (left, right) = p.split_at_mut(port_len);
                    // Swap src and dst port.
                    left.swap_with_slice(&mut right[0..left.len()]);
                }
            }
        }

        fn swap_tcp_ports(tcp: Option<MutableTcpPacket>, pnet_swap: bool) {
            if let Some(mut tcp) = tcp {
                if pnet_swap {
                    let tmp = tcp.get_source();
                    let dst = tcp.get_destination();
                    tcp.set_source(dst);
                    tcp.set_destination(tmp);
                } else {
                    // src port: packet[0-1], dst port: packet[2-3]
                    let port_len = 2;
                    // Get src and dst port.
                    let p = &mut tcp.packet_mut()[0..port_len * 2];
                    let (left, right) = p.split_at_mut(port_len);
                    // Swap src and dst port.
                    left.swap_with_slice(&mut right[0..left.len()]);
                }
            }
        }
    }

    pub fn set_udp_payload(&mut self, payload: &[u8]) {
        let ip = MutableIpv4Packet::new(self.eth_packet.payload_mut());
        if let Some(mut ip) = ip {
            let udp = MutableUdpPacket::new(ip.payload_mut());
            if let Some(mut udp) = udp {
                udp.set_payload(payload);
            }
        }
    }

    pub fn get_udp_payload_ptr(&mut self) -> (Option<*mut u8>, usize) {
        let ip = MutableIpv4Packet::new(self.eth_packet.payload_mut());
        if let Some(mut ip) = ip {
            let udp = MutableUdpPacket::new(ip.payload_mut());
            if let Some(mut udp) = udp {
                let payload = udp.payload_mut();
                return (Some(payload.as_mut_ptr()), payload.len());
            }
        }
        (None, 0)
    }

    pub fn get_udp_payload(&self, buf: &mut [u8]) -> usize {
        let ip = Ipv4Packet::new(self.eth_packet.payload());
        let mut payload_len = 0;
        if let Some(ip) = ip {
            let udp = UdpPacket::new(ip.payload());
            if let Some(udp) = udp {
                let payload = udp.payload();
                payload_len = payload.len();
                buf[..payload_len as usize].copy_from_slice(&payload[..]);
            }
        }
        payload_len
    }

    pub fn update_eth_udp_packet(
        &mut self,
        src_mac: MacAddr,
        dst_mac: MacAddr,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        transport_payload: &[u8],
    ) {
        self.eth_packet.set_source(src_mac);
        self.eth_packet.set_destination(dst_mac);
        match src_ip {
            IpAddr::V4(_) => {
                self.eth_packet.set_ethertype(EtherTypes::Ipv4);
                Self::update_udp_packet(
                    self.eth_packet.payload_mut(),
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    transport_payload,
                );
            }
            IpAddr::V6(_) => {
                panic!("Ipv6 Unsupported")
            }
        }
    }

    pub fn update_udp_packet(
        packet: &mut [u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        transport_payload: &[u8],
    ) -> u16 {
        let mut ip_header =
            Self::update_ipv4_header(packet, src_ip, dst_ip, transport_payload.len());
        let source = ip_header.get_source();
        let destination = ip_header.get_destination();
        let mut udp_header = Self::update_udp_header(
            ip_header.payload_mut(),
            src_port,
            dst_port,
            transport_payload.len(),
        );
        udp_header.set_payload(transport_payload);
        let checksum = udp::ipv4_checksum(&udp_header.to_immutable(), &source, &destination);
        udp_header.set_checksum(checksum);
        ip_header.get_total_length()
    }

    pub fn get_eth_udp_packet_len(udp_payload_len: usize) -> usize {
        let total_len = MutableEthernetPacket::minimum_packet_size()
            + CndpPacket::IPV4_HEADER_LEN
            + CndpPacket::UDP_HEADER_LEN
            + udp_payload_len;
        total_len
    }

    fn update_ipv4_header(
        packet: &mut [u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp_payload_len: usize,
    ) -> MutableIpv4Packet {
        let mut ip_header = MutableIpv4Packet::new(packet).unwrap();
        let total_len =
            (CndpPacket::IPV4_HEADER_LEN + CndpPacket::UDP_HEADER_LEN + udp_payload_len) as u16;
        ip_header.set_version(4);
        ip_header.set_header_length((CndpPacket::IPV4_HEADER_LEN / 4) as u8);
        ip_header.set_total_length(total_len);
        ip_header.set_ttl(100);
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        if let IpAddr::V4(src_ip) = src_ip {
            ip_header.set_source(src_ip);
        }
        if let IpAddr::V4(dst_ip) = dst_ip {
            ip_header.set_destination(dst_ip);
        }
        let checksum = ipv4::checksum(&ip_header.to_immutable());
        ip_header.set_checksum(checksum);
        ip_header
    }

    fn update_udp_header(
        packet: &mut [u8],
        src_port: u16,
        dst_port: u16,
        udp_payload_len: usize,
    ) -> MutableUdpPacket {
        let mut udp_header = MutableUdpPacket::new(packet).unwrap();
        udp_header.set_source(src_port);
        udp_header.set_destination(dst_port);
        udp_header.set_length((CndpPacket::UDP_HEADER_LEN + udp_payload_len) as u16);
        udp_header
    }

    pub fn get_network_interface(iface_name: &str) -> Option<NetworkInterface> {
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == iface_name);
        interface
    }

    pub fn get_ipv4_interface_address(interface: &NetworkInterface) -> Option<Ipv4Addr> {
        let source_ip = interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| match ip.ip() {
                IpAddr::V4(ip) => ip,
                _ => unreachable!(),
            });
        source_ip
    }

    pub fn get_ip_addr_from_ifname(iface_name: &str) -> Option<IpAddr> {
        let addr = Self::get_network_interface(iface_name)
            .map_or_else(
                || None,
                |interface| Self::get_ipv4_interface_address(&interface),
            )
            .map(|ipv4| IpAddr::V4(ipv4));
        addr
    }

    pub fn get_mac_through_arp(iface_name: &str, target_ip: Ipv4Addr) -> (MacAddr, MacAddr) {
        let interface = Self::get_network_interface(iface_name).unwrap();
        let source_mac = interface.mac.unwrap();
        let source_ip = Self::get_ipv4_interface_address(&interface).unwrap();
        let (mut sender, mut receiver) = match channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error {}", e),
        };
        let mut ethernet_buffer = [0u8; 42];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(target_ip);
        ethernet_packet.set_payload(arp_packet.packet_mut());
        sender
            .send_to(ethernet_packet.packet(), None)
            .unwrap()
            .unwrap();
        log::debug!("Sent ARP request");
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        log::debug!("Received ARP reply");
        (source_mac, arp.get_sender_hw_addr())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cndp_eth_packet() {
        // Create UDP payload.
        let udp_payload_size = 50;
        let udp_payload = vec![0xAA; udp_payload_size];
        // Fill some data for mac address, Ip address and port.
        let src_mac = MacAddr(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let dst_mac = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let src_ip = IpAddr::V4(Ipv4Addr::new(48, 0, 0, 154));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(48, 0, 0, 155));
        let src_port = 5400;
        let dst_port = 5500;
        // Get total length of ethernet packet based on udp payload.
        let data_len = CndpPacket::get_eth_udp_packet_len(udp_payload_size as usize);
        // Create Ethernet/IP/UDP Packet.
        let mut buf: Vec<u8> = vec![0; data_len];
        let mut cndp_eth_packet = CndpPacket::new(buf.as_mut_ptr(), buf.len()).unwrap();
        // Update CNDP UDP packet.
        cndp_eth_packet.update_eth_udp_packet(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            &udp_payload[..],
        );
        // Parse the ethernet packet and verify the data.
        let ret = cndp_eth_packet.parse_eth_udp_packet();
        // Check if parsing succeeds.
        assert_eq!(ret, 0);
        // Check src, dst mac.
        assert_eq!(cndp_eth_packet.src_mac, Some(src_mac));
        assert_eq!(cndp_eth_packet.dst_mac, Some(dst_mac));
        // Check src, dst ip.
        assert_eq!(cndp_eth_packet.src_ip, Some(src_ip));
        assert_eq!(cndp_eth_packet.dst_ip, Some(dst_ip));
        // Check src, dst port.
        assert_eq!(cndp_eth_packet.src_port, Some(src_port));
        assert_eq!(cndp_eth_packet.dst_port, Some(dst_port));
        // Create UDP payload read buffer.
        let max_payload_size = 1400;
        let mut udp_payload_parsed: Vec<u8> = vec![0; max_payload_size];
        // Get UDP payload.
        let payload_len = cndp_eth_packet.get_udp_payload(&mut udp_payload_parsed[..]);
        // Check parsed payload size is same as original payload size.
        assert_eq!(payload_len as usize, udp_payload_size as usize);
        // Compare contents of parsed payload with original payload.
        udp_payload_parsed.truncate(payload_len as usize);
        let match_buf_count = udp_payload
            .iter()
            .zip(udp_payload_parsed.iter())
            .filter(|&(a, b)| a == b)
            .count();
        let res = match_buf_count == udp_payload.len() && match_buf_count == udp_payload_parsed.len();
        assert_eq!(res, true);
    }
}
