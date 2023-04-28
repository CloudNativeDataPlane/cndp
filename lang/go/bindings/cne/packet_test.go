/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2023 Intel Corporation.
 */

package cne

import (
	"log"
	"testing"
	"encoding/binary"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func int2ip(nn uint32) net.IP {
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, nn)

    return ip
}

func createUdpPacket() *Packet{

	log.Println("Create UDP Packet")
	udpPkt := make([]*Packet, 2)
    for _, lport := range cneSys.LPortList() {

        //rxPackets := make([]*Packet, 256)

        size := PktBufferAlloc(lport.LPortID(), udpPkt)
        //size := RxBurst(lport.LPortID(), rxPackets)
        if size <= 0 {
            log.Println("PktBufferAlloc failed")
            return nil
        }
    }
    //size := PktBufferAlloc(1, udpPkt)
    //if size <= 0 {
	//    log.Println("PktBufferAlloc failed")
    //    return nil
    //}

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	buffer := gopacket.NewSerializeBuffer()
	ipLayer := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    int2ip(168427777),
		DstIP:    int2ip(168427778),
		Protocol: layers.IPProtocolUDP,
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC:       net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		EthernetType: layers.EthernetTypeIPv4,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(2152),
		DstPort: layers.UDPPort(2152),
	}

    err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Println("set checksum for UDP layer in endmarker failed")
		return nil
	}

	// And create the packet with the layers
	err = gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
	)

	if err == nil {
		outgoingPacket := buffer.Bytes()
        if WritePktData(udpPkt[0], 0, outgoingPacket) < 0 {
	        log.Println("WritePktData failed")
            return  nil
        }
        return udpPkt[0]
	} else {
		log.Println("go packet serialize failed : ", err)
	}

    return nil
}

func TestGetEtherHdr(t *testing.T) {

    t.Run("TestEtherHdrNull", func(t *testing.T) {
       ethHdr := GetEtherHdr(nil)
       if ethHdr != nil {
           t.Fatalf("Error getting EthHdr")
       }
    })
    t.Run("TestEtherHdrSuccess", func(t *testing.T) {
       pkt := createUdpPacket()
       if pkt != nil {
           ethHdr := GetEtherHdr(pkt)
           if ethHdr == nil {
               t.Fatalf("Error getting EthHdr")
           }
       }
    })
}

