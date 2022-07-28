/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use spin::{Mutex, MutexGuard};
use std::sync::Arc;

use super::error::*;
use super::packet::*;
use super::port::*;

/// CNE Buffered Tx Port.
#[derive(Clone)]
pub struct BufferedTxPort {
    port: Port,
    buffer_size: usize,
    pkts: Arc<Mutex<Vec<Packet>>>,
}

impl BufferedTxPort {
    /// Creates an instance of [BufferedTxPort] from an existing (port)[Port].
    ///
    /// This function takes an existing port and returns an instance of BufferedTxPort.
    /// this port. Buffered TX port allows to buffer one packet at a time and transmits
    /// the packets once buffer is full.
    ///
    /// Returns an instance of BufferedTxPort.
    ///
    /// # Arguments
    /// * `port` - An existing port.
    /// * `buffer_size` - Number of packets that can be buffered in port.
    ///
    pub fn new(port: Port, buffer_size: usize) -> BufferedTxPort {
        BufferedTxPort {
            port,
            buffer_size,
            pkts: Arc::new(Mutex::new(Vec::with_capacity(buffer_size))),
        }
    }

    /// Buffers a single [packet](Packet) for future transmission.
    ///
    /// This function takes a single packet and buffers it for future transmission on
    /// this port. Once the buffer is full, an attempt will be made to transmit all the
    /// buffered packets. This function transparently frees the packet after it is sent.
    ///
    /// Returns number of packets actually sent if buffer is full or 0 if packet is buffered.
    ///
    /// # Arguments
    /// * `pkt` - packet to be buffered.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortTxBuffError] if an error is encountered.
    ///
    pub fn tx_buff_add(&self, pkt: Packet) -> Result<u16, CneError> {
        let mut pkts = self.lock()?;
        pkts.push(pkt);

        if pkts.len() < self.buffer_size {
            Ok(0)
        } else {
            Self::flush(&self.port, &mut pkts)
        }
    }

    /// Get number of packets buffered.
    ///
    /// Returns number of packets buffered in this port or error.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortTxBuffError] if an error is encountered.
    ///
    pub fn tx_buff_count(&self) -> Result<u16, CneError> {
        let pkts = self.lock()?;
        Ok(pkts.len() as u16)
    }

    /// Flush all the packets buffered on this port for transmission.
    ///
    /// This function sends all the packets buffered on this port for
    /// transmission. It transparently frees the packet in the buffer.
    ///
    /// Returns number of packets actually sent or error.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortTxBuffError] if an error is encountered.
    ///
    pub fn tx_buff_flush(&self) -> Result<u16, CneError> {
        let mut pkts = self.lock()?;
        Self::flush(&self.port, &mut pkts)
    }

    /// Free all packets buffered in the port.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortTxBuffError] if an error is encountered.
    ///
    pub fn tx_buff_free(&self) -> Result<(), CneError> {
        let mut pkts = self.lock()?;
        if !pkts.is_empty() {
            Packet::free_packet_buffer(&mut pkts)
                .map_err(|e| CneError::PortTxBuffError(e.to_string()))?;
            pkts.clear();
        }
        Ok(())
    }

    /// Get port index of the [port](BufferedTxPort).
    ///
    /// Returns port index in lports section of JSONC file or error.
    ///
    /// # Errors
    ///
    /// Returns [CneError::PortTxBuffError] if an error is encountered.
    ///
    pub fn tx_buff_port_index(&self) -> Result<u16, CneError> {
        self.port
            .get_port_index()
            .map_err(|e| CneError::PortTxBuffError(e.to_string()))
    }
}

// BufferedTxPort private functions.
impl BufferedTxPort {
    fn flush(port: &Port, pkts: &mut Vec<Packet>) -> Result<u16, CneError> {
        if !pkts.is_empty() {
            let pkts_sent = port
                .tx_burst(pkts)
                .map_err(|e| CneError::PortTxBuffError(e.to_string()))?;
            // Free packets which are not sent.
            Packet::free_packet_buffer(&mut pkts[pkts_sent as usize..])
                .map_err(|e| CneError::PortTxBuffError(e.to_string()))?;
            pkts.clear();
            Ok(pkts_sent)
        } else {
            Ok(0)
        }
    }

    fn lock(&self) -> Result<MutexGuard<Vec<Packet>>, CneError> {
        Ok(self.pkts.lock())
    }
}
