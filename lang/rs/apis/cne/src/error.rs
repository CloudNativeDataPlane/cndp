/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;

/// Type for different errors that can be encountered.
/// String provides description of the error.
#[derive(Debug)]
pub enum CneError {
    /// Error allocating buffer in underlying Packet.
    BufferAllocError(String),
    /// Error configuring CNE instance.
    ConfigError(String),
    /// Packet error.
    PacketError(String),
    /// Port error.
    PortError(String),
    /// Buffered Tx Port error.
    PortTxBuffError(String),
    /// Error getting port statistics.
    PortStatsError(String),
    /// Error registering/unregistering thread with CNE.
    RegisterError(String),
    /// Error receiving packets.
    RxBurstError(String),
    /// Error transmitting packets.
    TxBurstError(String),
}

impl Display for CneError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let s = match self {
            CneError::BufferAllocError(s) => format!("CneError::BufferAllocError({})", s),
            CneError::ConfigError(s) => format!("CneError::ConfigError({})", s),
            CneError::PacketError(s) => format!("CneError::PacketError({})", s),
            CneError::PortError(s) => format!("CneError::PortError({})", s),
            CneError::PortTxBuffError(s) => format!("CneError::PortTxBuffError({})", s),
            CneError::PortStatsError(s) => format!("CneError::PortStatsError({})", s),
            CneError::RegisterError(s) => format!("CneError::RegisterError({})", s),
            CneError::RxBurstError(s) => format!("CneError::RxBurstError({})", s),
            CneError::TxBurstError(s) => format!("CneError::TxBurstError({})", s),
        };
        write!(f, "{}", s)
    }
}
