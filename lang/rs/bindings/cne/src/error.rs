/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::Result;

#[derive(Debug)]
pub enum CneError {
    BufferAllocError(String),
    ConfigError(String),
    PortError(String),
    PortStatsError(String),
    RegisterError(String),
    RxBurstError(String),
    TxBurstError(String),
}

impl Display for CneError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let s = match self {
            CneError::BufferAllocError(s) => format!("CneError::BufferAllocError({})", s),
            CneError::ConfigError(s) => format!("CneError::ConfigError({})", s),
            CneError::PortError(s) => format!("CneError::PortError({})", s),
            CneError::PortStatsError(s) => format!("CneError::PortStatsError({})", s),
            CneError::RegisterError(s) => format!("CneError::RegisterError({})", s),
            CneError::RxBurstError(s) => format!("CneError::RxBurstError({})", s),
            CneError::TxBurstError(s) => format!("CneError::TxBurstError({})", s),
        };
        write!(f, "{}", s)
    }
}
