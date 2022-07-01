/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

//! # Low Level Rust Bindings for CNDP.
//!
//! The project provides low-level Rust bindings (crate `cne-sys`) for CNDP CNE C library.
//!
//! This project is hosted on [GitHub](https://github.com/CloudNativeDataPlane/cndp/tree/main/lang/rs/bindings/cne-sys)
//!
//! ## Getting Started
//!
//! Refer [README.md](https://github.com/CloudNativeDataPlane/cndp/blob/main/lang/rs/bindings/cne-sys/README.md)
//!
//! Also see the high-level CNE API crate for CNDP [GitHub](https://github.com/CloudNativeDataPlane/cndp/tree/main/lang/rs/apis/cne)

#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(improper_ctypes)]
pub mod bindings;

#[cfg(test)]
mod tests {
    use super::bindings::cne_init;

    // Simple test case is to check if cne library can be loaded properly and call cne_init.
    #[test]
    fn test_cne_init() {
        let ret = unsafe { cne_init() };
        assert!(ret >= 0)
    }
}
