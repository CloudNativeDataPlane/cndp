/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

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
