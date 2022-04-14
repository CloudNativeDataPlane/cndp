/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

use std::ffi::CStr;
use std::ffi::CString;

pub fn get_cstring_from_str(s: &str) -> CString {
    let cstring = CString::new(s).unwrap();
    return cstring;
}

pub fn get_str_from_raw_ptr<'a>(s_raw: *mut i8) -> &'a str {
    let s_cstr: &CStr = unsafe { CStr::from_ptr(s_raw) };
    let s_str = s_cstr.to_str().unwrap();
    return s_str;
}

#[allow(dead_code)]
pub fn get_rust_arg_from_cvoid_ptr<'a, T>(cvoid_arg: *mut libc::c_void) -> Option<&'a mut T> {
    if cvoid_arg.is_null() {
        return None;
    }
    let rust_arg = unsafe { &mut *(cvoid_arg as *mut T) };
    return Some(rust_arg);
}

#[allow(dead_code)]
pub fn get_rust_arg_from_cvoid_double_ptr<'a, T>(
    cvoid_arg: *mut *mut libc::c_void,
) -> Option<&'a mut *mut T> {
    if cvoid_arg.is_null() {
        return None;
    }
    let rust_arg = unsafe { &mut *(cvoid_arg as *mut *mut T) };
    return Some(rust_arg);
}
