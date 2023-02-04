/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation.
 */

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::str::Utf8Error;

pub fn get_cstring_from_str(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[allow(dead_code)]
pub fn get_str_from_raw_ptr<'a>(s_raw: *mut i8) -> &'a str {
    let s_cstr: &CStr = unsafe { CStr::from_ptr(s_raw) };
    let s_str = s_cstr.to_str().unwrap();
    s_str
}

#[allow(dead_code)]
pub fn get_item_at_index<T>(index: u16, item_pptr: *mut *mut T) -> Option<*mut T> {
    if item_pptr.is_null() {
        return None;
    }
    let item = unsafe { *item_pptr.offset(index as isize) };
    Some(item)
}

pub fn copy_string_to_c_array(s: &str, c_arr: &mut [c_char]) {
    for (dest, src) in c_arr.iter_mut().zip(s.bytes().into_iter()) {
        *dest = src as _;
    }
}

#[allow(dead_code)]
pub fn get_string_from_c_array(c_arr: &[c_char]) -> Result<String, Utf8Error> {
    let c_str: &CStr = unsafe { CStr::from_ptr(c_arr.as_ptr()) };
    let ret = c_str.to_str().map(String::from);
    ret
}
