/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

extern crate mmap_cndp;
use mmap_cndp::mmap_t;

#[derive(Debug)]
pub struct Mmap {
	cookie: mmap_t;
}

impl Drop for Mmap {
	fn mmap_free(&mut self) {
		unsafe {
			mmap_cndp::mmap_free(self.cookie);
		}
	}
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
