/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2025 Intel Corporation.
 */

package cne

/*
#cgo CFLAGS: -I../../../../usr/local/include/cndp
#cgo LDFLAGS: -L../../../../usr/local/lib/x86_64-linux-gnu -Wl,--whole-archive -lcndp_pmds -Wl,--no-whole-archive -lcndp -lbsd
*/
import "C"
