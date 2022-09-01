/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 * Copyright (c) 2022 Canopus Networks.
 */

package cne

import (
	"reflect"
	"testing"
)

var lcoreInfoMarshalTests = []struct {
	cores LCoreInfo
	str   string
}{
	{LCoreInfo{}, `[]`},
	{LCoreInfo{3}, `[3]`},
	{LCoreInfo{4, 5, 6}, `["4-6"]`},
	{LCoreInfo{1, 4, 7}, `[1,4,7]`},
	{LCoreInfo{1, 7, 4}, `[1,4,7]`},
	{LCoreInfo{1, 7, 4, 1, 1, 4}, `[1,4,7]`},
	{LCoreInfo{4, 5, 6, 9}, `["4-6",9]`},
}

var lcoreInfoUnmarshalTests = []struct {
	str   string
	cores LCoreInfo
}{
	{`[]`, LCoreInfo{}},
	{` [  ]  `, LCoreInfo{}},
	{` [ "3" ] `, LCoreInfo{3}},
	{`[4,5,6]`, LCoreInfo{4, 5, 6}},
	{`["4-6"]`, LCoreInfo{4, 5, 6}},
	{`[1,4,7]`, LCoreInfo{1, 4, 7}},
	{` [ 1, 4 , 7] `, LCoreInfo{1, 4, 7}},
	{` [ 4, 7, 7, 9,4] `, LCoreInfo{4, 7, 9}},
}

func TestLCoreInfo(t *testing.T) {
	t.Run("MarshalJSON", func(t *testing.T) {
		for _, ct := range lcoreInfoMarshalTests {
			str, err := ct.cores.MarshalJSON()
			if err != nil {
				t.Errorf("LCoreInfo.MarshalJSON(%v) error: %s", ct.cores, err.Error())
			} else if string(str) != ct.str {
				t.Errorf("LCoreInfo.MarshalJSON(%v) failed: want '%s' got '%s'", ct.cores, ct.str, string(str))
			}
		}
	})
	t.Run("UnmarshalJSON", func(t *testing.T) {
		for _, ct := range lcoreInfoUnmarshalTests {
			var cores LCoreInfo
			err := cores.UnmarshalJSON([]byte(ct.str))

			if err != nil {
				t.Errorf("LCoreInfo.UnmarshalJSON(%s) error: %s", ct.str, err.Error())
			} else if !reflect.DeepEqual(cores, ct.cores) {
				t.Errorf("LCoreInfo.UnmarshalJSON(%s) failed: want '%v' got '%v'", ct.str, ct.cores, cores)
			}
		}
	})
}
