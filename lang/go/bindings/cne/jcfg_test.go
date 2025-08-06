/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022-2025 Intel Corporation.
 * Copyright (c) 2022 Canopus Networks.
 */

package cne

import (
	"fmt"
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
	noErr bool
}{
	{``, nil, false},
	{`{1,2}`, nil, false},
	{`["-1"]`, nil, false},
	{`[]`, LCoreInfo{}, true},
	{` [  ]  `, LCoreInfo{}, true},
	{` [ "3" ] `, LCoreInfo{3}, true},
	{`[4,5,6]`, LCoreInfo{4, 5, 6}, true},
	{`["4-6"]`, LCoreInfo{4, 5, 6}, true},
	{`["4-6-9"]`, nil, false},
	{`["4-n"]`, nil, false},
	{`["n-6"]`, nil, false},
	{`["6-4"]`, nil, false},
	{`["4-4"]`, LCoreInfo{4}, true},
	{`[1,4,7]`, LCoreInfo{1, 4, 7}, true},
	{` [ 1, 4 , 7] `, LCoreInfo{1, 4, 7}, true},
	{` [ 4, 7, 7, 9,4] `, LCoreInfo{4, 7, 9}, true},
}

var validateRegionsTests = []struct {
	jcfg *Config
	err  string
}{
	{
		&Config{
			UmemInfoMap: map[string]*UmemInfo{},
		},
		"",
	},
	{
		&Config{
			UmemInfoMap: map[string]*UmemInfo{
				"umem1": {Regions: []uint{1, 2}},
				"umem2": {Regions: []uint{3}},
			},
		},
		"",
	},
	{
		&Config{
			UmemInfoMap: map[string]*UmemInfo{
				"umem1": {Regions: make([]uint, UmemMaxRegions)},
			},
		},
		fmt.Sprintf("invalid number of regions %d with umem umem1", UmemMaxRegions),
	},
}

var validateLCoreGroupsTests = []struct {
	jcfg *Config
	err  string
}{
	{
		&Config{
			LCoreGroupData: map[string]LCoreInfo{
				"group0": {3, 4, 5},
			},
		},
		"",
	},
	{
		&Config{
			LCoreGroupData: map[string]LCoreInfo{
				"group0": {},
			},
		},
		"",
	},
	{
		&Config{
			LCoreGroupData: map[string]LCoreInfo{
				"group0": {-1, 1},
			},
		},
		"core -1 in lcore group group0 is < 0",
	},
}

var validateThreadInfoMapTests = []struct {
	jcfg *Config
	err  string
}{
	{
		&Config{
			ThreadInfoMap: map[string]*ThreadInfo{
				"thread0": {
					Group:  "group0",
					LPorts: []string{"eth0"},
				},
			},
			LCoreGroupData: map[string]LCoreInfo{
				"group0": {3, 4},
			},
			LPortInfoMap: map[string]*LPortInfo{
				"eth0": {},
			},
		},
		"",
	},
	{
		&Config{
			ThreadInfoMap: map[string]*ThreadInfo{
				"thread0": {
					Group:  "group1",
					LPorts: []string{"eth0"},
				},
			},
			LCoreGroupData: map[string]LCoreInfo{
				"group0": {3, 4},
			},
			LPortInfoMap: map[string]*LPortInfo{
				"eth0": {},
			},
		},
		"lcore group group1 for thread thread0 is missing or empty",
	},
	{
		&Config{
			ThreadInfoMap: map[string]*ThreadInfo{
				"thread0": {
					Group:  "group0",
					LPorts: []string{"eth1"},
				},
			},
			LCoreGroupData: map[string]LCoreInfo{
				"group0": {3, 4},
			},
			LPortInfoMap: map[string]*LPortInfo{
				"eth0": {},
			},
		},
		"invalid lport eth1 for thread thread0",
	},
}

var processConfigTests = []struct {
	input  []byte
	expect *Config
	err    string
}{
	{
		[]byte(" "),
		nil,
		"empty json text string",
	},
	{
		[]byte("#{}"),
		nil,
		"string does not appear to be a valid JSON text missing starting '{'",
	},
	{
		[]byte("{\"foo\":null,\"bar\":null"),
		nil,
		"unexpected end of JSON input",
	},
	{
		[]byte("{\"application\":null,\"defaults\":null}"),
		nil,
		"",
	},
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

			if err != nil && ct.noErr {
				t.Errorf("LCoreInfo.UnmarshalJSON(%s) error: %s", ct.str, err.Error())
			} else if !reflect.DeepEqual(cores, ct.cores) {
				t.Errorf("LCoreInfo.UnmarshalJSON(%s) failed: want '%v' got '%v'", ct.str, ct.cores, cores)
			}
		}
	})
}

func TestConfig(t *testing.T) {
	t.Run("validateRegions", func(t *testing.T) {
		for _, ct := range validateRegionsTests {
			err := ct.jcfg.validateRegions()
			if err != nil {
				if err.Error() != ct.err {
					t.Errorf("Config.validateRegions() error: %s", err.Error())
				}
			} else if len(ct.err) != 0 {
				t.Errorf("Config.validateRegions() failed: want '%s'", ct.err)
			}
		}
	})
	t.Run("validateLCoreGroups", func(t *testing.T) {
		for _, ct := range validateLCoreGroupsTests {
			err := ct.jcfg.validateLCoreGroups()
			if err != nil {
				if err.Error() != ct.err {
					t.Errorf("Config.validateLCoreGroups() error: %s", err.Error())
				}
			} else if len(ct.err) != 0 {
				t.Errorf("Config.validateLCoreGroups() failed: want '%s'", ct.err)
			}
		}
	})
	t.Run("validateThreadInfoMap", func(t *testing.T) {
		for _, ct := range validateThreadInfoMapTests {
			err := ct.jcfg.validateThreadInfoMap()
			if err != nil {
				if err.Error() != ct.err {
					t.Errorf("Config.validateThreadInfoMap() error: %s", err.Error())
				}
			} else if len(ct.err) != 0 {
				t.Errorf("Config.validateThreadInfoMap() failed: want '%s'", ct.err)
			}
		}
	})
	t.Run("processConfig", func(t *testing.T) {
		for _, ct := range processConfigTests {
			_, err := processConfig(ct.input)
			if err != nil {
				if err.Error() != ct.err {
					t.Errorf("processConfig(%s) error: %s", string(ct.input), err.Error())
				}
			} else if len(ct.err) != 0 {
				t.Errorf("processConfig(%s) failed: want '%s'", string(ct.input), ct.err)
			}
		}
	})

}
