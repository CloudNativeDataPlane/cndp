/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

package cne

/*
#cgo CFLAGS: -I${SRCDIR}/../../../../usr/local/include/cndp
#cgo LDFLAGS: -L${SRCDIR}/../../../../usr/local/lib/x86_64-linux-gnu -lcndp

#include <cne_common.h>
#include <msgchan.h>
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

type MsgChannel struct {
	name  string
	mChan unsafe.Pointer
}

type MsgChannelInfo struct {
	RecvRing     unsafe.Pointer
	SendRing     unsafe.Pointer
	ChildCount   int
	SendCalls    uint64
	SendCnt      uint64
	RecvCalls    uint64
	RecvCnt      uint64
	RecvTimeouts uint64
}

var msgChannel map[string]*MsgChannel
var msgChanMu sync.Mutex

func init() {
	msgChannel = make(map[string]*MsgChannel)
}

func NewMsgChannel(name string, sz uint) (*MsgChannel, error) {
	msgChanMu.Lock()
	defer msgChanMu.Unlock()

	mc := &MsgChannel{name: name}

	cStr := C.CString(name)
	defer C.free(unsafe.Pointer(cStr))

	mc.mChan = C.mc_create(cStr, C.int(sz), C.uint(0))
	if mc.mChan == nil {
		return nil, fmt.Errorf("unable to create message channel")
	}
	msgChannel[name] = mc

	return mc, nil
}

func (mc *MsgChannel) Close() error {
	msgChanMu.Lock()
	defer msgChanMu.Unlock()

	if mc == nil {
		return fmt.Errorf("MsgChannel is nil")
	}
	C.mc_destroy(mc.mChan)
	delete(msgChannel, mc.name)

	return nil
}

func (mc *MsgChannel) Name() string {
	if mc == nil {
		return ""
	}
	return mc.name
}

func (mc *MsgChannel) Send(objs []uintptr) int {

	cObjs := (*unsafe.Pointer)(unsafe.Pointer(&objs[0]))

	cnt := C.mc_send(mc.mChan, cObjs, C.int(len(objs)))

	return int(cnt)
}

func (mc *MsgChannel) Recv(objs []uintptr, timo uint64) int {

	cObjs := (*unsafe.Pointer)(unsafe.Pointer(&objs[0]))

	cnt := C.mc_recv(mc.mChan, cObjs, C.int(len(objs)), C.ulong(timo))

	return int(cnt)
}

func (mc *MsgChannel) Lookup(name string) *MsgChannel {
	msgChanMu.Lock()
	defer msgChanMu.Unlock()

	if m, ok := msgChannel[name]; ok {
		return m
	}

	return nil
}

func (mc *MsgChannel) Size() int {

	return int(C.mc_size(mc.mChan, nil, nil))
}

func (mc *MsgChannel) RecvFree() int {

	var rcvFree C.int

	if C.mc_size(mc.mChan, &rcvFree, nil) == -1 {
		return -1
	}

	return int(rcvFree)
}

func (mc *MsgChannel) SendFree() int {

	var sndFree C.int

	if C.mc_size(mc.mChan, nil, &sndFree) == -1 {
		return -1
	}

	return int(sndFree)
}

func (mc *MsgChannel) Info() *MsgChannelInfo {
	var mcInfo C.msgchan_info_t

	if mc == nil {
		return nil
	}
	if C.mc_info(mc.mChan, &mcInfo) == -1 {
		return nil
	}

	info := &MsgChannelInfo{
		RecvRing:     mcInfo.recv_ring,
		SendRing:     mcInfo.send_ring,
		ChildCount:   int(mcInfo.child_count),
		SendCalls:    uint64(mcInfo.send_calls),
		SendCnt:      uint64(mcInfo.send_cnt),
		RecvCalls:    uint64(mcInfo.recv_calls),
		RecvCnt:      uint64(mcInfo.recv_cnt),
		RecvTimeouts: uint64(mcInfo.recv_timeouts),
	}

	return info
}

func (mc *MsgChannel) Pointers() (recv unsafe.Pointer, send unsafe.Pointer) {
	if mc == nil {
		return nil, nil
	}

	info := mc.Info()
	if info == nil {
		return nil, nil
	}

	recv, send = info.RecvRing, info.SendRing

	return
}
