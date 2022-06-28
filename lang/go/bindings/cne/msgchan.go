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

// MsgChannel is the structure to hold information about the MsgChan
type MsgChannel struct {
	name  string         // Name of the channel
	mChan unsafe.Pointer // MsgChannel internal pointer
}

// MsgChannelInfo is the structure to hold information about a MsgChannel
type MsgChannelInfo struct {
	RecvRing     unsafe.Pointer // RecvRing pointer
	SendRing     unsafe.Pointer // SendRing pointer
	ChildCount   int            // Number of children attached to this msgChan
	SendCalls    uint64         // Number of calls to send routine
	SendCnt      uint64         // Number of items sent in send routine
	RecvCalls    uint64         // Number of calls to recv routine
	RecvCnt      uint64         // Number of items received in recv routine
	RecvTimeouts uint64         // Number of timeouts the receive routine had
}

var msgChannel map[string]*MsgChannel
var msgChanMu sync.Mutex

func init() {
	msgChannel = make(map[string]*MsgChannel)
}

// NewMsgChannel creates a new MsgChannel object with the given name and size
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

// Close the MsgChannel and release the resources
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

// Name for the message channel
// Returns the message channel string or empty if error
func (mc *MsgChannel) Name() string {

	if mc == nil {
		return ""
	}
	return mc.name
}

// Send object values on the msgChan
// Returns the number of objects sent
func (mc *MsgChannel) Send(objs []uintptr) int {

	var cnt int = 0

	if mc != nil {
		cObjs := (*unsafe.Pointer)(unsafe.Pointer(&objs[0]))

		cnt = int(C.mc_send(mc.mChan, cObjs, C.int(len(objs))))
	}

	return cnt
}

// Recv objs from the msgChan
func (mc *MsgChannel) Recv(objs []uintptr, timo uint64) int {

	var cnt int = 0

	if mc != nil {
		cObjs := (*unsafe.Pointer)(unsafe.Pointer(&objs[0]))

		cnt = int(C.mc_recv(mc.mChan, cObjs, C.int(len(objs)), C.ulong(timo)))
	}

	return cnt
}

// Lookup a msgchan by name and return MsgChannel pointer
func (mc *MsgChannel) Lookup(name string) *MsgChannel {

	msgChanMu.Lock()
	defer msgChanMu.Unlock()

	if m, ok := msgChannel[name]; ok {
		return m
	}

	return nil
}

// Size of the message channel structure and rings
func (mc *MsgChannel) Size() int {

	if mc == nil {
		return 0
	}
	return int(C.mc_size(mc.mChan, nil, nil))
}

// RecvFree is the number of free entries in the receive ring
// Return number of free entries or -1 on error
func (mc *MsgChannel) RecvFree() int {

	if mc != nil {
		var rcvFree C.int

		if C.mc_size(mc.mChan, &rcvFree, nil) == -1 {
			return -1
		}
		return int(rcvFree)
	}
	return -1
}

// SendFree is the number of free entries in the send ring
// Return number of free entries or -1 on error
func (mc *MsgChannel) SendFree() int {

	if mc != nil {
		var sndFree C.int

		if C.mc_size(mc.mChan, nil, &sndFree) == -1 {
			return -1
		}
		return int(sndFree)
	}
	return -1
}

// Info returns the msgchan information structure
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

// Pointers returns the recv and send ring pointers or nil on error
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
