/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

package distributor

import (
	"context"
	"sync"

	"github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne"
)

type RX struct {
	handle *cne.System
	ctx    context.Context

	lb LoadBalancer
	wg sync.WaitGroup
}

func NewRX(ctx context.Context, handle *cne.System, lb LoadBalancer) *RX {
	rx := &RX{
		ctx:    ctx,
		handle: handle,
		lb:     lb,
	}

	return rx
}

func (rx *RX) receive(thdName string, lportNames []string) {
	lports := rx.handle.LPortsByName(lportNames)
	if len(lports) == 0 {
		return
	}

	err := rx.handle.RegisterThread(thdName)
	if err != nil {
		return
	}
	defer rx.handle.UnregisterThread(thdName)

	packets := make([]*cne.Packet, numPackets)

	var lportIds []int
	for _, lport := range lports {
		lportIds = append(lportIds, lport.LPortID())
	}

	rx.wg.Add(1)
	for {
		for _, pid := range lportIds {
			select {
			case <-rx.ctx.Done():
				rx.wg.Done()
				return
			default:
				size := cne.RxBurst(pid, packets)
				for i := 0; i < size; {
					i += rx.lb.Handle(packets[i])
				}
			}
		}
	}
}

func (rx *RX) Start() {
	thdNamePrefix := "rx"
	for thdName, thd := range rx.handle.JsonCfg().ThreadInfoMap {
		if thdName[:len(thdNamePrefix)] == thdNamePrefix {
			go rx.receive(thdName, thd.LPorts)
		}
	}
}

func (rx *RX) Stop() {
	rx.wg.Wait()
}
