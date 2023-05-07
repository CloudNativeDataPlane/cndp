/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

package distributor

import (
	"context"
	"sync"
	"time"
	"unsafe"

	"github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne"
	"github.com/sirupsen/logrus"
)

type TX struct {
	ctx    context.Context
	handle *cne.System
	wg     sync.WaitGroup
	ring   *cne.LocklessRing
}

func NewTX(ctx context.Context, handle *cne.System, lb LoadBalancer) (*TX, error) {
	ring, err := cne.NewLRing("tx-ring", initialRingSize, []string{cne.RingFlagSingleConsumer})
	if err != nil {
		return nil, err
	}
	tx := &TX{
		ctx:    ctx,
		handle: handle,
		ring:   ring,
	}
	lb.SetCallBack(tx.Aggregate)

	return tx, nil
}

func (tx *TX) send(thdName string, lportNames []string) {
	lports := tx.handle.LPortsByName(lportNames)
	if len(lports) == 0 {
		return
	}

	err := tx.handle.RegisterThread(thdName)
	if err != nil {
		return
	}
	defer tx.handle.UnregisterThread(thdName)

	items := make([]uintptr, numPackets)

	var lportIds []int
	for _, lport := range lports {
		lportIds = append(lportIds, lport.LPortID())
	}

	tx.wg.Add(1)
	for {
		for _, pid := range lportIds {
			select {
			case <-tx.ctx.Done():
				tx.wg.Done()
				return
			default:
				n := tx.ring.DequeueN(items, numPackets)

				i, txN := 0, 0
				for start := time.Now(); i < n; i += txN {
					if time.Since(start) >= time.Second {
						logrus.Error("Sending packets timeout, maybe the link is down.")
						// free remaining packets
						for _, item := range items[i:] {
							packet := (*cne.Packet)(unsafe.Pointer(item))
							cne.PktBufferFree([]*cne.Packet{packet})
						}
						break
					}

					packet := (*cne.Packet)(unsafe.Pointer(items[i]))
					txN = cne.TxBurst(pid, []*cne.Packet{packet}, true)
					if txN == 1 {
						cne.PktBufferFree([]*cne.Packet{packet})
					}
				}

			}
		}
	}
}

func (tx *TX) Aggregate(obj interface{}) int {
	return tx.ring.EnqueueN([]uintptr{uintptr(unsafe.Pointer(obj.(*cne.Packet)))}, 1)
}

func (tx *TX) Start() {
	thdNamePrefix := "tx"
	for thdName, thd := range tx.handle.JsonCfg().ThreadInfoMap {
		if thdName[:len(thdNamePrefix)] == thdNamePrefix {
			go tx.send(thdName, thd.LPorts)
		}
	}
}

func (tx *TX) Stop() {
	tx.wg.Wait()
}
