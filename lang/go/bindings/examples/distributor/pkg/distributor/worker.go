/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

package distributor

import (
	"context"
	"unsafe"

	"github.com/CloudNativeDataPlane/cndp/lang/go/bindings/cne"
)

const (
	initialRingSize = 1024
	numPackets      = 256
)

type Worker struct {
	Name  string
	ring  *cne.LocklessRing
	cb    CallBackFunc
	Count int
}

func NewWorker(name string) (*Worker, error) {
	ring, err := cne.NewLRing(name+"-ring", initialRingSize, []string{cne.RingFlagSingleProducer, cne.RingFlagSingleConsumer})
	if err != nil {
		return nil, err
	}
	worker := &Worker{
		Name: name,
		ring: ring,
	}

	return worker, nil
}

func (w *Worker) process(packet *cne.Packet) {
	w.Count++
	cne.SwapMacAddr(packet)
}

func (w *Worker) SetCallBack(cb CallBackFunc) {
	w.cb = cb
}

func (w *Worker) Run(ctx context.Context) {
	items := make([]uintptr, numPackets)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n := w.ring.DequeueN(items, numPackets)
			for _, item := range items[:n] {
				pkt := (*cne.Packet)(unsafe.Pointer(item))
				w.process(pkt)
				for {
					count := w.cb(pkt)
					if count != 0 {
						break
					}
				}
			}

		}
	}
}

func (w *Worker) Distribute(obj interface{}) int {
	return w.ring.EnqueueN([]uintptr{uintptr(unsafe.Pointer(obj.(*cne.Packet)))}, 1)
}
