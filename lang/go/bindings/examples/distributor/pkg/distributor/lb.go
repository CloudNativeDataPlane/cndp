/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

package distributor

import (
	"context"
	"fmt"
	"sync"
)

type LoadBalancer interface {
	// Start load balancer
	Run(ctx context.Context)
	// Do the load balancing and distribute packets to workers
	Handle(obj interface{}) int
	// Return workers
	Workers() []*Worker
	// Set callback function for worker to do post processing
	SetCallBack(cb CallBackFunc)
}

// CallBackFunc will be called after processing an object
type CallBackFunc func(obj interface{}) int

type DefaultLoadBalancer struct {
	next    int
	workers []*Worker
}

func NewDefaultLoadBalancer(numWorkers int) (LoadBalancer, error) {
	lb := &DefaultLoadBalancer{
		workers: make([]*Worker, numWorkers),
	}

	var err error
	for i := 0; i < numWorkers; i++ {
		lb.workers[i], err = NewWorker(fmt.Sprintf("worker%d", i+1))
		if err != nil {
			return nil, err
		}
	}

	return lb, nil
}

func (lb *DefaultLoadBalancer) Run(ctx context.Context) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for _, worker := range lb.workers {
		wg.Add(1)
		go func(worker *Worker) {
			defer wg.Done()
			worker.Run(ctx)
		}(worker)
	}
}

func (lb *DefaultLoadBalancer) Handle(obj interface{}) int {
	cur := lb.next
	// Roundrobin workers
	lb.next = (lb.next + 1) % len(lb.workers)
	return lb.workers[cur].Distribute(obj)
}

func (lb *DefaultLoadBalancer) Workers() []*Worker {
	return lb.workers
}

func (lb *DefaultLoadBalancer) SetCallBack(cb CallBackFunc) {
	for _, worker := range lb.workers {
		worker.SetCallBack(cb)
	}
}
