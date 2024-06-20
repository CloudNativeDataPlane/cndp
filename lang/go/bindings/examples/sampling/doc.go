// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023 Intel Corporation

// Brief Description about Sampling Go Application
// 1. Go Sampling Application maintains.
//    Context information using 3 tuples (src ip, dst ip, protocol)
//    of a receiving packet. One of the pieces of information included in this context is
//    the "sampling count," which indicates the number of packets that have been forwarded
//    using this particular context.
// 2. If a port receives multiple packets with the same 3-tuple assume they are
//    part of the same context and increment the "sampling count".
// 3. Maximum limit on the number of packets that can be forwarded using a particular context, and
//    that limit is 15 packets.
// 4. If the packet count of the same context is greater than 15, drop the packet otherwise forward
//    the packet
// 5. Overall, using a 3-tuple to maintain context information can be a useful tool for managing
//    network traffic and ensuring that packets are delivered to their intended destinations.
// NOTE: This Sampling Application works only in lb mode
// Command to run in lb mode: ./run_sampling -c sampling.jsnoc -test lb

package main
