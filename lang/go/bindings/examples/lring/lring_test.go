// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2019-2022 Intel Corporation

package lring

import (
	"fmt"
	"time"

	. "github.com/franela/goblin"
	"testing"
)

var (
	MaxElementCnt       = 256
	RingSize      uint  = 4096
	LoopCount     int64 = 500000
)

// Equal tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
func EqualSlices(a, b []uintptr, cnt int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if i < cnt {
			if v != b[i] {
				return false
			}
		}
	}
	return true
}

func TestLRing(t *testing.T) {

	var lr *LocklessRing

	burst_sz := []int{1, 2, 4, 8, 16, 32, 64, 128, 256}

	vals := make([]uintptr, MaxElementCnt)
	rvals := make([]uintptr, MaxElementCnt)
	nsTimes := make([]int64, len(burst_sz))

	for i := 0; i < MaxElementCnt; i++ {
		vals[i] = uintptr(0x1234567890 + i)
	}

	g := Goblin(t)

	g.Describe("lring", func() {
		EnqDeqTst := func(bz int) {
			n := lr.EnqueueN(vals, bz)

			g.Assert(n == bz).IsTrue(fmt.Sprintf("EnqueueN error: %d != %d", n, bz))
			g.Assert(n == bz).IsTrue(fmt.Sprintf("enqueue %v items returned %v", bz, n))
			g.Assert(lr.Count() == uint(bz)).IsTrue(fmt.Sprintf("return count %v should be %v", lr.Count(), bz))
			g.Assert(lr.FreeCount() == (lr.Size()-1)-uint(bz)).IsTrue(fmt.Sprintf("free count %v should be %v", lr.FreeCount(), (lr.Size() - uint(bz))))
			g.Assert(lr.Full()).IsFalse("lring should not be full")

			n = lr.DequeueN(rvals, bz)

			g.Assert(n == bz).IsTrue(fmt.Sprintf("DequeueN error: %d != %d", n, bz))
			g.Assert(n == bz).IsTrue(fmt.Sprintf("DequeueN items returned %v", n))
			g.Assert(EqualSlices(vals, rvals, bz) == true).IsTrue(fmt.Sprintf("DequeueN returned invalid values: %v", rvals))
			g.Assert(lr.Count() == 0).IsTrue("return count not zero")
			g.Assert(lr.FreeCount() == (lr.Size() - 1)).IsTrue(fmt.Sprintf("return free count should be %v got %v", (lr.Size() - 1), lr.FreeCount()))
			g.Assert(lr.Empty()).IsTrue("should be empty")
		}

		g.It(fmt.Sprintf("create SP/SC ring %5d entries", RingSize), func() {
			var err error

			lr, err = Create("FooBar", RingSize, []string{RingFlagSingleConsumer, RingFlagSingleProducer})

			g.Assert(err == nil).IsTrue("err return should not be nil")
			g.Assert(lr.ring != nil).IsTrue("lr.ring should not be nil")

			g.Assert(lr.Name() == "FooBar").IsTrue("should return name as FooBar")
			g.Assert(lr.ElemSize() == uint(8)).IsTrue(fmt.Sprintf("elementSz should be %d", 8))
			g.Assert(lr.Size() == RingSize).IsTrue(fmt.Sprintf("elementCnt should be %v", RingSize))
			g.Assert(lr.RawFlags() == (RingFlagSingleConsumerValue | RingFlagSingleProducerValue)).IsTrue("flags should be RING_F_SC_DEQ")

			lr.Destroy()
		})

		g.It(fmt.Sprintf("create MP/MC ring %5d entries", RingSize), func() {
			var err error

			lr, err = Create("FooBar", RingSize, nil)

			g.Assert(err == nil).IsTrue("err return: %v", err)
			g.Assert(lr.ring != nil).IsTrue("lr.ring should not be nil")

			g.Assert(lr.Name() == "FooBar").IsTrue("should return name as FooBar")
			g.Assert(lr.ElemSize() == uint(8)).IsTrue(fmt.Sprintf("elementSz should be %d", 8))
			g.Assert(lr.Size() == RingSize).IsTrue(fmt.Sprintf("elementCnt should be %v", RingSize))
			g.Assert(lr.RawFlags() == 0).IsTrue("flags should be zero")
		})

		g.It(fmt.Sprintf("should      foreach burst %v EnqueueN/DequeueN for %v times per burst", burst_sz, LoopCount), func() {
			for _, bz := range burst_sz {
				EnqDeqTst(bz)
			}
		})

		g.It(fmt.Sprintf("should time foreach burst %v EnqueueN/DequeueN for %v times per burst", burst_sz, LoopCount), func() {
			for k, bz := range burst_sz {
				start := time.Now().UnixNano()
				for i := 0; i < int(LoopCount); i++ {
					lr.DequeueN(rvals, lr.EnqueueN(vals, bz))
				}
				nsTimes[k] = time.Now().UnixNano() - start
				g.Assert(lr.Empty()).IsTrue("should be empty")
			}
		})

		g.It("destroy ring", func() {
			lr.Destroy()
		})
	})
	fmt.Printf("   Interate %v times\n", LoopCount)
	for i, bz := range burst_sz {
		cyclesPerLoop := nsTimes[i] / LoopCount
		fmt.Printf("   Total Time %10vns for %4vns per EnqueueN(%3v)/DequeueN(%3v) pair (%4vns per item)\n",
			nsTimes[i], cyclesPerLoop, bz, bz, (cyclesPerLoop/2)/int64(bz))
	}
}
