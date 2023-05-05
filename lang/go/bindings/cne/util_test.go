package cne

import (
	"testing"
)

var swapUint16Tests = []struct {
	input  uint16
	expect uint16
}{
	{uint16(0x1234), uint16(0x3412)},
	{uint16(0xABCD), uint16(0xCDAB)},
	{uint16(0xFFFF), uint16(0xFFFF)},
}

func TestUtil(t *testing.T) {
	t.Run("SwapUint16", func(t *testing.T) {
		for _, ct := range swapUint16Tests {
			got := SwapUint16(ct.input)
			if got != ct.expect {
				t.Errorf("SwapUint16(%v) failed: want '%v' got '%v'", ct.input, ct.expect, got)
			}
		}
	})
}
