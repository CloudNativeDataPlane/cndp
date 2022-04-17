// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package utils

// Set of const values used in the tool

var (
	// Ten - number
	Ten = uint64(10)
	// Hundred - number of
	Hundred = uint64(Ten * Ten)
	// Thousand - number of
	Thousand = uint64(Ten * Hundred)
	// Million - number of
	Million = uint64(Thousand * Thousand)
	// Billion - number of
	Billion = uint64(Million * Thousand)

	// KiloBytes number of bytes
	KiloBytes uint64 = 1024
	// MegaBytes - number of bytes
	MegaBytes = (KiloBytes * KiloBytes)
	// GigaBytes - number of bytes
	GigaBytes = (MegaBytes * KiloBytes)
	// TeraBytes number of bytes
	TeraBytes = (GigaBytes * KiloBytes)

	// EtherCRCLen - number of bytes in CRC
	EtherCRCLen = uint64(4)
	// InterFrameGap - number of bytes between frames
	InterFrameGap = uint64(12)
	// StartFrameDelimiter - number of bytes in delimiter
	StartFrameDelimiter = uint64(1)
	// PktPreambleSize - number of bytes in frame preamble
	PktPreambleSize = uint64(7)
	// PktOverheadSize - Total bytes of overhead
	PktOverheadSize = uint64(InterFrameGap + StartFrameDelimiter +
		PktPreambleSize + EtherCRCLen)
)
