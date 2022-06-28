// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2019-2022 Intel Corporation

package colorize

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
)

// colorizeInfo structure
type colorizeInfo struct {
	defWidth       int
	floatPrecision int
	defForeground  string
	defBackground  string
	defFlags       string
}

var colorInfo colorizeInfo

// Default values for width and precision
const (
	defWidth     = int(0)
	defPrecision = int(2)
)

// Color constant names we can use
const (
	NoColor                = ""
	DefaultColor           = "white"
	YellowColor            = "yellow"
	GreenColor             = "green"
	GoldenRodColor         = "goldenrod"
	OrangeColor            = "orange"
	TealColor              = "teal"
	CornSilkColor          = "cornsilk"
	DeepPinkColor          = "deeppink"
	RedColor               = "red"
	BlueColor              = "blue"
	LightBlueColor         = "lightblue"
	LightCoralColor        = "lightcoral"
	LightCyanColor         = "lightcyan"
	LavenderColor          = "lavender"
	LightSalmonColor       = "lightsalmon"
	MediumBlueColor        = "mediumblue"
	MistyRoseColor         = "mistyrose"
	SkyBlueColor           = "skyblue"
	LightSkyBlueColor      = "lightskyblue"
	MediumSpringGreenColor = "mediumspringgreen"
	WheatColor             = "wheat"
	YellowGreenColor       = "yellowgreen"
	LightYellowColor       = "lightyellow"
	DarkOrangeColor        = "darkorange"
	LightGreenColor        = "lightgreen"
	DarkMagentaColor       = "darkmagenta"
	CyanColor              = "aqua"
)

// SetDefault - create a colorize instance
func SetDefault(foreground, background string, width, precision int, flags string) {

	// when precision is negative then set to the default value
	if precision < 0 {
		precision = defPrecision
	}

	colorInfo = colorizeInfo{
		defWidth:       width,
		floatPrecision: precision,
		defForeground:  foreground,
		defBackground:  background,
		defFlags:       flags,
	}
}

// DefaultForegroundColor returns the default color
func DefaultForegroundColor() string {
	return colorInfo.defForeground
}

// SetDefaultForegroundColor - Set the default foreground color
func SetDefaultForegroundColor(color string) {
	colorInfo.defForeground = color
}

// DefaultBackgroundColor returns the default color
func DefaultBackgroundColor() string {
	return colorInfo.defBackground
}

// SetDefaultBackgroundColor - Set the default background color
func SetDefaultBackgroundColor(color string) {
	colorInfo.defBackground = color
}

// DefaultWidth returns the default width
func DefaultWidth() int {
	return colorInfo.defWidth
}

// SetDefaultWidth - Set the default width
func SetDefaultWidth(w int) {
	colorInfo.defWidth = w
}

// SetFloatPrecision - Set float precision
func SetFloatPrecision(w int) {
	colorInfo.floatPrecision = w
}

// FloatPrecision returns the default precision
func FloatPrecision() int {
	return colorInfo.floatPrecision
}

// DefaultFlags returns the default flags
func DefaultFlags() string {
	return colorInfo.defFlags
}

// SetDefaultFlags - Set flags
func SetDefaultFlags(f string) {
	colorInfo.defFlags = f
}

// Colorize - Add color to the value passed, w size can be 0, 1 or 2
//   w[0] is the width and w[1] is precision or a float value if present
//   w[1] is not present then use default colorInfo.floatPrecision
//   w[2] is the foreground color
//   w[3] is the background color
//   w[4] is the attribute of the color
func Colorize(color string, v interface{}, w ...interface{}) string {
	if colorInfo.defForeground == "" {
		colorInfo.defForeground = "ivory"
	}

	width := int(0)
	precision := colorInfo.floatPrecision
	foreground := colorInfo.defForeground
	if len(color) > 0 {
		foreground = color
	}
	background := colorInfo.defBackground
	flags := colorInfo.defFlags

	for i, v := range w {
		switch i {
		case 0: // Width of the field
			p := v.(int)
			if p >= 0 {
				width = p
			}
		case 1: // Precision of the float value
			p := v.(int)
			if p >= 0 {
				precision = p
			}
		case 2: // foreground color */
			s := v.(string)
			if len(s) > 0 {
				foreground = s
			}
		case 3: // background color
			s := v.(string)
			if len(s) > 0 {
				background = s
			}
		case 4: // flags used for color attributes
			s := v.(string)
			if len(s) > 0 {
				flags = s
			}
		}
	}

	// Build up the color tag strings for begin and end of the field to be printed
	str := fmt.Sprintf("[%s:%s:%s]", foreground, background, flags)
	def := fmt.Sprintf("[%s:%s:%s]", colorInfo.defForeground, colorInfo.defBackground, colorInfo.defFlags)

	switch v.(type) {
	case string:
		return fmt.Sprintf("%[1]s%[3]*[2]s%[4]s", str, v, width, def)
	case uint64, uint32, uint16, uint8:
		return fmt.Sprintf("%[1]s%[3]*[2]d%[4]s", str, v, width, def)
	case int, int64, int32, int16, int8:
		return fmt.Sprintf("%[1]s%[3]*[2]d%[4]s", str, v, width, def)
	case float64, float32:
		return fmt.Sprintf("%[1]s%[3]*.[4]*[2]f%[5]s", str, v, width, precision, def)
	default:
		return fmt.Sprintf("%[1]s%[2]v%s", str, v, def)
	}
}

// ColorWithName - Find and set the color by name
func ColorWithName(color string, a interface{}, w ...interface{}) string {

	color = strings.ToLower(color)

	_, ok := tcell.ColorNames[color]

	if !ok {
		color = OrangeColor
	}
	return Colorize(color, a, w...)
}

// Yellow - return string based on the color given
func Yellow(a interface{}, w ...interface{}) string {

	return ColorWithName(YellowColor, a, w...)
}

// DarkMagenta - return string based on the color given
func DarkMagenta(a interface{}, w ...interface{}) string {

	return ColorWithName(DarkMagentaColor, a, w...)
}

// Green - return string based on the color given
func Green(a interface{}, w ...interface{}) string {

	return ColorWithName(GreenColor, a, w...)
}

// GoldenRod - return string based on the color given
func GoldenRod(a interface{}, w ...interface{}) string {

	return ColorWithName(GoldenRodColor, a, w...)
}

// Orange - return string based on the color given
func Orange(a interface{}, w ...interface{}) string {

	return ColorWithName(OrangeColor, a, w...)
}

// Teal - return string based on the color given
func Teal(a interface{}, w ...interface{}) string {

	return ColorWithName(TealColor, a, w...)
}

// CornSilk - return string based on the color given
func CornSilk(a interface{}, w ...interface{}) string {

	return ColorWithName(CornSilkColor, a, w...)
}

// DeepPink - return string based on the color given
func DeepPink(a interface{}, w ...interface{}) string {

	return ColorWithName(DeepPinkColor, a, w...)
}

// Red - return string based on the color given
func Red(a interface{}, w ...interface{}) string {

	return ColorWithName(RedColor, a, w...)
}

// Blue - return string based on the color given
func Blue(a interface{}, w ...interface{}) string {

	return ColorWithName(BlueColor, a, w...)
}

// LightBlue - return string based on the color given
func LightBlue(a interface{}, w ...interface{}) string {

	return ColorWithName(LightBlueColor, a, w...)
}

// LightCoral - return string based on the color given
func LightCoral(a interface{}, w ...interface{}) string {

	return ColorWithName(LightCoralColor, a, w...)
}

// LightCyan - return string based on the color given
func LightCyan(a interface{}, w ...interface{}) string {

	return ColorWithName(LightCyanColor, a, w...)
}

// Cyan - return string based on the color given
func Cyan(a interface{}, w ...interface{}) string {

	return ColorWithName(CyanColor, a, w...)
}

// Lavender - return string based on the color given
func Lavender(a interface{}, w ...interface{}) string {

	return ColorWithName(LavenderColor, a, w...)
}

// LightSalmon - return string based on the color given
func LightSalmon(a interface{}, w ...interface{}) string {

	return ColorWithName(LightSalmonColor, a, w...)
}

// MediumBlue - return string based on the color given
func MediumBlue(a interface{}, w ...interface{}) string {

	return ColorWithName(MediumBlueColor, a, w...)
}

// MistyRose - return string based on the color given
func MistyRose(a interface{}, w ...interface{}) string {

	return ColorWithName(MistyRoseColor, a, w...)
}

// SkyBlue - return string based on the color given
func SkyBlue(a interface{}, w ...interface{}) string {

	return ColorWithName(SkyBlueColor, a, w...)
}

// LightSkyBlue - return string based on the color given
func LightSkyBlue(a interface{}, w ...interface{}) string {

	return ColorWithName(LightSkyBlueColor, a, w...)
}

// MediumSpringGreen - return string based on the color given
func MediumSpringGreen(a interface{}, w ...interface{}) string {

	return ColorWithName(MediumSpringGreenColor, a, w...)
}

// Wheat - return string based on the color given
func Wheat(a interface{}, w ...interface{}) string {

	return ColorWithName(WheatColor, a, w...)
}

// YellowGreen - return string based on the color given
func YellowGreen(a interface{}, w ...interface{}) string {

	return ColorWithName(YellowGreenColor, a, w...)
}

// LightYellow - return string based on the color given
func LightYellow(a interface{}, w ...interface{}) string {

	return ColorWithName(LightYellowColor, a, w...)
}

// DarkOrange - return string based on the color given
func DarkOrange(a interface{}, w ...interface{}) string {

	return ColorWithName(DarkOrangeColor, a, w...)
}

// LightGreen - return string based on the color given
func LightGreen(a interface{}, w ...interface{}) string {

	return ColorWithName(LightGreenColor, a, w...)
}
