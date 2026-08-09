// Package devid normalises the several forms Windows uses to name one device.
//
// The same physical device is named differently by each source: the Enum tree
// writes USBSTOR\Disk&Ven_X\SERIAL&0, MountedDevices writes
// _??_USBSTOR#Disk&Ven_X#SERIAL&0#{guid}, a Kernel-PnP record writes
// STORAGE\VOLUME\_??_USBSTOR#... and Windows Portable Devices upper-cases the
// lot. Joining those requires one canonical form and one case-folded key, or a
// correlation silently returns nothing — which reads as "no evidence" rather
// than as the bug it is.
package devid

import "strings"

// markers are the device-path prefixes Windows uses for a kernel object name.
var markers = []string{`_??_`, `\??\`}

// Normalise converts any of the naming forms to the Enum-tree device instance
// ID form, preserving case as stored.
//
//	_??_USBSTOR#Disk&Ven_X&Prod_Y#SERIAL&0#{53f56307-...}  -> USBSTOR\Disk&Ven_X&Prod_Y\SERIAL&0
//	STORAGE\VOLUME\_??_USBSTOR#Disk&Ven_X#SERIAL&0#{guid}  -> USBSTOR\Disk&Ven_X\SERIAL&0
//	USBSTOR\Disk&Ven_X&Prod_Y\SERIAL&0                     -> unchanged
//
// A value that names a volume rather than a device — SWD\WPDBUSENUM\{guid}#offset
// — is returned unchanged, because resolving it to a device needs evidence this
// function does not have.
func Normalise(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "\x00")
	if value == "" {
		return ""
	}

	index := -1
	for _, marker := range markers {
		if found := strings.Index(value, marker); found >= 0 {
			index = found + len(marker)
			break
		}
	}
	if index < 0 {
		return value
	}

	parts := strings.Split(value[index:], "#")
	// A trailing device interface class GUID identifies the interface, not the
	// device, and is not part of the instance identity.
	if len(parts) > 1 && strings.HasPrefix(parts[len(parts)-1], "{") {
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 2 {
		return value
	}
	return strings.Join(parts, `\`)
}

// Key is the case-folded join key for a device instance ID. Every join on a
// device identity uses this, never the stored string.
func Key(value string) string {
	return strings.ToUpper(Normalise(value))
}

// Enumerator is the leading segment of a device instance ID: USBSTOR, USB, SWD,
// STORAGE and so on. It is upper-cased, since the casing varies by source.
func Enumerator(value string) string {
	normalised := Normalise(value)
	if index := strings.Index(normalised, `\`); index > 0 {
		return strings.ToUpper(normalised[:index])
	}
	return strings.ToUpper(normalised)
}

// usbEnumerators are the enumerators that place a device on, or behind, the USB
// bus. WPDBUSENUM is included: a portable device — a phone, a camera — is
// enumerated there and is squarely within scope.
var usbEnumerators = map[string]bool{
	"USBSTOR":    true,
	"USB":        true,
	"USBPRINT":   true,
	"USBHUB3":    true,
	"WPDBUSENUM": true,
	"USBVIDEO":   true,
	"USBAUDIO":   true,
}

// IsUSB reports whether an identifier names a device on, or behind, the USB bus.
//
// It is a statement about the identifier, not a conclusion about the device.
// A SWD\WPDBUSENUM node naming only a volume GUID answers true — a portable
// device was involved — while saying nothing about which one; resolving that is
// correlation's job. A bare STORAGE\VOLUME node with no embedded device path
// answers false, because nothing in it mentions a bus.
func IsUSB(value string) bool {
	normalised := strings.ToUpper(Normalise(value))
	if usbEnumerators[Enumerator(normalised)] {
		return true
	}

	// A path that embeds a device path under another enumerator —
	// STORAGE\VOLUME\_??_USBSTOR#..., SWD\WPDBUSENUM\{guid}#offset — still names
	// a USB or portable device, though its own leading enumerator does not.
	for enumerator := range usbEnumerators {
		if strings.Contains(normalised, `\`+enumerator+`\`) ||
			strings.Contains(normalised, `\`+enumerator+`#`) {
			return true
		}
	}
	return false
}
