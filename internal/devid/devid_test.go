package devid

import "testing"

func TestNormaliseHandlesEveryFormWindowsWrites(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{
			"mounted devices device path",
			`_??_USBSTOR#Disk&Ven_PATRIOT&Prod_&Rev_#24111912130128&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`,
			`USBSTOR\Disk&Ven_PATRIOT&Prod_&Rev_\24111912130128&0`,
		},
		{
			"kernel object form",
			`\??\USBSTOR#Disk&Ven_X#SERIAL&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`,
			`USBSTOR\Disk&Ven_X\SERIAL&0`,
		},
		{
			// A Kernel-PnP record names the volume node, not the disk. The
			// device is reachable through it and must not be lost.
			"storage volume wrapping a device path",
			`STORAGE\VOLUME\_??_USBSTOR#DISK&VEN_PATRIOT&PROD_&REV_#24111912130128&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`,
			`USBSTOR\DISK&VEN_PATRIOT&PROD_&REV_\24111912130128&0`,
		},
		{
			"portable device wrapping a device path",
			`SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_X#SERIAL&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`,
			`USBSTOR\DISK&VEN_X\SERIAL&0`,
		},
		{
			"already an instance id",
			`USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\SERIAL&0`,
			`USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\SERIAL&0`,
		},
		{
			// This names a volume. Claiming a device from it would be inventing
			// a link the evidence does not contain.
			"portable device volume form is left alone",
			`SWD\WPDBUSENUM\{CE3E8F0E-7B66-11F0-A0A3-806E6F6E6963}#0000000E530F6E00`,
			`SWD\WPDBUSENUM\{CE3E8F0E-7B66-11F0-A0A3-806E6F6E6963}#0000000E530F6E00`,
		},
		{
			// A stored REG_SZ keeps its terminator. Left in place it defeats
			// every later comparison, invisibly.
			"trailing NUL is stripped",
			"USBSTOR\\Disk&Ven_X\\SERIAL&0\x00",
			`USBSTOR\Disk&Ven_X\SERIAL&0`,
		},
		{"empty", "", ""},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := Normalise(testCase.value); got != testCase.want {
				t.Errorf("Normalise(%q)\n = %q\nwant %q", testCase.value, got, testCase.want)
			}
		})
	}
}

// The whole reason this package exists: MountedDevices keeps the device's own
// casing, Windows Portable Devices upper-cases it, and a case-sensitive join
// between them returns nothing while looking like an absence of evidence.
func TestKeyJoinsAcrossSourceCasing(t *testing.T) {
	fromMountedDevices := `_??_USBSTOR#Disk&Ven_PATRIOT&Prod_&Rev_#24111912130128&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`
	fromPortableDevices := `SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_PATRIOT&PROD_&REV_#24111912130128&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`

	if Key(fromMountedDevices) != Key(fromPortableDevices) {
		t.Errorf("the same device did not join:\n %q\n %q",
			Key(fromMountedDevices), Key(fromPortableDevices))
	}
	if Normalise(fromMountedDevices) == Normalise(fromPortableDevices) {
		t.Error("Normalise should preserve stored casing, so the two differ")
	}
}

func TestEnumerator(t *testing.T) {
	cases := map[string]string{
		`USBSTOR\Disk&Ven_X\SERIAL&0`:  "USBSTOR",
		`usbstor\Disk&Ven_X\SERIAL&0`:  "USBSTOR",
		`SWD\WPDBUSENUM\{guid}#0`:      "SWD",
		`STORAGE\Volume\{guid}`:        "STORAGE",
		`_??_USBPRINT#Brother#SERIAL#`: "USBPRINT",
		"":                             "",
	}
	for value, want := range cases {
		if got := Enumerator(value); got != want {
			t.Errorf("Enumerator(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestIsUSB(t *testing.T) {
	usb := []string{
		`USBSTOR\Disk&Ven_X&Prod_Y\SERIAL&0`,
		`USB\VID_0781&PID_5581\0401b570c5371292f08b`,
		`_??_USBSTOR#Disk&Ven_X#SERIAL&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`,
		`STORAGE\VOLUME\_??_USBSTOR#DISK&VEN_PATRIOT#241119&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`,
		`usbprint\brothermfc\serial`,
		// A portable device volume: which device is unresolved, that one was
		// involved is not.
		`SWD\WPDBUSENUM\{CE3E8F0E-7B66-11F0-A0A3-806E6F6E6963}#0000000E530F6E00`,
	}
	for _, value := range usb {
		if !IsUSB(value) {
			t.Errorf("IsUSB(%q) = false, want true", value)
		}
	}

	notUSB := []string{
		`PCI\VEN_8086&DEV_9A0D\3&11583659&0&B0`,
		`SCSI\Disk&Ven_NVMe&Prod_SAMSUNG\4&1e2cd3d3&0&000000`,
		// Names a volume with no bus in sight. Reading this as USB would be the
		// tool inventing a finding.
		`STORAGE\Volume\{d1ec6eb7-5d71-46d1-9791-e99443dd51a9}`,
		`\Device\HarddiskVolume6`,
		"",
	}
	for _, value := range notUSB {
		if IsUSB(value) {
			t.Errorf("IsUSB(%q) = true, want false", value)
		}
	}
}
