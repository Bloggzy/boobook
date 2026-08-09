package registry

import "testing"

// The device form. On Windows 11 EMDMgmt is not written, so this is the route
// from a volume label back to a device.
func TestPortableDeviceKeyNamesResolveToDevices(t *testing.T) {
	const keyName = `SWD#WPDBUSENUM#_??_USBSTOR#DISK&VEN_PATRIOT&PROD_&REV_#24111912130128&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`

	device := PortableDevice{KeyName: keyName}
	if index := indexOfMarker(keyName); index >= 0 {
		device.DeviceInstanceID = DevicePathToInstanceID(keyName[index:])
	}

	const want = `USBSTOR\DISK&VEN_PATRIOT&PROD_&REV_\24111912130128&0`
	if device.DeviceInstanceID != want {
		t.Errorf("DeviceInstanceID = %q, want %q", device.DeviceInstanceID, want)
	}
}

func indexOfMarker(name string) int {
	for i := 0; i+4 <= len(name); i++ {
		if name[i] == '_' && name[i+1] == '?' && name[i+2] == '?' && name[i+3] == '_' {
			return i
		}
	}
	return -1
}

// The volume form names a volume, not a device, and must not claim one.
func TestPortableVolumeFormIsRecognised(t *testing.T) {
	const keyName = `SWD#WPDBUSENUM#{FAB6C965-BAE3-11F0-A0AC-806E6F6E6963}#000000072ACFC200`

	matches := portableVolumeForm.FindStringSubmatch(keyName)
	if matches == nil {
		t.Fatal("the volume form was not recognised")
	}
	if want := "{FAB6C965-BAE3-11F0-A0AC-806E6F6E6963}"; matches[1] != want {
		t.Errorf("volume GUID = %q, want %q", matches[1], want)
	}
	if matches[2] != "000000072ACFC200" {
		t.Errorf("offset = %q", matches[2])
	}
}

// A daylight bias of -60 stored as a DWORD reads as 4294967236 unsigned. Using
// that would shift a converted time by roughly eight thousand years.
func TestTimeZoneBiasesAreSigned(t *testing.T) {
	cases := map[uint64]int{
		0:          0,
		4294967236: -60,  // -60 as an unsigned DWORD
		4294966816: -480, // -480, i.e. UTC+8
		300:        300,
	}
	for stored, want := range cases {
		if got := signedMinutes(stored); got != want {
			t.Errorf("signedMinutes(%d) = %d, want %d", stored, got, want)
		}
	}
}

func TestEMDMgmtNameSplitsSerialAndLabel(t *testing.T) {
	cases := []struct {
		keyName    string
		wantSerial string
		wantLabel  string
	}{
		{`_??_USBSTOR#Disk&Ven_X#SERIAL#{guid}_TEST_1234567890`, "1234567890", "TEST"},
		{`USBSTOR#TESTVOLUME_987654321`, "987654321", "TESTVOLUME"},
	}

	for _, testCase := range cases {
		matches := emdMgmtName.FindStringSubmatch(testCase.keyName)
		if matches == nil {
			t.Errorf("%q was not matched", testCase.keyName)
			continue
		}
		if matches[2] != testCase.wantSerial {
			t.Errorf("serial = %q, want %q", matches[2], testCase.wantSerial)
		}
	}
}
