package registry

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/Bloggzy/boobook/internal/wintime"
)

// filetimeBytes renders a FILETIME the way the hive stores it.
func filetimeBytes(filetime uint64) []byte {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, filetime)
	return raw
}

// These are the four dates the whole device timeline rests on. The values are
// taken from a real PATRIOT device in the USB-LENOVO-SANDISK-LATER collection.
func TestDecodeDeviceActivityDates(t *testing.T) {
	cases := []struct {
		id       uint32
		name     string
		raw      string
		wantTime string
	}{
		{100, "DEVPKEY_Device_InstallDate", "1e0263bad81cdd01", "2026-07-26T08:28:25.654735800Z"},
		{101, "DEVPKEY_Device_FirstInstallDate", "1e0263bad81cdd01", "2026-07-26T08:28:25.654735800Z"},
		{102, "DEVPKEY_Device_LastArrivalDate", "292764dde51cdd01", "2026-07-26T10:02:27.839978500Z"},
		{103, "DEVPKEY_Device_LastRemovalDate", "f23f4df8e51cdd01", "2026-07-26T10:03:12.988363400Z"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			raw, err := hex.DecodeString(testCase.raw)
			if err != nil {
				t.Fatal(err)
			}

			property := decodeProperty(devpkeyDeviceActivity, testCase.id, "", raw)

			if property.Name != testCase.name {
				t.Errorf("Name = %q, want %q", property.Name, testCase.name)
			}
			if !property.DeviceActivity {
				t.Error("must be marked as device activity")
			}
			if property.TimeUTC == nil {
				t.Fatal("no time was decoded")
			}
			if got := wintime.Format(*property.TimeUTC); got != testCase.wantTime {
				t.Errorf("= %s, want %s", got, testCase.wantTime)
			}
			// The raw form must survive so the conversion stays checkable.
			if property.Raw != testCase.raw {
				t.Errorf("Raw = %q, want %q", property.Raw, testCase.raw)
			}
			if property.RawFileTime == 0 {
				t.Error("the stored FILETIME must be retained")
			}
		})
	}
}

// A driver package date describes the driver, not the device. Reading
// DriverDate as device activity would put a 2006 Microsoft inbox driver date on
// a device connected in 2026.
func TestDriverDateIsNotDeviceActivity(t *testing.T) {
	raw, _ := hex.DecodeString("00808ca3c594c601")
	property := decodeProperty(devpkeyDriverPackage, 2, "0002", raw)

	if property.Name != "DEVPKEY_Device_DriverDate" {
		t.Fatalf("Name = %q", property.Name)
	}
	if property.DeviceActivity {
		t.Error("a driver package date must not be marked as device activity")
	}
	if property.TimeUTC == nil {
		t.Fatal("no time decoded")
	}
	if got := property.TimeUTC.Format("2006-01-02"); got != "2006-06-21" {
		t.Errorf("= %s, want 2006-06-21", got)
	}
}

// A property this project cannot name keeps its bytes and is given no meaning.
func TestUnknownPropertyIsPreservedNotInvented(t *testing.T) {
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	property := decodeProperty("{00000000-0000-0000-0000-000000000000}", 9999, "270F", raw)

	if property.Name != "" {
		t.Errorf("an unidentified property must not be named, got %q", property.Name)
	}
	if property.Kind != KindBinary {
		t.Errorf("Kind = %q, want %q", property.Kind, KindBinary)
	}
	if property.Raw != "deadbeef" {
		t.Errorf("Raw = %q, want %q", property.Raw, "deadbeef")
	}
	if property.TimeUTC != nil {
		t.Error("no time should be invented for an unidentified property")
	}
	if want := "{00000000-0000-0000-0000-000000000000}\\270F"; property.DisplayName() != want {
		t.Errorf("DisplayName() = %q, want %q", property.DisplayName(), want)
	}
}

func TestDecodeUTF16(t *testing.T) {
	// "PATRIOT" as Windows stores it, NUL terminated.
	raw := []byte{
		'P', 0, 'A', 0, 'T', 0, 'R', 0, 'I', 0, 'O', 0, 'T', 0, 0, 0,
	}
	if got := decodeUTF16(raw); got != "PATRIOT" {
		t.Errorf("= %q, want %q", got, "PATRIOT")
	}

	// An odd-length buffer is not a UTF-16 string.
	if got := decodeUTF16([]byte{0x41, 0x00, 0x42}); got != "" {
		t.Errorf("odd-length buffer decoded to %q, want empty", got)
	}
}

// A short buffer must not be read as a date.
func TestShortFileTimeFallsBackToBinary(t *testing.T) {
	property := decodeProperty(devpkeyDeviceActivity, 102, "0066", []byte{0x01, 0x02})
	if property.Kind != KindBinary {
		t.Errorf("Kind = %q, want %q", property.Kind, KindBinary)
	}
	if property.TimeUTC != nil {
		t.Error("a truncated value must not yield a time")
	}
}

func TestActivityFromSelectsOnlyDeviceDates(t *testing.T) {
	arrival, _ := hex.DecodeString("292764dde51cdd01")
	driver, _ := hex.DecodeString("00808ca3c594c601")

	properties := []Property{
		decodeProperty(devpkeyDeviceActivity, 102, "0066", arrival),
		decodeProperty(devpkeyDriverPackage, 2, "0002", driver),
	}

	activity := ActivityFrom(properties)
	if activity.LastArrivalDate == nil {
		t.Fatal("LastArrivalDate was not picked up")
	}
	if activity.RawLastArrivalDate == 0 {
		t.Error("the raw FILETIME must be carried through")
	}
	// The driver date must not have leaked into any device field.
	if activity.InstallDate != nil || activity.FirstInstallDate != nil ||
		activity.LastRemovalDate != nil {
		t.Error("a driver package date leaked into the device activity set")
	}
}
