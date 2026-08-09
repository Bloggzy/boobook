package registry

import "testing"

// A REG_SZ carries its NUL terminator. Left in place it silently breaks every
// string join — a ContainerID read here would not equal the same GUID read
// anywhere else, and the failure looks like "no correlation found" rather than
// like a bug.
func TestTrimStoredRemovesNulTerminator(t *testing.T) {
	cases := map[string]string{
		"{2988c0d8-c5c7-58a8-8331-991530145bee}\x00": "{2988c0d8-c5c7-58a8-8331-991530145bee}",
		"USBSTOR\\Disk\x00\x00":                      "USBSTOR\\Disk",
		"  spaced  ":                                 "spaced",
		"clean":                                      "clean",
		"":                                           "",
		"\x00":                                       "",
	}

	for input, want := range cases {
		if got := trimStored(input); got != want {
			t.Errorf("trimStored(%q) = %q, want %q", input, got, want)
		}
	}
}

// A NUL inside the string is data, not a terminator, and must survive: only a
// trailing run is stripped.
func TestTrimStoredKeepsInteriorBytes(t *testing.T) {
	const input = "a\x00b\x00"
	const want = "a\x00b"
	if got := trimStored(input); got != want {
		t.Errorf("trimStored(%q) = %q, want %q", input, got, want)
	}
}
