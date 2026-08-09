package registry

import (
	"encoding/hex"
	"testing"
)

// utf16Bytes renders text the way Windows stores a UTF-16LE registry value.
func utf16Bytes(text string) []byte {
	raw := make([]byte, 0, len(text)*2)
	for _, r := range text {
		raw = append(raw, byte(r), byte(r>>8))
	}
	return raw
}

// The strongest link in the whole chain: a drive letter whose stored value
// names the device outright. Taken from USB-LENOVO-SANDISK-LATER.
func TestDriveLetterResolvesToDevice(t *testing.T) {
	const devicePath = `_??_USBSTOR#Disk&Ven_PATRIOT&Prod_&Rev_#24111912130128&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`

	entry := decodeMountEntry(`\DosDevices\E:`, utf16Bytes(devicePath))

	if entry.Kind != MountDriveLetter {
		t.Errorf("Kind = %q, want %q", entry.Kind, MountDriveLetter)
	}
	if entry.DriveLetter != "E" {
		t.Errorf("DriveLetter = %q, want %q", entry.DriveLetter, "E")
	}
	if entry.TargetKind != TargetDevicePath {
		t.Errorf("TargetKind = %q, want %q", entry.TargetKind, TargetDevicePath)
	}

	// The instance ID must match the Enum form exactly, or the join fails.
	const want = `USBSTOR\Disk&Ven_PATRIOT&Prod_&Rev_\24111912130128&0`
	if entry.DeviceInstanceID != want {
		t.Errorf("DeviceInstanceID = %q, want %q", entry.DeviceInstanceID, want)
	}
}

func TestVolumeGUIDNameIsRecognised(t *testing.T) {
	const devicePath = `_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#04010d18#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`

	entry := decodeMountEntry(
		`\??\Volume{6585adb2-88d2-11f1-a0af-6f56a8262f00}`, utf16Bytes(devicePath))

	if entry.Kind != MountVolumeGUID {
		t.Errorf("Kind = %q, want %q", entry.Kind, MountVolumeGUID)
	}
	if want := "{6585adb2-88d2-11f1-a0af-6f56a8262f00}"; entry.VolumeGUID != want {
		t.Errorf("VolumeGUID = %q, want %q", entry.VolumeGUID, want)
	}
	if entry.TargetKind != TargetDevicePath {
		t.Errorf("TargetKind = %q, want %q", entry.TargetKind, TargetDevicePath)
	}
}

// The GPT form. Its layout is a documented marker plus a partition GUID, so it
// is decoded — but it names a partition, not a device.
func TestGPTPartitionGUIDIsDecoded(t *testing.T) {
	raw, err := hex.DecodeString("444d494f3a49443a8767c2d3ab1663468b6d20737e298b82")
	if err != nil {
		t.Fatal(err)
	}

	entry := decodeMountEntry(`\DosDevices\C:`, raw)

	if entry.TargetKind != TargetGPTPartitionGUID {
		t.Fatalf("TargetKind = %q, want %q", entry.TargetKind, TargetGPTPartitionGUID)
	}
	// Mixed-endian: first three fields little-endian, last two big-endian.
	// Cross-checked against Python's uuid.UUID(bytes_le=...).
	if want := "{d3c26787-16ab-4663-8b6d-20737e298b82}"; entry.PartitionGUID != want {
		t.Errorf("PartitionGUID = %q, want %q", entry.PartitionGUID, want)
	}
	if entry.DeviceInstanceID != "" {
		t.Error("a GPT partition GUID names no device and must not claim one")
	}
}

// The 12-byte form is what Windows writes for a partitioned disk — the common
// case. It names no device; reaching one needs the signature matched elsewhere.
func TestMBRSignatureFormIsDecoded(t *testing.T) {
	raw, err := hex.DecodeString("efbeadde0008000000000000")
	if err != nil {
		t.Fatal(err)
	}

	entry := decodeMountEntry(`\DosDevices\F:`, raw)

	if entry.TargetKind != TargetMBRSignature {
		t.Fatalf("TargetKind = %q, want %q", entry.TargetKind, TargetMBRSignature)
	}
	if entry.DiskSignature != 0xdeadbeef {
		t.Errorf("DiskSignature = %08x, want deadbeef", entry.DiskSignature)
	}
	if entry.PartitionOffset != 2048 {
		t.Errorf("PartitionOffset = %d, want 2048", entry.PartitionOffset)
	}
	if entry.DeviceInstanceID != "" {
		t.Error("an MBR signature names no device and must not claim one")
	}
}

func TestVolumeGUIDOffsetFormIsDecoded(t *testing.T) {
	entry := decodeMountEntry(`\DosDevices\F:`,
		utf16Bytes("{fab6c965-bae3-11f0-a0ac-806e6f6e6963}#000000072ACFC200"))

	if entry.TargetKind != TargetVolumeGUIDOffset {
		t.Fatalf("TargetKind = %q, want %q", entry.TargetKind, TargetVolumeGUIDOffset)
	}
	if want := "{fab6c965-bae3-11f0-a0ac-806e6f6e6963}"; entry.TargetVolumeGUID != want {
		t.Errorf("TargetVolumeGUID = %q, want %q", entry.TargetVolumeGUID, want)
	}
	if entry.TargetOffsetHex != "000000072ACFC200" {
		t.Errorf("TargetOffsetHex = %q", entry.TargetOffsetHex)
	}
}

// The mount manager writes #{GUID} for a volume with no mount point. That form
// is undocumented, so it is reported as its own kind rather than read as a
// Volume GUID.
func TestNoMountPointFormIsKeptDistinct(t *testing.T) {
	entry := decodeMountEntry(`#{fab6c968-bae3-11f0-a0ac-806e6f6e6963}`,
		utf16Bytes("{fab6c965-bae3-11f0-a0ac-806e6f6e6963}#0"))

	if entry.Kind != MountNoMountPoint {
		t.Errorf("Kind = %q, want %q", entry.Kind, MountNoMountPoint)
	}
}

// Every entry keeps its stored bytes whatever else was made of it.
func TestRawIsAlwaysPreserved(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	entry := decodeMountEntry(`\DosDevices\Z:`, raw)

	if entry.Raw != "010203" {
		t.Errorf("Raw = %q, want %q", entry.Raw, "010203")
	}
	if entry.TargetKind != TargetUnknown {
		t.Errorf("TargetKind = %q, want %q", entry.TargetKind, TargetUnknown)
	}
}

func TestDevicePathToInstanceID(t *testing.T) {
	cases := map[string]string{
		`_??_USBSTOR#Disk&Ven_X&Prod_Y&Rev_Z#SERIAL&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`: `USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\SERIAL&0`,
		`\??\USBSTOR#Disk&Ven_X#SERIAL#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`:                `USBSTOR\Disk&Ven_X\SERIAL`,
		`nonsense`: "",
	}
	for input, want := range cases {
		if got := DevicePathToInstanceID(input); got != want {
			t.Errorf("DevicePathToInstanceID(%q) = %q, want %q", input, got, want)
		}
	}
}
