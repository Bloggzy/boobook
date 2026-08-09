package registry

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"www.velocidex.com/golang/regparser"

	"github.com/Bloggzy/boobook/internal/devid"
)

// MountedDevices maps a mount point to whatever identifies the volume behind
// it. It is the registry's own record of which drive letter held which device,
// and the strongest route from a letter back to a physical device.
//
// A letter is reused. These are persisted historical associations, not
// time-bound leases, and nothing here says when the mapping was in force.

// MountEntryKind names what the value name identified.
type MountEntryKind string

const (
	// MountDriveLetter is \DosDevices\X:.
	MountDriveLetter MountEntryKind = "drive_letter"
	// MountVolumeGUID is \??\Volume{GUID}.
	MountVolumeGUID MountEntryKind = "volume_guid"
	// MountNoMountPoint is the #{GUID} form the mount manager writes for a
	// volume with no mount point. It is undocumented and reported as its own
	// kind rather than being read as a Volume GUID.
	MountNoMountPoint MountEntryKind = "no_mount_point"
	MountOther        MountEntryKind = "other"
)

// TargetKind names how the stored value identifies the volume.
type TargetKind string

const (
	// TargetDevicePath is a full device instance path: the strongest link,
	// because it names the device outright.
	TargetDevicePath TargetKind = "device_path"
	// TargetGPTPartitionGUID is the "DMIO:ID:" form holding a GPT partition GUID.
	TargetGPTPartitionGUID TargetKind = "gpt_partition_guid"
	// TargetMBRSignature is the 12-byte form: a 4-byte MBR disk signature
	// followed by an 8-byte partition offset.
	TargetMBRSignature TargetKind = "mbr_disk_signature"
	// TargetVolumeGUIDOffset is the "{GUID}#offset" text form.
	TargetVolumeGUIDOffset TargetKind = "volume_guid_offset"
	TargetUnknown          TargetKind = "unknown"
)

// MountEntry is one MountedDevices value.
type MountEntry struct {
	// ValueName is the stored name, unaltered.
	ValueName string
	Kind      MountEntryKind
	// DriveLetter is set for the \DosDevices\X: form.
	DriveLetter string
	// VolumeGUID is set for the \??\Volume{GUID} and #{GUID} forms.
	VolumeGUID string

	TargetKind TargetKind
	// Raw is the stored bytes, hex encoded. Always populated.
	Raw string
	// DevicePath is the decoded device instance path, for TargetDevicePath.
	DevicePath string
	// DeviceInstanceID is DevicePath normalised back to the Enum form, so it
	// can be joined against a devnode.
	DeviceInstanceID string
	// PartitionGUID is set for TargetGPTPartitionGUID.
	PartitionGUID string
	// DiskSignature is the MBR disk signature, for TargetMBRSignature.
	DiskSignature uint32
	// PartitionOffset is the byte offset, for TargetMBRSignature.
	PartitionOffset uint64
	// TargetVolumeGUID and TargetOffsetHex are set for TargetVolumeGUIDOffset.
	TargetVolumeGUID string
	TargetOffsetHex  string
}

var (
	driveLetterName = regexp.MustCompile(`(?i)^\\DosDevices\\([A-Z]):$`)
	volumeGUIDName  = regexp.MustCompile(`(?i)^\\\?\?\\Volume(\{[0-9a-f-]+\})$`)
	noMountPoint    = regexp.MustCompile(`(?i)^#(\{[0-9a-f-]+\})$`)
	volumeGUIDValue = regexp.MustCompile(`(?i)^(\{[0-9a-f-]+\})#([0-9A-F]+)$`)
)

// gptPrefix marks a value holding a GPT partition GUID.
var gptPrefix = []byte("DMIO:ID:")

// ReadMountedDevices parses HKLM\SYSTEM\MountedDevices.
//
// The key sits outside the control sets: there is one per hive, not one per
// control set.
func ReadMountedDevices(registry *regparser.Registry) []MountEntry {
	key := registry.OpenKey("MountedDevices")
	if key == nil {
		return nil
	}

	var entries []MountEntry
	for _, value := range key.Values() {
		data := value.ValueData()
		if data == nil {
			continue
		}
		entries = append(entries, decodeMountEntry(value.ValueName(), data.Data))
	}
	return entries
}

func decodeMountEntry(name string, raw []byte) MountEntry {
	entry := MountEntry{
		ValueName:  name,
		Raw:        hex.EncodeToString(raw),
		Kind:       MountOther,
		TargetKind: TargetUnknown,
	}

	switch {
	case driveLetterName.MatchString(name):
		entry.Kind = MountDriveLetter
		entry.DriveLetter = strings.ToUpper(
			driveLetterName.FindStringSubmatch(name)[1])
	case volumeGUIDName.MatchString(name):
		entry.Kind = MountVolumeGUID
		entry.VolumeGUID = strings.ToLower(
			volumeGUIDName.FindStringSubmatch(name)[1])
	case noMountPoint.MatchString(name):
		entry.Kind = MountNoMountPoint
		entry.VolumeGUID = strings.ToLower(
			noMountPoint.FindStringSubmatch(name)[1])
	}

	decodeMountTarget(&entry, raw)
	return entry
}

func decodeMountTarget(entry *MountEntry, raw []byte) {
	// GPT: an ASCII marker followed by a 16-byte partition GUID.
	if len(raw) >= len(gptPrefix)+16 && string(raw[:len(gptPrefix)]) == string(gptPrefix) {
		entry.TargetKind = TargetGPTPartitionGUID
		entry.PartitionGUID = formatGUID(raw[len(gptPrefix) : len(gptPrefix)+16])
		return
	}

	// MBR: a 4-byte disk signature followed by an 8-byte partition offset.
	// This is what Windows writes for a partitioned disk, and it names no
	// device — reaching one needs the signature matched elsewhere.
	if len(raw) == 12 {
		entry.TargetKind = TargetMBRSignature
		entry.DiskSignature = binary.LittleEndian.Uint32(raw[:4])
		entry.PartitionOffset = binary.LittleEndian.Uint64(raw[4:])
		return
	}

	text := decodeUTF16(raw)
	if text == "" {
		return
	}

	if matches := volumeGUIDValue.FindStringSubmatch(text); matches != nil {
		entry.TargetKind = TargetVolumeGUIDOffset
		entry.TargetVolumeGUID = strings.ToLower(matches[1])
		entry.TargetOffsetHex = matches[2]
		return
	}

	if strings.Contains(text, "#") && strings.Contains(strings.ToUpper(text), "_??_") {
		entry.TargetKind = TargetDevicePath
		entry.DevicePath = text
		entry.DeviceInstanceID = DevicePathToInstanceID(text)
		return
	}
}

// DevicePathToInstanceID converts a stored device path back to the device
// instance ID form the Enum tree uses.
//
// Case is preserved as stored, and it varies by source: MountedDevices keeps
// the device's own casing while Windows Portable Devices upper-cases the whole
// path. Any join on a device instance ID must therefore be case-insensitive,
// or it silently returns nothing — the same failure mode as an unstripped NUL
// terminator, and just as invisible.
//
//	_??_USBSTOR#Disk&Ven_X&Prod_Y&Rev_Z#SERIAL&0#{class-guid}
//	USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\SERIAL&0
//
// The trailing class GUID is the device interface class, not part of the
// instance identity, so it is dropped.
func DevicePathToInstanceID(devicePath string) string {
	normalised := devid.Normalise(devicePath)
	// A value that did not convert names no device, and saying so is different
	// from returning the input unchanged.
	if !strings.Contains(normalised, `\`) {
		return ""
	}
	return normalised
}

// formatGUID renders a 16-byte mixed-endian GUID the way Windows displays it:
// the first three fields are little-endian, the last two big-endian.
func formatGUID(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		binary.BigEndian.Uint16(raw[8:10]),
		raw[10:16]))
}
