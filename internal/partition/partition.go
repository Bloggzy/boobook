// Package partition decodes the disk layout structures a Partition/Diagnostic
// 1006 record carries.
//
// Those bytes matter because MountedDevices identifies a volume by a GPT
// partition GUID or an MBR disk signature and partition offset, and nothing
// else in the registry says which physical disk those belong to. The 1006
// record names both: the disk's device instance in ParentId, and its layout in
// these fields. Decoding them turns "some volume" into "a volume on this USB
// device".
//
// The structures are Windows' own DRIVE_LAYOUT_INFORMATION_EX and
// PARTITION_INFORMATION_EX, written to the log as raw memory. They are
// documented, but the padding between their members is not something to take on
// trust: a decoder reading at the wrong offset produces plausible-looking GUIDs.
// Everything here is therefore checked — the style must be a known value, the
// count must fit the bytes present, and a caller can confirm the result by
// finding the decoded identifiers in MountedDevices.
package partition

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Style is the PARTITION_STYLE enumeration.
type Style string

const (
	StyleMBR Style = "mbr"
	StyleGPT Style = "gpt"
	StyleRaw Style = "raw"
)

// Offsets within DRIVE_LAYOUT_INFORMATION_EX. The union that follows the count
// is sized by its largest member (the GPT form, 36 bytes) and padded to an
// eight-byte boundary, so the partition array begins at 48 whichever style the
// disk uses.
const (
	layoutHeaderSize   = 48
	gptDiskIDOffset    = 8
	mbrSignatureOffset = 8
	// entrySize is sizeof(PARTITION_INFORMATION_EX).
	entrySize = 144
	// nameLength is the WCHAR Name[36] a GPT entry carries.
	nameLength = 36
)

// mbrSignatureSectorOffset is where a master boot record keeps the disk
// signature that MountedDevices stores for an MBR volume.
const mbrSignatureSectorOffset = 0x1B8

// Layout is a decoded disk layout.
type Layout struct {
	Style          Style
	PartitionCount int

	// DiskSignature is the MBR disk signature; DiskGUID is the GPT disk
	// identifier. Exactly one is set, according to Style.
	DiskSignature uint32
	DiskGUID      string

	Partitions []Partition
	// EmptySlots counts partition table entries that held nothing, which an
	// MBR disk always reports four of.
	EmptySlots int
	Warnings   []string
}

// Partition is one entry from the layout.
type Partition struct {
	Number         int
	StartingOffset uint64
	Length         uint64

	// PartitionGUID is the unique identifier of this partition, which is what
	// MountedDevices stores in its "DMIO:ID:" form. TypeGUID says what kind of
	// partition it is, which is not unique and never identifies a volume.
	PartitionGUID string
	TypeGUID      string
	Name          string

	// MBRType is the partition type byte for an MBR disk, and BootIndicator
	// whether it was marked active.
	MBRType       byte
	BootIndicator bool
}

var errShort = errors.New("too short to hold a drive layout")

// DecodeLayout reads a DRIVE_LAYOUT_INFORMATION_EX.
func DecodeLayout(raw []byte) (*Layout, error) {
	if len(raw) < layoutHeaderSize {
		return nil, errShort
	}

	layout := &Layout{}
	switch style := binary.LittleEndian.Uint32(raw[0:4]); style {
	case 0:
		layout.Style = StyleMBR
	case 1:
		layout.Style = StyleGPT
	case 2:
		layout.Style = StyleRaw
	default:
		// Not a layout, or not one read at the right offset. Guessing past
		// this point would produce partition identifiers that look real.
		return nil, fmt.Errorf("unknown partition style %d", style)
	}

	count := int(binary.LittleEndian.Uint32(raw[4:8]))
	layout.PartitionCount = count

	switch layout.Style {
	case StyleMBR:
		layout.DiskSignature = binary.LittleEndian.Uint32(
			raw[mbrSignatureOffset : mbrSignatureOffset+4])
	case StyleGPT:
		layout.DiskGUID = FormatGUID(raw[gptDiskIDOffset : gptDiskIDOffset+16])
	}

	available := (len(raw) - layoutHeaderSize) / entrySize
	if count > available {
		// The record declares more partitions than it carries. What is present
		// is still evidence; presenting it as the whole layout would not be.
		layout.Warnings = append(layout.Warnings, fmt.Sprintf(
			"the layout declares %d partitions and holds %d", count, available))
		count = available
	}

	for index := 0; index < count; index++ {
		start := layoutHeaderSize + index*entrySize
		entry, ok := decodeEntry(raw[start : start+entrySize])
		if !ok {
			layout.Warnings = append(layout.Warnings, fmt.Sprintf(
				"partition entry %d does not decode and is not reported", index))
			continue
		}
		// An MBR disk always reports its four table slots whether or not they
		// hold anything. An empty slot is not a partition, and reporting it as
		// one would put three phantom volumes on every MBR disk.
		if entry.Length == 0 && entry.PartitionGUID == "" {
			layout.EmptySlots++
			continue
		}
		layout.Partitions = append(layout.Partitions, entry)
	}

	return layout, nil
}

// Offsets within PARTITION_INFORMATION_EX. StartingOffset is eight-byte
// aligned, so it sits at 8 and not at 4.
func decodeEntry(raw []byte) (Partition, bool) {
	style := binary.LittleEndian.Uint32(raw[0:4])
	if style > 2 {
		return Partition{}, false
	}

	entry := Partition{
		StartingOffset: binary.LittleEndian.Uint64(raw[8:16]),
		Length:         binary.LittleEndian.Uint64(raw[16:24]),
		Number:         int(binary.LittleEndian.Uint32(raw[24:28])),
	}

	switch style {
	case 0: // PARTITION_INFORMATION_MBR
		entry.MBRType = raw[32]
		entry.BootIndicator = raw[33] != 0
	case 1: // PARTITION_INFORMATION_GPT
		entry.TypeGUID = FormatGUID(raw[32:48])
		entry.PartitionGUID = FormatGUID(raw[48:64])
		entry.Name = decodeName(raw[72 : 72+nameLength*2])
	}

	return entry, true
}

func decodeName(raw []byte) string {
	units := make([]uint16, 0, nameLength)
	for offset := 0; offset+1 < len(raw); offset += 2 {
		unit := binary.LittleEndian.Uint16(raw[offset : offset+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return strings.TrimSpace(string(utf16.Decode(units)))
}

// MBRSignature reads the disk signature from a master boot record sector.
//
// This is the value MountedDevices stores, with the partition's byte offset,
// for a volume on an MBR disk.
func MBRSignature(sector []byte) (uint32, bool) {
	if len(sector) < mbrSignatureSectorOffset+4 {
		return 0, false
	}
	// A sector that is not a boot record has no signature to read, and the
	// 0x55AA marker is what says it is one.
	if len(sector) >= 512 && !(sector[510] == 0x55 && sector[511] == 0xAA) {
		return 0, false
	}

	signature := binary.LittleEndian.Uint32(
		sector[mbrSignatureSectorOffset : mbrSignatureSectorOffset+4])
	if signature == 0 {
		// Windows writes a signature when it first mounts a disk. A zero is
		// absence, and matching volumes on it would match everything.
		return 0, false
	}
	return signature, true
}

// FormatGUID renders the mixed-endian form Windows stores in memory: the first
// three fields little-endian, the rest big-endian.
func FormatGUID(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	if allZero(raw[:16]) {
		// An all-zero GUID is absence, not an identifier that happens to be
		// zero, and two disks carrying it are not the same disk.
		return ""
	}
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		binary.BigEndian.Uint16(raw[8:10]),
		raw[10:16])
}

func allZero(raw []byte) bool {
	for _, b := range raw {
		if b != 0 {
			return false
		}
	}
	return true
}
