package partition

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// guidBytes renders a GUID the way Windows holds one in memory: the first
// three fields little-endian, the rest big-endian.
func guidBytes(first uint32, second, third, fourth uint16, rest [6]byte) []byte {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[0:4], first)
	binary.LittleEndian.PutUint16(raw[4:6], second)
	binary.LittleEndian.PutUint16(raw[6:8], third)
	binary.BigEndian.PutUint16(raw[8:10], fourth)
	copy(raw[10:16], rest[:])
	return raw
}

var (
	diskGUID = guidBytes(0xc8e2e6eb, 0x1048, 0x45e2, 0xad39,
		[6]byte{0x86, 0xab, 0x23, 0x9e, 0xba, 0xc0})
	partGUID = guidBytes(0x12a58caa, 0x06b0, 0x4b51, 0xa16b,
		[6]byte{0x18, 0x11, 0xc3, 0x38, 0x1a, 0xbb})
	basicData = guidBytes(0xebd0a0a2, 0xb9e5, 0x4433, 0x87c0,
		[6]byte{0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7})
)

// gptEntry builds one PARTITION_INFORMATION_EX in its GPT form.
func gptEntry(number int, offset, length uint64, typeGUID, id []byte, name string) []byte {
	raw := make([]byte, entrySize)
	binary.LittleEndian.PutUint32(raw[0:4], 1)
	binary.LittleEndian.PutUint64(raw[8:16], offset)
	binary.LittleEndian.PutUint64(raw[16:24], length)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(number))
	copy(raw[32:48], typeGUID)
	copy(raw[48:64], id)

	at := 72
	for _, unit := range utf16.Encode([]rune(name)) {
		binary.LittleEndian.PutUint16(raw[at:at+2], unit)
		at += 2
	}
	return raw
}

// mbrEntry builds one entry in its MBR form. A zero-length entry is an unused
// table slot, which every MBR disk reports four of.
func mbrEntry(number int, offset, length uint64, partitionType byte, boot bool) []byte {
	raw := make([]byte, entrySize)
	binary.LittleEndian.PutUint32(raw[0:4], 0)
	binary.LittleEndian.PutUint64(raw[8:16], offset)
	binary.LittleEndian.PutUint64(raw[16:24], length)
	binary.LittleEndian.PutUint32(raw[24:28], uint32(number))
	raw[32] = partitionType
	if boot {
		raw[33] = 1
	}
	return raw
}

func gptLayout(count int, entries ...[]byte) []byte {
	raw := make([]byte, layoutHeaderSize)
	binary.LittleEndian.PutUint32(raw[0:4], 1)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(count))
	copy(raw[gptDiskIDOffset:gptDiskIDOffset+16], diskGUID)

	for _, entry := range entries {
		raw = append(raw, entry...)
	}
	return raw
}

func mbrLayout(signature uint32, count int, entries ...[]byte) []byte {
	raw := make([]byte, layoutHeaderSize)
	binary.LittleEndian.PutUint32(raw[0:4], 0)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(count))
	binary.LittleEndian.PutUint32(
		raw[mbrSignatureOffset:mbrSignatureOffset+4], signature)

	for _, entry := range entries {
		raw = append(raw, entry...)
	}
	return raw
}

// The partition identifier is the whole point: it is the value MountedDevices
// stores for a GPT volume, and matching it to this record is what says which
// device the volume sat on.
func TestGPTLayoutYieldsThePartitionIdentifier(t *testing.T) {
	raw := gptLayout(1, gptEntry(1, 1048576, 61521997824,
		basicData, partGUID, "Main Data Partition"))

	layout, err := DecodeLayout(raw)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Style != StyleGPT {
		t.Errorf("Style = %q", layout.Style)
	}
	if want := "{c8e2e6eb-1048-45e2-ad39-86ab239ebac0}"; layout.DiskGUID != want {
		t.Errorf("DiskGUID = %q, want %q", layout.DiskGUID, want)
	}
	if len(layout.Partitions) != 1 {
		t.Fatalf("got %d partitions, want 1", len(layout.Partitions))
	}

	entry := layout.Partitions[0]
	if want := "{12a58caa-06b0-4b51-a16b-1811c3381abb}"; entry.PartitionGUID != want {
		t.Errorf("PartitionGUID = %q, want %q", entry.PartitionGUID, want)
	}
	// The type identifier is shared by every basic data partition in the world
	// and must never be mistaken for the one that identifies this volume.
	if want := "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}"; entry.TypeGUID != want {
		t.Errorf("TypeGUID = %q, want %q", entry.TypeGUID, want)
	}
	if entry.Name != "Main Data Partition" {
		t.Errorf("Name = %q", entry.Name)
	}
	if entry.StartingOffset != 1048576 || entry.Length != 61521997824 {
		t.Errorf("offset/length = %d/%d", entry.StartingOffset, entry.Length)
	}
}

// An MBR disk always reports its four table slots whether or not they hold
// anything. Reporting the empty ones would put three phantom volumes on every
// MBR disk in the case.
func TestEmptyMBRSlotsAreNotPartitions(t *testing.T) {
	raw := mbrLayout(0x011AD246, 4,
		mbrEntry(1, 1048576, 61521997824, 0x07, true),
		mbrEntry(0, 0, 0, 0, false),
		mbrEntry(0, 0, 0, 0, false),
		mbrEntry(0, 0, 0, 0, false))

	layout, err := DecodeLayout(raw)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Style != StyleMBR {
		t.Errorf("Style = %q", layout.Style)
	}
	if layout.DiskSignature != 0x011AD246 {
		t.Errorf("DiskSignature = %08x", layout.DiskSignature)
	}
	if len(layout.Partitions) != 1 {
		t.Fatalf("got %d partitions, want 1: %+v", len(layout.Partitions), layout.Partitions)
	}
	if layout.EmptySlots != 3 {
		t.Errorf("EmptySlots = %d, want 3", layout.EmptySlots)
	}
	if layout.Partitions[0].MBRType != 0x07 || !layout.Partitions[0].BootIndicator {
		t.Errorf("entry = %+v", layout.Partitions[0])
	}
	// The declared count is what the record said and is kept as read.
	if layout.PartitionCount != 4 {
		t.Errorf("PartitionCount = %d, want the declared 4", layout.PartitionCount)
	}
}

// Reading at a guessed offset produces partition identifiers that look real and
// match nothing, which is worse than an absence. An unrecognised style is the
// first sign of that, and it stops the decode.
func TestUnknownStyleIsRefused(t *testing.T) {
	raw := make([]byte, layoutHeaderSize)
	binary.LittleEndian.PutUint32(raw[0:4], 99)

	if _, err := DecodeLayout(raw); err == nil {
		t.Error("a layout with an unknown style was decoded")
	}
	if _, err := DecodeLayout(make([]byte, 8)); err == nil {
		t.Error("a buffer too short to hold a layout was decoded")
	}
}

// A record declaring more partitions than it carries has been truncated. What
// is present is still evidence; presenting it as the whole layout is not.
func TestDeclaredCountBeyondTheBytesIsReported(t *testing.T) {
	raw := gptLayout(4, gptEntry(1, 1048576, 1024, basicData, partGUID, "Only one"))

	layout, err := DecodeLayout(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.Partitions) != 1 {
		t.Fatalf("got %d partitions, want 1", len(layout.Partitions))
	}
	if len(layout.Warnings) == 0 {
		t.Error("the shortfall against the declared count must be reported")
	}
}

func TestMBRSignatureIsReadOnlyFromABootRecord(t *testing.T) {
	sector := make([]byte, 512)
	binary.LittleEndian.PutUint32(sector[0x1B8:0x1BC], 0x011AD246)
	sector[510], sector[511] = 0x55, 0xAA

	signature, ok := MBRSignature(sector)
	if !ok || signature != 0x011AD246 {
		t.Errorf("MBRSignature = %08x, %v", signature, ok)
	}

	// Without the boot record marker these bytes are not a signature.
	sector[510] = 0
	if _, ok := MBRSignature(sector); ok {
		t.Error("a sector with no boot record marker yielded a signature")
	}

	// Windows writes a signature when it first mounts a disk. A zero is
	// absence, and matching volumes on it would match every unwritten disk.
	blank := make([]byte, 512)
	blank[510], blank[511] = 0x55, 0xAA
	if _, ok := MBRSignature(blank); ok {
		t.Error("a zero signature was reported as a signature")
	}

	if _, ok := MBRSignature(nil); ok {
		t.Error("an empty sector yielded a signature")
	}
}

// An all-zero GUID is absence, not an identifier that happens to be zero. Two
// disks carrying it are not the same disk.
func TestAllZeroGUIDIsNotAnIdentifier(t *testing.T) {
	if got := FormatGUID(make([]byte, 16)); got != "" {
		t.Errorf("FormatGUID(zero) = %q, want empty", got)
	}
	if got := FormatGUID(make([]byte, 4)); got != "" {
		t.Errorf("FormatGUID(short) = %q, want empty", got)
	}
}
