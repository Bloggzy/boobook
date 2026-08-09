package fixture

import (
	"encoding/binary"
	"fmt"
)

// Prefetch (SCCA) files built from the published format definition.
//
// The point of this file is that it does not import internal/prefetch and must
// never be changed to. Every offset and size below is taken from the libyal
// format research — "Windows Prefetch File (PF) format", the volume
// information and file information sections — and not from what the parser
// currently expects. A fixture that shares constants with the code it tests
// asserts that the code agrees with itself.
//
// That is not a hypothetical objection here. The previous prefetch fixture
// imported the parser's volDevicePathOffset and friends and wrote 40-byte
// volume entries for a version 23 file, because 40 is what the parser assumed.
// The documented size for versions 23 and 26 is 104. The fixture therefore
// proved the assumption rather than the format, and a genuine multi-volume
// Windows 7 or 8.1 file would have been misread with every test green.
//
// Where a field's meaning is not established it is left zero and named
// unknown, rather than given a plausible value.

// SCCA format versions, as stored in the first four bytes of the file.
const (
	SCCAWinXP   = 17 // Windows XP and 2003
	SCCAVista   = 23 // Windows Vista and 7
	SCCAWin81   = 26 // Windows 8.1
	SCCAWin10   = 30 // Windows 10 and 11
	SCCAWin11v2 = 31 // a later Windows 11 revision, same layout as 30
)

// Volume information entry sizes, by format version.
//
// This is the table the whole file exists to state independently. libyal
// documents four sizes across the five versions; the parser had one value for
// everything before Windows 10.
const (
	volumeEntryV17 = 40  // format 17
	volumeEntryV23 = 104 // formats 23 and 26
	volumeEntryV30 = 96  // formats 30 and 31
)

// VolumeEntrySize is the documented stride for a version, and the second
// return says whether the version is one this fixture knows how to build.
func VolumeEntrySize(version uint32) (int, bool) {
	switch version {
	case SCCAWinXP:
		return volumeEntryV17, true
	case SCCAVista, SCCAWin81:
		return volumeEntryV23, true
	case SCCAWin10, SCCAWin11v2:
		return volumeEntryV30, true
	}
	return 0, false
}

// File header. Common to every version.
const (
	sccaHeaderSize      = 84
	sccaVersionOffset   = 0  // uint32
	sccaSignatureOffset = 4  // "SCCA"
	sccaFileSizeOffset  = 12 // uint32
	sccaExeNameOffset   = 16 // UTF-16, up to 29 characters plus terminator
	sccaExeNameChars    = 29
	sccaHashOffset      = 76 // uint32, the hash in the filename
)

// File information section sizes, by version. It follows the header directly.
const (
	fileInfoV17 = 68
	fileInfoV23 = 156
	fileInfoV26 = 224
	fileInfoV30 = 224
)

// File information field offsets, relative to the start of the section.
//
// The first six fields are at the same place in every version, which is why
// the volume block can be located without knowing the rest of the layout. The
// run time and run count move, so they are per version below.
const (
	infoVolumesOffset = 0x18 // uint32, from the start of the file
	infoVolumeCount   = 0x1c // uint32
	infoVolumesSize   = 0x20 // uint32
)

// Volume information entry field offsets, relative to the start of the entry.
// Common to every version; only the stride after them differs.
const (
	volDevicePathOffset = 0x00 // uint32, from the start of the volume block
	volDevicePathChars  = 0x04 // uint32, UTF-16 units, excluding the terminator
	volCreationTime     = 0x08 // FILETIME
	volSerialNumber     = 0x10 // uint32
	volFileRefsOffset   = 0x14 // uint32
	volFileRefsSize     = 0x18 // uint32
	volDirStringsOffset = 0x1c // uint32
	volDirStringCount   = 0x20 // uint32
)

// SCCAVolume is one volume a prefetch file names.
type SCCAVolume struct {
	DevicePath   string
	SerialNumber uint32
	CreationTime uint64
}

// SCCAFile describes a prefetch file to build.
type SCCAFile struct {
	Version    uint32
	Executable string
	NameHash   uint32
	RunCount   uint32
	LastRun    uint64
	Volumes    []SCCAVolume

	// VolumeEntrySizeOverride writes the volume entries at a stride other than
	// the documented one. Zero means the documented one. This exists to build
	// the file a parser with the wrong stride would produce, so a test can say
	// which of the two it is reading.
	VolumeEntrySizeOverride int
	// DeclaredVolumeCount overrides the count written into the file
	// information, without changing how many entries are actually present.
	// Zero means the truth.
	DeclaredVolumeCount int
	// DeclaredBlockSize overrides the volume block size written into the file
	// information. Zero means the truth.
	DeclaredBlockSize int
}

// runTimeOffsets returns where the last run time and the run count live for a
// version, relative to the start of the file information section.
func runTimeOffsets(version uint32) (lastRun, runCount int, ok bool) {
	switch version {
	case SCCAWinXP:
		return 0x78 - sccaHeaderSize, 0x7c - sccaHeaderSize, true
	case SCCAVista:
		return 0x2c, 0x44, true
	case SCCAWin81, SCCAWin10, SCCAWin11v2:
		// 8.1 and 10 keep eight run times; the most recent is first.
		return 0x2c, 0xc4, true
	}
	return 0, 0, false
}

func fileInfoSize(version uint32) (int, bool) {
	switch version {
	case SCCAWinXP:
		return fileInfoV17, true
	case SCCAVista:
		return fileInfoV23, true
	case SCCAWin81:
		return fileInfoV26, true
	case SCCAWin10, SCCAWin11v2:
		return fileInfoV30, true
	}
	return 0, false
}

// BuildSCCA assembles an uncompressed prefetch file.
//
// Uncompressed on purpose: Windows 10 and 11 wrap the same structure in an
// LZXPRESS-Huffman container, and a fixture that had to compress itself would
// be testing the compressor. The parser decompresses first and then reads this
// same layout, so a bare file exercises everything the volume block decoding
// does.
func BuildSCCA(file SCCAFile) ([]byte, error) {
	stride, known := VolumeEntrySize(file.Version)
	if !known {
		return nil, fmt.Errorf("no documented layout for SCCA version %d",
			file.Version)
	}
	if file.VolumeEntrySizeOverride > 0 {
		stride = file.VolumeEntrySizeOverride
	}
	infoSize, _ := fileInfoSize(file.Version)
	lastRunAt, runCountAt, _ := runTimeOffsets(file.Version)

	blockAt := sccaHeaderSize + infoSize

	// The entries first, then the device path strings after them. Every offset
	// inside an entry is relative to the start of the block, which is the part
	// a parser gets wrong by reading it as a file offset.
	entries := make([]byte, stride*len(file.Volumes))
	var strings []byte
	for i, volume := range file.Volumes {
		entry := entries[i*stride:]
		binary.LittleEndian.PutUint32(entry[volDevicePathOffset:],
			uint32(len(entries)+len(strings)))
		binary.LittleEndian.PutUint32(entry[volDevicePathChars:],
			uint32(len([]rune(volume.DevicePath))))
		binary.LittleEndian.PutUint64(entry[volCreationTime:], volume.CreationTime)
		binary.LittleEndian.PutUint32(entry[volSerialNumber:], volume.SerialNumber)
		// The file reference and directory string fields are present in every
		// version and are not read by Boobook. They are written as empty
		// rather than left as whatever the zero value happens to mean.
		binary.LittleEndian.PutUint32(entry[volFileRefsOffset:], 0)
		binary.LittleEndian.PutUint32(entry[volFileRefsSize:], 0)
		binary.LittleEndian.PutUint32(entry[volDirStringsOffset:], 0)
		binary.LittleEndian.PutUint32(entry[volDirStringCount:], 0)

		strings = append(strings, encodeUTF16(volume.DevicePath)...)
		strings = append(strings, 0, 0)
	}
	block := append(entries, strings...)

	out := make([]byte, blockAt+len(block))
	binary.LittleEndian.PutUint32(out[sccaVersionOffset:], file.Version)
	copy(out[sccaSignatureOffset:], "SCCA")
	binary.LittleEndian.PutUint32(out[sccaFileSizeOffset:], uint32(len(out)))
	name := encodeUTF16(file.Executable)
	if len(name) > sccaExeNameChars*2 {
		name = name[:sccaExeNameChars*2]
	}
	copy(out[sccaExeNameOffset:], name)
	binary.LittleEndian.PutUint32(out[sccaHashOffset:], file.NameHash)

	info := out[sccaHeaderSize:]
	count := len(file.Volumes)
	if file.DeclaredVolumeCount > 0 {
		count = file.DeclaredVolumeCount
	}
	size := len(block)
	if file.DeclaredBlockSize > 0 {
		size = file.DeclaredBlockSize
	}
	binary.LittleEndian.PutUint32(info[infoVolumesOffset:], uint32(blockAt))
	binary.LittleEndian.PutUint32(info[infoVolumeCount:], uint32(count))
	binary.LittleEndian.PutUint32(info[infoVolumesSize:], uint32(size))
	binary.LittleEndian.PutUint64(info[lastRunAt:], file.LastRun)
	binary.LittleEndian.PutUint32(info[runCountAt:], file.RunCount)

	copy(out[blockAt:], block)
	return out, nil
}
