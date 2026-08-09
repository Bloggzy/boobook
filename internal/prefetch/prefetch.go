// Package prefetch reads Windows prefetch (.pf) files.
//
// Prefetch answers a question no other artefact Boobook reads can: it names an
// executable, says how often and when it ran, and — through its volume
// information block — records the serial of the volume the executable and the
// files it touched lived on. A programme run from a removable volume is
// therefore visible as such, and the serial joins straight to the same value a
// shell link records in its volume id.
//
// Parsing is www.velocidex.com/golang/go-prefetch's, which handles the five
// format versions and the LZXPRESS-Huffman container Windows 10 and 11 wrap
// them in. It does not read the volume information block: it reads the block's
// offset and count and stops there. That block is the part this package adds,
// because it is the part that makes prefetch worth reading for a USB case.
//
// Prefetch is not always present. It is off by default on Windows Server, and
// can be disabled on any host, so an empty directory is not evidence that
// nothing ran — see the EnablePrefetcher value in the SYSTEM hive.
package prefetch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	upstream "www.velocidex.com/golang/go-prefetch"

	"github.com/Bloggzy/boobook/internal/lnk"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// Run is one prefetch file: one executable, on one path, with the volumes and
// files its execution touched.
type Run struct {
	SourceFile string

	// Executable is the name as the header stores it, e.g. NOTEPAD.EXE.
	Executable string
	// ExecutablePath is the kernel path the Windows 10 and 11 formats record,
	// e.g. \VOLUME{01d7...}\TOOLS\RUNME.EXE. Empty on older formats, which do
	// not carry it.
	ExecutablePath string
	// PathHash is the hash Windows computed over the full path, and which forms
	// part of the file name. Two prefetch files for one executable name mean it
	// ran from two different paths, which is itself a finding.
	PathHash string
	Version  string

	RunCount uint32
	// RunTimes are the recorded executions, most recent first. Windows 8 and
	// later keep eight; XP, Vista and 7 keep one. A run count higher than the
	// number of times held means earlier executions have been overwritten.
	RunTimes []time.Time

	Volumes []Volume
	// Files are the kernel paths the loader touched. They are left exactly as
	// stored: which volume each belongs to is a prefix match against Volumes,
	// and that join belongs in SQL with the rest of the derivations.
	Files []string

	Warnings []string
}

// Volume is one entry from the volume information block.
type Volume struct {
	// DevicePath is how the kernel named the volume, either
	// \DEVICE\HARDDISKVOLUME2 or \VOLUME{GUID}. It is the prefix the file
	// paths carry, which is what ties a file to a volume.
	DevicePath string
	// SerialHex is the volume serial rendered the way Windows displays it and
	// the way a shell link records it, so the two join without conversion.
	SerialHex string
	RawSerial uint32
	// CreatedUTC is when the volume was formatted. A removable volume's
	// creation time is one of the few values that survives reformatting of
	// nothing else, and it is a UTC instant, not a wall clock.
	CreatedUTC *time.Time
}

var errNotPrefetch = errors.New("not a prefetch file")

// ParseFile reads one .pf file.
func ParseFile(path string) (*Run, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	run, err := Parse(data)
	if err != nil {
		return nil, err
	}
	run.SourceFile = path
	return run, nil
}

// Parse reads prefetch bytes.
//
// The container is opened here rather than left to the upstream loader so that
// the decompressed bytes can be read twice: once by that loader for the header
// and file list, and once by this package for the volume block it does not
// reach. Decompressing a Windows 10 prefetch file twice to read two halves of
// it would be the alternative.
func Parse(data []byte) (*Run, error) {
	reader, warnings, err := decompress(data)
	if err != nil {
		return nil, err
	}

	info, err := upstream.LoadPrefetch(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNotPrefetch, err)
	}

	run := &Run{
		Executable:     info.Executable,
		ExecutablePath: info.Path,
		PathHash:       info.Hash,
		Version:        info.Version,
		RunCount:       info.RunCount,
		Files:          info.FilesAccessed,
		Warnings:       warnings,
	}

	// Run times are read from the raw FILETIMEs rather than taken from the
	// upstream loader, for two reasons. Every Windows time conversion in this
	// project goes through wintime, so that a sentinel is refused the same way
	// everywhere. And the upstream conversion subtracts the epoch from an
	// unsigned value: a zeroed slot underflows and comes back as a date in the
	// year 60056, which the loader hides on the Windows 10 path by discarding
	// anything in the future, and does not hide at all on the XP and Vista
	// paths. A timeline that accepted either reading would be wrong by
	// centuries.
	times, timeWarnings := readRunTimes(reader, info.Version)
	run.RunTimes = times
	run.Warnings = append(run.Warnings, timeWarnings...)

	volumes, volumeWarnings := readVolumes(reader, info.Version)
	run.Volumes = volumes
	run.Warnings = append(run.Warnings, volumeWarnings...)

	return run, nil
}

// decompress unwraps the MAM container Windows 10 and 11 use, and passes
// anything else through untouched.
func decompress(data []byte) (io.ReaderAt, []string, error) {
	if len(data) < 8 {
		return nil, nil, errNotPrefetch
	}

	source := bytes.NewReader(data)
	profile := upstream.NewPrefetchProfile()

	header := profile.MAMHeader(source, 0)
	if header.Signature() != "MAM\x04" {
		return source, nil, nil
	}

	size := int(header.UncompressedSize())
	// A length field is an instruction to allocate, and this one comes from
	// the evidence. 256 MB is far beyond any real prefetch file — the largest
	// seen are a few hundred kilobytes — and refusing beyond it keeps a
	// corrupt or hostile header from exhausting memory.
	const maxUncompressed = 256 << 20
	if size <= 0 || size > maxUncompressed {
		return nil, nil, fmt.Errorf(
			"%w: MAM header declares an uncompressed size of %d bytes",
			errNotPrefetch, size)
	}

	compressed := data[header.Size():]
	out, err := upstream.LZXpressHuffmanDecompressWithFallback(compressed, size)
	if err != nil {
		return nil, nil, fmt.Errorf("decompress prefetch: %w", err)
	}

	var warnings []string
	if len(out) != size {
		warnings = append(warnings, fmt.Sprintf(
			"decompressed to %d bytes where the header declared %d", len(out), size))
	}
	return bytes.NewReader(out), warnings, nil
}

// Run time array offsets within the file information block, and how many slots
// each format reserves. Windows 8 and later keep the last eight executions;
// earlier formats keep one.
const (
	runTimesAtXP    = 36
	runTimesAtLater = 44
	runTimeSlots    = 8
)

// readRunTimes reads the recorded executions as raw FILETIMEs.
//
// Unused slots are zero, and wintime refuses those along with the FAT epoch and
// anything outside a plausible range, so a slot that never held an execution
// produces no time rather than a date to explain away.
func readRunTimes(reader io.ReaderAt, version string) ([]time.Time, []string) {
	at, slots := int64(runTimesAtLater), runTimeSlots
	switch version {
	case "WinXP":
		at, slots = runTimesAtXP, 1
	case "Vista":
		at, slots = runTimesAtLater, 1
	}

	profile := upstream.NewPrefetchProfile()
	header := profile.SCCAHeader(reader, 0)
	if header.Signature() != "SCCA" {
		return nil, nil
	}
	base := header.Offset + int64(header.Size()) + at

	raw := make([]byte, slots*8)
	n, err := reader.ReadAt(raw, base)
	if err != nil && err != io.EOF {
		return nil, []string{fmt.Sprintf("read run times: %v", err)}
	}
	raw = raw[:n-n%8]

	var times []time.Time
	var warnings []string
	for i := 0; i+8 <= len(raw); i += 8 {
		value := binary.LittleEndian.Uint64(raw[i:])
		when, ok := wintime.FromFileTime(value)
		if !ok {
			// Zero is the ordinary case for an unused slot and says nothing
			// worth reporting. Any other refused value means the bytes are not
			// what the format says they are.
			if value != 0 {
				warnings = append(warnings, fmt.Sprintf(
					"run time slot %d holds %d, which is not a usable time", i/8+1, value))
			}
			continue
		}
		times = append(times, when)
	}
	return times, warnings
}

// Volume information entry sizes and field offsets.
//
// The first six fields are common to every version; what follows them differs
// and is not read. Offsets within an entry are relative to the start of the
// volume information block, not to the file or to the entry, which is the
// mistake that produces a device path assembled from the middle of a string.
// The stride is per format version and there are three of them, not two. This
// said 40 bytes for everything before Windows 10, which is the size format 17
// uses; the libyal format research documents 104 for formats 23 and 26.
//
// It survived because the four fields read below all sit in the first 40 bytes
// of an entry, so volume 0 comes out right whatever the stride is. The second
// volume does not: advancing 40 bytes lands two thirds of the way inside entry
// 0, in fields nothing wrote, so a real volume was either lost or invented.
// And a prefetch record naming two volumes is the ordinary case for anything
// run from removable media — the system disk the loader touched, and the
// stick. Every reference collection is Windows 11, so nothing in the evidence
// exercised it.
const (
	volumeEntrySizeV17 = 40  // format 17: XP and 2003
	volumeEntrySizeV23 = 104 // formats 23 and 26: Vista, 7 and 8.1
	volumeEntrySizeV30 = 96  // formats 30 and 31: 10 and 11

	volDevicePathOffset = 0  // uint32, from the start of the block
	volDevicePathChars  = 4  // uint32, in UTF-16 code units, excluding the terminator
	volCreationTime     = 8  // FILETIME
	volSerialNumber     = 16 // uint32
)

// readVolumes parses the volume information block the upstream loader locates
// but does not read.
//
// Everything is bounds-checked and then sanity-checked, for the reason the
// partition decoder gives: a structure read at the wrong offset does not fail,
// it produces plausible values. A device path that does not look like one, or
// a serial of zero, is reported as a warning rather than stored as a fact.
func readVolumes(reader io.ReaderAt, version string) ([]Volume, []string) {
	profile := upstream.NewPrefetchProfile()
	header := profile.SCCAHeader(reader, 0)
	if header.Signature() != "SCCA" {
		return nil, []string{"no SCCA signature, so no volume information was read"}
	}
	infoAt := header.Offset + int64(header.Size())

	var blockAt, count, blockSize int64
	var entrySize int64

	switch version {
	case "WinXP":
		info := profile.FileInformationXP(reader, infoAt)
		blockAt = int64(info.VolumesInformationOffset())
		count = int64(info.NumberOfVolumes())
		blockSize = int64(info.VolumesInformationSize())
		entrySize = volumeEntrySizeV17
	case "Vista":
		// Format 23: Vista and 7.
		info := profile.FileInformationVista(reader, infoAt)
		blockAt = int64(info.VolumesInformationOffset())
		count = int64(info.NumberOfVolumes())
		blockSize = int64(info.VolumesInformationSize())
		entrySize = volumeEntrySizeV23
	case "Win8.1":
		// Format 26. It shares the Windows 10 file information layout and the
		// format 23 volume entry, which is why it needs a case of its own
		// rather than falling either way.
		info := profile.FileInformationWin10(reader, infoAt)
		blockAt = int64(info.VolumesInformationOffset())
		count = int64(info.NumberOfVolumes())
		blockSize = int64(info.VolumesInformationSize())
		entrySize = volumeEntrySizeV23
	case "Win10", "Win11":
		// Formats 30 and 31. Upstream names 31 separately and the layout is
		// the same, which is why both are here rather than one falling through
		// to a default.
		info := profile.FileInformationWin10(reader, infoAt)
		blockAt = int64(info.VolumesInformationOffset())
		count = int64(info.NumberOfVolumes())
		blockSize = int64(info.VolumesInformationSize())
		entrySize = volumeEntrySizeV30
	default:
		// Upstream reports "Unknown" for any version number it has no name
		// for, and that used to be read with the Windows 10 layout — a guess
		// presented as a reading. A future format that happened to place a
		// plausible number where the serial goes would have produced a volume
		// nobody could check, joined to a device, and reported at confirmed.
		// Refusing says what happened and loses only what was never reliably
		// there.
		return nil, []string{fmt.Sprintf(
			"prefetch format %q is not one this tool has a documented volume "+
				"layout for, so no volume information was read", version)}
	}

	if count <= 0 || blockAt <= 0 {
		return nil, nil
	}
	// A count is a number from the evidence. Sixteen volumes is already far
	// past anything a single execution touches.
	const maxVolumes = 16
	if count > maxVolumes {
		return nil, []string{fmt.Sprintf(
			"volume information declares %d volumes, which is beyond anything "+
				"real; none was read", count)}
	}

	// blockSize is a number from the evidence and it is an instruction to
	// allocate, which is the same shape as the MAM header's uncompressed size
	// and needs the same answer. A volume block is an array of entries plus the
	// device path strings after them; a megabyte of it would be thousands of
	// volumes, and the count is already capped at sixteen.
	const maxBlockSize = 1 << 20
	if blockSize < 0 || blockSize > maxBlockSize {
		return nil, []string{fmt.Sprintf(
			"volume information declares a block of %d bytes, which is beyond "+
				"anything real; none was read", blockSize)}
	}
	// And the block has to be big enough to hold the entries it claims. Where
	// it is not, the stride and the version disagree — which is exactly what a
	// wrong stride looks like from inside — and reading on would produce
	// entries assembled from whatever follows. This says so rather than
	// returning a volume nobody can check.
	if count*entrySize > blockSize {
		return nil, []string{fmt.Sprintf(
			"volume information declares %d volumes of %d bytes in a block of "+
				"%d, which does not fit; none was read. Either the block is "+
				"truncated or this is not the layout format %q uses",
			count, entrySize, blockSize, version)}
	}

	block := make([]byte, blockSize)
	n, err := reader.ReadAt(block, blockAt)
	if err != nil && err != io.EOF {
		return nil, []string{fmt.Sprintf("read volume information: %v", err)}
	}
	block = block[:n]

	var volumes []Volume
	var warnings []string

	for i := int64(0); i < count; i++ {
		at := i * entrySize
		if at+entrySize > int64(len(block)) {
			warnings = append(warnings, fmt.Sprintf(
				"volume %d runs past the end of the volume information block", i+1))
			break
		}
		entry := block[at : at+entrySize]

		pathAt := int64(binary.LittleEndian.Uint32(entry[volDevicePathOffset:]))
		chars := int64(binary.LittleEndian.Uint32(entry[volDevicePathChars:]))
		serial := binary.LittleEndian.Uint32(entry[volSerialNumber:])
		created := binary.LittleEndian.Uint64(entry[volCreationTime:])

		volume := Volume{RawSerial: serial}
		if serial != 0 {
			volume.SerialHex = lnk.SerialHex(serial)
		}
		if when, ok := wintime.FromFileTime(created); ok {
			volume.CreatedUTC = &when
		}

		// The path offset is from the start of the block, and the character
		// count excludes the terminator. Both come from the evidence, so both
		// are checked against the bytes actually present.
		declaresPath := pathAt > 0 || chars > 0
		fits := pathAt > 0 && chars > 0 && pathAt+chars*2 <= int64(len(block))
		if fits {
			volume.DevicePath = decodeUTF16(block[pathAt : pathAt+chars*2])
		}

		// An entry that declares a path which is not inside its own block is
		// an entry that is not framed where this read assumed. The serial is
		// read from a fixed offset *within that frame*, so it is only a serial
		// if the frame is right — and here the entry itself says it is not.
		//
		// Storing it anyway is precisely the failure looksLikeDevicePath below
		// exists to prevent, reached by the other road: a 32-bit number that
		// looks like a volume serial, joins to a shell link by exact match,
		// and puts a programme on a device. The adversarial fixture found this
		// by pointing one path offset past the end of its block — the serial
		// stayed, reached prefetch-volumes.csv, prefetch-runs.csv, the
		// attribution summary and the report, and nothing anywhere said it had
		// come out of a structure that had already contradicted itself.
		if declaresPath && !fits {
			warnings = append(warnings, fmt.Sprintf(
				"volume %d declares its device path at offset %d for %d "+
					"characters, which is outside its own %d-byte block, so the "+
					"entry is not where this read assumed and nothing from it "+
					"is stored", i+1, pathAt, chars, len(block)))
			continue
		}

		if volume.DevicePath == "" && volume.SerialHex == "" {
			warnings = append(warnings, fmt.Sprintf(
				"volume %d carried neither a device path nor a serial", i+1))
			continue
		}
		if volume.DevicePath != "" && !looksLikeDevicePath(volume.DevicePath) {
			warnings = append(warnings, fmt.Sprintf(
				"volume %d device path %q is not a shape the kernel uses, so the "+
					"entry was read at the wrong offset and is not stored",
				i+1, volume.DevicePath))
			continue
		}

		volumes = append(volumes, volume)
	}

	return volumes, warnings
}

// looksLikeDevicePath rejects a string that cannot be a volume name.
//
// The two forms Windows writes here are \DEVICE\HARDDISKVOLUME<n> and
// \VOLUME{<guid>}. Anything else means the offsets were wrong, and storing it
// would put a fabricated volume name in front of an analyst.
func looksLikeDevicePath(path string) bool {
	upper := strings.ToUpper(path)
	return strings.HasPrefix(upper, `\DEVICE\`) || strings.HasPrefix(upper, `\VOLUME{`)
}

// decodeUTF16 reads little-endian UTF-16, stopping at a NUL.
func decodeUTF16(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		unit := binary.LittleEndian.Uint16(raw[i:])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units))
}
