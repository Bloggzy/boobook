// Package lnk parses Windows shell link files.
//
// A shell link is the strongest file-activity evidence available for a
// removable device, because it records what the volume was at the moment the
// file was opened: the drive letter, the drive type, the volume serial number
// and the volume label, alongside the target file's own timestamps. Where the
// drive type is removable and the letter matches a letter MountedDevices gave
// to a USB device, a file access can be placed on that device.
//
// The link is not the file. Its timestamps describe the target as it was when
// the link was written, and the link's own MFT times describe the access. Both
// are kept, labelled by which is which, because conflating them is how a
// timeline acquires events that never happened.
package lnk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Bloggzy/boobook/internal/shellitem"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// headerSize is the fixed size of a ShellLinkHeader.
const headerSize = 0x4C

// linkCLSID is the class identifier every shell link carries.
var linkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// Link header flags, from MS-SHLLINK.
const (
	hasLinkTargetIDList uint32 = 1 << iota
	hasLinkInfo
	hasName
	hasRelativePath
	hasWorkingDir
	hasArguments
	hasIconLocation
	isUnicode
)

// DriveType values from the LinkInfo VolumeID.
const (
	DriveUnknown   uint32 = 0
	DriveNoRootDir uint32 = 1
	DriveRemovable uint32 = 2
	DriveFixed     uint32 = 3
	DriveRemote    uint32 = 4
	DriveCDROM     uint32 = 5
	DriveRamdisk   uint32 = 6
)

// Link is one parsed shell link.
type Link struct {
	SourceFile string
	// Origin names where the link came from: a file on disk, or a stream inside
	// a jump list. A finding has to say which.
	Origin string

	// Target times, as recorded in the link header. These describe the target
	// file, not the link, and are stored raw beside the derived value.
	RawTargetCreated, RawTargetAccessed, RawTargetWritten uint64
	TargetCreated, TargetAccessed, TargetWritten          *time.Time
	TargetSizeBytes                                       uint32
	FileAttributes                                        uint32

	// LocalBasePath is the local half of the target path, including its drive
	// letter, and CommonPath is the suffix that completes it. Both are kept as
	// recorded; FullPath joins them.
	LocalBasePath string
	CommonPath    string
	// DriveLetter is the letter LocalBasePath began with, upper-cased.
	DriveLetter string

	// VolumeIDPresent reports whether the link carried volume information at
	// all. Without it there is no drive type and no serial, and saying so is
	// different from reporting a fixed disk.
	VolumeIDPresent bool
	DriveType       uint32
	// DriveSerialNumber is the volume serial as recorded, which is the value
	// EMDMgmt and the file system record independently.
	DriveSerialNumber uint32
	VolumeLabel       string

	// NetworkShare is set where the target was on a network path.
	NetworkShare string

	// The target as the shell item list named it, which is a separate record
	// from LocalBasePath and can survive where that is absent. Kept apart from
	// the LinkInfo fields rather than merged: where a link carries both and
	// they differ, that is a finding, not a conflict to be resolved silently.
	TargetPath        string
	TargetName        string
	TargetDriveLetter string
	TargetPathHasGap  bool

	// The shell item's own FAT timestamps: local wall clock with no zone, so
	// never presented as UTC instants.
	RawTargetItemModified                                                    uint32
	TargetItemModifiedLocal, TargetItemCreatedLocal, TargetItemAccessedLocal *time.Time

	// MFTEntry and MFTSequence tie the target to a record in the volume's $MFT
	// rather than to a name, which can be reused.
	MFTEntry    uint64
	MFTSequence uint16

	Name         string
	RelativePath string
	WorkingDir   string
	Arguments    string
	IconLocation string

	// MachineID is the NetBIOS name recorded in the link tracker block.
	//
	// It was described here as the machine that last opened the target, and the
	// block does not support that. MS-SHLLINK 2.5.10 says the tracker records
	// the machine the *link* was made or last updated on, for the distributed
	// link tracking service to resolve a moved target from — which is a fact
	// about the shortcut, not about who used the file. On a link found on one
	// host naming another it is still a finding in itself; it is just a
	// different one.
	MachineID string
	// DroidVolumeID and DroidFileID are the link tracking identifiers; the
	// birth pair records the volume and object the target was created on, which
	// survives a copy.
	DroidVolumeID, DroidFileID           string
	BirthDroidVolumeID, BirthDroidFileID string

	// Warnings record what could not be read, so a partial parse is never
	// presented as a complete one.
	Warnings []string
}

// DriveTypeName names a drive type, returning the number where it is not known
// rather than inventing a description.
func DriveTypeName(driveType uint32) string {
	switch driveType {
	case DriveUnknown:
		return "unknown"
	case DriveNoRootDir:
		return "no_root_dir"
	case DriveRemovable:
		return "removable"
	case DriveFixed:
		return "fixed"
	case DriveRemote:
		return "remote"
	case DriveCDROM:
		return "cdrom"
	case DriveRamdisk:
		return "ramdisk"
	}
	return fmt.Sprintf("%d", driveType)
}

// SerialHex renders a volume serial the way Windows displays it, which is how
// it appears in EMDMgmt and in a `vol` listing.
func SerialHex(serial uint32) string {
	return fmt.Sprintf("%04X-%04X", serial>>16, serial&0xFFFF)
}

// Removable reports whether the link recorded the target as being on removable
// media. Absent volume information answers false: the link said nothing, which
// is not the same as saying "fixed".
func (l *Link) Removable() bool {
	return l.VolumeIDPresent && l.DriveType == DriveRemovable
}

// ParseFile reads a shell link from disk.
func ParseFile(path string) (*Link, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	link, err := Parse(data)
	if err != nil {
		return nil, err
	}
	link.SourceFile = path
	link.Origin = "file"
	return link, nil
}

var errNotALink = errors.New("not a shell link: header size or class id mismatch")

// Parse reads a shell link from bytes.
func Parse(data []byte) (*Link, error) {
	if len(data) < headerSize {
		return nil, errNotALink
	}
	if binary.LittleEndian.Uint32(data[0:4]) != headerSize {
		return nil, errNotALink
	}
	var clsid [16]byte
	copy(clsid[:], data[4:20])
	if clsid != linkCLSID {
		return nil, errNotALink
	}

	link := &Link{}
	flags := binary.LittleEndian.Uint32(data[20:24])
	link.FileAttributes = binary.LittleEndian.Uint32(data[24:28])

	link.RawTargetCreated = binary.LittleEndian.Uint64(data[28:36])
	link.RawTargetAccessed = binary.LittleEndian.Uint64(data[36:44])
	link.RawTargetWritten = binary.LittleEndian.Uint64(data[44:52])
	link.TargetCreated = convert(link.RawTargetCreated)
	link.TargetAccessed = convert(link.RawTargetAccessed)
	link.TargetWritten = convert(link.RawTargetWritten)

	link.TargetSizeBytes = binary.LittleEndian.Uint32(data[52:56])

	offset := headerSize

	if flags&hasLinkTargetIDList != 0 {
		if offset+2 > len(data) {
			link.warn("truncated before the target id list")
			return link, nil
		}
		size := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		end := offset + 2 + size
		if end > len(data) {
			link.warn("target id list runs past the end of the file")
			return link, nil
		}

		// The id list names the target through shell items. It is read as well
		// as LinkInfo, not instead of it: a link can carry one and not the
		// other, and where it carries both they can disagree — which is itself
		// worth seeing rather than resolving silently.
		list, err := shellitem.Parse(data[offset+2 : end])
		if err != nil {
			// The error used to be discarded. The link then parsed, the
			// shell-item target came out empty, and nothing said a structure
			// had been refused — so "the link named no target through shell
			// items" and "the shell items could not be read" produced
			// identical output. Those are statements about different things,
			// and only one of them is about the evidence.
			link.warn("target id list: " + err.Error())
		}
		if err == nil {
			link.TargetPath = list.Path()
			link.TargetPathHasGap = list.HasGap()
			if last := list.Last(); last != nil {
				link.TargetName = last.Name
				link.RawTargetItemModified = last.RawModified
				link.TargetItemModifiedLocal = last.ModifiedLocal
				link.TargetItemCreatedLocal = last.CreatedLocal
				link.TargetItemAccessedLocal = last.AccessedLocal
				link.MFTEntry = last.MFTEntry
				link.MFTSequence = last.MFTSequence
			}
			for _, item := range list.Items {
				if item.DriveLetter != "" {
					link.TargetDriveLetter = item.DriveLetter
				}
			}
			link.Warnings = append(link.Warnings, list.Warnings...)
		}

		offset = end
	}

	if flags&hasLinkInfo != 0 {
		next, err := parseLinkInfo(link, data, offset)
		if err != nil {
			link.warn(err.Error())
			return link, nil
		}
		offset = next
	}

	unicode := flags&isUnicode != 0
	stringFields := []struct {
		flag  uint32
		field *string
		what  string
	}{
		{hasName, &link.Name, "the description"},
		{hasRelativePath, &link.RelativePath, "the relative path"},
		{hasWorkingDir, &link.WorkingDir, "the working directory"},
		{hasArguments, &link.Arguments, "the arguments"},
		{hasIconLocation, &link.IconLocation, "the icon location"},
	}
	for _, entry := range stringFields {
		if flags&entry.flag == 0 {
			continue
		}
		value, next, ok := readStringData(data, offset, unicode)
		if !ok {
			link.warn("truncated string data")
			return link, nil
		}
		// The same caveat readANSI attaches to the LinkInfo strings. MS-SHLLINK
		// puts StringData in the host's ANSI code page when the Unicode flag is
		// clear, and it was the one family of non-Unicode strings here reading
		// the bytes as UTF-8 without saying so — which matters most for
		// RelativePath, the field that can be the only path a link carries.
		if !unicode {
			link.warnIfNotASCII(value, entry.what)
		}
		*entry.field = value
		offset = next
	}

	parseExtraData(link, data, offset)

	if link.LocalBasePath != "" {
		link.DriveLetter = driveLetter(link.LocalBasePath)
	}
	if link.DriveLetter == "" && link.RelativePath != "" {
		link.DriveLetter = driveLetter(link.RelativePath)
	}

	return link, nil
}

// parseLinkInfo reads the LinkInfo structure, which is where the volume
// identity lives.
func parseLinkInfo(link *Link, data []byte, offset int) (int, error) {
	if offset+4 > len(data) {
		return offset, errors.New("truncated before link info")
	}
	size := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	if size < 4 || offset+size > len(data) {
		return offset, errors.New("link info size runs past the end of the file")
	}
	info := data[offset : offset+size]

	if len(info) < 0x20 {
		return offset + size, errors.New("link info header is short")
	}
	headerSize := int(binary.LittleEndian.Uint32(info[4:8]))
	flags := binary.LittleEndian.Uint32(info[8:12])
	volumeIDOffset := int(binary.LittleEndian.Uint32(info[12:16]))
	localBasePathOffset := int(binary.LittleEndian.Uint32(info[16:20]))
	networkRelativeOffset := int(binary.LittleEndian.Uint32(info[20:24]))
	commonPathOffset := int(binary.LittleEndian.Uint32(info[24:28]))

	// The unicode offsets exist only in the longer header form.
	localBasePathUnicodeOffset := 0
	commonPathUnicodeOffset := 0
	if headerSize >= 0x24 && len(info) >= 0x24 {
		localBasePathUnicodeOffset = int(binary.LittleEndian.Uint32(info[28:32]))
	}
	if headerSize >= 0x28 && len(info) >= 0x28 {
		commonPathUnicodeOffset = int(binary.LittleEndian.Uint32(info[32:36]))
	}

	const volumeIDAndLocalBasePath = 0x1
	const commonNetworkRelativeLinkAndPathSuffix = 0x2

	if flags&volumeIDAndLocalBasePath != 0 {
		if err := parseVolumeID(link, info, volumeIDOffset); err != nil {
			link.warn(err.Error())
		}

		if localBasePathUnicodeOffset > 0 {
			link.LocalBasePath = readUTF16Z(info, localBasePathUnicodeOffset)
		} else {
			link.LocalBasePath = link.readANSI(info, localBasePathOffset, "the local base path")
		}
	}

	if flags&commonNetworkRelativeLinkAndPathSuffix != 0 {
		link.NetworkShare = parseNetworkShare(link, info, networkRelativeOffset)
	}

	if commonPathUnicodeOffset > 0 {
		link.CommonPath = readUTF16Z(info, commonPathUnicodeOffset)
	} else {
		link.CommonPath = link.readANSI(info, commonPathOffset, "the common path suffix")
	}

	return offset + size, nil
}

func parseVolumeID(link *Link, info []byte, offset int) error {
	if offset <= 0 || offset+16 > len(info) {
		return errors.New("volume id offset is outside the link info")
	}
	size := int(binary.LittleEndian.Uint32(info[offset : offset+4]))
	if size < 16 || offset+size > len(info) {
		return errors.New("volume id size runs past the link info")
	}
	volume := info[offset : offset+size]

	link.VolumeIDPresent = true
	link.DriveType = binary.LittleEndian.Uint32(volume[4:8])
	link.DriveSerialNumber = binary.LittleEndian.Uint32(volume[8:12])

	labelOffset := int(binary.LittleEndian.Uint32(volume[12:16]))
	// 0x14 in the label offset means the label is unicode and its real offset
	// follows. Reading the ANSI field in that case yields an empty label, which
	// would be reported as "no label" rather than as a label not read.
	if labelOffset == 0x14 && len(volume) >= 20 {
		unicodeOffset := int(binary.LittleEndian.Uint32(volume[16:20]))
		link.VolumeLabel = readUTF16Z(volume, unicodeOffset)
	} else {
		link.VolumeLabel = link.readANSI(volume, labelOffset, "the volume label")
	}
	return nil
}

// parseNetworkShare reads CommonNetworkRelativeLink, MS-SHLLINK 2.3.2.
//
// The Unicode arm is the part that was missing. The specification says a
// NetNameOffset greater than 0x14 means the structure carries the longer
// header, whose NetNameOffsetUnicode holds the real name and whose ANSI field
// is then empty. Reading the ANSI field alone returned "" for those links, and
// an empty share reports the link as having had no network target — an absence,
// which in this tool reads as "there was none" rather than "it was not read".
func parseNetworkShare(link *Link, info []byte, offset int) string {
	if offset <= 0 || offset+20 > len(info) {
		return ""
	}
	size := int(binary.LittleEndian.Uint32(info[offset : offset+4]))
	if size < 20 || offset+size > len(info) {
		return ""
	}
	share := info[offset : offset+size]

	nameOffset := int(binary.LittleEndian.Uint32(share[8:12]))
	if nameOffset > 0x14 && len(share) >= 0x18 {
		unicodeOffset := int(binary.LittleEndian.Uint32(share[20:24]))
		if name := readUTF16Z(share, unicodeOffset); name != "" {
			return name
		}
	}
	return link.readANSI(share, nameOffset, "the network share name")
}

// Extra data block signatures.
const (
	trackerDataSignature uint32 = 0xA0000003
)

func parseExtraData(link *Link, data []byte, offset int) {
	for offset+8 <= len(data) {
		size := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		// A terminal block is any size below four. Anything else that does not
		// fit is a malformed file, and the two used to end the loop the same
		// silent way — so a shortcut whose extra data was truncated mid-block
		// reported exactly what a shortcut with no tracker block reports, and
		// an absent machine id read as "there was none".
		if size < 4 {
			return
		}
		if size < 8 || offset+size > len(data) {
			link.warn(fmt.Sprintf("extra data block at offset %d declares %d "+
				"bytes, which does not fit the remaining %d: the blocks after "+
				"it, including any tracker block, were not read",
				offset, size, len(data)-offset))
			return
		}
		signature := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		block := data[offset : offset+size]

		if signature == trackerDataSignature && len(block) >= 0x60 {
			link.MachineID = trimZeros(string(block[16:32]))
			link.DroidVolumeID = formatGUID(block[32:48])
			link.DroidFileID = formatGUID(block[48:64])
			link.BirthDroidVolumeID = formatGUID(block[64:80])
			link.BirthDroidFileID = formatGUID(block[80:96])
		}

		offset += size
	}
}

func readStringData(data []byte, offset int, unicode bool) (string, int, bool) {
	if offset+2 > len(data) {
		return "", offset, false
	}
	count := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if !unicode {
		if offset+count > len(data) {
			return "", offset, false
		}
		return string(data[offset : offset+count]), offset + count, true
	}

	byteCount := count * 2
	if offset+byteCount > len(data) {
		return "", offset, false
	}
	return decodeUTF16(data[offset : offset+byteCount]), offset + byteCount, true
}

// readANSI reads a code-page string and says so when the bytes were not ASCII.
//
// MS-SHLLINK's non-Unicode strings are in the *host's* ANSI code page, and the
// shortcut does not record which one. Go's string conversion reads the bytes as
// UTF-8, which is right for ASCII and wrong above 0x7F: a path written on a
// CP1251 or Shift-JIS host comes out as replacement characters, or — worse —
// as a different string that still looks like a path.
//
// Guessing the code page from the bytes would invent evidence, and the one
// value that would settle it, the host's ANSI code page, is in the registry
// rather than in the file. So the bytes are kept exactly as read and the row
// says the decoding is in doubt, which is the same division as an unresolved
// wall clock: report the value, name the assumption.
func (l *Link) readANSI(data []byte, offset int, what string) string {
	value := readANSIZ(data, offset)
	l.warnIfNotASCII(value, what)
	return value
}

// warnIfNotASCII names the code-page assumption where the bytes force one.
//
// An ASCII string stays silent, or every ordinary shortcut on an
// English-language host carries a caveat and the real cases stop being visible.
func (l *Link) warnIfNotASCII(value, what string) {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			l.warn(what + " is a non-Unicode string with bytes above 0x7F and " +
				"was read as UTF-8; the shortcut does not record which ANSI " +
				"code page wrote it, so the text may not be what the shell stored")
			return
		}
	}
}

func readANSIZ(data []byte, offset int) string {
	if offset <= 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

func readUTF16Z(data []byte, offset int) string {
	if offset <= 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end+1 < len(data) {
		if data[end] == 0 && data[end+1] == 0 {
			break
		}
		end += 2
	}
	return decodeUTF16(data[offset:end])
}

func decodeUTF16(raw []byte) string {
	if len(raw) < 2 {
		return ""
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(raw[i:i+2]))
	}
	return trimZeros(string(utf16.Decode(units)))
}

func trimZeros(text string) string {
	return strings.TrimRight(text, "\x00")
}

// formatGUID renders a 16-byte mixed-endian GUID the way Windows displays it.
func formatGUID(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	empty := true
	for _, b := range raw[:16] {
		if b != 0 {
			empty = false
			break
		}
	}
	if empty {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		binary.BigEndian.Uint16(raw[8:10]),
		raw[10:16]))
}

// FullPath is the target as MS-SHLLINK records it: the local base path or the
// network share, joined to the common path suffix.
//
// Section 2.3 splits one path across two fields and Boobook read only the
// first, so a link to a document was recorded as the folder that held it —
// Explorer routinely puts the directory in the base and the file name in the
// suffix. The path is what reaches file-activity.csv, the timeline and the
// report, and a row saying somebody opened `E:\Reports\` when they opened
// `E:\Reports\payroll.xlsx` is wrong about the only thing it is read for. It
// also collapsed every file in a folder to one string in the distinct-path
// counts.
//
// The components are kept separately as well. Where a link carries both these
// and a shell-item target and they disagree, that is a finding rather than a
// conflict to resolve quietly.
func (l *Link) FullPath() string {
	base := l.LocalBasePath
	if base == "" {
		base = l.NetworkShare
	}
	if base == "" {
		return l.CommonPath
	}
	if l.CommonPath == "" {
		return base
	}
	// The base may or may not end in a separator depending on how the shell
	// split it, and joining without checking produces either a doubled
	// separator or a missing one — both of which break an exact-match join
	// against a path from another artefact.
	if strings.HasSuffix(base, `\`) {
		return base + l.CommonPath
	}
	return base + `\` + l.CommonPath
}

func driveLetter(path string) string {
	if len(path) >= 2 && path[1] == ':' {
		letter := strings.ToUpper(path[:1])
		if letter[0] >= 'A' && letter[0] <= 'Z' {
			return letter
		}
	}
	return ""
}

func convert(filetime uint64) *time.Time {
	value, ok := wintime.FromFileTime(filetime)
	if !ok {
		return nil
	}
	return &value
}

func (l *Link) warn(message string) {
	l.Warnings = append(l.Warnings, message)
}
