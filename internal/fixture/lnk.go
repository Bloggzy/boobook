package fixture

import (
	"encoding/binary"
)

// Shell links built from MS-SHLLINK.
//
// Same rule as scca.go: nothing here imports internal/lnk, and every offset is
// the specification's. See independence_test.go for why.
//
// The structure a shell link records its target in is the part worth building
// carefully, because MS-SHLLINK section 2.3 splits a path across two fields and
// Boobook read only one of them. A link to `C:\Users\Analyst\report.docx` can
// store `C:\Users\Analyst\` in LocalBasePath and `report.docx` in
// CommonPathSuffix, and reading the base alone yields a directory where the
// analyst expects a file. The same applies to a network target, where the share
// and the suffix are the two halves and neither is the path on its own.

// LinkInfo header flags, MS-SHLLINK 2.3.
const (
	linkInfoVolumeIDAndLocalBasePath           = 0x1
	linkInfoCommonNetworkRelativeLinkAndSuffix = 0x2
)

// LinkFlags, MS-SHLLINK 2.1.
const (
	LinkHasLinkTargetIDList = 0x00000001
	LinkHasLinkInfo         = 0x00000002
	LinkHasName             = 0x00000004
	LinkHasRelativePath     = 0x00000008
	LinkIsUnicode           = 0x00000080
)

// Drive types, MS-SHLLINK 2.3.1.
const (
	DriveRemovable = 2
	DriveFixed     = 3
	DriveRemote    = 4
)

const linkHeaderSize = 0x4C

var linkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// LinkSpec describes a shell link to build.
type LinkSpec struct {
	// LocalBasePath and CommonPathSuffix are the two halves MS-SHLLINK stores a
	// local target in. The full path is the concatenation; either may be empty.
	LocalBasePath    string
	CommonPathSuffix string

	// NetworkShare is the `\\server\share` half of a network target, and
	// CommonPathSuffix is the rest of it. NetworkShareUnicode writes the share
	// through the Unicode offset instead of the ANSI one, which is the form
	// Boobook did not read at all.
	NetworkShare        string
	NetworkShareUnicode bool

	// The volume, where the link records one.
	VolumeIDPresent bool
	DriveType       uint32
	DriveSerial     uint32
	VolumeLabel     string

	// Header times and size, as the target's own filesystem metadata.
	TargetCreated, TargetAccessed, TargetWritten uint64
	TargetSize                                   uint32

	// Name is the NAME_STRING the HasName flag promises.
	Name string

	// RelativePath is the RELATIVE_PATH StringData field, which MS-SHLLINK 2.4
	// defines as the path to use when resolving the target. A link can carry it
	// with no LinkInfo at all, which is the shape that showed Boobook throwing
	// the target away: it exported an empty path and kept the drive letter.
	RelativePath string

	// RelativePathANSI writes the relative path as raw bytes with the Unicode
	// flag clear, which is how the field is stored on a host that is not
	// running a Unicode shell. The bytes go in exactly as given, so a caller
	// can hand it CP1251 or Shift-JIS text that no UTF-8 reading recovers —
	// the case the parser has to name rather than silently mangle. It wins
	// over RelativePath where both are set.
	RelativePathANSI []byte

	// NoLinkInfo omits the LinkInfo structure entirely. Every historical
	// fixture here carried one, which is precisely why a link that names its
	// target only through StringData was never exercised.
	NoLinkInfo bool

	// TruncatedIDList writes a target ID list whose declared item size runs
	// past the end of the list. A shell link that cannot be fully parsed is
	// still evidence and the failure has to be visible rather than discarded.
	TruncatedIDList bool

	// TruncatedExtraData writes an ExtraData block whose declared size runs
	// past the end of the file, in place of the terminal block. MS-SHLLINK 2.5
	// ends the list with a size below four, so a block that simply does not fit
	// is a damaged file — and reading it as the end of the list makes a
	// shortcut whose tracker block was cut off look exactly like one that never
	// carried a tracker block.
	TruncatedExtraData bool
}

// BuildLink assembles a shell link file.
func BuildLink(spec LinkSpec) []byte {
	ansi := len(spec.RelativePathANSI) > 0
	flags := uint32(0)
	if !spec.NoLinkInfo {
		flags |= LinkHasLinkInfo
	}
	if !ansi {
		flags |= LinkIsUnicode
	}
	if spec.Name != "" {
		flags |= LinkHasName
	}
	if spec.RelativePath != "" || ansi {
		flags |= LinkHasRelativePath
	}
	if spec.TruncatedIDList {
		flags |= LinkHasLinkTargetIDList
	}

	header := make([]byte, linkHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], linkHeaderSize)
	copy(header[4:20], linkCLSID[:])
	binary.LittleEndian.PutUint32(header[20:24], flags)
	binary.LittleEndian.PutUint64(header[28:36], spec.TargetCreated)
	binary.LittleEndian.PutUint64(header[36:44], spec.TargetAccessed)
	binary.LittleEndian.PutUint64(header[44:52], spec.TargetWritten)
	binary.LittleEndian.PutUint32(header[52:56], spec.TargetSize)

	out := header
	if spec.TruncatedIDList {
		out = append(out, truncatedIDList()...)
	}
	if !spec.NoLinkInfo {
		out = append(out, buildLinkInfo(spec)...)
	}

	// StringData, in the order MS-SHLLINK 2.4 fixes: NAME_STRING then
	// RELATIVE_PATH. The count is characters, not bytes, and the Unicode flag
	// in the header decides which — so it governs every field in the run and
	// the two cannot be mixed within one file.
	if spec.Name != "" {
		out = append(out, buildStringData(spec.Name, nil, ansi)...)
	}
	if flags&LinkHasRelativePath != 0 {
		out = append(out, buildStringData(spec.RelativePath,
			spec.RelativePathANSI, ansi)...)
	}
	if spec.TruncatedExtraData {
		// A block declaring far more than remains, and a signature after it so
		// the first eight bytes are present: the damage is in the size alone.
		block := make([]byte, 8)
		binary.LittleEndian.PutUint32(block[0:4], 0x7000)
		binary.LittleEndian.PutUint32(block[4:8], 0xA0000003)
		return append(out, block...)
	}
	// The terminal block, so a reader walking ExtraData sees a clean end.
	out = append(out, 0, 0, 0, 0)
	return out
}

// buildStringData writes one counted StringData field. The count is in
// characters, which for the ANSI form is bytes and for the Unicode form is
// UTF-16 code units.
func buildStringData(text string, raw []byte, ansi bool) []byte {
	if !ansi {
		field := make([]byte, 2)
		binary.LittleEndian.PutUint16(field, uint16(len(encodeUTF16(text))/2))
		return append(field, encodeUTF16(text)...)
	}
	bytes := raw
	if bytes == nil {
		bytes = []byte(text)
	}
	field := make([]byte, 2)
	binary.LittleEndian.PutUint16(field, uint16(len(bytes)))
	return append(field, bytes...)
}

// truncatedIDList writes an IDList whose first item declares a size running
// past the end of the list. MS-SHLLINK 2.2: a two-byte size, then the list is
// terminated by a zero size.
func truncatedIDList() []byte {
	const declared = 0x7000
	item := make([]byte, 2)
	binary.LittleEndian.PutUint16(item, declared)
	item = append(item, 'x', 'x', 'x', 'x')

	list := make([]byte, 2)
	binary.LittleEndian.PutUint16(list, uint16(len(item)+2))
	list = append(list, item...)
	list = append(list, 0, 0)
	return list
}

// buildLinkInfo writes the LinkInfo structure, using the long header form so
// the Unicode offsets are available.
func buildLinkInfo(spec LinkSpec) []byte {
	// The long header: 0x24 reaches LocalBasePathOffsetUnicode, 0x28 reaches
	// CommonPathSuffixOffsetUnicode.
	const headerSize = 0x24

	var flags uint32
	if spec.VolumeIDPresent || spec.LocalBasePath != "" {
		flags |= linkInfoVolumeIDAndLocalBasePath
	}
	if spec.NetworkShare != "" {
		flags |= linkInfoCommonNetworkRelativeLinkAndSuffix
	}

	// Bodies first, then the offsets that point at them.
	var body []byte
	at := func() uint32 { return uint32(headerSize + len(body)) }

	var volumeOffset, localOffset, networkOffset, commonOffset uint32

	if spec.VolumeIDPresent {
		volumeOffset = at()
		body = append(body, buildVolumeID(spec)...)
	}
	if spec.LocalBasePath != "" {
		localOffset = at()
		body = append(body, []byte(spec.LocalBasePath)...)
		body = append(body, 0)
	}
	if spec.NetworkShare != "" {
		networkOffset = at()
		body = append(body, buildNetworkRelativeLink(spec, uint32(headerSize)+uint32(len(body)))...)
	}
	// The suffix is always written, because MS-SHLLINK always has the field
	// even when it is the empty string.
	commonOffset = at()
	body = append(body, []byte(spec.CommonPathSuffix)...)
	body = append(body, 0)

	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[4:8], headerSize)
	binary.LittleEndian.PutUint32(header[8:12], flags)
	binary.LittleEndian.PutUint32(header[12:16], volumeOffset)
	binary.LittleEndian.PutUint32(header[16:20], localOffset)
	binary.LittleEndian.PutUint32(header[20:24], networkOffset)
	binary.LittleEndian.PutUint32(header[24:28], commonOffset)
	// The Unicode offsets stay zero: these fixtures write the ANSI forms,
	// which is what a link from an English-language host carries.
	binary.LittleEndian.PutUint32(header[28:32], 0)
	binary.LittleEndian.PutUint32(header[32:36], 0)

	info := append(header, body...)
	binary.LittleEndian.PutUint32(info[0:4], uint32(len(info)))
	return info
}

// buildVolumeID writes the VolumeID structure, MS-SHLLINK 2.3.1.
func buildVolumeID(spec LinkSpec) []byte {
	volume := make([]byte, 16)
	binary.LittleEndian.PutUint32(volume[4:8], spec.DriveType)
	binary.LittleEndian.PutUint32(volume[8:12], spec.DriveSerial)
	binary.LittleEndian.PutUint32(volume[12:16], 16)
	volume = append(volume, []byte(spec.VolumeLabel)...)
	volume = append(volume, 0)
	binary.LittleEndian.PutUint32(volume[0:4], uint32(len(volume)))
	return volume
}

// buildNetworkRelativeLink writes the CommonNetworkRelativeLink structure,
// MS-SHLLINK 2.3.2. base is where this structure will sit inside the LinkInfo,
// which the Unicode offsets are relative to in the same way the ANSI ones are
// relative to the structure itself.
func buildNetworkRelativeLink(spec LinkSpec, base uint32) []byte {
	const validDevice = 0x1

	// The long header form, so NetNameOffsetUnicode is available. MS-SHLLINK
	// says a NetNameOffset greater than 0x14 means the Unicode fields follow.
	headerSize := 0x14
	if spec.NetworkShareUnicode {
		headerSize = 0x24
	}

	share := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(share[4:8], 0)
	binary.LittleEndian.PutUint32(share[8:12], uint32(headerSize)) // NetNameOffset
	binary.LittleEndian.PutUint32(share[12:16], 0)                 // DeviceNameOffset
	binary.LittleEndian.PutUint32(share[16:20], validDevice)

	if spec.NetworkShareUnicode {
		// The ANSI net name is written as an empty string and the real one
		// goes in the Unicode field, which is the shape Boobook did not read:
		// a reader taking the ANSI field alone gets nothing and reports the
		// link as having no network target at all.
		nameOffset := uint32(len(share))
		share = append(share, 0) // empty ANSI net name
		binary.LittleEndian.PutUint32(share[8:12], nameOffset)

		unicodeAt := uint32(len(share))
		binary.LittleEndian.PutUint32(share[20:24], unicodeAt) // NetNameOffsetUnicode
		binary.LittleEndian.PutUint32(share[24:28], 0)         // DeviceNameOffsetUnicode
		share = append(share, encodeUTF16(spec.NetworkShare)...)
		share = append(share, 0, 0)
	} else {
		share = append(share, []byte(spec.NetworkShare)...)
		share = append(share, 0)
	}

	binary.LittleEndian.PutUint32(share[0:4], uint32(len(share)))
	_ = base
	return share
}
