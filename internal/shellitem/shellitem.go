// Package shellitem reads the shell item lists (PIDLs) that Windows stores in
// shell bags, RecentDocs, the file dialog MRUs and shell links.
//
// A shell item list is how Explorer records a place it has been. For a USB
// examination that matters because a bag can name a folder on a removable
// volume long after the volume is gone, and the item carries the folder's own
// timestamps rather than the registry key's.
//
// Two things are treated carefully throughout. The timestamps are FAT date and
// time values, which are local wall clock with no zone recorded, so they are
// never presented as UTC instants. And the format is documented by reverse
// engineering rather than by specification: where a field cannot be read with
// confidence the item says so instead of offering a value.
package shellitem

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Bloggzy/boobook/internal/wintime"
)

// Kind names what a shell item identifies.
type Kind string

const (
	KindRootFolder   Kind = "root_folder"
	KindVolume       Kind = "volume"
	KindFileEntry    Kind = "file_entry"
	KindNetwork      Kind = "network"
	KindURI          Kind = "uri"
	KindControlPanel Kind = "control_panel"
	KindUnknown      Kind = "unknown"
)

// extensionSignature marks the file entry extension block that carries the long
// name and the creation and access times.
const extensionSignature = 0xBEEF0004

// fileAttributeDirectory is FILE_ATTRIBUTE_DIRECTORY.
const fileAttributeDirectory = 0x10

// Item is one element of a shell item list.
//
// Raw holds the stored bytes in hex for every item, decoded or not. An item
// this package cannot read is still evidence, and a list that silently dropped
// one would misstate the path.
type Item struct {
	Kind     Kind
	TypeByte byte
	Position int

	// Name is the most complete name the item carried: the long name where the
	// extension block held one, otherwise the name stored in the item body.
	Name      string
	ShortName string
	LongName  string

	// GUID is set for root folder and control panel items, and KnownFolder
	// names it where the GUID is one of the common shell folders.
	GUID        string
	KnownFolder string

	DriveLetter string
	Directory   bool

	FileSizeBytes uint32
	Attributes    uint16

	// FAT date and time values, stored as read. The derived times are local
	// wall clock readings, not UTC instants: see the package comment.
	RawModified   uint32
	RawCreated    uint32
	RawAccessed   uint32
	ModifiedLocal *time.Time
	CreatedLocal  *time.Time
	AccessedLocal *time.Time

	// MFTEntry and MFTSequence are the NTFS file reference later extension
	// block versions carry. Zero means the block did not hold one.
	MFTEntry    uint64
	MFTSequence uint16

	// ExtensionVersion is the version of the 0xBEEF0004 block, which decides
	// where its fields sit. Zero means no block was read.
	ExtensionVersion uint16

	Raw      string
	Warnings []string
}

func (i *Item) warn(format string, args ...any) {
	i.Warnings = append(i.Warnings, fmt.Sprintf(format, args...))
}

// List is a parsed shell item list.
type List struct {
	Items []Item
	// Truncated records that the list ran out before its terminator, so the
	// path it names is a prefix of the real one rather than the whole of it.
	Truncated bool
	Warnings  []string
}

// Path joins the items into the place they name.
//
// Items that carried no name contribute nothing, and where that happens the
// path is a partial reading of the list rather than a place the user visited.
// HasGap reports it.
func (l *List) Path() string {
	parts := make([]string, 0, len(l.Items))

	for _, item := range l.Items {
		name := item.Name
		if name == "" {
			name = item.KnownFolder
		}
		if name == "" {
			continue
		}
		parts = append(parts, strings.TrimSuffix(name, `\`))
	}

	return strings.Join(parts, `\`)
}

// HasGap reports whether any item in the list contributed no name, which makes
// the path a reading with something missing from the middle.
func (l *List) HasGap() bool {
	for _, item := range l.Items {
		if item.Name == "" && item.KnownFolder == "" {
			return true
		}
	}
	return false
}

// Last returns the final item, which is the thing the list names rather than
// the containers it sits in.
func (l *List) Last() *Item {
	if len(l.Items) == 0 {
		return nil
	}
	return &l.Items[len(l.Items)-1]
}

var errEmpty = errors.New("empty shell item list")

// ParseItem reads a single shell item stored without a list terminator, which
// is how a shell bag stores one step of a path.
func ParseItem(data []byte) (Item, error) {
	if len(data) < 3 {
		return Item{}, errEmpty
	}

	size := int(binary.LittleEndian.Uint16(data[0:2]))
	// The stored size can cover less than the value holds, and a value can be
	// padded. Reading past what the item declared would pull the next thing in.
	//
	// A size that is impossible is a different matter and used to be treated
	// the same way: `size = len(data)` and carry on, so a declared size of 1 or
	// of 60000 both silently became "parse the whole input". That turns
	// malformed framing into apparently valid data — the item comes back with a
	// name and a timestamp assembled from whatever the buffer held, and nothing
	// downstream can tell it from a well-formed one. It is the same failure the
	// prefetch volume decoder guards against: a structure read at the wrong
	// offset does not fail, it produces plausible values.
	//
	// Under-run is refused outright. Over-run is clamped and reported, because
	// a bag value legitimately carries padding after the item and truncating to
	// the buffer is the right reading there — but the caller is told, so the
	// difference between "padded" and "truncated" is not lost.
	if size < 3 {
		return Item{}, fmt.Errorf(
			"shell item declares a size of %d bytes, which is smaller than the "+
				"size field itself", size)
	}
	if size > len(data) {
		item := parseItem(data[2:])
		item.Warnings = append(item.Warnings, fmt.Sprintf(
			"the item declares %d bytes and %d are present, so it is truncated "+
				"and what follows was read from what there was", size, len(data)))
		return item, nil
	}

	return parseItem(data[2:size]), nil
}

// Parse reads a shell item list.
func Parse(data []byte) (*List, error) {
	if len(data) < 2 {
		return nil, errEmpty
	}

	list := &List{}
	offset := 0
	position := 0

	for {
		if offset+2 > len(data) {
			// No terminator was reached. The list names a prefix of a path, and
			// reporting it as complete would understate where the user went.
			list.Truncated = true
			return list, nil
		}

		size := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		if size == 0 {
			return list, nil
		}
		if size < 3 || offset+size > len(data) {
			list.Truncated = true
			list.Warnings = append(list.Warnings, fmt.Sprintf(
				"item %d declares %d bytes with %d left in the list",
				position, size, len(data)-offset))
			return list, nil
		}

		item := parseItem(data[offset+2 : offset+size])
		item.Position = position
		list.Items = append(list.Items, item)

		offset += size
		position++
	}
}

func parseItem(body []byte) Item {
	item := Item{
		Kind:     KindUnknown,
		TypeByte: body[0],
		Raw:      hex.EncodeToString(body),
	}

	switch {
	case item.TypeByte == 0x1F:
		parseRootFolder(&item, body)
	case item.TypeByte&0xF0 == 0x20:
		parseVolume(&item, body)
	case item.TypeByte&0x70 == 0x30:
		parseFileEntry(&item, body)
	case item.TypeByte&0xF0 == 0x40:
		parseNetwork(&item, body)
	case item.TypeByte&0xF0 == 0x60:
		item.Kind = KindURI
	case item.TypeByte&0xF0 == 0x70:
		item.Kind = KindControlPanel
	}

	return item
}

func parseRootFolder(item *Item, body []byte) {
	item.Kind = KindRootFolder
	if len(body) < 18 {
		item.warn("root folder item is too short to hold a class identifier")
		return
	}

	item.GUID = formatGUID(body[2:18])
	item.KnownFolder = knownFolders[strings.ToLower(item.GUID)]
	item.Name = nameFor(item)
}

// nameFor falls back to the class identifier where the folder is not one of the
// well-known ones. A GUID is a poor name and it is the name the evidence held;
// an empty one would read as a gap in the path, which is a different claim.
func nameFor(item *Item) string {
	if item.KnownFolder != "" {
		return item.KnownFolder
	}
	return item.GUID
}

func parseVolume(item *Item, body []byte) {
	item.Kind = KindVolume

	// 0x2F carries the mount point as ASCII, which is the form that names a
	// drive letter and so the form a USB examination turns on.
	if item.TypeByte == 0x2F {
		item.Name = trimNUL(string(body[1:]))
		if len(item.Name) >= 2 && item.Name[1] == ':' {
			item.DriveLetter = strings.ToUpper(item.Name[:1])
		}
		return
	}

	if len(body) >= 17 {
		item.GUID = formatGUID(body[1:17])
		item.KnownFolder = knownFolders[strings.ToLower(item.GUID)]
		item.Name = nameFor(item)
	}
}

func parseNetwork(item *Item, body []byte) {
	item.Kind = KindNetwork
	if len(body) < 6 {
		item.warn("network item is too short to hold a location")
		return
	}
	item.Name = trimNUL(string(body[5:]))
}

func parseFileEntry(item *Item, body []byte) {
	item.Kind = KindFileEntry
	if len(body) < 13 {
		item.warn("file entry is too short to hold its fixed fields")
		return
	}

	item.FileSizeBytes = binary.LittleEndian.Uint32(body[2:6])
	item.RawModified = binary.LittleEndian.Uint32(body[6:10])
	item.ModifiedLocal = dosTime(item.RawModified)
	item.Attributes = binary.LittleEndian.Uint16(body[10:12])

	// The low nibble distinguishes a directory from a file, and the attribute
	// flags say the same thing. Either is enough.
	item.Directory = item.TypeByte&0x01 != 0 ||
		item.Attributes&fileAttributeDirectory != 0

	nameEnd := 12
	if item.TypeByte&0x04 != 0 {
		name, end := readUTF16(body, 12)
		item.ShortName = name
		nameEnd = end
	} else {
		name, end := readASCII(body, 12)
		item.ShortName = name
		nameEnd = end
	}
	item.Name = item.ShortName

	parseExtension(item, body, nameEnd)
}

// parseExtension reads the 0xBEEF0004 block, which is where the long name and
// the creation and access times live.
//
// The block is located by the offset the item stores in its last two bytes
// rather than by computing where it ought to start. Where that offset does not
// point at the signature the block is looked for from the aligned end of the
// name instead, and the item records that its position was inferred.
func parseExtension(item *Item, body []byte, nameEnd int) {
	offset, located := locateExtension(body, nameEnd)
	if !located {
		return
	}

	block := body[offset:]
	if len(block) < 18 {
		item.warn("extension block is too short to hold its fixed fields")
		return
	}

	item.ExtensionVersion = binary.LittleEndian.Uint16(block[2:4])
	item.RawCreated = binary.LittleEndian.Uint32(block[8:12])
	item.RawAccessed = binary.LittleEndian.Uint32(block[12:16])
	item.CreatedLocal = dosTime(item.RawCreated)
	item.AccessedLocal = dosTime(item.RawAccessed)

	position := 18
	if item.ExtensionVersion >= 7 {
		// An NTFS file reference, which ties the entry to a specific record in
		// the volume's $MFT rather than to a name that can be reused.
		if len(block) < 36 {
			item.warn("extension block version %d is too short for a file reference",
				item.ExtensionVersion)
			return
		}
		reference := binary.LittleEndian.Uint64(block[20:28])
		item.MFTEntry = reference & 0x0000FFFFFFFFFFFF
		item.MFTSequence = uint16(reference >> 48)
		position = 36
	}

	if item.ExtensionVersion >= 3 {
		if position+2 > len(block) {
			item.warn("extension block ends before its long name")
			return
		}
		position += 2
	}

	if position >= len(block) {
		return
	}

	name, _ := readUTF16(block, position)
	if name == "" {
		return
	}
	item.LongName = name
	item.Name = name
}

// locateExtension finds the 0xBEEF0004 block within a file entry.
func locateExtension(body []byte, nameEnd int) (int, bool) {
	hasSignature := func(offset int) bool {
		return offset >= 0 && offset+8 <= len(body) &&
			binary.LittleEndian.Uint32(body[offset+4:offset+8]) == extensionSignature
	}

	// The item's last two bytes hold the offset of its first extension block.
	if len(body) >= 2 {
		stored := int(binary.LittleEndian.Uint16(body[len(body)-2:]))
		// The offset is relative to the whole item, which includes the two size
		// bytes this body does not.
		if hasSignature(stored - 2) {
			return stored - 2, true
		}
	}

	// Blocks start on a two-byte boundary after the name.
	aligned := nameEnd
	if aligned%2 != 0 {
		aligned++
	}
	if hasSignature(aligned) {
		return aligned, true
	}

	return 0, false
}

func dosTime(value uint32) *time.Time {
	moment, ok := wintime.FromDOSDateTime(value)
	if !ok {
		return nil
	}
	return &moment
}

func readASCII(data []byte, offset int) (string, int) {
	for i := offset; i < len(data); i++ {
		if data[i] == 0 {
			return string(data[offset:i]), i + 1
		}
	}
	return string(data[offset:]), len(data)
}

func readUTF16(data []byte, offset int) (string, int) {
	units := make([]uint16, 0, 32)
	for i := offset; i+1 < len(data); i += 2 {
		unit := binary.LittleEndian.Uint16(data[i : i+2])
		if unit == 0 {
			return string(utf16.Decode(units)), i + 2
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units)), len(data)
}

func trimNUL(text string) string {
	if index := strings.IndexByte(text, 0); index >= 0 {
		return text[:index]
	}
	return text
}

// formatGUID renders the mixed-endian form Windows stores: the first three
// fields little-endian, the rest big-endian.
func formatGUID(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		binary.BigEndian.Uint16(raw[8:10]),
		raw[10:16])
}

// knownFolders names the shell folders that appear at the head of a bag path.
// Without them a path reads as a GUID, which tells an analyst nothing about
// where the user was.
var knownFolders = map[string]string{
	"{20d04fe0-3aea-1069-a2d8-08002b30309d}": "This PC",
	"{208d2c60-3aea-1069-a2d7-08002b30309d}": "Network",
	"{21ec2020-3aea-1069-a2dd-08002b30309d}": "Control Panel",
	"{450d8fba-ad25-11d0-98a8-0800361b1103}": "My Documents",
	"{645ff040-5081-101b-9f08-00aa002f954e}": "Recycle Bin",
	"{59031a47-3f72-44a7-89c5-5595fe6b30ee}": "Users Files",
	"{031e4825-7b94-4dc3-b131-e946b44c8dd5}": "Libraries",
	"{b4bfcc3a-db2c-424c-b029-7fe99a87c641}": "Desktop",
	"{f02c1a0d-be21-4350-88b0-7367fc96ef3c}": "Network Places",
	"{679f85cb-0220-4080-b29b-5540cc05aab6}": "Quick Access",
	"{d3162b92-9365-467a-956b-92703aca08af}": "Documents",
	"{088e3905-0323-4b02-9826-5d99428e115f}": "Downloads",
	"{24ad3ad4-a569-4530-98e1-ab02f9417aa8}": "Pictures",
	"{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}": "Videos",
	"{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}": "Music",
	"{5e6c858f-0e22-4760-9afe-ea3317b67173}": "User Profile",
}
