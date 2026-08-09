package shellitem

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func dosValue(year, month, day, hour, minute, second int) uint32 {
	date := uint16((year-1980)<<9 | month<<5 | day)
	clock := uint16(hour<<11 | minute<<5 | second/2)
	return uint32(date) | uint32(clock)<<16
}

func utf16Bytes(text string) []byte {
	out := make([]byte, 0, len(text)*2+2)
	for _, unit := range utf16.Encode([]rune(text)) {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return append(out, 0, 0)
}

// fileEntry builds a file entry item in the shape Explorer writes: fixed
// fields, a short name, then a 0xBEEF0004 extension block holding the long
// name, and the offset of that block in the item's last two bytes.
func fileEntry(typeByte byte, shortName, longName string,
	version uint16, modified, created, accessed uint32,
	fileReference uint64) []byte {

	fixed := make([]byte, 12)
	fixed[0] = typeByte
	binary.LittleEndian.PutUint32(fixed[2:6], 4096)
	binary.LittleEndian.PutUint32(fixed[6:10], modified)
	binary.LittleEndian.PutUint16(fixed[10:12], 0x20)

	body := append(fixed, append([]byte(shortName), 0)...)
	if len(body)%2 != 0 {
		body = append(body, 0)
	}
	blockStart := len(body)

	block := make([]byte, 18)
	binary.LittleEndian.PutUint16(block[2:4], version)
	binary.LittleEndian.PutUint32(block[4:8], extensionSignature)
	binary.LittleEndian.PutUint32(block[8:12], created)
	binary.LittleEndian.PutUint32(block[12:16], accessed)

	if version >= 7 {
		reference := make([]byte, 18)
		binary.LittleEndian.PutUint64(reference[2:10], fileReference)
		block = append(block, reference...)
	}
	if version >= 3 {
		block = append(block, 0, 0) // localised name size
	}
	block = append(block, utf16Bytes(longName)...)
	binary.LittleEndian.PutUint16(block[0:2], uint16(len(block)))

	body = append(body, block...)
	// The offset of the first extension block, relative to the whole item.
	body = binary.LittleEndian.AppendUint16(body, uint16(blockStart+2))

	return item(body)
}

// item wraps a body in the size field every shell item carries.
func item(body []byte) []byte {
	out := binary.LittleEndian.AppendUint16(nil, uint16(len(body)+2))
	return append(out, body...)
}

func volumeItem(mount string) []byte {
	return item(append([]byte{0x2F}, append([]byte(mount), 0)...))
}

func rootFolder(guid []byte) []byte {
	body := append([]byte{0x1F, 0x00}, guid...)
	return item(body)
}

// thisPC is {20D04FE0-3AEA-1069-A2D8-08002B30309D} in the mixed-endian form
// Windows stores: the first three fields little-endian.
var thisPC = []byte{
	0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10,
	0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D,
}

func list(items ...[]byte) []byte {
	var out []byte
	for _, item := range items {
		out = append(out, item...)
	}
	return append(out, 0, 0)
}

// A bag names a folder on a removable volume long after the volume is gone,
// which is the whole reason this parser exists.
func TestPathAcrossRootVolumeAndFolders(t *testing.T) {
	data := list(
		rootFolder(thisPC),
		volumeItem(`E:\`),
		fileEntry(0x31, "EVIDEN~1", "Evidence", 8,
			dosValue(2026, 7, 26, 10, 0, 6),
			dosValue(2026, 7, 20, 9, 30, 0),
			dosValue(2026, 7, 26, 11, 15, 0), 0x0002000000012345),
	)

	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Truncated {
		t.Error("a terminated list was reported as truncated")
	}
	if len(parsed.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(parsed.Items))
	}
	if parsed.HasGap() {
		t.Error("every item named something, so the path has no gap")
	}

	if want := `This PC\E:\Evidence`; parsed.Path() != want {
		t.Errorf("Path() = %q, want %q", parsed.Path(), want)
	}
	if parsed.Items[1].DriveLetter != "E" {
		t.Errorf("drive letter = %q, want E", parsed.Items[1].DriveLetter)
	}

	folder := parsed.Items[2]
	if folder.Kind != KindFileEntry {
		t.Errorf("kind = %q", folder.Kind)
	}
	if !folder.Directory {
		t.Error("a 0x31 item is a directory")
	}
	// The long name is what the user saw; the short name is what survives in
	// the fixed fields. Both are kept.
	if folder.LongName != "Evidence" || folder.ShortName != "EVIDEN~1" {
		t.Errorf("names = %q / %q", folder.LongName, folder.ShortName)
	}
	if folder.MFTEntry != 0x12345 || folder.MFTSequence != 2 {
		t.Errorf("file reference = %d/%d, want 74565/2",
			folder.MFTEntry, folder.MFTSequence)
	}
	if folder.ModifiedLocal == nil || folder.CreatedLocal == nil ||
		folder.AccessedLocal == nil {
		t.Fatal("the extension block times were not read")
	}
	if got := folder.ModifiedLocal.Format("2006-01-02 15:04:05"); got != "2026-07-26 10:00:06" {
		t.Errorf("modified = %s", got)
	}
	if got := folder.CreatedLocal.Format("2006-01-02 15:04:05"); got != "2026-07-20 09:30:00" {
		t.Errorf("created = %s", got)
	}
	// The raw value is kept beside the derived one so a conversion can be
	// checked rather than trusted.
	if folder.RawCreated != dosValue(2026, 7, 20, 9, 30, 0) {
		t.Error("the stored FAT value was not kept")
	}
}

// Version 3 blocks carry no file reference, and reading one from where version
// 7 keeps it would invent an $MFT record number.
func TestOlderExtensionBlockCarriesNoFileReference(t *testing.T) {
	data := list(fileEntry(0x32, "REPORT~1.DOC", "report final.docx", 3,
		dosValue(2026, 7, 26, 10, 0, 6), 0, 0, 0))

	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	entry := parsed.Items[0]

	if entry.LongName != "report final.docx" {
		t.Errorf("long name = %q", entry.LongName)
	}
	if entry.MFTEntry != 0 {
		t.Errorf("MFTEntry = %d, want 0 for a version 3 block", entry.MFTEntry)
	}
	if entry.Directory {
		t.Error("a 0x32 item is a file")
	}
	// A zero FAT value is absence, not midnight on 1 January 1980.
	if entry.CreatedLocal != nil {
		t.Errorf("created = %v, want no derived time", entry.CreatedLocal)
	}
}

// An item this package cannot read is still evidence. Dropping it would shorten
// the path silently and misstate where the user went.
func TestUnreadableItemIsKeptAndTheGapIsReported(t *testing.T) {
	data := list(
		volumeItem(`E:\`),
		item([]byte{0x74, 0x00, 0x11, 0x22, 0x33}),
	)

	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(parsed.Items))
	}
	if !parsed.HasGap() {
		t.Error("an item that named nothing must be reported as a gap")
	}
	if parsed.Items[1].Raw == "" {
		t.Error("an item that could not be read must still carry its bytes")
	}
}

// A list that ends without its terminator names a prefix of a path. Reporting
// it as complete would understate where the user went.
func TestTruncatedListIsReportedAsTruncated(t *testing.T) {
	data := list(volumeItem(`E:\`), rootFolder(thisPC))
	data = data[:len(data)-6]

	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Truncated {
		t.Error("a list with no terminator must be reported as truncated")
	}
	if len(parsed.Warnings) == 0 {
		t.Error("the shortfall must be described")
	}
}

func TestRootFolderResolvesAKnownShellFolder(t *testing.T) {
	parsed, err := Parse(list(rootFolder(thisPC)))
	if err != nil {
		t.Fatal(err)
	}

	root := parsed.Items[0]
	if root.GUID != "{20d04fe0-3aea-1069-a2d8-08002b30309d}" {
		t.Errorf("GUID = %q", root.GUID)
	}
	if root.KnownFolder != "This PC" {
		t.Errorf("KnownFolder = %q", root.KnownFolder)
	}
}

// A GUID is a poor name and it is the name the evidence held. An empty one
// would read as a gap in the path, which is a different claim.
func TestUnknownRootFolderIsNamedByItsClassIdentifier(t *testing.T) {
	guid := make([]byte, 16)
	guid[0] = 0x11
	guid[15] = 0x99

	parsed, err := Parse(list(rootFolder(guid)))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.HasGap() {
		t.Error("an item that named a class identifier is not a gap")
	}
	if got := parsed.Items[0].Name; got != "{00000011-0000-0000-0000-000000000099}" {
		t.Errorf("Name = %q", got)
	}
}

// A unicode file entry stores its short name as UTF-16, and reading it as ASCII
// yields a name with a NUL between every character.
func TestUnicodeFileEntryName(t *testing.T) {
	fixed := make([]byte, 12)
	fixed[0] = 0x36
	body := append(fixed, utf16Bytes("naïve.txt")...)

	parsed, err := Parse(list(item(body)))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Items[0].ShortName; got != "naïve.txt" {
		t.Errorf("ShortName = %q", got)
	}
}

// An impossible declared size is refused or reported, not silently replaced
// with "parse everything".
//
// The clamp was `if size < 3 || size > len(data) { size = len(data) }`, so a
// declared size of 1 and a declared size of 60000 both became "parse the whole
// input". That turns malformed framing into apparently valid data: the item
// comes back with a name and a timestamp assembled from whatever the buffer
// held, and nothing downstream can tell it from a well-formed one.
//
// It is the same failure the prefetch volume decoder guards against and states
// in its own comment — a structure read at the wrong offset does not fail, it
// produces plausible values. The clamp was the guard's opposite.
func TestAnImpossibleItemSizeIsNotSilentlyReadAsTheWholeBuffer(t *testing.T) {
	body := []byte{0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00}

	// Under-run: a size smaller than the size field itself describes nothing.
	// There is no reading to salvage, so it is an error.
	for _, size := range []uint16{0, 1, 2} {
		data := append([]byte{byte(size), byte(size >> 8)}, body...)
		if _, err := ParseItem(data); err == nil {
			t.Errorf("a declared size of %d parsed without error; the whole "+
				"buffer was read as one item and whatever came out is not "+
				"evidence", size)
		}
	}

	// Over-run: the item claims more than is present. A bag value legitimately
	// carries padding, so this is read as far as it goes rather than refused —
	// and the row has to say so, or "padded" and "truncated" are the same
	// output.
	over := append([]byte{0x00, 0xF0}, body...)
	item, err := ParseItem(over)
	if err != nil {
		t.Fatalf("a truncated item must still yield what it has: %v", err)
	}
	if len(item.Warnings) == 0 {
		t.Error("an item declaring 61440 bytes with 10 present carries no " +
			"warning, so a truncated read is indistinguishable from a clean one")
	}

	// And a well-formed item is untouched by any of it.
	good := append([]byte{byte(len(body) + 2), 0x00}, body...)
	if _, err := ParseItem(good); err != nil {
		t.Errorf("a well-formed item was refused: %v", err)
	}
}
