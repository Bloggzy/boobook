package lnk

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/Bloggzy/boobook/internal/fixture"
)

// build assembles a shell link with the parts a test needs, so the parser is
// exercised against the layout rather than against a fixture whose provenance
// nobody can check.
type builder struct {
	flags      uint32
	created    uint64
	accessed   uint64
	written    uint64
	size       uint32
	linkInfo   []byte
	strings    []string
	unicode    bool
	extraData  []byte
	idListSize int
}

func (b *builder) bytes() []byte {
	header := make([]byte, headerSize)
	binary.LittleEndian.PutUint32(header[0:4], headerSize)
	copy(header[4:20], linkCLSID[:])
	binary.LittleEndian.PutUint32(header[20:24], b.flags)
	binary.LittleEndian.PutUint64(header[28:36], b.created)
	binary.LittleEndian.PutUint64(header[36:44], b.accessed)
	binary.LittleEndian.PutUint64(header[44:52], b.written)
	binary.LittleEndian.PutUint32(header[52:56], b.size)

	out := header
	if b.idListSize > 0 {
		list := make([]byte, 2+b.idListSize)
		binary.LittleEndian.PutUint16(list[0:2], uint16(b.idListSize))
		out = append(out, list...)
	}
	out = append(out, b.linkInfo...)

	for _, text := range b.strings {
		field := make([]byte, 2)
		if b.unicode {
			binary.LittleEndian.PutUint16(field[0:2], uint16(len(text)))
			for _, r := range text {
				unit := make([]byte, 2)
				binary.LittleEndian.PutUint16(unit, uint16(r))
				field = append(field, unit...)
			}
		} else {
			binary.LittleEndian.PutUint16(field[0:2], uint16(len(text)))
			field = append(field, []byte(text)...)
		}
		out = append(out, field...)
	}

	out = append(out, b.extraData...)
	return out
}

// removableLinkInfo builds a LinkInfo naming a removable volume, which is the
// structure the whole drive-letter chain depends on.
func removableLinkInfo(driveType, serial uint32, label, path string) []byte {
	const infoHeader = 0x1C
	volume := make([]byte, 16+len(label)+1)
	binary.LittleEndian.PutUint32(volume[0:4], uint32(len(volume)))
	binary.LittleEndian.PutUint32(volume[4:8], driveType)
	binary.LittleEndian.PutUint32(volume[8:12], serial)
	binary.LittleEndian.PutUint32(volume[12:16], 16)
	copy(volume[16:], label)

	volumeOffset := infoHeader
	pathOffset := volumeOffset + len(volume)
	commonOffset := pathOffset + len(path) + 1

	info := make([]byte, commonOffset+1)
	binary.LittleEndian.PutUint32(info[0:4], uint32(len(info)))
	binary.LittleEndian.PutUint32(info[4:8], infoHeader)
	binary.LittleEndian.PutUint32(info[8:12], 0x1) // volume id and local base path
	binary.LittleEndian.PutUint32(info[12:16], uint32(volumeOffset))
	binary.LittleEndian.PutUint32(info[16:20], uint32(pathOffset))
	copy(info[volumeOffset:], volume)
	copy(info[pathOffset:], path)

	return info
}

func TestParseReadsRemovableVolumeEvidence(t *testing.T) {
	const written = uint64(133700000000000000)

	link, err := Parse((&builder{
		flags:    hasLinkInfo | hasName | isUnicode,
		written:  written,
		size:     10485760,
		linkInfo: removableLinkInfo(DriveRemovable, 0xE6079156, "TEST", `E:\10MB-TESTFILE.ORG.pdf`),
		strings:  []string{"a test file"},
		unicode:  true,
	}).bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !link.Removable() {
		t.Error("the link recorded removable media and Removable() said otherwise")
	}
	if link.DriveLetter != "E" {
		t.Errorf("DriveLetter = %q, want E", link.DriveLetter)
	}
	if link.VolumeLabel != "TEST" {
		t.Errorf("VolumeLabel = %q", link.VolumeLabel)
	}
	if got := SerialHex(link.DriveSerialNumber); got != "E607-9156" {
		t.Errorf("serial = %q, want E607-9156", got)
	}
	if link.LocalBasePath != `E:\10MB-TESTFILE.ORG.pdf` {
		t.Errorf("LocalBasePath = %q", link.LocalBasePath)
	}
	if link.TargetWritten == nil {
		t.Fatal("no written time was derived")
	}
	// The raw value is kept beside the derived one so the conversion can be
	// checked rather than trusted.
	if link.RawTargetWritten != written {
		t.Errorf("RawTargetWritten = %d, want %d", link.RawTargetWritten, written)
	}
	if link.Name != "a test file" {
		t.Errorf("Name = %q", link.Name)
	}
}

// A link with no volume information said nothing about the media. Reporting it
// as a fixed disk would be inventing evidence, so Removable() must be false and
// VolumeIDPresent must say why.
func TestLinkWithoutVolumeInformationClaimsNothing(t *testing.T) {
	link, err := Parse((&builder{flags: hasName | isUnicode, strings: []string{"x"}}).bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if link.VolumeIDPresent {
		t.Error("VolumeIDPresent should be false")
	}
	if link.Removable() {
		t.Error("a link with no volume information must not be reported as removable")
	}
	if link.DriveType != DriveUnknown {
		t.Errorf("DriveType = %d, want unknown", link.DriveType)
	}
}

func TestParseRejectsNonLinks(t *testing.T) {
	cases := map[string][]byte{
		"empty":        {},
		"short":        make([]byte, 20),
		"wrong size":   append([]byte{0xFF, 0, 0, 0}, make([]byte, 100)...),
		"wrong clsid":  append([]byte{0x4C, 0, 0, 0}, make([]byte, 100)...),
		"prefetch-ish": []byte("MAM\x04SCCA"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// A truncated link must yield what was readable with a warning, not a silent
// half-parse presented as complete.
func TestTruncatedLinkWarns(t *testing.T) {
	data := (&builder{flags: hasLinkTargetIDList, idListSize: 200}).bytes()
	data = data[:headerSize+10]

	link, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(link.Warnings) == 0 {
		t.Error("a truncated link must warn")
	}
}

func TestTrackerBlockGivesMachineAndVolumeIdentity(t *testing.T) {
	block := make([]byte, 0x60)
	binary.LittleEndian.PutUint32(block[0:4], 0x60)
	binary.LittleEndian.PutUint32(block[4:8], trackerDataSignature)
	copy(block[16:32], "DESKTOP-SGI03ED\x00")
	// A mixed-endian GUID: the first three fields little-endian.
	copy(block[32:48], []byte{
		0x18, 0xf0, 0xb1, 0x0e, 0xc4, 0x1b, 0xf0, 0x11,
		0xbd, 0xde, 0x00, 0x0c, 0x29, 0x98, 0x9b, 0xd3,
	})

	link, err := Parse((&builder{extraData: block}).bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if link.MachineID != "DESKTOP-SGI03ED" {
		t.Errorf("MachineID = %q", link.MachineID)
	}
	if want := "{0eb1f018-1bc4-11f0-bdde-000c29989bd3}"; link.DroidVolumeID != want {
		t.Errorf("DroidVolumeID = %q, want %q", link.DroidVolumeID, want)
	}
	// An all-zero GUID is absence, not an identifier.
	if link.BirthDroidFileID != "" {
		t.Errorf("BirthDroidFileID = %q, want empty", link.BirthDroidFileID)
	}
}

func TestDriveTypeNameDoesNotInvent(t *testing.T) {
	if got := DriveTypeName(DriveRemovable); got != "removable" {
		t.Errorf("DriveTypeName(2) = %q", got)
	}
	if got := DriveTypeName(99); got != "99" {
		t.Errorf("DriveTypeName(99) = %q, want the value back", got)
	}
}

// A shortcut to a drive root carries the FAT epoch in all three header times at
// once, beside a zero size: the target had no timestamps, and Windows widened a
// zeroed DOS date into a FILETIME. Read as a write time it puts the record in
// 1980 and drags the reported span of a whole case back with it.
func TestAShortcutToADriveRootReportsNoTargetTimes(t *testing.T) {
	const fatEpoch = uint64(119600064000000000)

	builder := &builder{
		flags:    0x83,
		created:  fatEpoch,
		accessed: fatEpoch,
		written:  fatEpoch,
		linkInfo: removableLinkInfo(2, 0xE6079156, "FIELDWORK", `E:\`),
	}

	link, err := Parse(builder.bytes())
	if err != nil {
		t.Fatal(err)
	}

	if link.TargetWritten != nil || link.TargetCreated != nil ||
		link.TargetAccessed != nil {
		t.Errorf("the FAT epoch was read as a real time: written=%v created=%v "+
			"accessed=%v", link.TargetWritten, link.TargetCreated,
			link.TargetAccessed)
	}

	// The stored value stays. What the record holds is evidence; what it means
	// is the reading, and only the reading is refused here.
	if link.RawTargetWritten != fatEpoch {
		t.Errorf("raw written = %d, want the stored %d",
			link.RawTargetWritten, fatEpoch)
	}
}

// MS-SHLLINK stores a local target in two fields and the path is both of them.
//
// Section 2.3: LinkInfo carries a LocalBasePath and a CommonPathSuffix, and the
// full path is the concatenation. Explorer routinely splits one — the directory
// in the base, the file name in the suffix — and Boobook read the base alone,
// so a link to a document was recorded as the folder that held it.
//
// That is not a cosmetic loss. The path is what reaches file-activity.csv, the
// timeline and the report, and a row saying a user opened `E:\Reports\` when
// they opened `E:\Reports\payroll.xlsx` is wrong about the only thing an
// analyst is reading it for. It also breaks the distinct-path counts, because
// every file in one folder collapses to the same string.
//
// Nothing caught it because every fixture in this file put the whole path in
// the base — the shape that happens to make the missing half invisible.
func TestATargetPathIsItsBaseAndItsCommonSuffixTogether(t *testing.T) {
	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		LocalBasePath:    `E:\Reports\`,
		CommonPathSuffix: `payroll.xlsx`,
		VolumeIDPresent:  true,
		DriveType:        fixture.DriveRemovable,
		DriveSerial:      0xE6079156,
		VolumeLabel:      "FIELDWORK",
	}))
	if err != nil {
		t.Fatal(err)
	}

	// Both halves are kept as recorded, because where they disagree with the
	// shell items that is a finding rather than a conflict to resolve quietly.
	if link.LocalBasePath != `E:\Reports\` {
		t.Errorf("LocalBasePath = %q", link.LocalBasePath)
	}
	if link.CommonPath != "payroll.xlsx" {
		t.Errorf("CommonPath = %q", link.CommonPath)
	}

	const want = `E:\Reports\payroll.xlsx`
	if got := link.FullPath(); got != want {
		t.Errorf("FullPath() = %q, want %q — the base alone names the folder, "+
			"not the file the user opened", got, want)
	}
	if link.DriveLetter != "E" {
		t.Errorf("DriveLetter = %q, want E", link.DriveLetter)
	}
}

// A network target is the share plus the suffix, and the share can be recorded
// in a Unicode field the ANSI read returns nothing for.
//
// MS-SHLLINK 2.3.2 gives CommonNetworkRelativeLink a NetNameOffsetUnicode that
// is used whenever NetNameOffset is greater than 0x14. Boobook read only the
// ANSI name, so a link with the Unicode form was reported as having no network
// target at all — an absence, which in this tool reads as "there was none"
// rather than "it was not read".
func TestANetworkTargetIsTheShareAndTheSuffixAndIsReadInBothEncodings(t *testing.T) {
	for _, unicode := range []bool{false, true} {
		link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
			NetworkShare:        `\FILESRV01\Cases`,
			NetworkShareUnicode: unicode,
			CommonPathSuffix:    `2026\brief.pdf`,
		}))
		if err != nil {
			t.Fatalf("unicode=%v: %v", unicode, err)
		}

		if link.NetworkShare != `\FILESRV01\Cases` {
			t.Errorf("unicode=%v: NetworkShare = %q, want the share — a share "+
				"read as empty reports the link as having no network target",
				unicode, link.NetworkShare)
		}
		const want = `\FILESRV01\Cases\2026\brief.pdf`
		if got := link.FullPath(); got != want {
			t.Errorf("unicode=%v: FullPath() = %q, want %q", unicode, got, want)
		}
	}
}

// A link whose target ID list cannot be parsed is still evidence, and the
// failure has to be visible.
//
// The ID list error was discarded outright: the link parsed, the shell-item
// target came out empty, and nothing anywhere said a structure had been
// refused. An empty target reads as "the link named no target", which is a
// statement about the evidence rather than about the parse.
func TestAnUnreadableTargetIDListIsWarnedAboutRatherThanDiscarded(t *testing.T) {
	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		TruncatedIDList:  true,
		LocalBasePath:    `E:\`,
		CommonPathSuffix: `report.docx`,
	}))
	if err != nil {
		t.Fatalf("a link with a bad ID list must still parse: %v", err)
	}

	// The half that did parse survives, which is the standing rule: kept and
	// labelled, never dropped.
	if got := link.FullPath(); got != `E:\report.docx` {
		t.Errorf("FullPath() = %q; the LinkInfo is intact and must survive a "+
			"bad ID list", got)
	}
	if len(link.Warnings) == 0 {
		t.Error("the ID list failed to parse and the link carries no warning, " +
			"so an empty shell-item target is indistinguishable from a link " +
			"that named none")
	}
}

// An extra data list that stops mid-block says so, rather than reading as a
// clean end.
//
// MS-SHLLINK 2.5 terminates the list with a size below four. Any other size
// that does not fit is a damaged file — and both used to end the walk the same
// silent way, so a shortcut whose tracker block was cut off by a collector
// copying it mid-write produced exactly the output of a shortcut that never
// carried one. An absent machine id then reads as "the link recorded none".
func TestAnExtraDataListThatStopsMidBlockIsWarnedAbout(t *testing.T) {
	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		TruncatedExtraData: true,
		LocalBasePath:      `E:\`,
		CommonPathSuffix:   `report.docx`,
		VolumeIDPresent:    true,
		DriveType:          fixture.DriveRemovable,
	}))
	if err != nil {
		t.Fatalf("a link with damaged extra data must still parse: %v", err)
	}
	if got := link.FullPath(); got != `E:\report.docx` {
		t.Errorf("FullPath() = %q; what parsed before the damage survives", got)
	}
	if len(link.Warnings) == 0 {
		t.Error("the extra data ran off the end of the file and the link " +
			"carries no warning, so a missing tracker block is " +
			"indistinguishable from a link that never had one")
	}
}

// A non-Unicode string above 0x7F is read as UTF-8 and the row says so.
//
// MS-SHLLINK's ANSI strings are in the host's own code page and the shortcut
// does not record which. Go reads the bytes as UTF-8, which is right for ASCII
// and wrong above it: a path written on a CP1251 host comes out as replacement
// characters, or as a different string that still looks like a path. Guessing
// the code page would invent evidence, so the value is kept and the assumption
// is named — the same division as an unresolved wall clock.
func TestANonUnicodePathAboveASCIISaysItsDecodingIsInDoubt(t *testing.T) {
	// Two CP1251 bytes, which are not valid UTF-8 and are what an ANSI field
	// from a Russian-language host actually holds.
	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		LocalBasePath:    "E:\\" + string([]byte{0xCF, 0xF0}) + "\\",
		CommonPathSuffix: "report.docx",
		VolumeIDPresent:  true,
		DriveType:        fixture.DriveRemovable,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(link.Warnings) == 0 {
		t.Fatal("a non-Unicode path above 0x7F was decoded silently as UTF-8")
	}
	if !strings.Contains(strings.Join(link.Warnings, " "), "code page") {
		t.Errorf("warnings = %q, want one naming the code page assumption",
			link.Warnings)
	}

	// And an ASCII link must stay silent, or every ordinary shortcut on an
	// English-language host carries a caveat and the real cases stop being
	// visible.
	plain, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		LocalBasePath:    `E:\Reports\`,
		CommonPathSuffix: `payroll.xlsx`,
		VolumeIDPresent:  true,
		DriveType:        fixture.DriveRemovable,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(plain.Warnings) != 0 {
		t.Errorf("an ASCII link warned: %q", plain.Warnings)
	}
}

// A link can name its target through RelativePath and nothing else, and reading
// LinkInfo alone threw the name away.
//
// MS-SHLLINK 2.4 defines RELATIVE_PATH as the path to use when resolving the
// target. Boobook parsed the field, stored it nowhere, and built the row's path
// from LinkInfo — so a shortcut carrying only this completed a whole run with a
// drive letter, an empty path, and a timeline row asserting that an unnamed file
// was opened. The shortcut held the name the whole time.
//
// Nothing caught it because every fixture here gave its links a LocalBasePath.
// A fixture that is easier to build than the real artefact is usually easier
// because it left out the part that goes wrong.
func TestALinkThatNamesItsTargetOnlyThroughTheRelativePathStillNamesIt(t *testing.T) {
	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		NoLinkInfo:   true,
		RelativePath: `..\Reports\payroll.xlsx`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if want := `..\Reports\payroll.xlsx`; link.RelativePath != want {
		t.Errorf("RelativePath = %q, want %q", link.RelativePath, want)
	}
	// And it is kept as recorded rather than joined onto something to make it
	// absolute. A relative path is relative to a directory the link does not
	// record, so completing it would be a guess in the shape of a path.
	if link.FullPath() != "" {
		t.Errorf("FullPath() = %q: a relative path must not be promoted to the "+
			"resolved LinkInfo target", link.FullPath())
	}
}

// The same field in the form that cannot be read as UTF-8.
//
// Non-Unicode StringData is in the host's ANSI code page and the shortcut does
// not record which one, exactly as for the LinkInfo strings — but only the
// LinkInfo path said so. A path written on a CP1251 host came back as
// replacement characters with nothing marking the row as doubtful.
func TestANonUnicodeRelativePathSaysItsCodePageIsUnknown(t *testing.T) {
	// CP1251 for "Отчет" — bytes no UTF-8 decoding recovers.
	cyrillic := []byte{0xCE, 0xF2, 0xF7, 0xE5, 0xF2}
	raw := append([]byte(`E:\`), cyrillic...)

	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		NoLinkInfo:       true,
		RelativePathANSI: raw,
	}))
	if err != nil {
		t.Fatal(err)
	}

	// The bytes are kept exactly as read. Guessing the code page would invent
	// evidence and the value that would settle it is in the registry.
	if link.RelativePath != string(raw) {
		t.Errorf("RelativePath = %q, want the bytes as recorded", link.RelativePath)
	}
	var warned bool
	for _, warning := range link.Warnings {
		if strings.Contains(warning, "relative path") &&
			strings.Contains(warning, "code page") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("no warning named the code page assumption; warnings were %v. "+
			"A row read under an assumption the reader cannot see is one they "+
			"cannot check", link.Warnings)
	}
	if link.DriveLetter != "E" {
		t.Errorf("DriveLetter = %q, want E: the letter is ASCII whatever the "+
			"rest of the path is", link.DriveLetter)
	}
}

// An ASCII link stays silent, or every ordinary shortcut on an English-language
// host carries the caveat and the real cases stop being visible.
func TestAnASCIIRelativePathCarriesNoCodePageCaveat(t *testing.T) {
	link, err := Parse(fixture.BuildLink(fixture.LinkSpec{
		NoLinkInfo:       true,
		RelativePathANSI: []byte(`E:\report.docx`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range link.Warnings {
		if strings.Contains(warning, "code page") {
			t.Errorf("an ASCII string was reported as doubtful: %q", warning)
		}
	}
}
