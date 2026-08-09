package registry

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/Bloggzy/boobook/internal/shellitem"
)

// utf16String renders text as a NUL-terminated UTF-16LE value, which is how
// these lists store the string that precedes their shell items.
func utf16String(text string) []byte {
	out := make([]byte, 0, len(text)*2+2)
	for _, unit := range utf16.Encode([]rune(text)) {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return append(out, 0, 0)
}

func shellItem(body []byte) []byte {
	out := binary.LittleEndian.AppendUint16(nil, uint16(len(body)+2))
	return append(out, body...)
}

func volumeItem(mount string) []byte {
	return shellItem(append([]byte{0x2F}, append([]byte(mount), 0)...))
}

func fileItem(name string) []byte {
	body := make([]byte, 12)
	body[0] = 0x32
	return shellItem(append(body, append([]byte(name), 0)...))
}

// MRUListEx records the order entries were last used in, most recent first. It
// is what turns a set of values into a sequence, and without it a report cannot
// say which file was opened last.
func TestDecodeMRUListExStopsAtTheTerminator(t *testing.T) {
	raw := binary.LittleEndian.AppendUint32(nil, 4)
	raw = binary.LittleEndian.AppendUint32(raw, 0)
	raw = binary.LittleEndian.AppendUint32(raw, 2)
	raw = binary.LittleEndian.AppendUint32(raw, 0xFFFFFFFF)
	// Anything after the terminator is not part of the order.
	raw = binary.LittleEndian.AppendUint32(raw, 9)

	order := decodeMRUListEx(raw)
	if len(order) != 3 {
		t.Fatalf("got %d entries, want 3: %v", len(order), order)
	}
	if order[0] != 4 || order[2] != 2 {
		t.Errorf("order = %v, want [4 0 2]", order)
	}
}

// The file dialog stores the executable that was doing the opening, then the
// place it was pointed at. Which application opened a file on a removable
// volume is often the question being asked.
func TestLastVisitedValueYieldsBothTheApplicationAndThePlace(t *testing.T) {
	raw := utf16String("brave.exe")
	raw = append(raw, volumeItem(`E:\`)...)
	raw = append(raw, fileItem("report.docx")...)
	raw = append(raw, 0, 0)

	entry := MRUEntry{Position: -1}
	executable, next := readUTF16(raw, 0)
	entry.Name = executable
	applyTrailingItems(&entry, raw, next)

	if entry.Name != "brave.exe" {
		t.Errorf("Name = %q", entry.Name)
	}
	if want := `E:\report.docx`; entry.Path != want {
		t.Errorf("Path = %q, want %q", entry.Path, want)
	}
	if entry.DriveLetter != "E" {
		t.Errorf("DriveLetter = %q, want E", entry.DriveLetter)
	}
	if entry.PathHasGap {
		t.Error("every item named something, so there is no gap")
	}
}

// Guessing at a format is how a report acquires a path nobody can find in the
// evidence. Trailing bytes that do not parse into items must leave no path
// behind, only the stored bytes.
func TestTrailingBytesThatAreNotShellItemsClaimNoPath(t *testing.T) {
	raw := utf16String("thing.txt")
	raw = append(raw, 0x41, 0x42, 0x43, 0x44)

	entry := MRUEntry{Position: -1}
	_, next := readUTF16(raw, 0)
	applyTrailingItems(&entry, raw, next)

	if entry.Path != "" {
		t.Errorf("Path = %q, want empty", entry.Path)
	}
}

// The bag tree stores one item per level and the path is built on the way down.
// A level whose item named nothing leaves a hole in the middle of the path, and
// the row has to say so rather than presenting a shorter path as a real place.
func TestBagPathIsBuiltFromTheParentAndSaysWhenAnItemNamedNothing(t *testing.T) {
	volume, err := shellitem.ParseItem(volumeItem(`E:\`))
	if err != nil {
		t.Fatal(err)
	}

	bag := ShellBag{MRUPosition: -1}
	applyItem(&bag, volume, "This PC")
	if bag.Path != `This PC\E:` {
		t.Errorf("Path = %q", bag.Path)
	}
	if bag.DriveLetter != "E" {
		t.Errorf("DriveLetter = %q", bag.DriveLetter)
	}
	if bag.PathHasGap {
		t.Error("the volume item named something")
	}

	// An item type this package does not decode.
	unknown, err := shellitem.ParseItem(shellItem([]byte{0x74, 0x00, 0x11}))
	if err != nil {
		t.Fatal(err)
	}

	child := ShellBag{MRUPosition: -1}
	applyItem(&child, unknown, `This PC\E:`)
	if !child.PathHasGap {
		t.Error("an item that named nothing must be reported as a gap")
	}
	if child.Path != `This PC\E:` {
		// The path stops where the naming stopped rather than inventing a step.
		t.Errorf("Path = %q, want the parent path", child.Path)
	}
}

func TestShortSourceTrimsTheExplorerPrefix(t *testing.T) {
	got := shortSource(`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx`)
	if got != `RecentDocs\.docx` {
		t.Errorf("shortSource = %q", got)
	}
	// A path the prefixes do not cover comes back whole rather than mangled.
	if got := shortSource(`MountedDevices`); got != "MountedDevices" {
		t.Errorf("shortSource = %q", got)
	}
}

// RecentDocs stores the caption Explorer displayed, and for a drive root that
// caption carries both the volume's label and its letter. The shell items that
// follow point at the shortcut in the Recent folder rather than at the drive,
// so they yield a .lnk name and no letter — which is why these entries reached
// the report with no drive letter at all, five of them naming a stick on
// USB-LENOVO-Multi-USBs.
//
// The label is the half worth having. MountedDevices records only the mapping
// as it stood at collection, and on that host it was a minute stale; this
// caption is what the volume called itself when the entry was written.
func TestADriveRootRemembersWhatTheLetterMeantAtTheTime(t *testing.T) {
	for _, test := range []struct {
		name, letter, label string
	}{
		{`PATRIOT (E:)`, "E", "PATRIOT"},
		{`A2-64 (G:)`, "G", "A2-64"},
		// No label to show, so the shell shows the letter alone.
		{`E:\`, "E", ""},
		{`E:`, "E", ""},
		// A lower-case letter is normalised, because a shell item's letter is.
		{`Backup (f:)`, "F", "Backup"},
		// A label may itself contain brackets; only the tail is the letter.
		{`Job (2024) (E:)`, "E", "Job (2024)"},
	} {
		entry := MRUEntry{Name: test.name, Position: -1}
		applyDriveRootName(&entry)

		if entry.DriveLetter != test.letter {
			t.Errorf("%q: DriveLetter = %q, want %q",
				test.name, entry.DriveLetter, test.letter)
		}
		if entry.VolumeLabel != test.label {
			t.Errorf("%q: VolumeLabel = %q, want %q",
				test.name, entry.VolumeLabel, test.label)
		}
		if test.letter != "" && !entry.LetterFromName {
			t.Errorf("%q: the letter came from the name and must say so",
				test.name)
		}
	}
}

// Where a volume carries no label of its own the shell substitutes a caption of
// its own making. Taking that for a label would offer the label routes a name
// no volume ever had, and "Removable Disk" matching a device somebody really
// did label that way would be an attribution built on nothing.
//
// The letter is still read: that part of the caption is as good as any other.
func TestTheShellsOwnCaptionIsNotAVolumeLabel(t *testing.T) {
	for _, name := range []string{
		`Removable Disk (E:)`, `Local Disk (C:)`, `USB Drive (E:)`,
		`DVD RW Drive (D:)`, `Floppy Disk Drive (A:)`,
	} {
		entry := MRUEntry{Name: name, Position: -1}
		applyDriveRootName(&entry)

		if entry.VolumeLabel != "" {
			t.Errorf("%q: VolumeLabel = %q, want none — the shell wrote that "+
				"caption, the volume did not", name, entry.VolumeLabel)
		}
		if entry.DriveLetter == "" {
			t.Errorf("%q: the letter is still evidence and must survive", name)
		}
	}
}

// A colon cannot appear in a Windows file or folder name, so a caption ending
// " (X:)" was generated by the shell. Anything else is a file the user named,
// and inventing a drive letter for it would put a record on a volume no
// artefact mentions.
func TestAFileNameIsNotADriveRoot(t *testing.T) {
	for _, name := range []string{
		`report.docx`, `Notes (draft)`, `Q1 (final).pdf`, `E`, `E:\folder`,
		`SanDisk-64GB-FAT32.pdf`, ``, `(E:)`,
	} {
		entry := MRUEntry{Name: name, Position: -1}
		applyDriveRootName(&entry)

		if entry.DriveLetter != "" || entry.VolumeLabel != "" {
			t.Errorf("%q: read letter %q and label %q out of a name that is "+
				"not a drive root", name, entry.DriveLetter, entry.VolumeLabel)
		}
	}
}

// The shell items are a parsed structure and the caption is a parsed string.
// Where the items already named a drive, they are the better evidence and the
// caption must not overwrite them — nor claim the letter came from the name.
func TestAParsedShellItemOutranksTheCaption(t *testing.T) {
	entry := MRUEntry{Name: `PATRIOT (E:)`, DriveLetter: "F", Position: -1}
	applyDriveRootName(&entry)

	if entry.DriveLetter != "F" {
		t.Errorf("DriveLetter = %q, want F — the shell item found it first",
			entry.DriveLetter)
	}
	if entry.LetterFromName {
		t.Error("the letter did not come from the name and must not say it did")
	}
	// The label is the caption's alone, so it is still taken.
	if entry.VolumeLabel != "PATRIOT" {
		t.Errorf("VolumeLabel = %q, want PATRIOT", entry.VolumeLabel)
	}
}

// UserAssist stores its names ROT13'd. It is not a secret and never was — it
// keeps them out of a plain string search of the hive — and a reader who has
// not undone it sees nothing but noise.
func TestAUserAssistNameIsStoredUnderROT13(t *testing.T) {
	cases := map[string]string{
		`S:\XNCR\txncr.rkr`: `F:\KAPE\gkape.exe`,
		`HRZR_PGYFRFFVBA`:   `UEME_CTLSESSION`,
		// Digits, punctuation and the path separators are left alone, which is
		// what makes a decoded name usable as a path.
		`P:\Hfref\Nqzva\Qrfxgbc\7m2201-k64.rkr`: `C:\Users\Admin\Desktop\7z2201-x64.exe`,
	}
	for stored, want := range cases {
		if got := rot13(stored); got != want {
			t.Errorf("rot13(%q) = %q, want %q", stored, got, want)
		}
		// It is its own inverse, which is the property that makes one function
		// enough for both directions.
		if got := rot13(rot13(stored)); got != stored {
			t.Errorf("rot13 is not its own inverse for %q", stored)
		}
	}
}

// The Windows 7 and later record: a run count, a focus count, a focus duration
// and the last launch. The focus figures are the reason this artefact is worth
// reading beside prefetch — prefetch can say a programme ran, and nothing else
// can say a person had it in front of them for eighty-three seconds.
func TestALaunchRecordCarriesItsCountsAndItsTime(t *testing.T) {
	raw := make([]byte, 72)
	binary.LittleEndian.PutUint32(raw[0:4], 9)       // session
	binary.LittleEndian.PutUint32(raw[4:8], 2)       // runs
	binary.LittleEndian.PutUint32(raw[8:12], 5)      // focus count
	binary.LittleEndian.PutUint32(raw[12:16], 83220) // focus milliseconds
	binary.LittleEndian.PutUint64(raw[60:68], 133892125800000000)

	entry := readUserAssistValue(
		"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", `...\Count`, "Admin",
		`S:\XNCR\txncr.rkr`, raw)

	if entry.Name != `F:\KAPE\gkape.exe` {
		t.Errorf("Name = %q", entry.Name)
	}
	if entry.DriveLetter != "F" {
		t.Errorf("DriveLetter = %q, want F", entry.DriveLetter)
	}
	if entry.RunCount != 2 || entry.FocusCount != 5 {
		t.Errorf("runs = %d, focus = %d, want 2 and 5",
			entry.RunCount, entry.FocusCount)
	}
	if entry.FocusTime != 83220*time.Millisecond {
		t.Errorf("FocusTime = %v, want 83.22s", entry.FocusTime)
	}
	if entry.LastExecutedUTC == nil {
		t.Fatal("the last launch time was not read")
	}
	if entry.CategoryName != "an executable file" {
		t.Errorf("CategoryName = %q", entry.CategoryName)
	}
	if entry.Bookkeeping {
		t.Error("a launch is not one of the shell's own counters")
	}
}

// A zero run count beside a focus count is a real shape, not an empty record:
// the shell tracked the window in the foreground without ever recording a
// launch. F:\KAPE\kape.exe on USB-CTF is exactly that — three focus events,
// sixty-one seconds, no run and no time. Reading the zero FILETIME as a date
// would put it in 1601, and reading the row as "never run" would throw away the
// evidence that somebody was looking at it.
func TestAFocusedProgrammeWithNoRecordedLaunchIsStillEvidence(t *testing.T) {
	raw := make([]byte, 72)
	binary.LittleEndian.PutUint32(raw[8:12], 3)
	binary.LittleEndian.PutUint32(raw[12:16], 61703)
	// The last-executed slot is left zero, as it is on that entry.

	entry := readUserAssistValue(
		"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", `...\Count`, "Admin",
		`S:\XNCR\xncr.rkr`, raw)

	if entry.RunCount != 0 {
		t.Errorf("RunCount = %d, want 0", entry.RunCount)
	}
	if entry.FocusCount != 3 {
		t.Errorf("FocusCount = %d, want 3", entry.FocusCount)
	}
	if entry.LastExecutedUTC != nil {
		t.Errorf("a zero FILETIME became %v; it is no time at all",
			entry.LastExecutedUTC)
	}
}

// The shell's own tallies are not launches. They are kept — a silently filtered
// artefact is one nobody can audit — and flagged, so nothing downstream reports
// UEME_CTLSESSION as a programme somebody ran.
func TestTheShellsOwnCountersAreNotLaunches(t *testing.T) {
	for _, stored := range []string{`HRZR_PGYFRFFVBA`, `HRZR_PGYPHNPbhag:pgbe`} {
		entry := readUserAssistValue("{GUID}", `...\Count`, "Admin",
			stored, make([]byte, 72))
		if !entry.Bookkeeping {
			t.Errorf("%q decodes to %q and is a shell counter, not a launch",
				stored, entry.Name)
		}
	}

	entry := readUserAssistValue("{GUID}", `...\Count`, "Admin",
		`S:\XNCR\txncr.rkr`, make([]byte, 72))
	if entry.Bookkeeping {
		t.Error("a real programme was marked as a shell counter")
	}
}

// An older execution entry is a launch, not a shell counter.
//
// The predicate was every name beginning UEME_, and the XP and Vista
// categories record executions as UEME_RUNPATH, UEME_RUNPIDL and UEME_RUNCPL —
// so it suppressed the launches along with the tallies. Nothing is lost on
// current evidence, because Windows 7 and later write a path or an application
// identity; the moment the 16-byte record is decoded, every execution on those
// hives would vanish from the report with nothing to say it had.
func TestAnOlderExecutionEntryIsALaunchRatherThanAShellCounter(t *testing.T) {
	for _, stored := range []string{
		`HRZR_EHACNGU`, `HRZR_EHACVQY`, `HRZR_EHAPCY`,
	} {
		entry := readUserAssistValue("{GUID}", `...\Count`, "Admin",
			stored, make([]byte, 72))
		if entry.Bookkeeping {
			t.Errorf("%q decodes to %q, which is an execution the older "+
				"categories record, and was suppressed as a shell counter",
				stored, entry.Name)
		}
	}

	// A UEME_ form that is neither a control counter nor a run entry is not
	// suppressed — the prefix rule is what this replaced — but it will be
	// counted as a launch, and the row has to say that is what happened.
	entry := readUserAssistValue("{GUID}", `...\Count`, "Admin",
		`HRZR_HVFPHG`, make([]byte, 72))
	if entry.Bookkeeping {
		t.Errorf("%q was suppressed by a rule that does not cover it",
			entry.Name)
	}
	if len(entry.Warnings) == 0 {
		t.Errorf("%q is an unrecognised UEME_ form counted as a launch, "+
			"with nothing on the row to say so", entry.Name)
	}
}

// A UserAssist name is as often a packaged application or a path rooted at a
// folder GUID as it is a path with a letter. Inventing a letter for those would
// place a record on a volume no artefact mentions.
func TestOnlyAPathWithALetterYieldsADriveLetter(t *testing.T) {
	for name, want := range map[string]string{
		`F:\KAPE\gkape.exe`:                                     "F",
		`c:\windows\explorer.exe`:                               "C",
		`Microsoft.WindowsCalculator_8wekyb3d8bbwe!App`:         "",
		`{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\powershell.exe`: "",
		`UEME_CTLSESSION`:                                       "",
		`F:`:                                                    "",
		``:                                                      "",
	} {
		if got := pathDriveLetter(name); got != want {
			t.Errorf("pathDriveLetter(%q) = %q, want %q", name, got, want)
		}
	}
}

// The 16-byte Windows XP record stores its run count with an offset of five, so
// a naive read reports five extra executions of everything and a genuine single
// run as "not run". There is no XP evidence here to check a fix against, so it
// is not decoded — and the row has to say so rather than reporting zeroes that
// would read as a programme that never ran.
func TestAnUndecodedRecordReportsNothingRatherThanZeroes(t *testing.T) {
	entry := readUserAssistValue("{GUID}", `...\Count`, "Admin",
		`S:\XNCR\txncr.rkr`, make([]byte, 16))

	if len(entry.Warnings) == 0 {
		t.Fatal("a record that was not decoded must say so")
	}
	if !strings.Contains(entry.Warnings[0], "not decoded") {
		t.Errorf("warning does not say the counts were not read: %q",
			entry.Warnings[0])
	}
	if entry.LastExecutedUTC != nil {
		t.Error("a time was read out of a record that was not decoded")
	}
	// The bytes are kept, so the decision can be revisited against real XP
	// evidence without recollecting anything.
	if entry.Raw == "" {
		t.Error("the stored value was not kept")
	}
}
