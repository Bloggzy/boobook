package jumplist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bloggzy/boobook/internal/fixture"
)

// The layouts differ by sixteen bytes in the middle. Picking the wrong one
// yields a plausible-looking record with the wrong time and the wrong path,
// which is worse than no record at all — so the parser validates rather than
// trusting a version number.
//
// The entries come from internal/fixture, which takes its offsets from the
// format description. Built from the parser's own table, as this test used to
// be, it could only ever prove that a value written at an offset comes back
// from the same offset.
func TestDestListLayoutIsChosenByValidation(t *testing.T) {
	const filetime = uint64(133999041944852345)

	cases := []struct {
		version uint32
		layout  string
	}{
		{fixture.DestListV1, "legacy"},
		{fixture.DestListV3, "modern"},
		{fixture.DestListV4, "modern"},
		{fixture.DestListV6, "modern"},
	}

	for _, want := range cases {
		t.Run(want.layout, func(t *testing.T) {
			data := fixture.BuildDestList(want.version, fixture.DestListEntry{
				EntryNumber:  7,
				FileTime:     filetime,
				Hostname:     "DESKTOP-TEST",
				Path:         `E:\evidence.docx`,
				RankingValue: 3.7,
				AccessCount:  2,
			})

			entries, declared, warnings := parseDestList(data)
			if len(entries) != 1 {
				t.Fatalf("got %d entries, want 1 (warnings: %v)", len(entries), warnings)
			}
			if declared != 1 {
				t.Errorf("declared = %d, want 1", declared)
			}
			if len(warnings) != 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}

			entry := entries[0]
			if entry.layout != want.layout {
				t.Errorf("layout = %q, want %q", entry.layout, want.layout)
			}
			if entry.entryNumber != 7 {
				t.Errorf("entryNumber = %d, want 7", entry.entryNumber)
			}
			if entry.rawTime != filetime {
				t.Errorf("rawTime = %d, want %d", entry.rawTime, filetime)
			}
			if entry.pinned {
				t.Error("pinned should be false for a pin status of -1")
			}
			if entry.path != `E:\evidence.docx` {
				t.Errorf("path = %q", entry.path)
			}
			if entry.machineID != "DESKTOP-TEST" {
				t.Errorf("machineID = %q", entry.machineID)
			}
		})
	}
}

// The float beside the entry number is not the access count.
//
// It was read as one — truncated to an integer and exported as `access_count`
// — and on the reference collections that is demonstrably wrong: the float
// holds values such as 3.7, 19.98 and 25.98, and it disagreed with the integer
// the DestList actually counts with on 14 of 76 entries. One known folder was
// reported as opened twenty-five times when the recorded count is six.
//
// The fixture below makes the two disagree on purpose. A parser reading the
// float would report 3 for a count of 2, and truncation would hide that the
// value is not even a whole number.
func TestTheUndocumentedFloatIsNotTheAccessCount(t *testing.T) {
	data := fixture.BuildDestList(fixture.DestListV6, fixture.DestListEntry{
		EntryNumber:  1,
		FileTime:     133999041944852345,
		Hostname:     "HOST",
		Path:         `E:\evidence.docx`,
		RankingValue: 3.7,
		AccessCount:  2,
	})

	entries, _, _ := parseDestList(data)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	entry := entries[0]

	if !entry.accessRead {
		t.Fatal("a version 6 entry records an access count and it was not read")
	}
	if entry.accessCount != 2 {
		t.Errorf("accessCount = %d, want 2 — %g would mean the undocumented "+
			"float is still being read as the count", entry.accessCount,
			entry.rankingValue)
	}
	if entry.rankingValue != 3.7 {
		t.Errorf("rankingValue = %g, want 3.7", entry.rankingValue)
	}
}

// A Windows 7 DestList records no access count, and zero is not the answer.
//
// Absence is reported as absence throughout this tool, and a count is where
// that matters most: "opened zero times" is a claim about behaviour, while
// "the entry does not record how many times it was opened" is a claim about
// the artefact. Exporting the first for the second would be a finding nobody
// could contradict.
func TestAVersionOneEntryRecordsNoAccessCountRatherThanZero(t *testing.T) {
	data := fixture.BuildDestList(fixture.DestListV1, fixture.DestListEntry{
		EntryNumber:  1,
		FileTime:     133999041944852345,
		Hostname:     "HOST",
		Path:         `E:\evidence.docx`,
		RankingValue: 1,
	})

	entries, _, _ := parseDestList(data)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].layout != "legacy" {
		t.Fatalf("layout = %q, want legacy", entries[0].layout)
	}
	if entries[0].accessRead {
		t.Error("a version 1 entry has no access count field and one was claimed")
	}
}

// Where the declared version and the shape that validated disagree, the
// reading rests on a layout the file did not declare — and the access count is
// read from an offset that layout decides. Saying so is not the same as
// overriding the validation, which is still what chooses: the parser reports
// the disagreement and leaves the judgement to a reader.
func TestAVersionThatDisagreesWithTheValidatedShapeIsReported(t *testing.T) {
	// A version 1 entry under a version 6 header, which is what a file written
	// by something other than Explorer, or a misread stream, looks like.
	data := fixture.BuildDestList(fixture.DestListV1, fixture.DestListEntry{
		EntryNumber:  1,
		FileTime:     133999041944852345,
		Hostname:     "HOST",
		Path:         `E:\evidence.docx`,
		RankingValue: 1,
	})
	data[0] = 6

	entries, _, warnings := parseDestList(data)
	if len(entries) != 1 || entries[0].layout != "legacy" {
		t.Fatalf("the validating layout should still win: %+v", entries)
	}
	if len(warnings) == 0 {
		t.Error("the disagreement between the declared version and the " +
			"validated shape must be reported")
	}
}

// A DestList that declares more entries than can be read must say so. Silently
// returning what parsed would present a partial list as the whole one.
func TestDestListShortfallIsReported(t *testing.T) {
	data := fixture.BuildDestList(fixture.DestListV6, fixture.DestListEntry{
		EntryNumber:  1,
		FileTime:     133999041944852345,
		Hostname:     "HOST",
		Path:         `E:\a.txt`,
		RankingValue: 1,
		AccessCount:  1,
	})
	// Claim five where one was written.
	data[4] = 5

	entries, declared, warnings := parseDestList(data)
	if len(entries) != 1 || declared != 5 {
		t.Fatalf("got %d entries, declared %d", len(entries), declared)
	}
	if len(warnings) == 0 {
		t.Error("a shortfall against the declared count must be reported")
	}
}

func TestPlausiblePathRejectsAWrongLayout(t *testing.T) {
	// What a misaligned read produces.
	bad := []string{"", "  ", "E:\x01\x02broken", string(rune(0xFFFD)) + "path"}
	for _, path := range bad {
		if plausiblePath(path) {
			t.Errorf("plausiblePath(%q) = true", path)
		}
	}
	good := []string{`E:\2024 financial audit.pptx`, "knownfolder:{FDD39AD0-238F-46AF}"}
	for _, path := range good {
		if !plausiblePath(path) {
			t.Errorf("plausiblePath(%q) = false", path)
		}
	}
}

// A zero timestamp is not a date in 1601, and a layout that produces one has
// been read at the wrong offset.
func TestImplausibleTimestampRejectsALayout(t *testing.T) {
	data := fixture.BuildDestList(fixture.DestListV6, fixture.DestListEntry{
		EntryNumber:  1,
		Hostname:     "HOST",
		Path:         `E:\a.txt`,
		RankingValue: 1,
	})

	entries, _, warnings := parseDestList(data)
	if len(entries) != 0 {
		t.Errorf("an entry with no readable timestamp was accepted: %+v", entries)
	}
	if len(warnings) == 0 {
		t.Error("the failure must be reported")
	}
}

// A stream size is a number the evidence supplies, so allocating it before
// reading lets a small file ask for the whole of memory. The cost is not a bad
// row: the run dies and the case produces nothing, which is the one failure
// mode a forensic tool cannot recover from by labelling.
//
// The bound that does the work is the file's own length, because it is evidence
// rather than a figure chosen here — a stream cannot hold more bytes than the
// file containing it. The ceilings behind it only matter where the length could
// not be read.
//
// Both halves are asserted. Refusing the whole file would pass this test and be
// the wrong answer: the DestList and the link streams are independent, so a
// damaged one must not cost the others. Keep what parsed, invent nothing from
// what did not.
func TestAStreamLargerThanItsFileIsRefusedWithoutEndingTheRun(t *testing.T) {
	// Four gigabytes, from a file of a few kilobytes. A version 3 compound file
	// stores a stream size in 32 bits, so this is close to the largest lie the
	// format can tell — and it is an allocation no run survives.
	const fourGigabytes = uint64(0xF0000000)

	path := filepath.Join(t.TempDir(), "1234567890abcdef.automaticDestinations-ms")
	file := fixture.BuildCompoundFile([]fixture.CompoundStream{
		{
			Name:     "1",
			Declared: fourGigabytes,
			Data:     []byte("this stream is a few bytes long and says otherwise"),
		},
		{
			Name: "DestList",
			Data: fixture.BuildDestList(fixture.DestListV4, fixture.DestListEntry{
				EntryNumber:  1,
				Path:         `E:\report.docx`,
				Hostname:     "HOST01",
				FileTime:     133999041944852345,
				AccessCount:  3,
				RankingValue: 3.7,
			}),
		},
	})
	if err := os.WriteFile(path, file, 0o644); err != nil {
		t.Fatal(err)
	}

	entries, stats := ParseFile(path)

	if stats.Err != nil {
		t.Fatalf("the file failed outright: %v. A stream that cannot be "+
			"believed is one stream, not the whole jump list", stats.Err)
	}
	var refused bool
	for _, warning := range stats.Warnings {
		if strings.Contains(warning, "stream 1") &&
			strings.Contains(warning, "was not read") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("nothing said the oversized stream was refused; warnings were "+
			"%v. A stream skipped silently is indistinguishable from one that "+
			"was never there", stats.Warnings)
	}
	// The DestList sits after the bad stream in the file, so reading it at all
	// proves the refusal did not end the walk.
	if stats.DestListRead != 1 {
		t.Errorf("DestList entries read = %d, want 1: the streams either side "+
			"of a refused one must still be read", stats.DestListRead)
	}
	// And nothing was invented from the stream that was not read.
	for _, entry := range entries {
		if entry.StreamName == "1" && entry.Link != nil {
			t.Error("a link was reported for the stream whose bytes were never " +
				"read")
		}
	}
}

// Where the declared version and the validated shape disagree, the fields read
// at offsets that shape decides are refused rather than reported.
//
// The layout is still chosen by validation, and that is right: a version number
// is a claim the file makes about itself, while the framing is a fact about its
// bytes. But once the two contradict each other, an access count read at a
// modern offset out of a legacy-shaped entry is not a reading — it is four
// bytes from somewhere, and it comes back as a plausible integer with nothing
// about it to look wrong. The one thing an analyst cannot do with "opened nine
// times" is check it.
//
// The path, the machine id and the timestamp survive, because each had to be
// affirmatively right for the layout to be accepted at all: the character count
// fitted, the path decoded without control characters, and the time was a
// FILETIME. That is evidence rather than a coincidence of offsets.
func TestADestListWhoseVersionContradictsItsShapeReportsNoAccessCount(t *testing.T) {
	const filetime = uint64(133999041944852345)

	// Version 4 in the header — whose entries are the modern shape — with
	// entries written in the version 1 shape.
	stream := fixture.BuildDestListWithShape(fixture.DestListV4, fixture.DestListV1,
		fixture.DestListEntry{
			EntryNumber:  1,
			Path:         `E:\report.docx`,
			Hostname:     "HOST01",
			FileTime:     filetime,
			RankingValue: 3.7,
		})

	entries, declared, warnings := parseDestList(stream)

	if declared != 1 || len(entries) != 1 {
		t.Fatalf("declared %d and read %d entries, want 1 and 1: the framing is "+
			"still readable and the entry must not be discarded", declared,
			len(entries))
	}
	if entries[0].accessRead {
		t.Errorf("an access count of %d was reported from a shape the file did "+
			"not declare", entries[0].accessCount)
	}
	if entries[0].pinRead {
		t.Error("a pin status was reported from a shape the file did not declare")
	}
	// The evidence that validated is kept. Refusing the whole entry would lose
	// a real record to tidy away a contradiction.
	if entries[0].path != `E:\report.docx` {
		t.Errorf("path = %q, want E:\report.docx", entries[0].path)
	}
	if entries[0].rawTime != filetime {
		t.Errorf("rawTime = %d, want %d", entries[0].rawTime, filetime)
	}

	var said bool
	for _, warning := range warnings {
		if strings.Contains(warning, "version") &&
			strings.Contains(warning, "are not reported for this file") {
			said = true
		}
	}
	if !said {
		t.Errorf("the contradiction was not reported; warnings were %v. A field "+
			"withheld in silence is indistinguishable from one the artefact "+
			"never carried", warnings)
	}
}

// The ordinary case, which is the half that matters: where the version and the
// shape agree, the count is read exactly as before.
func TestADestListWhoseVersionMatchesItsShapeStillReportsItsAccessCount(t *testing.T) {
	entries, _, warnings := parseDestList(fixture.BuildDestList(fixture.DestListV4,
		fixture.DestListEntry{
			EntryNumber:  1,
			Path:         `E:\report.docx`,
			Hostname:     "HOST01",
			FileTime:     133999041944852345,
			RankingValue: 3.7,
			AccessCount:  6,
		}))

	if len(entries) != 1 {
		t.Fatalf("read %d entries, want 1", len(entries))
	}
	if !entries[0].accessRead || entries[0].accessCount != 6 {
		t.Errorf("accessCount = %d (read %t), want 6 read",
			entries[0].accessCount, entries[0].accessRead)
	}
	for _, warning := range warnings {
		if strings.Contains(warning, "version") {
			t.Errorf("a file whose version and shape agree was reported as "+
				"contradictory: %q", warning)
		}
	}
}
