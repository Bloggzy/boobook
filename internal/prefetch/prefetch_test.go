package prefetch

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Bloggzy/boobook/internal/fixture"
)

// The fixtures below are built rather than collected. A real .pf file is
// evidence and does not belong in the repository, and a constructed one can be
// made to carry the exact shape a claim is about — a volume with no creation
// time, a device path read from the wrong offset — which a captured file
// cannot be relied on to contain.
//
// They are built by internal/fixture, which takes its layout from the published
// format definition and does not import this package. That separation is the
// point and it was learned here: the previous builder lived in this file, used
// this package's own offset constants, and wrote 40-byte volume entries for a
// version 23 file because 40 is what this package assumed. The documented size
// for formats 23 and 26 is 104, so every test below passed against a file no
// version of Windows would write, and a genuine multi-volume Windows 7 record
// was misread with the suite green.
//
// A fixture that shares constants with the code under test can only prove the
// code agrees with itself.

const sccaHeaderSize = 84

type testVolume struct {
	devicePath string
	serial     uint32
	created    uint64
}

// buildVistaPrefetch assembles an uncompressed version 23 prefetch file at the
// documented layout.
func buildVistaPrefetch(volumes []testVolume, lastRun uint64, runCount uint32) []byte {
	built := make([]fixture.SCCAVolume, len(volumes))
	for i, volume := range volumes {
		built[i] = fixture.SCCAVolume{
			DevicePath:   volume.devicePath,
			SerialNumber: volume.serial,
			CreationTime: volume.created,
		}
	}
	out, err := fixture.BuildSCCA(fixture.SCCAFile{
		Version:    fixture.SCCAVista,
		Executable: "RUNME.EXE",
		NameHash:   0xDEADBEEF,
		RunCount:   runCount,
		LastRun:    lastRun,
		Volumes:    built,
	})
	if err != nil {
		panic(err)
	}
	return out
}

// fileTime renders a time the way Windows stores one.
func fileTime(t time.Time) uint64 {
	return uint64((t.Unix() + 11644473600) * 10000000)
}

// The volume block is the reason this package exists: it is the only place an
// artefact records a volume serial beside an executable, and the serial is
// what joins prefetch to the volume a shell link already named. The upstream
// parser reads the block's offset and count and stops, so this is Boobook's
// own decoding and has to be held to the values it produces.
func TestAPrefetchFileNamesItsVolumesAndTheirSerials(t *testing.T) {
	created := time.Date(2025, 4, 8, 22, 36, 32, 0, time.UTC)

	run, err := Parse(buildVistaPrefetch([]testVolume{
		{`\VOLUME{01dba8d6adc1d678-e2adef98}`, 0xE2ADEF98, fileTime(created)},
		// A removable volume, which on the reference evidence carries a zeroed
		// creation time. Absence there must stay absence rather than becoming
		// a date in 1601.
		{`\VOLUME{0000000000000000-00c90010}`, 0x00C90010, 0},
	}, fileTime(created), 3))
	if err != nil {
		t.Fatal(err)
	}

	if run.Executable != "RUNME.EXE" {
		t.Errorf("executable %q, want RUNME.EXE", run.Executable)
	}
	if run.RunCount != 3 {
		t.Errorf("run count %d, want 3", run.RunCount)
	}
	if len(run.Volumes) != 2 {
		t.Fatalf("got %d volumes, want 2: %+v", len(run.Volumes), run.Volumes)
	}

	first := run.Volumes[0]
	if first.DevicePath != `\VOLUME{01dba8d6adc1d678-e2adef98}` {
		t.Errorf("device path %q", first.DevicePath)
	}
	// E2AD-EF98 is how Windows displays it, how EMDMgmt stores it and how a
	// shell link records it. Any other spelling breaks the join silently.
	if first.SerialHex != "E2AD-EF98" {
		t.Errorf("serial %q, want E2AD-EF98", first.SerialHex)
	}
	if first.CreatedUTC == nil || !first.CreatedUTC.Equal(created) {
		t.Errorf("creation time %v, want %v", first.CreatedUTC, created)
	}

	second := run.Volumes[1]
	if second.SerialHex != "00C9-0010" {
		t.Errorf("second serial %q, want 00C9-0010", second.SerialHex)
	}
	if second.CreatedUTC != nil {
		t.Errorf("a zeroed creation time became %v, and should have stayed absent",
			second.CreatedUTC)
	}
}

// A structure read at the wrong offset does not fail, it produces plausible
// values — the lesson the partition decoder already records. A device path
// that is not one of the two shapes the kernel writes means the offsets were
// wrong, and putting a fabricated volume name in front of an analyst is worse
// than reporting nothing.
func TestAVolumeReadAtTheWrongOffsetIsRefusedRatherThanReported(t *testing.T) {
	run, err := Parse(buildVistaPrefetch([]testVolume{
		{"NOTAVOLUMEPATH", 0x11112222, 0},
	}, 0, 1))
	if err != nil {
		t.Fatal(err)
	}

	if len(run.Volumes) != 0 {
		t.Errorf("stored %+v, want nothing stored", run.Volumes)
	}
	if len(run.Warnings) == 0 {
		t.Error("refused the volume silently; the warning is the finding")
	}
}

// Windows 8 and later reserve eight run time slots and zero the ones not used
// yet. Converted rather than refused, a zero becomes 1601-01-01, and a
// timeline that accepted it would stretch the reported span of the case back
// four centuries — the same failure the FAT epoch caused with shortcuts.
func TestAnUnusedRunSlotIsNotATime(t *testing.T) {
	run, err := Parse(buildVistaPrefetch([]testVolume{
		{`\DEVICE\HARDDISKVOLUME2`, 0x12345678, 0},
	}, 0, 1))
	if err != nil {
		t.Fatal(err)
	}

	if len(run.RunTimes) != 0 {
		t.Errorf("got run times %v from a zeroed slot, want none", run.RunTimes)
	}
}

// The uncompressed size is a number from the evidence, and it is an
// instruction to allocate. A corrupt or hostile header must not be able to ask
// for more memory than the machine has.
func TestAMAMHeaderCannotAskForUnboundedMemory(t *testing.T) {
	data := make([]byte, 32)
	copy(data, "MAM\x04")
	binary.LittleEndian.PutUint32(data[4:], 0xFFFFFFF0)

	if _, err := Parse(data); err == nil {
		t.Error("accepted a MAM header declaring a four-gigabyte prefetch file")
	}
}

// The volume count is evidence too, and multiplying it by an entry size is how
// a bad count becomes a bad read.
func TestTheDeclaredVolumeCountIsNotTrustedBlindly(t *testing.T) {
	data := buildVistaPrefetch([]testVolume{
		{`\DEVICE\HARDDISKVOLUME2`, 0x12345678, 0},
	}, 0, 1)
	binary.LittleEndian.PutUint32(data[sccaHeaderSize+28:], 4000)

	run, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Volumes) != 0 {
		t.Errorf("read %d volumes from a count of 4000", len(run.Volumes))
	}
	if len(run.Warnings) == 0 {
		t.Error("no warning recorded for an impossible volume count")
	}
}

// Not every byte sequence is a prefetch file, and the answer to one that is
// not has to be an error rather than an empty result that reads as "this
// programme never ran".
func TestSomethingThatIsNotPrefetchIsAnErrorNotAnEmptyRun(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("short"),
		make([]byte, 512),
	} {
		if _, err := Parse(data); err == nil {
			t.Errorf("%d bytes of non-prefetch parsed without error", len(data))
		}
	}
}

// A version 23 or 26 volume entry is 104 bytes, not 40.
//
// This is the finding an independent review raised, and the reason the tests
// above it could not have caught it. Every one of them names a single volume,
// and volume 0 comes out right at any stride.
//
// The libyal format research documents four sizes: 40 bytes for format 17,
// 104 for formats 23 and 26, and 96 for format 30. Boobook assigned 40 to
// everything before Windows 10.
//
// It survived because the four fields Boobook reads all sit in the first 40
// bytes of an entry, so volume 0 comes out right at any stride. The second
// volume does not: advancing 40 bytes lands two thirds of the way inside entry
// 0, in fields nothing has written, and the read either yields a fabricated
// volume or silently loses a real one. A prefetch record naming two volumes is
// the ordinary case for anything run from removable media — the system disk
// the loader touched, and the stick.
//
// The reference collections are all Windows 11, so nothing in the evidence
// exercises this and nothing could have caught it.
func TestAVistaOrWindows81VolumeEntryIsAHundredAndFourBytes(t *testing.T) {
	created := time.Date(2025, 4, 8, 22, 36, 32, 0, time.UTC)

	for _, version := range []uint32{fixture.SCCAVista, fixture.SCCAWin81} {
		stride, known := fixture.VolumeEntrySize(version)
		if !known {
			t.Fatalf("the fixture has no layout for version %d", version)
		}
		if stride != 104 {
			t.Fatalf("version %d: the fixture believes the stride is %d; the "+
				"documented size for formats 23 and 26 is 104", version, stride)
		}

		data, err := fixture.BuildSCCA(fixture.SCCAFile{
			Version:    version,
			Executable: "RUNME.EXE",
			RunCount:   3,
			LastRun:    fileTime(created),
			Volumes: []fixture.SCCAVolume{
				{DevicePath: `\DEVICE\HARDDISKVOLUME2`,
					SerialNumber: 0xE2ADEF98, CreationTime: fileTime(created)},
				{DevicePath: `\VOLUME{01dc0f73aaaabbbb-00c90010}`,
					SerialNumber: 0x00C90010},
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		run, err := Parse(data)
		if err != nil {
			t.Fatalf("version %d: %v", version, err)
		}
		if len(run.Volumes) != 2 {
			t.Fatalf("version %d: got %d volumes, want 2 — a stride of 40 "+
				"lands inside the first entry and the second volume is lost "+
				"or invented. Volumes: %+v, warnings: %v",
				version, len(run.Volumes), run.Volumes, run.Warnings)
		}
		if run.Volumes[0].SerialHex != "E2AD-EF98" {
			t.Errorf("version %d: first serial %q, want E2AD-EF98",
				version, run.Volumes[0].SerialHex)
		}
		// The one that only comes out right at the documented stride.
		if run.Volumes[1].SerialHex != "00C9-0010" {
			t.Errorf("version %d: second serial %q, want 00C9-0010 — this is "+
				"the volume a wrong stride misreads", version,
				run.Volumes[1].SerialHex)
		}
		if run.Volumes[1].DevicePath != `\VOLUME{01dc0f73aaaabbbb-00c90010}` {
			t.Errorf("version %d: second device path %q",
				version, run.Volumes[1].DevicePath)
		}
	}
}

// And the same for the two versions the parser already had right, so a fix to
// the middle of the table cannot quietly break the ends of it.
func TestEveryDocumentedFormatVersionReadsBothItsVolumes(t *testing.T) {
	for _, version := range []uint32{
		fixture.SCCAWinXP, fixture.SCCAVista, fixture.SCCAWin81,
		fixture.SCCAWin10, fixture.SCCAWin11v2,
	} {
		data, err := fixture.BuildSCCA(fixture.SCCAFile{
			Version:    version,
			Executable: "RUNME.EXE",
			RunCount:   1,
			Volumes: []fixture.SCCAVolume{
				{DevicePath: `\DEVICE\HARDDISKVOLUME2`, SerialNumber: 0xAAAA1111},
				{DevicePath: `\DEVICE\HARDDISKVOLUME9`, SerialNumber: 0xBBBB2222},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		run, err := Parse(data)
		if err != nil {
			t.Errorf("version %d: %v", version, err)
			continue
		}
		if len(run.Volumes) != 2 {
			t.Errorf("version %d: got %d volumes, want 2 (warnings: %v)",
				version, len(run.Volumes), run.Warnings)
			continue
		}
		if run.Volumes[1].SerialHex != "BBBB-2222" {
			t.Errorf("version %d: second serial %q, want BBBB-2222",
				version, run.Volumes[1].SerialHex)
		}
	}
}
