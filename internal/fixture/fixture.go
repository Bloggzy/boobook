// Package fixture builds a synthetic evidence tree.
//
// It exists because every check on this tool so far has been a person running
// it by hand against five collections that live outside the repository and that
// nobody else can run. Real evidence is not here and cannot be — the standing
// rule forbids committing it, and the collections cannot be shared — so a
// continuous check needs a tree that is built rather than captured.
//
// Built is also better, for the same reason the parser fixtures are built: a
// constructed artefact carries exactly the shape a claim is about, and its
// provenance is the code beside it rather than a binary blob nobody can audit.
//
// What it does not build is as deliberate as what it does. There are no
// registry hives and no event logs: those formats are large enough that a
// half-correct forgery would test the forgery, and their absence is a case
// worth exercising in itself. A collection with no SYSTEM hive must produce a
// report that says so rather than a crash or a silent zero, and that is the
// failure this fixture is most likely to catch.
//
// Nothing in the tool imports this package; only tests do.
package fixture

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf16"
)

// Profile is the user directory the built tree carries its file activity under.
const Profile = "Analyst"

// The volume the built artefacts agree on. A shell link records the serial and
// the label, a prefetch file records the same serial, and the two meeting on it
// is the join the whole attribution chain rests on — so a fixture that used two
// different serials would exercise the parsers and none of the correlation.
const (
	VolumeSerial    = 0xE6079156
	VolumeSerialHex = "E607-9156"
	VolumeLabel     = "FIELDWORK"
	DriveLetter     = "E"
	DevicePath      = `\VOLUME{01dc0f73-e6079156}`
	Executable      = "RUNME.EXE"
	// The target, and the two halves MS-SHLLINK actually stores it in: a
	// LocalBasePath ending in a separator and a CommonPathSuffix holding the
	// file name. A fixture that put the whole path in the base would exercise
	// a shape real links do not always have, and is how reading the base alone
	// went unnoticed.
	LinkedDir  = `E:\`
	LinkedName = `report.docx`
	LinkedFile = LinkedDir + LinkedName
)

// Write lays out a mounted-volume collection beneath root.
func Write(root string) error {
	recent := filepath.Join(append([]string{root, "Users", Profile},
		"AppData", "Roaming", "Microsoft", "Windows", "Recent")...)

	for _, dir := range []string{
		// Present and empty. Discovery probes for Windows to decide the layout,
		// and an empty config directory is what a collection taken without the
		// hives looks like.
		filepath.Join(root, "Windows", "System32", "config"),
		filepath.Join(root, "Windows", "System32", "winevt", "Logs"),
		filepath.Join(root, "Windows", "INF"),
		filepath.Join(root, "Windows", "Prefetch"),
		recent,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	files := map[string][]byte{
		filepath.Join(root, "Windows", "INF", "setupapi.dev.log"): []byte(setupAPILog),
		filepath.Join(root, "Windows", "Prefetch",
			Executable+"-DEADBEEF.pf"): prefetchFile(),
		filepath.Join(recent, "report.docx.lnk"): shellLink(),
	}
	for path, content := range files {
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// setupAPILog is one device install and one removal, in the form Windows
// writes. These times are a local wall clock with no zone, which is the whole
// reason the artefact is worth having in a smoke test: it is the one input that
// exercises the conversion path with no host bias available to convert it.
const setupAPILog = `[Device Install Log]
     OS Version = 10.0.26100

>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_Generic&Prod_FLASH_DRIVE&Rev_1.00\FIXTURE0001&0]
>>>  Section start 2026/03/04 09:15:22.101
     ump: Install needed due to device having problem code CM_PROB_NOT_CONFIGURED
     dvi:           Driver INF     - disk.inf
     utl:           Class GUID     - {4D36E967-E325-11CE-BFC1-08002BE10318}
<<<  Section end 2026/03/04 09:15:23.400
<<<  [Exit status: SUCCESS]

>>>  [Delete Device - STORAGE\VOLUME\_??_USBSTOR#Disk&Ven_Generic&Prod_FLASH_DRIVE&Rev_1.00#FIXTURE0001&0#]
>>>  Section start 2026/03/04 09:41:07.512
<<<  Section end 2026/03/04 09:41:07.515
<<<  [Exit status: SUCCESS]
`

// The shell link, built through BuildLink so the tree and the parser tests
// share one implementation of MS-SHLLINK rather than two.
//
// It used to assemble the bytes here, which meant the smoke test exercised a
// LinkInfo layout nothing else did. The path is split across LocalBasePath and
// CommonPathSuffix the way MS-SHLLINK stores one, because that is the shape a
// real link carries and the shape Boobook read only half of.
const (
	// 2026-03-04 09:20:00 UTC as a FILETIME, inside the install window above.
	targetWritten = uint64(133849464000000000)
)

func shellLink() []byte {
	return BuildLink(LinkSpec{
		LocalBasePath:    LinkedDir,
		CommonPathSuffix: LinkedName,
		VolumeIDPresent:  true,
		DriveType:        DriveRemovable,
		DriveSerial:      VolumeSerial,
		VolumeLabel:      VolumeLabel,
		TargetWritten:    targetWritten,
		TargetSize:       4096,
		Name:             "a fixture file",
	})
}

// The prefetch file: an uncompressed version 23 record naming one volume by the
// same serial the shell link recorded.
//
// Built through BuildSCCA, which takes its layout from the published format
// definition rather than from internal/prefetch. This file used to assemble the
// bytes itself with a 40-byte volume entry, which is the size version 17 uses
// and not the 104 bytes versions 23 and 26 use — so the smoke test agreed with
// the parser's error and would have gone on agreeing with it.
//
// 2026-03-04 09:22:00 UTC.
const lastRun = uint64(133849465200000000)

func prefetchFile() []byte {
	out, err := BuildSCCA(SCCAFile{
		Version:    SCCAVista,
		Executable: Executable,
		NameHash:   0xDEADBEEF,
		RunCount:   4,
		LastRun:    lastRun,
		Volumes: []SCCAVolume{
			{DevicePath: DevicePath, SerialNumber: VolumeSerial,
				CreationTime: lastRun},
		},
	})
	if err != nil {
		// The version is a constant in this file, so a failure here is a
		// programming error rather than anything a caller can cause.
		panic(err)
	}
	return out
}

func encodeUTF16(text string) []byte {
	units := utf16.Encode([]rune(text))
	out := make([]byte, 2*len(units))
	for i, unit := range units {
		binary.LittleEndian.PutUint16(out[2*i:], unit)
	}
	return out
}

// Describe names what the tree holds, for a test that wants to say what it is
// asserting over.
func Describe() string {
	return fmt.Sprintf(
		"a mounted-volume collection: one setupapi log, one shell link to %s on "+
			"a removable volume labelled %s (serial %s), and one prefetch record "+
			"for %s naming the same serial. No registry hives and no event logs.",
		LinkedFile, VolumeLabel, VolumeSerialHex, Executable)
}
