package fixture

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
)

// A deliberately broken collection, beside the well-formed one.
//
// internal/fixture built only the case where everything parses, and a tool's
// behaviour on malformed evidence was asserted nowhere except in unit tests on
// individual parsers. Those check that a function returns an error; they cannot
// check that a *run* survives it, reports it, and does not turn it into a
// finding — which is the thing that matters, because a forensic tool meets
// damaged evidence routinely. A truncated hive from a live acquisition, a
// half-written prefetch file from a machine that lost power, a shortcut a
// collector copied mid-write: none of these is exotic.
//
// Three claims are being made about every file below.
//
// It must not crash the run. One unreadable artefact in a collection of
// thousands must cost that artefact, not the case.
//
// It must be reported. A file that could not be read and a file that held
// nothing produce the same silence otherwise, and the standing rule is that
// absence is reported as absence — which is worthless if a parse failure is
// indistinguishable from an empty artefact.
//
// And it must not become evidence. This is the one worth the most. Every
// parser in this project has a comment somewhere saying that a structure read
// at the wrong offset does not fail but produces plausible values; a device
// invented out of a corrupt volume block would reach the report at `confirmed`
// with nothing to mark it as fabricated.

// The identifiers the adversarial tree uses, so a test can assert that none of
// them reached the output. They are deliberately distinctive: a grep for
// BADF-BADF across a report answers the question directly.
const (
	// AdversarialSerial is written into a prefetch volume block whose offsets
	// point outside the block. Reaching the output means the decoder read past
	// the structure and believed what it found.
	AdversarialSerial = 0xBADFBADF
	// AdversarialLabel is in the truncated link's volume ID, past the point the
	// file ends. Deliberately not a prefix or a substring of any other
	// identifier in this tree: an assertion that greps for it must not be
	// satisfied — or defeated — by matching part of something else.
	AdversarialLabel = "GHOSTVOL"
)

// WriteAdversarial lays out a collection where every artefact is damaged.
//
// The tree is the same shape as Write's so discovery finds the same places;
// what differs is that nothing in it parses cleanly.
func WriteAdversarial(root string) error {
	recent := filepath.Join(root, "Users", Profile,
		"AppData", "Roaming", "Microsoft", "Windows", "Recent")
	config := filepath.Join(root, "Windows", "System32", "config")
	logs := filepath.Join(root, "Windows", "System32", "winevt", "Logs")
	prefetch := filepath.Join(root, "Windows", "Prefetch")
	inf := filepath.Join(root, "Windows", "INF")

	for _, dir := range []string{config, logs, prefetch, inf, recent} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	files := map[string][]byte{
		// A hive that announces itself and then stops. This is what a live
		// acquisition of a file being written produces, and the registry
		// reader has to survive one: it is the artefact the whole device
		// picture rests on, so a panic here loses the case rather than a file.
		filepath.Join(config, "SYSTEM"):   truncatedHive(),
		filepath.Join(config, "SOFTWARE"): truncatedHive(),

		// An event log with a valid signature and nothing behind it. The EVTX
		// reader hands chunks to several goroutines, so a failure here is a
		// failure inside a worker, which is where an unrecovered panic takes
		// the process down rather than the file.
		filepath.Join(logs, "System.evtx"): truncatedEVTX(),

		// A prefetch file whose volume device path offset points past the end
		// of its own block. The serial is real and the path is not: a decoder
		// that trusts the offset assembles a device path out of whatever
		// follows and reports a volume that does not exist.
		filepath.Join(prefetch, "OUTSIDE-11111111.pf"): prefetchOffsetOutsideBlock(),
		// A format version nothing documents. It used to be read with the
		// Windows 10 layout, which is a guess presented as a reading.
		filepath.Join(prefetch, "FUTURE-22222222.pf"): prefetchUnknownVersion(),
		// Eight volumes declared in a block with room for one.
		filepath.Join(prefetch, "COUNT-33333333.pf"): prefetchCountOverrunsBlock(),

		// A link whose flags promise structures the body does not contain.
		filepath.Join(recent, "flags-disagree.lnk"): linkFlagsWithoutBody(),
		// A link truncated inside its LinkInfo, with the volume label past the
		// end of the file.
		filepath.Join(recent, "truncated.lnk"): truncatedLink(),
		// A link whose target ID list declares an item running past the list.
		filepath.Join(recent, "bad-idlist.lnk"): BuildLink(LinkSpec{
			TruncatedIDList:  true,
			LocalBasePath:    `E:\`,
			CommonPathSuffix: "report.docx",
		}),
		// Not a link at all, under a name that says it is.
		filepath.Join(recent, "not-a-link.lnk"): []byte(
			"This is a text file that somebody renamed.\r\n"),
		// Empty, which a collector produces when it cannot read a file but
		// creates the destination anyway.
		filepath.Join(recent, "empty.lnk"): nil,
		// A jump list that is not an OLE compound file.
		filepath.Join(recent, "AutomaticDestinations",
			"1234567890abcdef.automaticDestinations-ms"): []byte("not OLE"),
		// And one that is, which is the harder case. A file that fails at its
		// header exercises nothing below it; this one is a valid compound file
		// whose directory declares a four-gigabyte stream inside a few
		// kilobytes. A reader that allocates a declared size before reading it
		// does not produce a bad row here — it ends the run, and with it the
		// whole case, which is the one failure a label cannot mitigate.
		filepath.Join(recent, "AutomaticDestinations",
			"fedcba0987654321.automaticDestinations-ms"): oversizedJumpListStream(),

		// A setupapi log with an unterminated section and a line long enough
		// to exercise the buffer growth.
		filepath.Join(inf, "setupapi.dev.log"): []byte(brokenSetupAPILog()),
	}

	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// truncatedHive is a registry hive header and nothing else.
func truncatedHive() []byte {
	hive := make([]byte, 128)
	copy(hive, "regf")
	// A sequence number and a plausible-looking root cell offset, so the
	// failure happens while following the structure rather than at the
	// signature check — which is the harder case and the realistic one.
	binary.LittleEndian.PutUint32(hive[4:], 1)
	binary.LittleEndian.PutUint32(hive[8:], 1)
	binary.LittleEndian.PutUint32(hive[36:], 0x20)
	binary.LittleEndian.PutUint32(hive[40:], 0x1000)
	return hive
}

// truncatedEVTX is an event log file header with no chunks behind it.
// oversizedJumpListStream is a valid compound file that lies about how much it
// holds.
//
// It carries one stream and no DestList, so there is nothing here that could
// legitimately become evidence even if the refusal were removed — which keeps
// the third adversarial claim checkable. The declared size is close to the
// largest a version 3 compound file can express in its 32-bit size field.
func oversizedJumpListStream() []byte {
	return BuildCompoundFile([]CompoundStream{{
		Name:     "1",
		Declared: 0xF0000000,
		Data:     []byte("far less than four gigabytes"),
	}})
}

func truncatedEVTX() []byte {
	file := make([]byte, 4096)
	copy(file, "ElfFile\x00")
	// Claim chunks that are not there. The reader enumerates chunks in a first
	// pass and hands batches to workers, so a count that outruns the file is
	// the value that decides how much work is dispatched against nothing.
	binary.LittleEndian.PutUint64(file[8:], 0)
	binary.LittleEndian.PutUint64(file[16:], 64)
	binary.LittleEndian.PutUint32(file[40:], 64)
	binary.LittleEndian.PutUint16(file[42:], 128)
	return file
}

// prefetchOffsetOutsideBlock writes a volume entry whose device path offset
// points past the end of the volume information block.
func prefetchOffsetOutsideBlock() []byte {
	out, err := BuildSCCA(SCCAFile{
		Version:    SCCAVista,
		Executable: "OUTSIDE.EXE",
		NameHash:   0x11111111,
		RunCount:   1,
		Volumes: []SCCAVolume{
			{DevicePath: `\DEVICE\HARDDISKVOLUME1`, SerialNumber: AdversarialSerial},
		},
	})
	if err != nil {
		panic(err)
	}
	// Reach into the built file and move the device path offset far past the
	// block. Done by patching rather than by a builder option because the
	// point is a file no builder would produce.
	stride, _ := VolumeEntrySize(SCCAVista)
	_ = stride
	blockAt := int(binary.LittleEndian.Uint32(out[sccaHeaderSize+infoVolumesOffset:]))
	binary.LittleEndian.PutUint32(out[blockAt+volDevicePathOffset:], 0xFFF0)
	binary.LittleEndian.PutUint32(out[blockAt+volDevicePathChars:], 260)
	return out
}

// prefetchUnknownVersion writes a well-formed file claiming a format version
// nothing documents.
func prefetchUnknownVersion() []byte {
	out, err := BuildSCCA(SCCAFile{
		Version:    SCCAWin10,
		Executable: "FUTURE.EXE",
		NameHash:   0x22222222,
		RunCount:   1,
		Volumes: []SCCAVolume{
			{DevicePath: `\DEVICE\HARDDISKVOLUME1`, SerialNumber: AdversarialSerial},
		},
	})
	if err != nil {
		panic(err)
	}
	binary.LittleEndian.PutUint32(out[sccaVersionOffset:], 99)
	return out
}

// prefetchCountOverrunsBlock declares more volumes than the block can hold.
func prefetchCountOverrunsBlock() []byte {
	out, err := BuildSCCA(SCCAFile{
		Version:             SCCAVista,
		Executable:          "COUNT.EXE",
		NameHash:            0x33333333,
		RunCount:            1,
		DeclaredVolumeCount: 8,
		Volumes: []SCCAVolume{
			{DevicePath: `\DEVICE\HARDDISKVOLUME1`, SerialNumber: AdversarialSerial},
		},
	})
	if err != nil {
		panic(err)
	}
	return out
}

// linkFlagsWithoutBody sets HasLinkInfo and HasName and supplies neither.
func linkFlagsWithoutBody() []byte {
	header := make([]byte, linkHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], linkHeaderSize)
	copy(header[4:20], linkCLSID[:])
	binary.LittleEndian.PutUint32(header[20:24],
		LinkHasLinkInfo|LinkHasName|LinkHasLinkTargetIDList|LinkIsUnicode)
	return header
}

// truncatedLink builds a well-formed link and then cuts it short, so its
// LinkInfo declares a size and a volume label that are not in the file.
func truncatedLink() []byte {
	full := BuildLink(LinkSpec{
		LocalBasePath:    `E:\phantom\`,
		CommonPathSuffix: "ghost.docx",
		VolumeIDPresent:  true,
		DriveType:        DriveRemovable,
		DriveSerial:      AdversarialSerial,
		VolumeLabel:      AdversarialLabel,
	})
	// Keep the header and the first few bytes of the LinkInfo: enough that a
	// reader starts on the structure, not enough for any of it to be there.
	cut := linkHeaderSize + 8
	if cut > len(full) {
		cut = len(full)
	}
	return full[:cut]
}

// brokenSetupAPILog has a section that never ends and one very long line.
func brokenSetupAPILog() string {
	var out bytes.Buffer
	out.WriteString("[Device Install Log]\n     OS Version = 10.0.26100\n\n")
	// A section header with no matching end, which is what a log being written
	// when the machine was imaged looks like.
	out.WriteString(">>>  [Device Install (Hardware initiated) - " +
		`USBSTOR\Disk&Ven_Ghost&Prod_NOWHERE&Rev_1.00\PHANTOM0001&0]` + "\n")
	out.WriteString(">>>  Section start 2026/03/04 09:15:22.101\n")
	out.WriteString("     dvi:           Driver INF     - " +
		strings.Repeat("A", 300000) + "\n")
	// A section end with no start above it.
	out.WriteString("<<<  Section end 2026/03/04 09:41:07.515\n")
	out.WriteString("<<<  [Exit status: SUCCESS]\n")
	// A timestamp that is not one.
	out.WriteString(">>>  Section start 9999/99/99 99:99:99.999\n")
	return out.String()
}

// DescribeAdversarial names what the broken tree holds.
func DescribeAdversarial() string {
	return "a collection where nothing parses: truncated SYSTEM and SOFTWARE " +
		"hives, a headerless event log, three prefetch files with a device path " +
		"offset outside the block, an undocumented format version and a volume " +
		"count that overruns its block, four unreadable shortcuts, a jump list " +
		"that is not an OLE file, a second that is one and declares a " +
		"four-gigabyte stream inside a few kilobytes, and a setupapi log with " +
		"an unterminated section and an impossible timestamp."
}
