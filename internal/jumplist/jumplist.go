// Package jumplist reads Windows jump lists.
//
// A jump list is where a file opened from a removable device is still recorded
// after the device is gone and after the Recent folder has turned over. Each
// entry embeds a full shell link, so the drive letter, drive type and volume
// serial that place a file on a device are all present.
//
// Two forms exist and they are not alike. An automatic destinations file is an
// OLE compound file whose numbered streams each hold one shell link, with a
// DestList stream giving the order and the per-entry metadata. A custom
// destinations file is a plain sequence of shell links, and is read here by
// finding each link header rather than by walking a structure — which is
// stated plainly because it is a weaker claim about completeness.
package jumplist

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/richardlehane/mscfb"

	"github.com/Bloggzy/boobook/internal/lnk"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// Entry is one jump list entry: the link it holds, and the DestList metadata
// belonging to it where that could be read.
type Entry struct {
	SourceFile string
	// AppID is the jump list filename without its extension, which identifies
	// the application. Boobook does not translate it to an application name:
	// the published lists are incomplete and a wrong name is worse than a hash.
	AppID string
	// StreamName is where inside the file this entry came from.
	StreamName string

	Link *lnk.Link

	// The DestList fields. Present is false where no DestList entry matched,
	// in which case the link is still reported and the ordering is not.
	Present bool
	// EntryNumber is the DestList's own identifier, matching the stream name.
	EntryNumber uint32
	// Position is the entry's place in the most-recently-used order, 1 being
	// the most recent.
	Position int
	// Pinned is whether the application pinned the entry, and PinnedRecorded
	// whether that could be read at all. They come apart where the declared
	// DestList version contradicts the shape that validated: the pin status is
	// one sign bit at an offset the disputed shape decides, so a wrong reading
	// is a plausible boolean with nothing about it to look wrong.
	Pinned         bool
	PinnedRecorded bool
	// AccessCount is how many times the application recorded opening the entry,
	// read from the integer field the modern DestList carries. Recorded says
	// whether the entry had one at all: the Windows 7 layout does not, and
	// reporting zero there would read as "never opened".
	AccessCount         uint32
	AccessCountRecorded bool
	// RankingValue is the undocumented float the DestList stores beside the
	// entry number. It is not a count and must not be reported as one — on the
	// reference collections it holds 3.7, 19.98 and 25.98, and it disagreed
	// with the integer count on 14 of 76 entries. It is carried because it is
	// evidence and refusing to export it would leave an analyst unable to check
	// the claim, and named for what is known about it rather than for what it
	// was once assumed to be.
	RankingValue float32
	// RecordedPath is the path as the DestList stored it, which can differ from
	// the link's own path.
	RecordedPath string
	// MachineID is the NetBIOS name recorded with the entry.
	MachineID string

	RawLastAccess uint64
	LastAccessUTC *time.Time
}

// Stats accounts for one jump list file.
type Stats struct {
	Path    string
	Bytes   int64
	Kind    string
	Streams int
	Links   int
	// OtherStreams counts streams that are not links and not the DestList,
	// which a jump list carries as a matter of course.
	OtherStreams int
	// DestListEntries is how many entries the DestList declared, against which
	// the number actually read can be checked.
	DestListDeclared int
	DestListRead     int
	Warnings         []string
	Err              error
}

// ParseFile reads either form of jump list, choosing by extension.
func ParseFile(path string) ([]Entry, Stats) {
	stats := Stats{Path: path}
	if info, err := os.Stat(path); err == nil {
		stats.Bytes = info.Size()
	}

	name := filepath.Base(path)
	appID := name
	if index := strings.Index(name, "."); index > 0 {
		appID = name[:index]
	}

	switch {
	case strings.HasSuffix(strings.ToLower(name), ".automaticdestinations-ms"):
		stats.Kind = "automatic"
		return parseAutomatic(path, appID, &stats), stats
	case strings.HasSuffix(strings.ToLower(name), ".customdestinations-ms"):
		stats.Kind = "custom"
		return parseCustom(path, appID, &stats), stats
	}

	stats.Err = fmt.Errorf("not a jump list: %s", name)
	return nil, stats
}

// A compound file's directory declares each stream's size, and that number is
// evidence: it is whatever the bytes on disk say, including on a file that was
// truncated mid-write or written to be hostile. Allocating it before reading
// lets a two-kilobyte file ask for the whole of memory, and the cost is not a
// bad row — it is the run dying and the case producing nothing.
//
// The first bound is the file's own length, because it is the evidence rather
// than a number chosen here: a stream cannot hold more bytes than the file that
// contains it. The two ceilings below are the backstop for the case where the
// length could not be read at all. A jump list is a small file — the largest in
// any reference collection is under a megabyte — so both are orders of
// magnitude above anything genuine, which is the right side to be wrong on: a
// bound that refused a real stream would lose evidence to prevent a crash that
// has never happened.
//
// An oversized stream is skipped and the rest of the file is still read. That
// is the same division as the adversarial fixture asks for everywhere else —
// keep what parsed, invent nothing from what did not — and it matters here
// because the DestList and the link streams are independent: one damaged link
// must not cost the ordering of the others.
const (
	maxStreamBytes = 16 << 20
	maxFileBudget  = 64 << 20
)

// oversized says whether a declared stream size can be believed, and why not.
func oversized(size, fileBytes, spent int64) string {
	switch {
	case size < 0:
		return fmt.Sprintf("declares a size of %d bytes, which is not a size", size)
	case fileBytes > 0 && size > fileBytes:
		return fmt.Sprintf("declares %d bytes, more than the %d-byte file "+
			"containing it", size, fileBytes)
	case size > maxStreamBytes:
		return fmt.Sprintf("declares %d bytes, beyond the %d-byte ceiling for "+
			"one jump list stream", size, maxStreamBytes)
	case spent+size > maxFileBudget:
		return fmt.Sprintf("declares %d bytes, which would take this file past "+
			"the %d-byte total read budget", size, maxFileBudget)
	}
	return ""
}

func parseAutomatic(path, appID string, stats *Stats) []Entry {
	file, err := os.Open(path)
	if err != nil {
		stats.Err = err
		return nil
	}
	defer file.Close()

	reader, err := mscfb.New(file)
	if err != nil {
		stats.Err = fmt.Errorf("compound file: %w", err)
		return nil
	}

	var entries []Entry
	var destList []destEntry
	var spent int64

	for entry, err := reader.Next(); err == nil; entry, err = reader.Next() {
		if entry.Size == 0 {
			continue
		}
		if reason := oversized(entry.Size, stats.Bytes, spent); reason != "" {
			stats.Warnings = append(stats.Warnings,
				fmt.Sprintf("stream %s %s, and was not read", entry.Name, reason))
			continue
		}
		spent += entry.Size
		data := make([]byte, entry.Size)
		read, readErr := io.ReadFull(entry, data)
		if readErr != nil && read == 0 {
			stats.Warnings = append(stats.Warnings,
				fmt.Sprintf("stream %s could not be read: %v", entry.Name, readErr))
			continue
		}
		data = data[:read]

		if strings.EqualFold(entry.Name, "DestList") {
			parsed, declared, warnings := parseDestList(data)
			destList = parsed
			stats.DestListDeclared = declared
			stats.DestListRead = len(parsed)
			stats.Warnings = append(stats.Warnings, warnings...)
			continue
		}

		// A link stream is named with its entry number in hexadecimal. Other
		// streams — DestListPropertyStore among them — are not links and are
		// counted rather than reported as damage.
		if _, err := strconv.ParseUint(strings.TrimSpace(entry.Name), 16, 32); err != nil {
			stats.OtherStreams++
			continue
		}

		stats.Streams++
		link, err := lnk.Parse(data)
		if err != nil {
			stats.Warnings = append(stats.Warnings,
				fmt.Sprintf("stream %s is not a shell link: %v", entry.Name, err))
			continue
		}
		link.SourceFile = path
		link.Origin = "jumplist_stream:" + entry.Name
		stats.Links++

		entries = append(entries, Entry{
			SourceFile: path,
			AppID:      appID,
			StreamName: entry.Name,
			Link:       link,
		})
	}

	attachDestList(entries, destList)
	return entries
}

// destEntry is the part of a DestList record Boobook uses.
type destEntry struct {
	// layout names which shape read it, so a recovered entry can say how.
	layout       string
	entryNumber  uint32
	position     int
	pinned       bool
	pinRead      bool
	accessCount  uint32
	accessRead   bool
	rankingValue float32
	path         string
	machineID    string
	rawTime      uint64
}

// destLayout is one DestList entry shape.
//
// The layouts differ by where the path length sits and by four bytes in the
// middle, not by anything at the end. Rather than trusting the version number
// to be honest about which applies, each candidate is tried and accepted only
// where the declared path length fits and the path and timestamp it produces
// are believable. A wrong layout announces itself as a control character or a
// date in the seventeenth century.
type destLayout struct {
	name string
	// fixed is the size of the entry before the path length field.
	fixed int
	// trailing is what follows the path before the next entry.
	trailing    int
	entryNumber int
	// rankingValue is the undocumented float. Every version carries one.
	rankingValue int
	// accessCount is the integer count the modern entry adds after its pin
	// status. -1 where the layout has no such field, which is not the same as
	// a count of zero and is why it is not simply an offset.
	accessCount int
	fileTime    int
	pinStatus   int
}

var destLayouts = []destLayout{
	{
		// Confirmed against DestList versions 4 and 6 in the reference
		// collections, on two different hosts.
		name: "modern", fixed: 0x80, trailing: 4,
		entryNumber: 0x58, rankingValue: 0x60, fileTime: 0x64, pinStatus: 0x6C,
		accessCount: 0x74,
	},
	{
		// Windows 7 and 8. Not present in the reference collections, so it is
		// tried second and only accepted when it validates. Version 1 records
		// no access count, so none is claimed for it.
		name: "legacy", fixed: 0x70, trailing: 0,
		entryNumber: 0x58, rankingValue: 0x5C, fileTime: 0x60, pinStatus: 0x68,
		accessCount: -1,
	},
}

func parseDestList(data []byte) ([]destEntry, int, []string) {
	const headerSize = 32
	if len(data) < headerSize {
		return nil, 0, []string{"DestList is too short to hold a header"}
	}

	version := int(binary.LittleEndian.Uint32(data[0:4]))
	declared := int(binary.LittleEndian.Uint32(data[4:8]))

	var entries []destEntry
	var warnings []string
	offset := headerSize
	position := 0

	for offset < len(data) {
		entry, next, ok := readDestEntry(data, offset)
		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"DestList entry at offset %d could not be read; %d of %d entries were recovered",
				offset, len(entries), declared))
			break
		}
		position++
		entry.position = position
		entries = append(entries, entry)
		offset = next
	}

	if declared > 0 && len(entries) != declared {
		warnings = append(warnings, fmt.Sprintf(
			"DestList declared %d entries and %d were read", declared, len(entries)))
	}

	// The layout is still chosen by what validates rather than by the version,
	// for the reason destLayout records: a version number is a claim the file
	// makes about itself and the framing is a fact about its bytes.
	//
	// But where the two disagree, the fields read at offsets the disputed shape
	// decides stop being readings and become guesses, and they are refused.
	// Which fields is the whole of the judgement here.
	//
	// The path, the machine id and the timestamp survive, because each had to
	// be *affirmatively* right for the layout to be accepted at all — the
	// declared character count had to fit, the path had to decode without
	// control characters, and the time had to be a FILETIME wintime accepts.
	// That is evidence, not a coincidence of offsets.
	//
	// The access count and the pin status do not survive. Neither is validated
	// by anything: a count is whatever four bytes say and a pin status is one
	// sign bit, so read at the wrong offset they produce a plausible number and
	// a plausible boolean with nothing about either to look wrong. An analyst
	// told a file was opened nine times has no way to check it, which is
	// exactly the shape of the defect that made this field worth revisiting in
	// the first place.
	//
	// The entry keeps its place in the order and the row says the count was not
	// read, which is a different and weaker claim than a count of zero.
	if len(entries) > 0 {
		if want := layoutForVersion(version); want != "" && want != entries[0].layout {
			warnings = append(warnings, fmt.Sprintf(
				"DestList declares version %d, whose entries are the %s shape, "+
					"and the %s shape is what validated against the data. The "+
					"access count and pin status are read at offsets that shape "+
					"decides and are not reported for this file",
				version, want, entries[0].layout))
			for i := range entries {
				entries[i].accessCount = 0
				entries[i].accessRead = false
				entries[i].pinned = false
				entries[i].pinRead = false
			}
		}
	}

	return entries, declared, warnings
}

// layoutForVersion is the entry shape a DestList version implies, or "" where
// the version is one nothing here has a shape for — in which case the
// validating layout stands unremarked, because a guess is not a contradiction.
func layoutForVersion(version int) string {
	switch {
	case version == 1:
		return "legacy"
	case version >= 3:
		return "modern"
	}
	return ""
}

func readDestEntry(data []byte, offset int) (destEntry, int, bool) {
	for _, layout := range destLayouts {
		if offset+layout.fixed+2 > len(data) {
			continue
		}
		body := data[offset : offset+layout.fixed]

		pathChars := int(binary.LittleEndian.Uint16(
			data[offset+layout.fixed : offset+layout.fixed+2]))
		pathBytes := pathChars * 2
		pathStart := offset + layout.fixed + 2
		if pathChars == 0 || pathChars > 4096 || pathStart+pathBytes > len(data) {
			continue
		}

		path := decodeUTF16(data[pathStart : pathStart+pathBytes])
		if !plausiblePath(path) {
			continue
		}

		rawTime := binary.LittleEndian.Uint64(
			body[layout.fileTime : layout.fileTime+8])
		if _, ok := wintime.FromFileTime(rawTime); !ok {
			continue
		}

		entry := destEntry{
			layout:      layout.name,
			machineID:   trimZeros(string(body[0x48:0x58])),
			entryNumber: binary.LittleEndian.Uint32(body[layout.entryNumber : layout.entryNumber+4]),
			// Read as the float it is. This was truncated to an integer and
			// exported as the access count, and it is not one: entries on the
			// reference collections carry 3.7, 19.98 and 25.98, which no count
			// can be, and truncating turned one folder the DestList records as
			// opened six times into a claim it was opened twenty-five.
			rankingValue: math.Float32frombits(binary.LittleEndian.Uint32(
				body[layout.rankingValue : layout.rankingValue+4])),
			rawTime: rawTime,
			pinned: int32(binary.LittleEndian.Uint32(
				body[layout.pinStatus:layout.pinStatus+4])) >= 0,
			pinRead: true,
			path:    path,
		}

		if layout.accessCount >= 0 {
			entry.accessCount = binary.LittleEndian.Uint32(
				body[layout.accessCount : layout.accessCount+4])
			entry.accessRead = true
		}

		return entry, pathStart + pathBytes + layout.trailing, true
	}

	return destEntry{}, offset, false
}

// plausiblePath rejects a decode that produced control characters, which is how
// a wrong layout announces itself.
func plausiblePath(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	for _, r := range path {
		if r < 0x20 && r != '\t' {
			return false
		}
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

func attachDestList(entries []Entry, destList []destEntry) {
	if len(destList) == 0 {
		return
	}

	byNumber := make(map[uint32]destEntry, len(destList))
	for _, entry := range destList {
		byNumber[entry.entryNumber] = entry
	}

	for i := range entries {
		// A stream is named with the entry number in hexadecimal.
		number, err := strconv.ParseUint(strings.TrimSpace(entries[i].StreamName), 16, 32)
		if err != nil {
			continue
		}
		record, ok := byNumber[uint32(number)]
		if !ok {
			continue
		}

		entries[i].Present = true
		entries[i].EntryNumber = record.entryNumber
		entries[i].Position = record.position
		entries[i].Pinned = record.pinned
		entries[i].PinnedRecorded = record.pinRead
		entries[i].AccessCount = record.accessCount
		entries[i].AccessCountRecorded = record.accessRead
		entries[i].RankingValue = record.rankingValue
		entries[i].RecordedPath = record.path
		entries[i].MachineID = record.machineID
		entries[i].RawLastAccess = record.rawTime
		if converted, ok := wintime.FromFileTime(record.rawTime); ok {
			entries[i].LastAccessUTC = &converted
		}
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Position < entries[j].Position
	})
}

// linkSignature is the first 20 bytes of every shell link: the header size
// followed by the link class identifier.
var linkSignature = []byte{
	0x4C, 0x00, 0x00, 0x00,
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// parseCustom reads a custom destinations file by locating each shell link
// header.
//
// The file is a sequence of links separated by structure Boobook does not
// parse. Finding the links directly recovers every one of them, but it cannot
// say that nothing was missed between them, so the method is recorded with the
// result rather than left to be assumed.
func parseCustom(path, appID string, stats *Stats) []Entry {
	data, err := os.ReadFile(path)
	if err != nil {
		stats.Err = err
		return nil
	}

	var entries []Entry
	offset := 0
	index := 0

	for {
		found := bytes.Index(data[offset:], linkSignature)
		if found < 0 {
			break
		}
		start := offset + found

		link, err := lnk.Parse(data[start:])
		if err != nil {
			offset = start + len(linkSignature)
			continue
		}
		link.SourceFile = path
		link.Origin = fmt.Sprintf("jumplist_custom:%d", index)

		stats.Links++
		entries = append(entries, Entry{
			SourceFile: path,
			AppID:      appID,
			StreamName: fmt.Sprintf("link_%d", index),
			Link:       link,
		})

		index++
		offset = start + len(linkSignature)
	}

	stats.Streams = index
	return entries
}

func decodeUTF16(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(raw[i:i+2]))
	}
	return trimZeros(string(utf16Decode(units)))
}

func utf16Decode(units []uint16) []rune {
	runes := make([]rune, 0, len(units))
	for i := 0; i < len(units); i++ {
		unit := units[i]
		switch {
		case unit >= 0xD800 && unit < 0xDC00 && i+1 < len(units) &&
			units[i+1] >= 0xDC00 && units[i+1] < 0xE000:
			runes = append(runes,
				0x10000+(rune(unit-0xD800)<<10)+rune(units[i+1]-0xDC00))
			i++
		case unit >= 0xD800 && unit < 0xE000:
			runes = append(runes, 0xFFFD)
		default:
			runes = append(runes, rune(unit))
		}
	}
	return runes
}

func trimZeros(text string) string {
	return strings.TrimRight(text, "\x00")
}
