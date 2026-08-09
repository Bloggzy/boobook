package fixture

import (
	"encoding/binary"
	"math"
)

// DestList entries, built from the documented layout rather than from the
// parser's own offset table.
//
// The offsets below come from the reverse-engineered description of the
// automatic destinations DestList stream, and the distinction that matters is
// between two fields that were once read as one. Every version stores an
// undocumented 32-bit float beside the entry number; version 2 and later add a
// separate 32-bit integer after the pin status, which is the field that counts
// accesses. Boobook read the float, truncated it to an integer, and exported
// that as the access count — which on real evidence produced 25 for an entry
// whose recorded count is 6, because the float is not a count and holds values
// such as 3.7 and 25.98.
//
// A builder that took its offsets from the parser could not express that
// difference: it would put one value in one place and read it back from the
// same place, which is the failure this package exists to prevent.

// DestList format versions. 1 is Windows 7 and 8; 3 and above are Windows 10
// and 11, and are the versions that carry an access count.
const (
	DestListV1 = 1
	DestListV3 = 3
	DestListV4 = 4
	DestListV6 = 6
)

// The version 1 entry. Sizes and offsets are from the format description.
const (
	destV1Size        = 0x70
	destV1Hostname    = 0x48
	destV1EntryNumber = 0x58
	destV1Ranking     = 0x5C
	destV1FileTime    = 0x60
	destV1PinStatus   = 0x68
	destV1Trailing    = 0
)

// The version 3 and later entry. It is sixteen bytes longer, and the four
// bytes at destV3AccessCount are the addition that matters here.
const (
	destV3Size        = 0x80
	destV3Hostname    = 0x48
	destV3EntryNumber = 0x58
	destV3Ranking     = 0x60
	destV3FileTime    = 0x64
	destV3PinStatus   = 0x6C
	destV3AccessCount = 0x74
	destV3Trailing    = 4
)

// DestListEntry is one entry to build.
type DestListEntry struct {
	EntryNumber uint32
	FileTime    uint64
	Hostname    string
	Path        string
	Pinned      bool
	// RankingValue is the undocumented float. Deliberately non-integral in the
	// tests, because that is what proves it is not being read as a count.
	RankingValue float32
	// AccessCount is written only for version 2 and later. A version 1 entry
	// has nowhere to put it.
	AccessCount uint32
}

// BuildDestList assembles a DestList stream of the given version.
func BuildDestList(version uint32, entries ...DestListEntry) []byte {
	return BuildDestListWithShape(version, version, entries...)
}

// BuildDestListWithShape writes a header declaring one version and entries in
// the shape of another.
//
// A real DestList does not do this, and that is the point: the version number
// is a claim the file makes about itself and the entry framing is a fact about
// its bytes, so a parser that picks the layout by validation has to say what it
// does when the two disagree. Built with one argument for both, as BuildDestList
// does, the fixture can only ever exercise the case where they agree.
func BuildDestListWithShape(declared, shape uint32, entries ...DestListEntry) []byte {
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:4], declared)
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(entries)))

	out := header
	for _, entry := range entries {
		out = append(out, buildDestListEntry(shape, entry)...)
	}
	return out
}

func buildDestListEntry(version uint32, entry DestListEntry) []byte {
	size, hostname, entryNumber, ranking, fileTime, pinStatus, trailing :=
		destV3Size, destV3Hostname, destV3EntryNumber, destV3Ranking,
		destV3FileTime, destV3PinStatus, destV3Trailing
	accessCount := destV3AccessCount
	if version < 2 {
		size, hostname, entryNumber, ranking, fileTime, pinStatus, trailing =
			destV1Size, destV1Hostname, destV1EntryNumber, destV1Ranking,
			destV1FileTime, destV1PinStatus, destV1Trailing
		accessCount = -1
	}

	body := make([]byte, size)
	copy(body[hostname:hostname+16], entry.Hostname)
	binary.LittleEndian.PutUint32(body[entryNumber:], entry.EntryNumber)
	binary.LittleEndian.PutUint32(body[ranking:], math.Float32bits(entry.RankingValue))
	binary.LittleEndian.PutUint64(body[fileTime:], entry.FileTime)

	// A pin status of -1 means the entry is not pinned; anything else is a
	// pinned entry's index in the pinned list.
	status := uint32(0xFFFFFFFF)
	if entry.Pinned {
		status = 0
	}
	binary.LittleEndian.PutUint32(body[pinStatus:], status)

	if accessCount >= 0 {
		binary.LittleEndian.PutUint32(body[accessCount:], entry.AccessCount)
	}

	units := make([]byte, 0, len([]rune(entry.Path))*2)
	for _, r := range entry.Path {
		unit := make([]byte, 2)
		binary.LittleEndian.PutUint16(unit, uint16(r))
		units = append(units, unit...)
	}

	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len([]rune(entry.Path))))

	out := append(body, length...)
	out = append(out, units...)
	return append(out, make([]byte, trailing)...)
}
