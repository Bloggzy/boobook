package fixture

import (
	"encoding/binary"
	"unicode/utf16"
)

// A minimal OLE compound file, built from MS-CFB rather than from the reader
// Boobook uses to walk one.
//
// This exists for one claim: a stream's size is a number the evidence supplies,
// and a parser that allocates it before reading has handed an attacker — or a
// file truncated mid-write — the ability to end the whole case. Proving that
// needs a file that is *valid enough to reach the allocation*, which "not OLE"
// in the adversarial tree never was: it fails at the header and exercises
// nothing below it.
//
// So the header, FAT and directory here are real, and only the declared stream
// size is a lie. Everything else has to be right or the file is refused for the
// wrong reason and the test proves nothing.
//
// Version 3 layout throughout: 512-byte sectors, 128-byte directory entries,
// the 4096-byte cutoff below which a stream would live in the mini stream. The
// declared sizes used here are far above that, so the streams are ordinary
// FAT-chained ones and no mini FAT is needed.
const (
	cfbSectorSize    = 512
	cfbDirEntrySize  = 128
	cfbFreeSector    = 0xFFFFFFFF
	cfbEndOfChain    = 0xFFFFFFFE
	cfbFATSector     = 0xFFFFFFFD
	cfbNoStream      = 0xFFFFFFFF
	cfbTypeStorage   = 1
	cfbTypeStream    = 2
	cfbTypeRootEntry = 5
)

// CompoundStream is one stream to place in a built compound file.
type CompoundStream struct {
	Name string
	// Declared is the size written into the directory entry. Where it differs
	// from len(Data) the file is claiming something the bytes do not support,
	// which is the case this builder exists for.
	//
	// Left at zero it becomes the length of Data, padded up to the mini-stream
	// cutoff. MS-CFB puts any stream below that cutoff in the mini stream,
	// which needs a mini FAT and a root-entry chain of its own — a lot of
	// machinery to build for a fixture whose claim is about a declared size, so
	// every stream here is made large enough to be an ordinary FAT-chained one
	// instead. The padding is trailing zeroes: a DestList is read by the entry
	// count in its header and a link by its own structure sizes, so neither
	// notices bytes after the end of what it declares.
	Declared uint64
	Data     []byte
}

// BuildCompoundFile writes a compound file holding the given streams.
//
// The layout is the simplest one MS-CFB permits: sector 0 is the only FAT,
// sector 1 the only directory sector, and each stream occupies whole sectors
// after them. A directory sector holds four entries, so four streams is the
// most this builds — enough for a DestList and a link beside it, which is the
// shape of a real jump list.
func BuildCompoundFile(streams []CompoundStream) []byte {
	if len(streams) > cfbSectorSize/cfbDirEntrySize-1 {
		panic("fixture: more streams than one directory sector holds")
	}

	// Lay the stream data out first, because the FAT and the directory both
	// need to know which sectors each one took.
	const firstDataSector = 2
	const miniStreamCutoff = 4096
	starts := make([]uint32, len(streams))
	lengths := make([]int, len(streams))
	held := make([]uint64, len(streams))
	next := uint32(firstDataSector)
	var data []byte
	for i, stream := range streams {
		bytes := len(stream.Data)
		if bytes < miniStreamCutoff {
			bytes = miniStreamCutoff
		}
		sectors := (bytes + cfbSectorSize - 1) / cfbSectorSize
		if sectors == 0 {
			starts[i] = cfbEndOfChain
			continue
		}
		starts[i] = next
		lengths[i] = sectors
		held[i] = uint64(sectors * cfbSectorSize)
		padded := make([]byte, sectors*cfbSectorSize)
		copy(padded, stream.Data)
		data = append(data, padded...)
		next += uint32(sectors)
	}

	// The FAT. Sector 0 is the FAT itself and sector 1 the directory; each
	// stream's sectors chain forward and end with ENDOFCHAIN.
	fat := make([]uint32, cfbSectorSize/4)
	for i := range fat {
		fat[i] = cfbFreeSector
	}
	fat[0] = cfbFATSector
	fat[1] = cfbEndOfChain
	for i := range streams {
		if lengths[i] == 0 {
			continue
		}
		start := int(starts[i])
		for s := 0; s < lengths[i]; s++ {
			if s == lengths[i]-1 {
				fat[start+s] = cfbEndOfChain
			} else {
				fat[start+s] = uint32(start + s + 1)
			}
		}
	}

	out := make([]byte, 0, cfbSectorSize*3+len(data))
	out = append(out, cfbHeader()...)
	out = append(out, cfbFATSectorBytes(fat)...)
	out = append(out, cfbDirectory(streams, starts, held)...)
	out = append(out, data...)
	return out
}

func cfbHeader() []byte {
	header := make([]byte, cfbSectorSize)
	copy(header, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(header[24:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(header[26:], 0x0003) // major version 3
	binary.LittleEndian.PutUint16(header[28:], 0xFFFE) // little endian
	binary.LittleEndian.PutUint16(header[30:], 9)      // 512-byte sectors
	binary.LittleEndian.PutUint16(header[32:], 6)      // 64-byte mini sectors
	binary.LittleEndian.PutUint32(header[44:], 1)      // one FAT sector
	binary.LittleEndian.PutUint32(header[48:], 1)      // directory at sector 1
	binary.LittleEndian.PutUint32(header[56:], 4096)   // mini stream cutoff
	binary.LittleEndian.PutUint32(header[60:], cfbEndOfChain)
	binary.LittleEndian.PutUint32(header[64:], 0) // no mini FAT sectors
	binary.LittleEndian.PutUint32(header[68:], cfbEndOfChain)
	binary.LittleEndian.PutUint32(header[72:], 0) // no DIFAT sectors

	// The DIFAT, 109 entries in the header itself. The first names sector 0 as
	// the FAT and the rest are free.
	for i := 0; i < 109; i++ {
		value := uint32(cfbFreeSector)
		if i == 0 {
			value = 0
		}
		binary.LittleEndian.PutUint32(header[76+i*4:], value)
	}
	return header
}

func cfbFATSectorBytes(fat []uint32) []byte {
	sector := make([]byte, cfbSectorSize)
	for i, entry := range fat {
		binary.LittleEndian.PutUint32(sector[i*4:], entry)
	}
	return sector
}

func cfbDirectory(streams []CompoundStream, starts []uint32, held []uint64) []byte {
	sector := make([]byte, cfbSectorSize)
	for i := range sector {
		sector[i] = 0
	}
	// Every entry begins with its sibling and child pointers unset. An entry
	// left as all zeroes would name entry 0 as its left sibling and the reader
	// would walk in a circle.
	for slot := 0; slot < cfbSectorSize/cfbDirEntrySize; slot++ {
		entry := sector[slot*cfbDirEntrySize:][:cfbDirEntrySize]
		binary.LittleEndian.PutUint32(entry[68:], cfbNoStream)
		binary.LittleEndian.PutUint32(entry[72:], cfbNoStream)
		binary.LittleEndian.PutUint32(entry[76:], cfbNoStream)
	}

	root := sector[0:cfbDirEntrySize]
	cfbName(root, "Root Entry")
	root[66] = cfbTypeRootEntry
	root[67] = 1 // black
	if len(streams) > 0 {
		binary.LittleEndian.PutUint32(root[76:], 1) // child: the first stream
	}
	binary.LittleEndian.PutUint32(root[116:], cfbEndOfChain) // no mini stream

	// The streams hang off the root as a chain of right siblings, which is a
	// legal if unbalanced red-black tree and is what a reader walking the whole
	// directory sees either way.
	for i, stream := range streams {
		slot := i + 1
		entry := sector[slot*cfbDirEntrySize:][:cfbDirEntrySize]
		cfbName(entry, stream.Name)
		entry[66] = cfbTypeStream
		entry[67] = 1
		if i+1 < len(streams) {
			binary.LittleEndian.PutUint32(entry[72:], uint32(slot+1))
		}
		binary.LittleEndian.PutUint32(entry[116:], starts[i])
		declared := stream.Declared
		if declared == 0 {
			declared = held[i]
		}
		binary.LittleEndian.PutUint64(entry[120:], declared)
	}

	// Unused slots must say they are unused, or a reader counts them as
	// storages with empty names.
	for slot := len(streams) + 1; slot < cfbSectorSize/cfbDirEntrySize; slot++ {
		sector[slot*cfbDirEntrySize+66] = 0
	}
	return sector
}

// cfbName writes a directory entry name: UTF-16LE, null terminated, with the
// byte length including that terminator in the two bytes after it.
func cfbName(entry []byte, name string) {
	encoded := utf16.Encode([]rune(name))
	for i, unit := range encoded {
		binary.LittleEndian.PutUint16(entry[i*2:], unit)
	}
	binary.LittleEndian.PutUint16(entry[64:], uint16((len(encoded)+1)*2))
}
