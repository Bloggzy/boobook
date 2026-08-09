package main

import (
	"bytes"
	"fmt"
)

// This file writes the .syso: a COFF object file holding nothing but a .rsrc
// section, which the Go linker copies into the executable's resource
// directory. The format is documented in the Microsoft PE specification, and
// the shape below is the minimum a resource-only object needs.
//
// The layout is a three-level tree — type, then name or id, then language —
// with the leaves pointing at the bytes. The one subtlety is that those
// pointers are image-relative addresses, which are not known until the linker
// places the section, so each is emitted as zero plus a relocation and the
// linker fills it in.

const (
	rtIcon      = 3  // RT_ICON: one image.
	rtGroupIcon = 14 // RT_GROUP_ICON: the directory naming them all.

	// langNeutral is en-US. Windows falls back to whatever language is
	// present when it finds no match, so a single entry serves everywhere;
	// this is a lookup key, not prose, and en-US is the one every tool that
	// might later read the resource expects to find.
	langNeutral = 0x0409

	dirSize   = 16 // IMAGE_RESOURCE_DIRECTORY
	entrySize = 8  // IMAGE_RESOURCE_DIRECTORY_ENTRY
	dataSize  = 16 // IMAGE_RESOURCE_DATA_ENTRY

	subdirFlag = 0x80000000 // Set in an entry's offset to mean "another directory".

	relAMD64Addr32NB = 0x0003 // IMAGE_REL_AMD64_ADDR32NB: a 32-bit image-relative address.
	symClassStatic   = 3      // IMAGE_SYM_CLASS_STATIC
)

// buildCOFF produces the object file. The icons become RT_ICON resources
// numbered from 1, and a single RT_GROUP_ICON names them; the group is given
// id 1 because Windows takes the lowest-numbered group icon as the
// application icon, which is what Explorer and the taskbar display.
func buildCOFF(images []iconImage) ([]byte, error) {
	if len(images) == 0 {
		return nil, fmt.Errorf("no icon images to write")
	}
	group := buildGroupIcon(images)
	n := len(images)

	// Every offset is fixed before a byte is written, because a directory
	// entry has to point forward at a structure that has not been emitted
	// yet. Walking the tree twice would work too; arithmetic is shorter and
	// the tree here has a known shape.
	offRoot := 0
	offTypeIcon := offRoot + dirSize + 2*entrySize
	offTypeGroup := offTypeIcon + dirSize + n*entrySize
	offNameIcon := offTypeGroup + dirSize + entrySize
	offNameGroup := offNameIcon + n*(dirSize+entrySize)
	offDataIcon := offNameGroup + dirSize + entrySize
	offDataGroup := offDataIcon + n*dataSize
	offBlobs := align(offDataGroup+dataSize, 8)

	blobAt := make([]int, n)
	at := offBlobs
	for i, img := range images {
		blobAt[i] = at
		at = align(at+len(img.data), 8)
	}
	groupAt := at
	sectionSize := align(groupAt+len(group), 8)

	var s bytes.Buffer

	// Level 1: the two resource types, which must be in ascending id order
	// because the loader binary-searches them.
	writeDir(&s, 0, 2)
	write(&s, uint32(rtIcon), uint32(offTypeIcon|subdirFlag))
	write(&s, uint32(rtGroupIcon), uint32(offTypeGroup|subdirFlag))

	// Level 2: the ids within each type.
	writeDir(&s, 0, uint16(n))
	for i := range images {
		write(&s, uint32(i+1), uint32((offNameIcon+i*(dirSize+entrySize))|subdirFlag))
	}
	writeDir(&s, 0, 1)
	write(&s, uint32(1), uint32(offNameGroup|subdirFlag))

	// Level 3: the language under each id, and the leaf pointing at it.
	for i := range images {
		writeDir(&s, 0, 1)
		write(&s, uint32(langNeutral), uint32(offDataIcon+i*dataSize))
	}
	writeDir(&s, 0, 1)
	write(&s, uint32(langNeutral), uint32(offDataGroup))

	// The leaves. The first field of each is the address the linker patches,
	// and the section-relative offset written here is the addend it adds to
	// the section's own address.
	for i, img := range images {
		write(&s, uint32(blobAt[i]), uint32(len(img.data)), uint32(0), uint32(0))
	}
	write(&s, uint32(groupAt), uint32(len(group)), uint32(0), uint32(0))

	for i, img := range images {
		pad(&s, blobAt[i])
		s.Write(img.data)
	}
	pad(&s, groupAt)
	s.Write(group)
	pad(&s, sectionSize)

	if s.Len() != sectionSize {
		return nil, fmt.Errorf("resource section is %d bytes, computed %d: the offset arithmetic and the writing disagree", s.Len(), sectionSize)
	}

	var relocs bytes.Buffer
	for i := range images {
		write(&relocs, uint32(offDataIcon+i*dataSize), uint32(0), uint16(relAMD64Addr32NB))
	}
	write(&relocs, uint32(offDataGroup), uint32(0), uint16(relAMD64Addr32NB))

	const fileHeader = 20
	const sectionHeader = 40
	rawAt := fileHeader + sectionHeader
	relocAt := rawAt + sectionSize
	symbolAt := relocAt + relocs.Len()

	var out bytes.Buffer

	// IMAGE_FILE_HEADER. One section, one symbol, no optional header: this is
	// an object file, not an image.
	write(&out, uint16(0x8664), uint16(1), uint32(0), uint32(symbolAt), uint32(1), uint16(0), uint16(0))

	// IMAGE_SECTION_HEADER. Initialised data, readable; the virtual address
	// and size stay zero because the linker decides where this lands.
	out.WriteString(".rsrc\x00\x00\x00")
	write(&out, uint32(0), uint32(0), uint32(sectionSize), uint32(rawAt))
	write(&out, uint32(relocAt), uint32(0), uint16(len(images)+1), uint16(0), uint32(0x40000040))

	out.Write(s.Bytes())
	out.Write(relocs.Bytes())

	// The one symbol: the section itself, which every relocation above is
	// expressed relative to.
	out.WriteString(".rsrc\x00\x00\x00")
	write(&out, uint32(0), uint16(1), uint16(0), uint8(symClassStatic), uint8(0))

	// An empty string table, which is four bytes holding its own length.
	// Omitting it entirely makes some readers run off the end of the file.
	write(&out, uint32(4))

	return out.Bytes(), nil
}

func writeDir(buf *bytes.Buffer, named, ids uint16) {
	write(buf, uint32(0), uint32(0), uint16(0), uint16(0), named, ids)
}

// pad writes zeroes until the buffer reaches the given length, which is how
// the gaps the alignment arithmetic assumed actually get filled.
func pad(buf *bytes.Buffer, to int) {
	if n := to - buf.Len(); n > 0 {
		buf.Write(make([]byte, n))
	}
}

func align(v, to int) int {
	if r := v % to; r != 0 {
		return v + to - r
	}
	return v
}
