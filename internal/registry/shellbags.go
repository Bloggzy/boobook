package registry

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"www.velocidex.com/golang/regparser"

	"github.com/Bloggzy/boobook/internal/shellitem"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// ShellBag is one folder a user's Explorer recorded having displayed.
//
// A bag survives the folder. It names a place on a volume that may never be
// seen again, which for a removable device is often the only record that the
// folder existed at all — so a bag on a drive letter is evidence about a
// device even when the device is long gone.
//
// The path is Explorer's own reading of a place, not a filesystem path that was
// resolved: the drive letter in it is the letter as it was when the folder was
// displayed, and letters are reused.
type ShellBag struct {
	Profile string
	Hive    string

	// Path is the place the chain of shell items names.
	Path string
	// PathHasGap records that an item in the chain named nothing, so the path
	// is a reading with something missing from the middle rather than a place.
	PathHasGap bool

	// DriveLetter is set where a volume item in the chain named one.
	DriveLetter string
	// Name is the last item's name: the folder this bag is about.
	Name string
	Kind string

	// Depth is how far down the tree the bag sits, and NodeSlot is the bag
	// number Explorer stored the view settings under.
	Depth    int
	NodeSlot uint32
	// MRUPosition is the bag's place in its parent's MRUListEx order, where the
	// parent recorded one. -1 means the order was not recorded.
	MRUPosition int

	// The shell item's own timestamps. FAT values: local wall clock with no
	// zone, never presented as UTC instants.
	RawModified   uint32
	RawCreated    uint32
	RawAccessed   uint32
	ModifiedLocal *time.Time
	CreatedLocal  *time.Time
	AccessedLocal *time.Time

	MFTEntry    uint64
	MFTSequence uint16

	RegistryPath    string
	RawKeyLastWrite uint64
	KeyLastWriteUTC *time.Time

	Raw      string
	Warnings []string
}

// bagRoots are where the shell bag trees live. NTUSER holds the network and
// virtual folder tree; UsrClass holds the local one, which is where a removable
// volume's folders are recorded on any current Windows.
var bagRoots = map[string][]string{
	"NTUSER": {
		`Software\Microsoft\Windows\Shell\BagMRU`,
		`Software\Microsoft\Windows\ShellNoRoam\BagMRU`,
	},
	"USRCLASS": {
		`Local Settings\Software\Microsoft\Windows\Shell\BagMRU`,
		`Local Settings\Software\Microsoft\Windows\ShellNoRoam\BagMRU`,
	},
}

// maxBagDepth stops a malformed or circular tree from walking forever. A real
// tree is nowhere near this deep, and a run that hit the limit says so.
const maxBagDepth = 64

// ReadShellBags walks a hive's shell bag trees.
func ReadShellBags(registry *regparser.Registry, hive, profile string) []ShellBag {
	var bags []ShellBag

	for _, root := range bagRoots[hive] {
		key := registry.OpenKey(root)
		if key == nil {
			continue
		}
		bags = append(bags, walkBags(key, root, hive, profile, "", "", 0)...)
	}

	return bags
}

// walkBags descends one level of the bag tree.
//
// Each numbered value at a key holds the shell item for the child of the same
// number, so the path is built on the way down rather than read from any single
// key. A child whose value is missing still exists as a key, and it is kept
// with the gap recorded: dropping it would silently shorten the tree.
func walkBags(key *regparser.CM_KEY_NODE, path, hive, profile,
	parentPath, driveLetter string, depth int) []ShellBag {

	if depth > maxBagDepth {
		return []ShellBag{{
			Profile: profile, Hive: hive, RegistryPath: path, Depth: depth,
			Path:        parentPath,
			MRUPosition: -1,
			Warnings: []string{
				"the bag tree is deeper than " + strconv.Itoa(maxBagDepth) +
					" levels and was not followed further"},
		}}
	}

	items := map[string][]byte{}
	order := map[string]int{}

	for _, value := range key.Values() {
		name := value.ValueName()
		data := value.ValueData()
		if data == nil {
			continue
		}
		if strings.EqualFold(name, "MRUListEx") {
			for position, index := range decodeMRUListEx(data.Data) {
				order[strconv.FormatUint(uint64(index), 10)] = position
			}
			continue
		}
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}
		items[name] = data.Data
	}

	var bags []ShellBag
	for _, subkey := range key.Subkeys() {
		name := subkey.Name()
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}

		bag := ShellBag{
			Profile:         profile,
			Hive:            hive,
			Depth:           depth,
			MRUPosition:     -1,
			RegistryPath:    path + `\` + name,
			RawKeyLastWrite: RawLastWrite(subkey),
			NodeSlot:        readNodeSlot(subkey),
		}
		if converted, ok := wintime.FromFileTime(bag.RawKeyLastWrite); ok {
			bag.KeyLastWriteUTC = &converted
		}
		if position, ok := order[name]; ok {
			bag.MRUPosition = position
		}

		childPath := parentPath
		childLetter := driveLetter

		raw, ok := items[name]
		if !ok {
			// The key exists and the item naming it does not. The subtree below
			// is still real, so it is walked with the gap marked.
			bag.PathHasGap = true
			bag.Path = parentPath
			bag.Warnings = append(bag.Warnings,
				"no shell item is stored for this bag, so its own name is not known")
		} else {
			bag.Raw = hex.EncodeToString(raw)
			item, err := shellitem.ParseItem(raw)
			if err != nil {
				bag.PathHasGap = true
				bag.Path = parentPath
				bag.Warnings = append(bag.Warnings, err.Error())
			} else {
				applyItem(&bag, item, parentPath)
				childPath = bag.Path
				if bag.DriveLetter != "" {
					childLetter = bag.DriveLetter
				}
			}
		}

		if bag.DriveLetter == "" {
			bag.DriveLetter = driveLetter
		}
		bags = append(bags, bag)
		bags = append(bags, walkBags(subkey, bag.RegistryPath, hive, profile,
			childPath, childLetter, depth+1)...)
	}

	return bags
}

func applyItem(bag *ShellBag, item shellitem.Item, parentPath string) {
	bag.Kind = string(item.Kind)
	bag.Name = item.Name
	if bag.Name == "" {
		bag.Name = item.KnownFolder
	}
	bag.DriveLetter = item.DriveLetter

	bag.RawModified = item.RawModified
	bag.RawCreated = item.RawCreated
	bag.RawAccessed = item.RawAccessed
	bag.ModifiedLocal = item.ModifiedLocal
	bag.CreatedLocal = item.CreatedLocal
	bag.AccessedLocal = item.AccessedLocal
	bag.MFTEntry = item.MFTEntry
	bag.MFTSequence = item.MFTSequence
	bag.Warnings = append(bag.Warnings, item.Warnings...)

	if bag.Name == "" {
		bag.PathHasGap = true
		bag.Path = parentPath
		return
	}

	name := strings.TrimSuffix(bag.Name, `\`)
	if parentPath == "" {
		bag.Path = name
		return
	}
	bag.Path = parentPath + `\` + name
}

func readNodeSlot(key *regparser.CM_KEY_NODE) uint32 {
	for _, value := range key.Values() {
		if !strings.EqualFold(value.ValueName(), "NodeSlot") {
			continue
		}
		if data := value.ValueData(); data != nil && len(data.Data) >= 4 {
			return binary.LittleEndian.Uint32(data.Data[:4])
		}
	}
	return 0
}

// decodeMRUListEx reads the little-endian DWORD list that records the order
// entries were last used in, most recent first. The list ends with 0xFFFFFFFF.
func decodeMRUListEx(raw []byte) []uint32 {
	var order []uint32
	for offset := 0; offset+4 <= len(raw); offset += 4 {
		value := binary.LittleEndian.Uint32(raw[offset : offset+4])
		if value == 0xFFFFFFFF {
			break
		}
		order = append(order, value)
	}
	return order
}

// MRUEntry is one entry from a most-recently-used list: RecentDocs, or one of
// the file dialog's own lists.
//
// These are the record of a file being opened or saved. Where the path names a
// drive letter that a removable volume held, it places file activity on that
// volume — the same chain as a shell link, from a different artefact, and one
// that survives the .lnk file being deleted.
type MRUEntry struct {
	Profile string
	// Source names which list this came from, e.g. "RecentDocs\.docx".
	Source string
	// Kind is recent_doc, open_save or last_visited.
	Kind string

	// Name is the value the list stored: a file name for RecentDocs, an
	// executable name for LastVisited.
	Name string
	// Path is the place the shell items in the value named, where the value
	// carried any. RecentDocs stores a name and a path; the file dialog lists
	// store a path alone.
	Path        string
	PathHasGap  bool
	DriveLetter string
	// VolumeLabel is the label Explorer showed beside the letter, where the
	// entry was a drive root. It is the volume's own name at the moment the
	// entry was made, which is the one thing MountedDevices cannot supply.
	VolumeLabel string
	// LetterFromName records that DriveLetter was read out of the displayed
	// name rather than out of a shell item, because the two are found in
	// different ways and a reader checking the row needs to know which.
	LetterFromName bool

	// Position is the entry's place in the MRUListEx order, 0 being the most
	// recent. -1 means the list did not record its order.
	Position int
	// ValueName is the stored value name, which is what an analyst matches
	// against the key when checking this row.
	ValueName string

	RawModified   uint32
	ModifiedLocal *time.Time

	RegistryPath    string
	RawKeyLastWrite uint64
	KeyLastWriteUTC *time.Time

	Raw      string
	Warnings []string
}

const (
	recentDocsPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
	comDlg32Path   = `Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32`
)

// ReadRecentDocs parses the RecentDocs key and its per-extension subkeys.
func ReadRecentDocs(registry *regparser.Registry, profile string) []MRUEntry {
	root := registry.OpenKey(recentDocsPath)
	if root == nil {
		return nil
	}

	entries := readRecentDocsKey(root, recentDocsPath, profile)
	for _, subkey := range root.Subkeys() {
		path := recentDocsPath + `\` + subkey.Name()
		entries = append(entries, readRecentDocsKey(subkey, path, profile)...)
	}

	return entries
}

func readRecentDocsKey(key *regparser.CM_KEY_NODE, path, profile string) []MRUEntry {
	order := mruOrder(key)

	var entries []MRUEntry
	for _, value := range key.Values() {
		name := value.ValueName()
		if strings.EqualFold(name, "MRUListEx") {
			continue
		}
		data := value.ValueData()
		if data == nil || len(data.Data) == 0 {
			continue
		}

		entry := newEntry(key, path, profile, "recent_doc", name, order)

		// The value holds the displayed file name, then the shell items that
		// name where it was. The name is read first because it is reliable;
		// what follows it is offered to the item parser and kept only if that
		// produced something readable.
		displayed, next := readUTF16(data.Data, 0)
		entry.Name = displayed
		entry.Raw = hex.EncodeToString(data.Data)
		applyTrailingItems(&entry, data.Data, next)
		applyDriveRootName(&entry)

		entries = append(entries, entry)
	}

	return entries
}

// ReadFileDialogMRU parses the common file dialog's own lists: the places a
// user navigated to when opening or saving, per file type and per application.
func ReadFileDialogMRU(registry *regparser.Registry, profile string) []MRUEntry {
	var entries []MRUEntry

	// The PIDL forms store shell items. The older string forms store a path as
	// text and are read where a host still has them.
	for _, list := range []struct{ key, kind string }{
		{"OpenSavePidlMRU", "open_save"},
		{"LastVisitedPidlMRU", "last_visited"},
		{"LastVisitedPidlMRULegacy", "last_visited"},
	} {
		path := comDlg32Path + `\` + list.key
		root := registry.OpenKey(path)
		if root == nil {
			continue
		}

		entries = append(entries,
			readDialogKey(root, path, profile, list.kind)...)
		for _, subkey := range root.Subkeys() {
			entries = append(entries, readDialogKey(subkey,
				path+`\`+subkey.Name(), profile, list.kind)...)
		}
	}

	return entries
}

func readDialogKey(key *regparser.CM_KEY_NODE, path, profile, kind string) []MRUEntry {
	order := mruOrder(key)

	var entries []MRUEntry
	for _, value := range key.Values() {
		name := value.ValueName()
		if strings.EqualFold(name, "MRUListEx") {
			continue
		}
		data := value.ValueData()
		if data == nil || len(data.Data) == 0 {
			continue
		}

		entry := newEntry(key, path, profile, kind, name, order)
		entry.Raw = hex.EncodeToString(data.Data)

		if kind == "last_visited" {
			// LastVisited stores the executable that was doing the opening,
			// then the place it was pointed at. Which application opened a file
			// on a removable volume is often the question being asked.
			executable, next := readUTF16(data.Data, 0)
			entry.Name = executable
			applyTrailingItems(&entry, data.Data, next)
		} else {
			applyItems(&entry, data.Data)
			entry.Name = lastSegment(entry.Path)
		}

		entries = append(entries, entry)
	}

	return entries
}

func newEntry(key *regparser.CM_KEY_NODE, path, profile, kind, valueName string,
	order map[string]int) MRUEntry {

	entry := MRUEntry{
		Profile:         profile,
		Source:          shortSource(path),
		Kind:            kind,
		ValueName:       valueName,
		Position:        -1,
		RegistryPath:    path,
		RawKeyLastWrite: RawLastWrite(key),
	}
	if converted, ok := wintime.FromFileTime(entry.RawKeyLastWrite); ok {
		entry.KeyLastWriteUTC = &converted
	}
	if position, ok := order[valueName]; ok {
		entry.Position = position
	}
	return entry
}

// applyTrailingItems reads shell items that follow a string in a value.
//
// The trailing bytes are only reported as a path when they parse into items
// that named something. Where they do not, they stay in Raw and no path is
// claimed: guessing at a format is how a report acquires a path nobody can find
// in the evidence.
func applyTrailingItems(entry *MRUEntry, raw []byte, offset int) {
	if offset >= len(raw) {
		return
	}
	applyItems(entry, raw[offset:])
}

func applyItems(entry *MRUEntry, raw []byte) {
	list, err := shellitem.Parse(raw)
	if err != nil || len(list.Items) == 0 {
		return
	}

	path := list.Path()
	if path == "" {
		return
	}

	entry.Path = path
	entry.PathHasGap = list.HasGap()
	entry.Warnings = append(entry.Warnings, list.Warnings...)
	if list.Truncated {
		entry.Warnings = append(entry.Warnings,
			"the shell item list had no terminator, so the path is a prefix")
	}

	for _, item := range list.Items {
		if item.DriveLetter != "" {
			entry.DriveLetter = item.DriveLetter
		}
	}
	if last := list.Last(); last != nil {
		entry.RawModified = last.RawModified
		entry.ModifiedLocal = last.ModifiedLocal
	}
}

// applyDriveRootName reads a drive letter, and where there is one the volume's
// label, out of the name RecentDocs displayed.
//
// RecentDocs stores the caption Explorer showed, and for a drive root that
// caption is the volume's label followed by its letter — `PATRIOT (E:)` — or,
// where the shell had no label to show, the bare `E:\`. The shell items that
// follow the caption point at the shortcut in the Recent folder rather than at
// the drive, so they yield a `.lnk` name and no letter, and these rows reached
// the report with no letter at all: 40-odd of them on
// USB-LENOVO-Multi-USBs, five of which name a stick.
//
// The label is the part worth having. MountedDevices records only the mapping
// as it stood at collection, and on that collection it was a minute stale and
// named the wrong device; this caption is the label the volume *itself* carried
// when the entry was written, which reaches the device by a route the mount
// table cannot contradict. On that host `PATRIOT (E:)` names the stick that
// really held E:, independently of any of it.
//
// A colon cannot appear in a Windows file or folder name, so a caption ending
// ` (X:)` was generated by the shell and is not a name a user could have
// produced. The letter is taken only where the shell items gave none: where
// both exist the item parsed a structure and this parsed a string.
func applyDriveRootName(entry *MRUEntry) {
	name := entry.Name
	letter, label := "", ""

	switch {
	// `E:` or `E:\`, which is what the shell shows for a volume with no label.
	case (len(name) == 2 || (len(name) == 3 && name[2] == '\\')) &&
		name[1] == ':' && isDriveLetter(name[0]):
		letter = strings.ToUpper(name[:1])

	// `LABEL (E:)`. The tail is exactly five characters — space, bracket,
	// letter, colon, bracket — and everything before it is the label.
	case len(name) > 5 && strings.HasSuffix(name, ":)") &&
		strings.HasSuffix(name[:len(name)-3], " (") &&
		isDriveLetter(name[len(name)-3]):
		letter = strings.ToUpper(name[len(name)-3 : len(name)-2])
		label = name[:len(name)-5]
	}

	if letter == "" {
		return
	}
	if entry.DriveLetter == "" {
		entry.DriveLetter = letter
		entry.LetterFromName = true
	}
	// Where the volume has no label of its own the shell substitutes a caption
	// of its own — "Removable Disk (E:)", "Local Disk (C:)" — and taking that
	// for a label would offer the label routes a name no volume ever carried.
	// The list is the English captions; on a host in another language an
	// unlabelled volume's caption is not recognised and is carried as a label,
	// where it matches no device and the route stays silent.
	if label != "" && !isShellDriveCaption(label) {
		entry.VolumeLabel = label
	}
}

func isDriveLetter(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isShellDriveCaption(label string) bool {
	switch strings.ToLower(label) {
	case "local disk", "removable disk", "usb drive", "network drive",
		"floppy disk drive", "cd drive", "cd-rw drive", "dvd drive",
		"dvd rw drive", "dvd-ram drive", "bd-rom drive", "blu-ray drive":
		return true
	}
	return false
}

func mruOrder(key *regparser.CM_KEY_NODE) map[string]int {
	order := map[string]int{}
	for _, value := range key.Values() {
		if !strings.EqualFold(value.ValueName(), "MRUListEx") {
			continue
		}
		if data := value.ValueData(); data != nil {
			for position, index := range decodeMRUListEx(data.Data) {
				order[strconv.FormatUint(uint64(index), 10)] = position
			}
		}
	}
	return order
}

// shortSource trims the long Explorer key prefix, which is the same on every
// row and pushes the part that differs off the end of a column.
func shortSource(path string) string {
	for _, prefix := range []string{
		`Software\Microsoft\Windows\CurrentVersion\Explorer\`,
		`Local Settings\Software\Microsoft\Windows\`,
		`Software\Microsoft\Windows\`,
	} {
		if strings.HasPrefix(path, prefix) {
			return strings.TrimPrefix(path, prefix)
		}
	}
	return path
}

func lastSegment(path string) string {
	if index := strings.LastIndex(path, `\`); index >= 0 {
		return path[index+1:]
	}
	return path
}

func readUTF16(data []byte, offset int) (string, int) {
	units := make([]uint16, 0, 32)
	for i := offset; i+1 < len(data); i += 2 {
		unit := binary.LittleEndian.Uint16(data[i : i+2])
		if unit == 0 {
			return string(utf16.Decode(units)), i + 2
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units)), len(data)
}
