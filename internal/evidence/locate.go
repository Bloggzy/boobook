// Package evidence locates artefacts within an evidence root.
//
// An evidence root is a mounted Windows volume, or a triage collection that
// wraps one or more volumes in a collector-specific layout. Nothing beneath the
// root is ever written, and nothing outside it is ever read.
package evidence

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Layout names how a collection presents its volumes.
type Layout string

const (
	// LayoutPlain is a mounted volume: Windows\, Users\, ProgramData\ at the root.
	LayoutPlain Layout = "plain_volume"
	// LayoutVelociraptor is an offline collector: uploads\auto\C%3A\ or
	// uploads\ntfs\%5C%5C.%5CC%3A\.
	LayoutVelociraptor Layout = "velociraptor"
	// LayoutKAPE is a KAPE target collection: C\ or C%3A\ at the root.
	LayoutKAPE Layout = "kape"
)

// VolumeRoot is one Windows volume found inside the evidence root.
type VolumeRoot struct {
	// Path is where the volume's Windows\ directory sits.
	Path string
	// DriveLetter is the letter the collector encoded, where it recorded one.
	DriveLetter string
	Layout      Layout
}

// Artefact is one located evidence file.
type Artefact struct {
	// Kind names what it is: SYSTEM, SOFTWARE, NTUSER, USRCLASS, EVTX, SETUPAPI,
	// PREFETCH.
	Kind string
	Path string
	// VolumeRoot is the volume it belongs to.
	VolumeRoot string
	// Profile is the user profile it came from, for per-user artefacts.
	Profile string
	// LogPaths are the registry transaction logs belonging to a hive.
	LogPaths []string
	// Channel is the decoded event log channel name, for EVTX.
	Channel string
	// Context is which of the shortcut directories this file was found in,
	// for LNK and JUMPLIST. It is what licenses reading the file's own mtime
	// as an opening: see ModifiedUTC and LinkContext.
	Context string
}

// ModifiedUTC is the artefact file's own last-written time.
//
// For a shortcut this can be evidence in its own right rather than
// housekeeping: where the shell maintains the link it rewrites the .lnk each
// time the target is opened, so the file's own mtime is when that target was
// most recently opened. The timestamps inside the link describe the target and
// say nothing about the opening.
//
// *Where the shell maintains it* is the whole condition, and this method
// cannot check it — a Desktop shortcut or a pinned Quick Launch item is
// written when a user makes, edits, pins or copies it, and calling that an
// opening asserts an interaction nobody evidenced. Context carries which
// directory the file came from and v_file_activity decides what the mtime is
// worth there, which is the same division of labour as every other route: the
// parser supplies the fact, the view draws the conclusion.
//
// It is also the collected copy's time, so it is only as good as the
// collector. Velociraptor and KAPE preserve it; a tree copied with Explorer
// would carry the copy's time instead. Zero where it could not be read, and
// never substituted for by anything else.
func (a Artefact) ModifiedUTC() *time.Time {
	info, err := os.Stat(a.Path)
	if err != nil {
		return nil
	}
	modified := info.ModTime().UTC()
	return &modified
}

// Set is everything found beneath an evidence root.
type Set struct {
	Root      string
	Volumes   []VolumeRoot
	Artefacts []Artefact
	// Missing names expected artefacts that were not present. An absence is a
	// finding about the collection, so it is reported rather than passed over.
	Missing []string
	// Collisions records names differing only in case, where a collection was
	// made on a case-sensitive filesystem. The choice is deterministic and the
	// collision is reported rather than silently resolved.
	Collisions []string
	// Failures records places discovery could not look. See DiscoveryFailure.
	Failures []DiscoveryFailure
}

// Why discovery could not look somewhere, weakest claim last.
const (
	// FailureUnreadable is a directory or file the run could not read: a
	// permission, a broken link, a device error.
	FailureUnreadable = "unreadable"
	// FailureBoundaryRefused is a path that resolved outside the evidence
	// root, which is a junction or a symlink escaping the collection.
	FailureBoundaryRefused = "boundary_refused"
	// FailureWalkFailed is an error part way through a directory walk, where
	// what was found before it is kept and what lay beyond it was not seen.
	FailureWalkFailed = "walk_failed"
)

// DiscoveryFailure is a place the run could not look.
//
// Set.Missing already says an expected artefact was not there. This says
// something different and stronger: it was not looked at. Both used to produce
// the same silence — every walker discarded its errors and every boundary
// refusal returned nil — so a Recent folder the collector could not read was
// indistinguishable from one holding no shortcuts, and the report's silence
// read as "nobody opened a file from a device" when it meant "nobody looked".
//
// That is the failure mode this whole project is written against, arriving
// through the one door nothing else guards: absence is reported as absence, and
// an unreadable directory is not an absence.
type DiscoveryFailure struct {
	// Path is what could not be read.
	Path string
	// Kind names the artefact class the path would have supplied, so a reader
	// can tell what the run is missing rather than only where.
	Kind string
	// Why is one of the constants above.
	Why string
	// Detail is the underlying error, where there was one.
	Detail string
}

// admit is the one place a resolved path is tested against the evidence
// boundary, and the only one allowed to be.
//
// A refusal is recorded whether or not the caller had somewhere to put it,
// which is the whole point: three call sites used to write
// `boundary.Check(path) == nil` inline and drop the path in silence when it
// failed. A `Users` directory or a `Windows\INF` implemented as a junction
// pointing outside the collection was therefore enumerated, refused file by
// file, and reported nowhere — the manifest named neither a missing hive nor a
// failure, so the whole of a host's per-user activity could vanish behind a
// clean-looking run. Reproduced by a review with exactly that tree.
//
// Fail-closed and report: the path is not admitted, and the refusal is a
// finding. TestOnlyOneFunctionDecidesWhetherAPathIsInsideTheEvidence holds the
// line structurally, because the inline form is the natural thing to write and
// compiles just as well.
func admit(set *Set, boundary *Boundary, kind, path string) bool {
	if err := boundary.Check(path); err != nil {
		set.failed(kind, path, FailureBoundaryRefused, err)
		return false
	}
	return true
}

// failed records a place discovery could not look.
func (s *Set) failed(kind, path, why string, err error) {
	failure := DiscoveryFailure{Path: path, Kind: kind, Why: why}
	if err != nil {
		failure.Detail = err.Error()
	}
	s.Failures = append(s.Failures, failure)
}

// machineHives are the system-wide hives, with the profile-relative user hives
// handled separately.
var machineHives = map[string]string{
	"SYSTEM":   "SYSTEM",
	"SOFTWARE": "SOFTWARE",
}

// Locate walks an evidence root and catalogues the artefacts Boobook reads.
func Locate(root string) (*Set, error) {
	boundary, err := NewBoundary(root)
	if err != nil {
		return nil, err
	}

	set := &Set{Root: boundary.Root()}

	volumes, err := detectVolumes(set, boundary)
	if err != nil {
		return nil, err
	}
	if len(volumes) == 0 {
		return nil, fmt.Errorf(
			"no Windows volume found beneath %s: expected a Windows\\ directory, "+
				"a Velociraptor uploads\\ tree, or a KAPE volume folder", root)
	}
	set.Volumes = volumes

	for _, volume := range volumes {
		collectMachineHives(set, boundary, volume)
		collectUserHives(set, boundary, volume)
		collectEventLogs(set, boundary, volume)
		collectSetupAPI(set, boundary, volume)
		collectPrefetch(set, boundary, volume)
	}

	sort.Strings(set.Missing)
	sort.Strings(set.Collisions)
	return set, nil
}

// detectVolumes finds every Windows volume the collection presents.
func detectVolumes(set *Set, boundary *Boundary) ([]VolumeRoot, error) {
	root := boundary.Root()

	// A mounted volume has Windows\ directly beneath it.
	if isDir(filepath.Join(root, "Windows")) {
		return []VolumeRoot{{
			Path:        root,
			DriveLetter: "",
			Layout:      LayoutPlain,
		}}, nil
	}

	var volumes []VolumeRoot

	// Velociraptor: uploads\auto\C%3A\ and uploads\ntfs\%5C%5C.%5CC%3A\.
	for _, accessor := range []string{"auto", "ntfs", "lazy_ntfs", "file"} {
		dir := filepath.Join(root, "uploads", accessor)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			candidate := filepath.Join(dir, entry.Name())
			if !isDir(filepath.Join(candidate, "Windows")) {
				continue
			}
			// A whole volume, refused in silence before this was recorded.
			// Everything on it would then be absent from the report with
			// nothing saying why.
			if !admit(set, boundary, "VOLUME", candidate) {
				continue
			}
			volumes = append(volumes, VolumeRoot{
				Path:        candidate,
				DriveLetter: decodeDriveLetter(entry.Name()),
				Layout:      LayoutVelociraptor,
			})
		}
	}
	if len(volumes) > 0 {
		return volumes, nil
	}

	// KAPE: a volume folder named C, C%3A or similar at the root.
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read evidence root %s: %w", root, err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(root, entry.Name())
		if !isDir(filepath.Join(candidate, "Windows")) {
			continue
		}
		if !admit(set, boundary, "VOLUME", candidate) {
			continue
		}
		volumes = append(volumes, VolumeRoot{
			Path:        candidate,
			DriveLetter: decodeDriveLetter(entry.Name()),
			Layout:      LayoutKAPE,
		})
	}

	return volumes, nil
}

func collectMachineHives(set *Set, boundary *Boundary, volume VolumeRoot) {
	configDir := filepath.Join(volume.Path, "Windows", "System32", "config")

	for kind, name := range machineHives {
		path, outcome := resolveInsensitive(set, kind, configDir, name)
		switch outcome {
		case nameAbsent:
			set.Missing = append(set.Missing,
				fmt.Sprintf("%s (%s)", kind, filepath.Join(configDir, name)))
			continue
		case nameUnreadable:
			// Already recorded as a failure. Not also Missing: a directory
			// nobody could read is not a collection that lacks the hive, and
			// saying both would let the weaker claim be read as the stronger.
			continue
		}
		if !admit(set, boundary, kind, path) {
			continue
		}

		artefact := Artefact{
			Kind:       kind,
			Path:       path,
			VolumeRoot: volume.Path,
			LogPaths:   transactionLogs(set, boundary, configDir, name),
		}
		set.Artefacts = append(set.Artefacts, artefact)
	}
}

func collectUserHives(set *Set, boundary *Boundary, volume VolumeRoot) {
	usersDir := filepath.Join(volume.Path, "Users")

	// The directory itself, before its contents. os.ReadDir follows a junction,
	// so a Users directory pointing outside the collection enumerates normally
	// and every hive below it is then refused one at a time — which names the
	// files and never the reason. A review built exactly this tree and got a
	// run reporting neither a missing NTUSER nor a failure.
	if _, err := os.Stat(usersDir); err == nil &&
		!admit(set, boundary, "NTUSER", usersDir) {
		return
	}

	entries, err := os.ReadDir(usersDir)
	if err != nil {
		// Not there and not readable are different findings. Every per-user
		// artefact in the collection hangs off this directory, so reading the
		// second as the first would silence the whole of a host's file
		// activity behind a permission error.
		if !os.IsNotExist(err) {
			set.failed("NTUSER", usersDir, FailureUnreadable, err)
		}
		set.Missing = append(set.Missing, fmt.Sprintf("Users (%s)", usersDir))
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profile := entry.Name()
		profileDir := filepath.Join(usersDir, profile)

		if path, outcome := resolveInsensitive(
			set, "NTUSER", profileDir, "NTUSER.DAT"); outcome == nameResolved &&
			admit(set, boundary, "NTUSER", path) {
			set.Artefacts = append(set.Artefacts, Artefact{
				Kind:       "NTUSER",
				Path:       path,
				VolumeRoot: volume.Path,
				Profile:    profile,
				LogPaths:   transactionLogs(set, boundary, profileDir, "NTUSER.DAT"),
			})
		}

		usrClassDir := filepath.Join(profileDir,
			"AppData", "Local", "Microsoft", "Windows")
		if path, outcome := resolveInsensitive(
			set, "USRCLASS", usrClassDir, "UsrClass.dat"); outcome == nameResolved &&
			admit(set, boundary, "USRCLASS", path) {
			set.Artefacts = append(set.Artefacts, Artefact{
				Kind:       "USRCLASS",
				Path:       path,
				VolumeRoot: volume.Path,
				Profile:    profile,
				LogPaths:   transactionLogs(set, boundary, usrClassDir, "UsrClass.dat"),
			})
		}

		collectFileActivity(set, boundary, volume, profile, profileDir)
	}
}

// ShortcutDir is one directory walked for shell links and jump lists, and what
// kind of directory it is.
//
// The context travels with every artefact found there because it decides what
// the file's own last-written time means. A link the shell maintains is
// rewritten on each open; a link a user made, pinned or copied is written when
// they did that. Both are shortcuts and only one of them times an opening.
type ShortcutDir struct {
	// Context is the value that reaches link_context in the database:
	// recent, office_recent, quick_launch or desktop.
	Context string
	// Path is the directory, relative to a user profile.
	Path []string
}

// RecentDirs are where a profile's shell links and jump lists live. Both the
// Roaming and the Internet Explorer paths are walked: the Quick Launch tree
// holds pinned items, and a pinned item is still a record that a file on a
// removable volume was opened.
//
// Exported so the source catalogue can describe where these are looked for
// without keeping its own copy of the list. A capability document that has
// drifted from the code is worse than none.
var RecentDirs = []ShortcutDir{
	{"recent", []string{"AppData", "Roaming", "Microsoft", "Windows", "Recent"}},
	{"office_recent", []string{"AppData", "Roaming", "Microsoft", "Office", "Recent"}},
	{"quick_launch", []string{"AppData", "Roaming", "Microsoft", "Internet Explorer", "Quick Launch"}},
	{"desktop", []string{"Desktop"}},
}

func collectFileActivity(set *Set, boundary *Boundary, volume VolumeRoot,
	profile, profileDir string) {

	for _, directory := range RecentDirs {
		root := filepath.Join(append([]string{profileDir}, directory.Path...)...)

		// A shortcut directory that is not there, one that cannot be stat'd,
		// and one that is a junction pointing out of the collection all used to
		// take the same silent `continue`. Only the first is an absence. The
		// other two are places nobody looked, and the report's silence about
		// shortcuts then reads as nobody having opened a file from a device.
		info, err := os.Stat(root)
		if err != nil {
			if !os.IsNotExist(err) {
				set.failed("LNK", root, FailureUnreadable, err)
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		// The root itself, before anything under it. WalkDir happily descends a
		// junction that escapes the evidence, and refusing each file it yields
		// leaves one failure per shortcut and nothing naming the directory that
		// caused them.
		if !admit(set, boundary, "LNK", root) {
			continue
		}

		filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				// A shortcut directory that cannot be walked is the worst
				// place for this to be silent: a Recent folder the run could
				// not read looks exactly like one holding no shortcuts, and
				// the report's silence then reads as nobody having opened a
				// file from a device.
				set.failed("LNK", path, FailureWalkFailed, err)
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if !admit(set, boundary, "LNK", path) {
				return nil
			}

			kind := ""
			switch strings.ToLower(filepath.Ext(entry.Name())) {
			case ".lnk":
				kind = "LNK"
			case ".automaticdestinations-ms", ".customdestinations-ms":
				kind = "JUMPLIST"
			default:
				return nil
			}

			set.Artefacts = append(set.Artefacts, Artefact{
				Kind:       kind,
				Path:       path,
				VolumeRoot: volume.Path,
				Profile:    profile,
				Context:    directory.Context,
			})
			return nil
		})
	}
}

func collectEventLogs(set *Set, boundary *Boundary, volume VolumeRoot) {
	logsDir := filepath.Join(volume.Path,
		"Windows", "System32", "winevt", "Logs")

	// The directory before its contents, as for Users and Windows\INF.
	// os.ReadDir follows a junction, so a Logs directory pointing out of the
	// collection enumerates normally and every log below it is refused one at a
	// time — and an empty one out of root yields neither an artefact nor a
	// failure, which is the silence that reads as "this host logged nothing".
	if _, err := os.Stat(logsDir); err == nil &&
		!admit(set, boundary, "EVTX", logsDir) {
		return
	}

	entries, err := os.ReadDir(logsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			set.failed("EVTX", logsDir, FailureUnreadable, err)
		}
		set.Missing = append(set.Missing, fmt.Sprintf("EVTX (%s)", logsDir))
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".evtx") {
			continue
		}
		path := filepath.Join(logsDir, entry.Name())
		if !admit(set, boundary, "EVTX", path) {
			continue
		}
		set.Artefacts = append(set.Artefacts, Artefact{
			Kind:       "EVTX",
			Path:       path,
			VolumeRoot: volume.Path,
			Channel:    DecodeChannel(entry.Name()),
		})
	}
}

// collectSetupAPI finds the device installation log and its rotated copies.
//
// Windows renames the log when it grows past its limit and starts a new one, so
// the current file holds only recent history. The rotated copies are where a
// device connected months ago still appears, which makes them evidence rather
// than clutter.
func collectSetupAPI(set *Set, boundary *Boundary, volume VolumeRoot) {
	infDir := filepath.Join(volume.Path, "Windows", "INF")

	// As for Users above: the directory before the files in it, so a junction
	// escaping the collection is one failure naming the cause rather than one
	// per log naming the symptom.
	if _, err := os.Stat(infDir); err == nil &&
		!admit(set, boundary, "SETUPAPI", infDir) {
		return
	}

	current, outcome := resolveInsensitive(
		set, "SETUPAPI", infDir, "setupapi.dev.log")
	if outcome == nameAbsent {
		set.Missing = append(set.Missing,
			fmt.Sprintf("SETUPAPI (%s)", filepath.Join(infDir, "setupapi.dev.log")))
	} else if outcome == nameResolved && admit(set, boundary, "SETUPAPI", current) {
		set.Artefacts = append(set.Artefacts, Artefact{
			Kind:       "SETUPAPI",
			Path:       current,
			VolumeRoot: volume.Path,
		})
	}

	entries, err := os.ReadDir(infDir)
	if err != nil {
		if !os.IsNotExist(err) {
			set.failed("SETUPAPI_ROTATED", infDir, FailureUnreadable, err)
		}
		return
	}
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		// setupapi.dev.20260726_091001.log — a rotated copy, distinguished from
		// the current log by having something between "dev" and "log".
		if entry.IsDir() || !strings.HasPrefix(name, "setupapi.dev.") ||
			!strings.HasSuffix(name, ".log") || name == "setupapi.dev.log" {
			continue
		}
		path := filepath.Join(infDir, entry.Name())
		if !admit(set, boundary, "SETUPAPI_ROTATED", path) {
			continue
		}
		set.Artefacts = append(set.Artefacts, Artefact{
			Kind:       "SETUPAPI_ROTATED",
			Path:       path,
			VolumeRoot: volume.Path,
		})
	}
}

// collectPrefetch finds the prefetch files beneath Windows\Prefetch.
//
// An absent directory is recorded as missing rather than passed over, because
// there are three reasons for it and they are not the same finding: prefetch is
// off by default on Windows Server, it can be disabled on any host, and a
// triage collection may simply not have taken it. The registry's
// EnablePrefetcher value separates the first two from the third, and the
// coverage section reports which case this is.
func collectPrefetch(set *Set, boundary *Boundary, volume VolumeRoot) {
	prefetchDir := filepath.Join(volume.Path, "Windows", "Prefetch")

	// The directory before its contents. The three readings of an empty
	// Prefetch directory in the comment above are all about the collection; a
	// junction out of the evidence root is a fourth and is not one of them.
	if _, err := os.Stat(prefetchDir); err == nil &&
		!admit(set, boundary, "PREFETCH", prefetchDir) {
		return
	}

	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		// The doc comment above names three reasons the directory can be
		// absent. A fourth — it is there and could not be read — is not one of
		// them and must not be reported as one.
		if !os.IsNotExist(err) {
			set.failed("PREFETCH", prefetchDir, FailureUnreadable, err)
		}
		set.Missing = append(set.Missing, fmt.Sprintf("PREFETCH (%s)", prefetchDir))
		return
	}

	for _, entry := range entries {
		// The directory also holds ReadyBoot\, layout.ini and the Ag*.db
		// application-launch databases. Only the .pf files are read.
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".pf") {
			continue
		}
		path := filepath.Join(prefetchDir, entry.Name())
		if !admit(set, boundary, "PREFETCH", path) {
			continue
		}
		set.Artefacts = append(set.Artefacts, Artefact{
			Kind:       "PREFETCH",
			Path:       path,
			VolumeRoot: volume.Path,
		})
	}
}

// transactionLogs finds the .LOG1/.LOG2 files belonging to a hive.
//
// It takes the boundary, and that is the whole of this function's history. The
// hive above it was admitted and its logs were not: the paths went straight
// into LogPaths, where the run hashes each one as a source of its own and
// regparser opens it to replay pages into the recovered copy. A file reparse
// point named SYSTEM.LOG1 could therefore resolve outside the evidence root,
// contribute pages to the hive every device fact is read from, and leave the
// manifest attesting that the run was bounded to the collection.
//
// The logs are inputs to what was read, which is why they are hashed at all —
// so they are admitted like anything else, and a refusal is a recorded failure
// rather than a shorter list.
func transactionLogs(set *Set, boundary *Boundary, dir, hiveName string) []string {
	var logs []string
	for _, suffix := range []string{".LOG1", ".LOG2"} {
		path, outcome := resolveInsensitive(set, "TRANSACTION_LOG", dir, hiveName+suffix)
		if outcome != nameResolved {
			continue
		}
		if !admit(set, boundary, "TRANSACTION_LOG", path) {
			continue
		}
		logs = append(logs, path)
	}
	return logs
}

// Why a name did or did not resolve to a file.
//
// The two failures used to be one `false`, and they are not the same claim: a
// directory that was read and does not hold the name is an absence, and a
// directory that could not be read says nothing at all about what is in it.
// Collapsed together, a denied config directory reported the SYSTEM hive as
// missing from the collection — which is the exact confusion Set.Failures
// exists to prevent, arriving one level below where it was being watched for.
type resolution int

const (
	// nameResolved: the file is there and the path is returned.
	nameResolved resolution = iota
	// nameAbsent: the directory was read and does not hold the name.
	nameAbsent
	// nameUnreadable: the directory could not be read. Nothing is known about
	// whether the file exists, and a failure has been recorded.
	nameUnreadable
)

// resolveInsensitive finds a file by case-insensitive name.
//
// Windows is case-insensitive but a collection made on Linux is not, so a
// triage pack can hold both NTUSER.DAT and ntuser.dat. The choice is
// deterministic — first in sort order — and the collision is reported rather
// than silently resolved.
//
// kind names the artefact class the directory would have supplied, so a
// recorded failure says what the run is missing rather than only where.
func resolveInsensitive(set *Set, kind, dir, name string) (string, resolution) {
	// The common case: the name is exactly as expected.
	direct := filepath.Join(dir, name)
	if fileExists(direct) {
		return direct, nameResolved
	}

	// The directory is classified by stat rather than by the ReadDir error,
	// because on Windows os.ReadDir of a path that is a *file* reports "the
	// system cannot find the path specified" and os.IsNotExist is true for it —
	// so a collector that captured a hive directory as a file would have been
	// reported as a collection that never held the hive.
	info, statErr := os.Stat(dir)
	switch {
	case statErr != nil && os.IsNotExist(statErr):
		return "", nameAbsent
	case statErr != nil:
		set.failed(kind, dir, FailureUnreadable, statErr)
		return "", nameUnreadable
	case !info.IsDir():
		set.failed(kind, dir, FailureUnreadable,
			fmt.Errorf("%s is not a directory", dir))
		return "", nameUnreadable
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		set.failed(kind, dir, FailureUnreadable, err)
		return "", nameUnreadable
	}

	var matches []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(entry.Name(), name) {
			matches = append(matches, entry.Name())
		}
	}
	if len(matches) == 0 {
		return "", nameAbsent
	}

	sort.Strings(matches)
	if len(matches) > 1 {
		set.Collisions = append(set.Collisions, fmt.Sprintf(
			"%s: %s (using %s)", dir, strings.Join(matches, ", "), matches[0]))
	}
	return filepath.Join(dir, matches[0]), nameResolved
}

// DecodeChannel turns an event log filename back into its channel name.
//
// Windows writes the '/' in a channel name as '%4'. A collector that
// percent-escapes the paths it writes turns that into '%254'. Both forms name
// the same channel and must resolve identically.
func DecodeChannel(filename string) string {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	name = strings.ReplaceAll(name, "%254", "/")
	name = strings.ReplaceAll(name, "%4", "/")
	return name
}

// decodeDriveLetter reads the drive letter a collector encoded in a directory
// name: "C%3A", "%5C%5C.%5CC%3A" or plain "C".
func decodeDriveLetter(name string) string {
	decoded := name
	// Decoding can need two passes: a doubly-escaped name carries %255C.
	for i := 0; i < 2; i++ {
		unescaped, err := url.QueryUnescape(decoded)
		if err != nil {
			break
		}
		if unescaped == decoded {
			break
		}
		decoded = unescaped
	}

	decoded = strings.TrimPrefix(decoded, `\\.\`)
	decoded = strings.TrimSuffix(decoded, ":")

	if len(decoded) == 1 && isLetter(rune(decoded[0])) {
		return strings.ToUpper(decoded)
	}
	return ""
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ByKind returns the located artefacts of one kind.
func (s *Set) ByKind(kind string) []Artefact {
	var out []Artefact
	for _, artefact := range s.Artefacts {
		if artefact.Kind == kind {
			out = append(out, artefact)
		}
	}
	return out
}

// Size reports how large the artefact is, transaction logs included: replaying
// them is part of reading the hive, so it is part of what reading it costs.
func (a Artefact) Size() int64 {
	total := fileSize(a.Path)
	for _, logPath := range a.LogPaths {
		total += fileSize(logPath)
	}
	return total
}

// Bytes reports the size of a set of artefacts.
func Bytes(artefacts []Artefact) int64 {
	var total int64
	for _, artefact := range artefacts {
		total += artefact.Size()
	}
	return total
}

// TotalBytes reports the size of everything located.
func (s *Set) TotalBytes() int64 {
	var total int64
	for _, artefact := range s.Artefacts {
		total += fileSize(artefact.Path)
		for _, logPath := range artefact.LogPaths {
			total += fileSize(logPath)
		}
	}
	return total
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
