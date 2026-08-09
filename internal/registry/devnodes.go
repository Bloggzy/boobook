// Package registry extracts USB-relevant device nodes from a SYSTEM hive.
package registry

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/Bloggzy/boobook/internal/evidence"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// Enumerators we walk beneath Enum. Storage is not the only thing that matters:
// a phone, a printer or a dock never reaches USBSTOR.
var Enumerators = []string{
	"USB", "USBSTOR", "USBPRINT", "SCSI", "STORAGE", "HID",
	"WPDBUSENUM", "SWD", "BTHENUM", "BTHLEDEVICE",
}

// Devnode is one device instance as recorded in the hive.
//
// Raw stored values only — no normalisation, no classification. Meaning is
// applied later, in SQL.
type Devnode struct {
	ControlSet       string
	Enumerator       string
	DeviceID         string
	InstanceID       string
	DeviceInstanceID string

	// RawKeyLastWrite is the FILETIME the hive stores; KeyLastWriteUTC is the
	// conversion of it. A key last-write is not a connection time: it records
	// the last change to the key, which may be an install, a driver update, a
	// property refresh or a re-enumeration.
	RawKeyLastWrite uint64
	KeyLastWriteUTC *time.Time

	// Properties is the device's stored property set, raw values preserved.
	Properties []Property
	// Activity is the PnP lifecycle read from those properties.
	Activity Activity

	DeviceDesc          string
	FriendlyName        string
	Mfg                 string
	Class               string
	ClassGUID           string
	Service             string
	ContainerID         string
	ParentIDPrefix      string
	HardwareID          string
	CompatibleIDs       string
	LocationInformation string
	BusReportedDesc     string
}

// StoredValues returns the devnode's stored registry values by name, for
// provenance recording. The key names match the registry value names, so an
// observation resolves back to the exact value it was read from.
func (d Devnode) StoredValues() map[string]string {
	return map[string]string{
		"DeviceDesc":            d.DeviceDesc,
		"FriendlyName":          d.FriendlyName,
		"Mfg":                   d.Mfg,
		"Class":                 d.Class,
		"ClassGUID":             d.ClassGUID,
		"Service":               d.Service,
		"ContainerID":           d.ContainerID,
		"ParentIdPrefix":        d.ParentIDPrefix,
		"HardwareID":            d.HardwareID,
		"CompatibleIDs":         d.CompatibleIDs,
		"LocationInformation":   d.LocationInformation,
		"BusReportedDeviceDesc": d.BusReportedDesc,
	}
}

// Result carries what was read from a SYSTEM hive.
type Result struct {
	Devnodes     []Devnode
	MountEntries []MountEntry
	ControlSets  ControlSets
	Warnings     []string
}

// ReadSystem reads everything Boobook takes from a SYSTEM hive.
//
// Every stored control set is walked, not only the current one: an alternate
// control set can hold a device record the current one no longer does, and each
// devnode records which set supplied it.
func ReadSystem(registry *regparser.Registry) *Result {
	result := &Result{ControlSets: ReadControlSets(registry)}

	for _, controlSet := range result.ControlSets.Names {
		devnodes := ReadDevnodes(registry, controlSet)
		result.Devnodes = append(result.Devnodes, devnodes.Devnodes...)
		result.Warnings = append(result.Warnings, devnodes.Warnings...)
	}

	// MountedDevices sits outside the control sets: one per hive.
	result.MountEntries = ReadMountedDevices(registry)

	return result
}

// Replay states for one transaction log, weakest claim last.
const (
	// LogApplicable means the log is a supported version whose sequence
	// continues the hive's, so replay could take pages from it. It is not a
	// claim that any page was applied: only the hive itself can say that.
	LogApplicable = "applicable"
	// LogSuperseded means the hive is already at or beyond the log's first
	// sequence number, so the log holds nothing the hive does not have.
	LogSuperseded = "superseded"
	// LogUnsupported is the old single-log format, which regparser refuses.
	LogUnsupported = "unsupported_version"
	LogEmpty       = "empty"
	LogUnreadable  = "unreadable"
)

// LogReplay is what became of one transaction log.
type LogReplay struct {
	Path   string
	State  string
	Detail string
}

// Replay is what happened when a hive's transaction logs were replayed.
//
// It exists because the honest answer is not a boolean and the boolean was
// being asserted anyway. regparser.RecoverHive copies the hive to a temporary
// file, applies whatever dirty pages it finds, and returns that file — and it
// returns it successfully when there were no logs at all, when every log was
// empty, when every log was a version it does not support, and when every log's
// sequence number was already behind the hive. Boobook set replayed = true in
// every one of those cases and then listed every discovered log in replay_logs,
// which reads as an assertion that those logs are behind the values in the
// report. A later reviewer would have no way to tell.
type Replay struct {
	// Attempted is false where recovery failed outright and the hive was
	// parsed as stored.
	Attempted bool
	// Changed is whether the recovered copy differs from the hive as stored.
	// This is the only claim about replay that rests on the hive rather than
	// on what the logs said about themselves: recovery copies first and writes
	// pages second, so an identical copy means nothing was applied.
	Changed bool
	Logs    []LogReplay
	// Note is whatever regparser printed while recovering, which it writes to
	// the process standard output rather than returning. Captured so -quiet
	// stays quiet and so the dependency's account survives in the ledger.
	Note string
}

// Applied says a transaction log reached the values this hive supplied.
func (r Replay) Applied() bool { return r.Attempted && r.Changed }

// AppliedLogs names the logs that could have supplied those pages. Only
// meaningful where Applied is true, and it is deliberately narrower than "every
// log found beside the hive": a superseded or unsupported log is present and
// contributed nothing.
func (r Replay) AppliedLogs() []string {
	if !r.Applied() {
		return nil
	}
	var paths []string
	for _, log := range r.Logs {
		if log.State == LogApplicable {
			paths = append(paths, log.Path)
		}
	}
	return paths
}

// Describe is one sentence for the ledger and the report's limitations.
func (r Replay) Describe() string {
	if !r.Attempted {
		return "transaction logs were not replayed; the hive is parsed as " +
			"stored and may be missing its most recent writes"
	}
	if r.Changed {
		return fmt.Sprintf("transaction logs were replayed and changed the hive: "+
			"%d of %d logs beside it could apply", len(r.AppliedLogs()), len(r.Logs))
	}
	if len(r.Logs) == 0 {
		return "no transaction log was found beside the hive, so the hive is " +
			"read exactly as stored"
	}
	// The important case, and the one that used to read as a successful replay.
	var reasons []string
	for _, log := range r.Logs {
		reasons = append(reasons, log.State)
	}
	return fmt.Sprintf("recovery ran and changed nothing: the recovered copy is "+
		"byte-identical to the hive as stored, so none of the %d transaction "+
		"logs beside it contributed a page (%s)",
		len(r.Logs), strings.Join(reasons, ", "))
}

// Account is Describe with the recovery's own words after it, where it had any.
func (r Replay) Account() string {
	if r.Note == "" {
		return r.Describe()
	}
	return r.Describe() + "; the recovery reported: " +
		strings.Join(strings.Fields(r.Note), " ")
}

// LoadHive opens a registry hive, replaying its transaction logs into a
// recovered copy first. The source file is only ever read.
//
// The returned cleanup function removes the recovered copy.
func LoadHive(hive evidence.Artefact) (*regparser.Registry, func(), Replay, error) {
	source, err := os.Open(hive.Path)
	if err != nil {
		return nil, nil, Replay{}, fmt.Errorf("open hive: %w", err)
	}
	defer source.Close()

	replay := Replay{Attempted: true}

	// The hive's own sequence, read once. regparser reads through ReadAt, so
	// this leaves the file offset where RecoverHive's copy expects it.
	var baseSequence uint32
	baseKnown := false
	if base, err := regparser.NewRegistry(source); err == nil {
		baseSequence, baseKnown = base.BaseBlock.Sequence2(), true
	}

	var logs []*os.File
	for _, logPath := range hive.LogPaths {
		logFile, err := os.Open(logPath)
		if err != nil {
			// Previously skipped in silence, so a log the collector could not
			// read was indistinguishable from one that was not there.
			replay.Logs = append(replay.Logs, LogReplay{
				Path: logPath, State: LogUnreadable, Detail: err.Error()})
			continue
		}
		defer logFile.Close()
		replay.Logs = append(replay.Logs,
			classifyLog(logPath, logFile, baseSequence, baseKnown))
		logs = append(logs, logFile)
	}

	// Replay produces a separate recovered file; the source is untouched.
	recovered, chatter, err := recoverQuietly(source, logs...)
	if chatter != "" {
		// regparser reports its skips with fmt.Printf, straight to the process
		// standard output, where -quiet cannot reach it: the standard logger is
		// redirected through the progress reporter and this is not the standard
		// logger. Kept as the dependency's own account of what it did, beside
		// the states classifyLog worked out independently.
		replay.Note = strings.TrimSpace(chatter)
	}
	if err != nil {
		// A hive that will not replay is still worth parsing as-stored, but the
		// caller must be told the newest writes may be missing.
		registry, cleanup, openErr := openPlain(hive.Path)
		if openErr != nil {
			return nil, nil, Replay{}, fmt.Errorf(
				"recover and plain open both failed: %v / %w", err, openErr)
		}
		replay.Attempted = false
		return registry, cleanup, replay, nil
	}

	cleanup := func() {
		name := recovered.Name()
		recovered.Close()
		os.Remove(name)
	}

	// Whether anything was actually applied. RecoverHive copies and then writes
	// pages in place, so comparing the recovered copy with the hive as stored
	// answers the question the library will not: an identical copy is a replay
	// that did nothing.
	changed, err := recoveredDiffers(hive.Path, recovered)
	if err != nil {
		// Not knowing is not the same as knowing nothing was applied, and the
		// stronger of the two claims is the one that must not be invented.
		replay.Logs = append(replay.Logs, LogReplay{
			Path: recovered.Name(), State: LogUnreadable,
			Detail: "the recovered copy could not be compared with the hive " +
				"as stored: " + err.Error()})
	}
	replay.Changed = changed

	registry, err := regparser.NewRegistry(recovered)
	if err != nil {
		cleanup()
		return nil, nil, Replay{}, fmt.Errorf("parse recovered hive: %w", err)
	}

	return registry, cleanup, replay, nil
}

// recoverStdout serialises the standard-output swap below. Hives are read one
// at a time by the run, but a swap of a process-wide variable must not depend
// on that staying true.
var recoverStdout sync.Mutex

// recoverQuietly runs the recovery with the process standard output diverted,
// and returns whatever it printed.
//
// regparser reports an empty log, an unsupported log version and a superseded
// sequence with fmt.Printf. That is the process's stdout, not the standard
// logger, so the redirect that makes -quiet mean silent does not cover it: a
// run asked to be silent printed "[warn] version 1 of log file ... skipping"
// into whatever was consuming its output. The text is worth keeping — it is the
// dependency's own account of a decision this package re-derives — so it is
// captured rather than discarded.
func recoverQuietly(hive *os.File, logs ...*os.File) (*os.File, string, error) {
	recoverStdout.Lock()
	defer recoverStdout.Unlock()

	read, write, err := os.Pipe()
	if err != nil {
		// Not being able to divert it is no reason not to do the work.
		recovered, recoverErr := regparser.RecoverHive(hive, logs...)
		return recovered, "", recoverErr
	}

	saved := os.Stdout
	os.Stdout = write

	// Drained in the background: a pipe buffer that fills would deadlock the
	// recovery mid-write.
	captured := make(chan string, 1)
	go func() {
		var buffer bytes.Buffer
		io.Copy(&buffer, read)
		captured <- buffer.String()
	}()

	recovered, recoverErr := regparser.RecoverHive(hive, logs...)

	os.Stdout = saved
	write.Close()
	text := <-captured
	read.Close()

	return recovered, text, recoverErr
}

// classifyLog answers, before recovery runs, whether a log could contribute
// anything — using the log's own base block, which is what regparser tests.
//
// Duplicating those three conditions is worth it because the library reports
// them to stdout and returns nothing, so this is the only way the run can say
// which logs mattered. The conditions are read from the artefacts themselves,
// so a wrong answer here is visible against the log rather than being a private
// disagreement with a dependency.
func classifyLog(path string, logFile *os.File,
	baseSequence uint32, baseKnown bool) LogReplay {

	info, err := logFile.Stat()
	if err != nil {
		return LogReplay{Path: path, State: LogUnreadable, Detail: err.Error()}
	}
	if info.Size() == 0 {
		return LogReplay{Path: path, State: LogEmpty,
			Detail: "the log is zero bytes"}
	}

	logRegistry, err := regparser.NewRegistry(logFile)
	if err != nil {
		return LogReplay{Path: path, State: LogUnreadable, Detail: err.Error()}
	}
	if kind := logRegistry.BaseBlock.Type(); kind == 1 || kind == 2 {
		return LogReplay{Path: path, State: LogUnsupported,
			Detail: fmt.Sprintf("log format type %d is the old single-log "+
				"layout, which is not replayed", kind)}
	}

	if !baseKnown {
		return LogReplay{Path: path, State: LogUnreadable,
			Detail: "the hive's own base block could not be read, so whether " +
				"this log continues its sequence cannot be decided"}
	}
	if logRegistry.BaseBlock.Sequence1() < baseSequence {
		return LogReplay{Path: path, State: LogSuperseded,
			Detail: fmt.Sprintf("the log starts at sequence %d and the hive is "+
				"already at %d", logRegistry.BaseBlock.Sequence1(), baseSequence)}
	}
	return LogReplay{Path: path, State: LogApplicable,
		Detail: fmt.Sprintf("a supported log continuing the hive's sequence %d",
			baseSequence)}
}

// recoveredDiffers answers the same question as filesDiffer for the file the
// recovery is still holding open.
//
// It goes through that handle rather than through the path, which is not a
// tidy-up. Windows is not obliged to update a file's directory entry while a
// handle is open to it, so os.Stat on the recovered copy's name can report a
// size the file no longer has -- and this comparison decides whether the run
// says a hive was replayed. A stale size makes the two files differ, and the
// run then reports a replay that did not happen, which is the claim the whole
// of this was written to stop being invented.
//
// Latent on all five reference collections: every hive compares equal either
// way. Sync first so the bytes are on disk, take the size from the handle,
// which is always current, and read through it with ReadAt so the offset the
// caller is about to parse from is left where it was.
func recoveredDiffers(hivePath string, recovered *os.File) (bool, error) {
	if err := recovered.Sync(); err != nil {
		return false, err
	}
	info, err := recovered.Stat()
	if err != nil {
		return false, err
	}
	return readersDiffer(hivePath, io.NewSectionReader(recovered, 0, info.Size()),
		info.Size())
}

// filesDiffer compares two files without holding either in memory. Hives run to
// tens of megabytes and a run reads several.
func filesDiffer(left, right string) (bool, error) {
	rightFile, err := os.Open(right)
	if err != nil {
		return false, err
	}
	defer rightFile.Close()
	rightInfo, err := rightFile.Stat()
	if err != nil {
		return false, err
	}
	return readersDiffer(left, rightFile, rightInfo.Size())
}

// readersDiffer is the comparison itself, against a file named by path.
func readersDiffer(left string, rightFile io.Reader, rightSize int64) (bool, error) {
	leftInfo, err := os.Stat(left)
	if err != nil {
		return false, err
	}
	if leftInfo.Size() != rightSize {
		return true, nil
	}

	leftFile, err := os.Open(left)
	if err != nil {
		return false, err
	}
	defer leftFile.Close()

	leftBuf := make([]byte, 1<<20)
	rightBuf := make([]byte, 1<<20)
	for {
		leftRead, leftErr := io.ReadFull(leftFile, leftBuf)
		rightRead, rightErr := io.ReadFull(rightFile, rightBuf)
		if leftRead != rightRead || !bytes.Equal(leftBuf[:leftRead], rightBuf[:rightRead]) {
			return true, nil
		}
		if leftErr != nil || rightErr != nil {
			// Both files are the same size, so they run out together.
			if isEOF(leftErr) && isEOF(rightErr) {
				return false, nil
			}
			if !isEOF(leftErr) {
				return false, leftErr
			}
			return false, rightErr
		}
	}
}

func isEOF(err error) bool {
	return err == nil || err == io.EOF || err == io.ErrUnexpectedEOF
}

// openPlain returns the registry and a cleanup that closes the file. The file
// used to be left open for the life of the run: a collection with several
// hives that all failed to replay leaked a descriptor each.
func openPlain(path string) (*regparser.Registry, func(), error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	registry, err := regparser.NewRegistry(fd)
	if err != nil {
		fd.Close()
		return nil, nil, err
	}
	return registry, func() { fd.Close() }, nil
}

// CurrentControlSet reads SYSTEM\Select\Current and names the active control
// set. On an offline hive there is no CurrentControlSet key to follow.
func CurrentControlSet(registry *regparser.Registry) string {
	key := registry.OpenKey("Select")
	if key == nil {
		return "ControlSet001"
	}
	for _, value := range key.Values() {
		if strings.EqualFold(value.ValueName(), "Current") {
			data := value.ValueData()
			if data != nil && data.Uint64 > 0 {
				return fmt.Sprintf("ControlSet%03d", data.Uint64)
			}
		}
	}
	return "ControlSet001"
}

// ReadDevnodes walks Enum beneath one control set and returns every device
// instance under the enumerators we care about.
//
// The Enum tree is three levels: Enum\<Enumerator>\<DeviceID>\<InstanceID>.
func ReadDevnodes(registry *regparser.Registry, controlSet string) *Result {
	result := &Result{}

	for _, enumerator := range Enumerators {
		path := fmt.Sprintf("%s\\Enum\\%s", controlSet, enumerator)
		enumKey := registry.OpenKey(path)
		if enumKey == nil {
			continue
		}

		for _, deviceKey := range enumKey.Subkeys() {
			deviceID := deviceKey.Name()

			for _, instanceKey := range deviceKey.Subkeys() {
				instanceID := instanceKey.Name()

				devnode := Devnode{
					ControlSet:       controlSet,
					Enumerator:       enumerator,
					DeviceID:         deviceID,
					InstanceID:       instanceID,
					DeviceInstanceID: enumerator + "\\" + deviceID + "\\" + instanceID,
					RawKeyLastWrite:  RawLastWrite(instanceKey),
				}
				if converted, ok := wintime.FromFileTime(devnode.RawKeyLastWrite); ok {
					devnode.KeyLastWriteUTC = &converted
				}

				devnode.Properties = ReadProperties(instanceKey)
				devnode.Activity = ActivityFrom(devnode.Properties)

				for _, value := range instanceKey.Values() {
					data := value.ValueData()
					if data == nil {
						continue
					}
					assign(&devnode, value.ValueName(), data)
				}

				result.Devnodes = append(result.Devnodes, devnode)
			}
		}
	}

	return result
}

// trimStored strips the NUL terminator a REG_SZ carries and any surrounding
// whitespace. Left in place, a trailing NUL silently breaks every string join:
// a ContainerID read from one hive would not equal the same GUID read anywhere
// else. The value is otherwise unaltered.
func trimStored(text string) string {
	return strings.TrimSpace(strings.TrimRight(text, "\x00"))
}

// assign copies a stored value into its field. Unknown values are ignored here;
// the full property set is Phase 1 work.
func assign(devnode *Devnode, name string, data *regparser.ValueData) {
	text := trimStored(data.String)
	if len(data.MultiSz) > 0 {
		parts := make([]string, 0, len(data.MultiSz))
		for _, part := range data.MultiSz {
			if trimmed := trimStored(part); trimmed != "" {
				parts = append(parts, trimmed)
			}
		}
		text = strings.Join(parts, "|")
	}

	switch strings.ToLower(name) {
	case "devicedesc":
		devnode.DeviceDesc = text
	case "friendlyname":
		devnode.FriendlyName = text
	case "mfg":
		devnode.Mfg = text
	case "class":
		devnode.Class = text
	case "classguid":
		devnode.ClassGUID = text
	case "service":
		devnode.Service = text
	case "containerid":
		devnode.ContainerID = text
	case "parentidprefix":
		devnode.ParentIDPrefix = text
	case "hardwareid":
		devnode.HardwareID = text
	case "compatibleids":
		devnode.CompatibleIDs = text
	case "locationinformation":
		devnode.LocationInformation = text
	case "busreporteddevicedesc":
		devnode.BusReportedDesc = text
	}
}
