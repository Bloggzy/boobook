package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Bloggzy/boobook/internal/provenance"
)

// Manifest is the record of what a run read, when, and with what tool.
//
// It is the chain-of-custody document: without it, a set of CSVs is a claim
// about a host with nothing tying it to the evidence it came from.
type Manifest struct {
	Tool     ToolInfo     `json:"tool"`
	Run      RunInfo      `json:"run"`
	Case     CaseInfo     `json:"case"`
	Evidence EvidenceInfo `json:"evidence"`
	// Classification records which rule set and which profile produced the
	// categories and scores. A score without the weights that made it is a
	// number nobody can check.
	Classification ClassificationInfo   `json:"classification"`
	Sources        []provenance.Source  `json:"sources"`
	Warnings       []provenance.Warning `json:"warnings"`
	Timings        []Timing             `json:"timings"`
	Counts         Counts               `json:"counts"`
	// EventSelection is the accounting for what was read from the event logs
	// and what was not. It is in the manifest rather than in a log so that the
	// claim "these are the USB events" can be checked against the evidence
	// without rerunning the tool.
	EventSelection *EventSelection `json:"event_selection,omitempty"`
	// Outputs names every file the run wrote, with the view that produced it
	// and its hash. A CSV quoted in a report can then be shown to be the file
	// this run wrote, and the query behind any column can be found.
	Outputs []OutputFile `json:"outputs,omitempty"`
}

// OutputFile is one file a run produced.
type OutputFile struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	View   string `json:"view,omitempty"`
	Format string `json:"format,omitempty"`
	Rows   int    `json:"rows"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// EventSelection accounts for every event log record read.
type EventSelection struct {
	ChannelsRead []string `json:"channels_read"`
	FilesParsed  int      `json:"files_parsed"`
	FilesSkipped int      `json:"files_skipped"`
	BytesParsed  int64    `json:"bytes_parsed"`
	BytesSkipped int64    `json:"bytes_skipped"`
	RecordsRead  int      `json:"records_read"`
	Retained     int      `json:"retained"`
	FilesFailed  int      `json:"files_failed"`

	// ExcludedByReason accounts for every record read and not retained.
	ExcludedByReason map[string]int `json:"excluded_by_reason,omitempty"`
	// Unselected counts, per channel and event ID, what was seen in a channel
	// that is read but is not selected by any rule. This is the part an analyst
	// can argue with.
	Unselected map[string]int `json:"unselected_events,omitempty"`
	// SelectedByRule counts what each rule contributed.
	SelectedByRule map[string]int `json:"selected_by_rule,omitempty"`
	// ChannelMismatches records files whose contents disagree with the channel
	// their name encodes, which would undermine selecting files by name.
	ChannelMismatches map[string]int `json:"channel_mismatches,omitempty"`
	// SkippedFiles names every event log present and not read, with the reason.
	SkippedFiles []SkippedFile `json:"skipped_files,omitempty"`
}

// SkippedFile is an event log that was present and deliberately not parsed.
type SkippedFile struct {
	Path    string `json:"path"`
	Channel string `json:"channel"`
	Bytes   int64  `json:"bytes"`
	Reason  string `json:"reason"`
	// OptIn marks a channel Boobook reads that this run did not ask for, as
	// against one nothing reads. The two say opposite things about what a
	// silence in the report means.
	OptIn bool `json:"opt_in,omitempty"`
}

// ToolInfo identifies the build that produced a result.
type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	BuildHash string `json:"build_hash,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// RunInfo is when and where the run happened.
type RunInfo struct {
	ID          string    `json:"id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	DurationMS  int64     `json:"duration_ms"`
	// OutputDir is where the results were written.
	OutputDir string `json:"output_dir"`
	// WorkingRoot is where scratch went, and WorkingKept whether it survived
	// the run. Both are recorded because "where did the recovered hives go"
	// is a custody question even when the answer is that they were removed.
	WorkingRoot string   `json:"working_root"`
	WorkingKept bool     `json:"working_kept"`
	CommandLine []string `json:"command_line"`
}

// CaseInfo is the examiner-supplied context. Boodie's manifest carried no
// examiner or case reference, which a formal custody record has to name.
type CaseInfo struct {
	Reference string `json:"reference,omitempty"`
	Examiner  string `json:"examiner,omitempty"`
	HostLabel string `json:"host_label,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

// ClassificationInfo names the rule set and profile a run classified with.
type ClassificationInfo struct {
	RuleSetVersion string `json:"rule_set_version"`
	RuleSetSource  string `json:"rule_set_source"`
	Profile        string `json:"profile"`
}

// EvidenceInfo describes the input.
type EvidenceInfo struct {
	Root          string   `json:"root"`
	Layout        string   `json:"layout"`
	VolumeRoots   []string `json:"volume_roots"`
	TotalBytes    int64    `json:"total_bytes"`
	ArtefactCount int      `json:"artefact_count"`
	NotCollected  []string `json:"not_collected,omitempty"`
	NameCollision []string `json:"name_collisions,omitempty"`
	// NotLooked names places discovery could not read, which is a different
	// and stronger statement than NotCollected: one says an artefact was not
	// there, the other says nobody could see whether it was.
	NotLooked []string `json:"not_looked,omitempty"`
}

// Timing records how long a phase took, so a slow run can be explained.
type Timing struct {
	Phase      string `json:"phase"`
	DurationMS int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"`
}

// Counts is the headline accounting for the run.
type Counts struct {
	Sources      int `json:"sources"`
	Observations int `json:"observations"`
	Warnings     int `json:"warnings"`
	Devnodes     int `json:"devnodes"`
	EventRecords int `json:"event_records"`
	// Devices counts distinct device identities across every source, which is
	// not the devnode count: a device can be named by events alone.
	Devices     int `json:"devices"`
	FileTargets int `json:"file_targets"`
	ShellBags   int `json:"shell_bags"`
	MRUEntries  int `json:"mru_entries"`
	// UserAssistEntries counts what the shell recorded a user launching, which
	// is a different population from PrefetchRuns: per user and only what
	// Explorer started, against per machine and anything the loader touched.
	UserAssistEntries int `json:"user_assist_entries"`
	ShellLinks        int `json:"shell_links"`
	// RemovableTargets counts file accesses the recording application placed
	// on removable media.
	RemovableTargets int `json:"removable_targets"`
	// PrefetchRuns counts the prefetch files read, and PrefetchExecutions the
	// executions they recorded. The second is not the sum of the run counts:
	// Windows keeps the last eight executions per programme and overwrites the
	// rest, so what was recorded and what happened are different numbers and
	// the manifest states the one it can stand behind.
	PrefetchRuns       int `json:"prefetch_runs"`
	PrefetchExecutions int `json:"prefetch_executions"`
	// TimelineEntries counts every timestamped record the timeline holds, and
	// WallClockEntries how many of those rest on a local wall clock converted
	// with the host biases rather than on a recorded UTC instant. The second
	// number says how much of the timeline is placed by conversion.
	TimelineEntries  int `json:"timeline_entries"`
	WallClockEntries int `json:"wall_clock_entries"`
}

// Version is the tool version, and the default a build carries when nothing
// overrides it. Set at build time via -ldflags to stamp a release.
//
// The scheme is a three-segment count, not semantic versioning: each segment
// runs 0 to 9 and then carries into the one to its left, so 0.2.9 is followed
// by 0.3.0. It says how far the tool has come, not what it promises about
// compatibility — there is no published API to make that promise about.
//
// This string reaches evidence. It is written into every manifest and printed
// on every report, so a report produced months ago can be tied to the build
// that produced it. Bump it in the same commit as the change it describes,
// or the two disagree and the manifest is the one that gets believed.
var Version = "0.6.3"

// BuildHash is the commit the binary was built from. Set at build time.
var BuildHash = ""

// NewManifest starts a manifest for a run.
func (w *Workspace) NewManifest(startedAt time.Time) *Manifest {
	return &Manifest{
		Tool: ToolInfo{
			Name:      "Boobook",
			Version:   Version,
			BuildHash: BuildHash,
			GoVersion: runtime.Version(),
			Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		},
		Run: RunInfo{
			ID:          w.RunID,
			StartedAt:   startedAt.UTC(),
			OutputDir:   w.Dir,
			WorkingRoot: w.WorkingRoot,
			CommandLine: os.Args,
		},
	}
}

// AddTiming records a phase duration.
func (m *Manifest) AddTiming(phase string, duration time.Duration, detail string) {
	m.Timings = append(m.Timings, Timing{
		Phase:      phase,
		DurationMS: duration.Milliseconds(),
		Detail:     detail,
	})
}

// Finalise fills in the closing fields from the ledger.
func (m *Manifest) Finalise(ledger *provenance.Ledger, completedAt time.Time) {
	m.Run.CompletedAt = completedAt.UTC()
	m.Run.DurationMS = completedAt.Sub(m.Run.StartedAt).Milliseconds()

	m.Sources = ledger.Sources()
	m.Warnings = ledger.Warnings()

	sources, observations, warnings := ledger.Counts()
	m.Counts.Sources = sources
	m.Counts.Observations = observations
	m.Counts.Warnings = warnings
}

// Write saves the manifest into the run's output directory.
func (w *Workspace) WriteManifest(manifest *Manifest) (string, error) {
	outputDir, err := w.OutputDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(outputDir, "manifest.json")
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode manifest: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return "", fmt.Errorf("write manifest %s: %w", path, err)
	}
	return path, nil
}
