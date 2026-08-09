// Package provenance is the chain that makes a finding checkable.
//
// The rule the whole tool rests on: every extracted fact names the source file
// it came from, the hash of that file as read, and where inside it the value
// sat. A report figure an analyst cannot resolve back to a source is not
// evidence, it is an assertion.
package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Source is one evidence file, recorded as it was read.
type Source struct {
	// ID is stable within a run and is what observations refer to.
	ID string `json:"id"`

	// Path is the location within the evidence root, kept as discovered.
	Path string `json:"path"`

	// StagedPath is where the working copy sits, if the file was staged.
	StagedPath string `json:"staged_path,omitempty"`

	// Artefact names what this file is (e.g. "SYSTEM", "EVTX", "setupapi").
	Artefact string `json:"artefact"`

	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	ReadAt    time.Time `json:"read_at"`
	// ModifiedAt is the file's own last-written time as it stood when the run
	// hashed it. Recorded because it is the cheapest evidence that the file the
	// digest attests is the file the parser read.
	ModifiedAt time.Time `json:"modified_at,omitempty"`

	// Verified is the answer to the question the digest alone cannot settle:
	// is this still the file that was hashed?
	//
	// The hash and the parse are separate opens — the ledger hashes a path and
	// each parser opens it again — so on evidence that can change under the run
	// the observations could be attached to the digest of different bytes. A
	// mounted image will not move; a live host, a network share or a collection
	// being written to will. Every source is re-stated and re-hashed at the end
	// of the run and this records what that found, per file, rather than the
	// run assuming stability it cannot check.
	//
	// nil means the check has not run.
	Verified *bool `json:"verified,omitempty"`
	// VerifyNote is what changed, where anything did.
	VerifyNote string `json:"verify_note,omitempty"`

	// Replayed records that registry transaction logs were applied — that a
	// page from a log reached the values read out of this hive. A hive parsed
	// without replay may be missing its most recent writes, and that difference
	// must never be invisible.
	//
	// It is a pointer because replay does not apply to an event log or a
	// shortcut at all, and nil says so. Stored as a plain false, every LNK in a
	// collection reads as a hive that was parsed without its logs — a caveat
	// attached to evidence it has nothing to do with.
	//
	// True is a claim about the hive, not about the recovery call returning
	// without an error. Recovery succeeds when it has merely copied the file,
	// so this was set on hives no log had touched.
	Replayed *bool `json:"replayed,omitempty"`

	// ReplayLogs names the transaction logs that supplied pages — not every log
	// found beside the hive. A superseded, empty or unsupported log is there
	// and contributed nothing, and naming it here asserted otherwise.
	ReplayLogs []string `json:"replay_logs,omitempty"`

	// ReplayNote is what happened, in one sentence, including the case a
	// boolean cannot express: recovery ran, and changed nothing.
	ReplayNote string `json:"replay_note,omitempty"`
}

// Locator says where inside a source an observation came from. Which fields
// are set depends on the artefact: a registry value has a key path, an event
// record has a record ID, a log line has a line number.
type Locator struct {
	RegistryKey   string `json:"registry_key,omitempty"`
	RegistryValue string `json:"registry_value,omitempty"`
	ControlSet    string `json:"control_set,omitempty"`
	EventRecordID uint64 `json:"event_record_id,omitempty"`
	Channel       string `json:"channel,omitempty"`
	LineNumber    int    `json:"line_number,omitempty"`
	ByteOffset    int64  `json:"byte_offset,omitempty"`
}

// Observation is one fact read from one place in one source.
//
// Raw is what was stored; Value is what we made of it. Both are kept, because a
// derived value that cannot be checked against the bytes it came from is a
// conclusion wearing the clothes of an observation.
//
// Four fields, and the difference between them is the whole point:
//
//	Field    which fact within the kind — a name, never a value.
//	Raw      the stored form of that fact, unaltered. Empty where the
//	         artefact has no single stored form to point at.
//	Value    what was made of it.
//	Summary  narration: everything else the record carried, for a reader.
//
// Summary exists because the first three were being used for the fourth. Eight
// recorders put a joined description into Raw — "version=30 run_count=3
// times=1 volumes=2" — and two put the value in Field and a key name in Raw.
// So observations.jsonl said raw is the stored form and a consumer had no way
// to know whether a given row held bytes, decoded text or a sentence, which
// makes the column unusable for the one thing it is for: checking a derived
// value against what the artefact actually holds.
type Observation struct {
	ID       string  `json:"id"`
	SourceID string  `json:"source_id"`
	Locator  Locator `json:"locator"`

	// Kind names the sort of fact (e.g. "devnode.value", "event.record").
	Kind string `json:"kind"`

	// Field names which fact within that kind (e.g. "ContainerID").
	Field string `json:"field,omitempty"`

	// Raw is the stored form, unaltered.
	Raw string `json:"raw,omitempty"`

	// Value is the normalised form, where one was derived.
	Value string `json:"value,omitempty"`

	// Summary is the rest of what the record carried, as a sentence. It is for
	// a reader; nothing joins on it and nothing should.
	Summary string `json:"summary,omitempty"`

	// RawTimestamp is the stored time value (e.g. a FILETIME) and TimeUTC the
	// conversion of it. Keeping both is what makes a conversion checkable.
	RawTimestamp uint64     `json:"raw_timestamp,omitempty"`
	TimeUTC      *time.Time `json:"time_utc,omitempty"`
}

// Warning records something that went wrong or was absent. A run reports these
// rather than aborting: a missing artefact is a finding about the collection,
// not a reason to produce nothing.
type Warning struct {
	SourceID string `json:"source_id,omitempty"`
	Artefact string `json:"artefact,omitempty"`
	Path     string `json:"path,omitempty"`
	// Severity is one of:
	//
	//	absent     an expected artefact was not in the collection
	//	partial    records parsed, but something inside them did not
	//	truncated  a file ended before its structure did
	//	malformed  a file's structure did not hold
	//	failed     nothing could be read, or the run could not look
	//
	// partial and failed are the pair worth keeping apart. A partial parse
	// leaves real records in the outputs that a reader will rely on; a failure
	// leaves a silence that must never be offered as evidence there was
	// nothing there.
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
	At       time.Time `json:"at"`
}

// Ledger accumulates sources, observations and warnings for a run. It is safe
// for concurrent use: parsers run one goroutine per artefact.
type Ledger struct {
	mu           sync.Mutex
	sources      []Source
	observations []Observation
	warnings     []Warning

	sourceSeq      atomic.Uint64
	observationSeq atomic.Uint64
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger { return &Ledger{} }

// AddSource hashes a file and records it, returning the source ID that
// observations from it must carry.
func (l *Ledger) AddSource(path, artefact string) (Source, error) {
	source := Source{
		ID:       fmt.Sprintf("src-%04d", l.sourceSeq.Add(1)),
		Path:     path,
		Artefact: artefact,
		ReadAt:   time.Now().UTC(),
	}

	info, err := os.Stat(path)
	if err != nil {
		return source, fmt.Errorf("stat %s: %w", path, err)
	}
	source.SizeBytes = info.Size()
	source.ModifiedAt = info.ModTime().UTC()

	digest, err := hashFile(path)
	if err != nil {
		return source, fmt.Errorf("hash %s: %w", path, err)
	}
	source.SHA256 = digest

	l.mu.Lock()
	l.sources = append(l.sources, source)
	l.mu.Unlock()

	return source, nil
}

// Reverify re-stats and re-hashes every source, and records whether each is
// still the file the run attested.
//
// This exists because hashing and parsing are separate opens. Ledger.AddSource
// hashes a path; every parser opens that path again; nothing tied the two to
// one immutable stream. On a mounted image that is academic, and Boobook also
// accepts a directory of evidence, which can be a live host, a network share,
// or a collection still being written. A file that changed in between would
// leave observations attached to the digest of bytes nobody read, and the
// report would carry a hash an examiner could not reproduce with no indication
// why.
//
// Re-hashing rather than comparing size and modification time is deliberate.
// Those two are what an inadvertent change disturbs, and they are exactly what
// anything deliberate would preserve; a forensic tool should not report on the
// strength of the check that is easiest to defeat. It costs one more pass over
// the evidence — about 160 MB on the reference collections, against a run of
// twenty seconds — which is a small price for the difference between attesting
// bytes and assuming them.
//
// It reports rather than fails. A source that moved is a finding about the
// evidence, and discarding everything read from it would lose real observations
// to tidy away a fact the analyst needs to see.
func (l *Ledger) Reverify() int {
	l.mu.Lock()
	sources := make([]Source, len(l.sources))
	copy(sources, l.sources)
	l.mu.Unlock()

	moved := 0
	for _, source := range sources {
		note := verifySource(source)
		stable := note == ""
		source.Verified = &stable
		source.VerifyNote = note
		l.UpdateSource(source)

		if stable {
			continue
		}
		moved++
		l.Warn(Warning{
			SourceID: source.ID, Artefact: source.Artefact, Path: source.Path,
			Severity: "failed",
			Message: "this file is not the file the run hashed, so the digest " +
				"recorded against everything read from it attests bytes that " +
				"may not be the bytes that were parsed: " + note,
		})
	}
	return moved
}

// verifySource returns what changed, or "" where nothing did.
func verifySource(source Source) string {
	info, err := os.Stat(source.Path)
	if err != nil {
		return "the file could not be read a second time: " + err.Error()
	}
	if info.Size() != source.SizeBytes {
		return fmt.Sprintf("it was %d bytes when hashed and is %d now",
			source.SizeBytes, info.Size())
	}

	digest, err := hashFile(source.Path)
	if err != nil {
		return "it could not be hashed a second time: " + err.Error()
	}
	if digest != source.SHA256 {
		return fmt.Sprintf("its SHA-256 was %s when read and is %s now",
			source.SHA256, digest)
	}
	// Only worth saying once the content has been shown to be the same: a
	// touched file whose bytes did not move is a much weaker finding than one
	// whose did, and calling both "changed" would flatten the difference.
	if modified := info.ModTime().UTC(); !modified.Equal(source.ModifiedAt) {
		return fmt.Sprintf("its content is unchanged, but its last-written "+
			"time moved from %s to %s",
			source.ModifiedAt.Format(time.RFC3339),
			modified.Format(time.RFC3339))
	}
	return ""
}

// UpdateSource replaces a recorded source, for when staging or replay adds
// detail after the initial hash.
func (l *Ledger) UpdateSource(source Source) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.sources {
		if l.sources[i].ID == source.ID {
			l.sources[i] = source
			return
		}
	}
	l.sources = append(l.sources, source)
}

// NextObservationID mints an ID without recording anything, for parsers that
// build an observation before they have its value.
func (l *Ledger) NextObservationID() string {
	return fmt.Sprintf("obs-%08d", l.observationSeq.Add(1))
}

// Observe records one observation and returns its ID.
func (l *Ledger) Observe(observation Observation) string {
	if observation.ID == "" {
		observation.ID = l.NextObservationID()
	}

	l.mu.Lock()
	l.observations = append(l.observations, observation)
	l.mu.Unlock()

	return observation.ID
}

// ObserveBatch records many observations at once, which is what a parser
// producing thousands of rows should use.
func (l *Ledger) ObserveBatch(observations []Observation) {
	for i := range observations {
		if observations[i].ID == "" {
			observations[i].ID = l.NextObservationID()
		}
	}

	l.mu.Lock()
	l.observations = append(l.observations, observations...)
	l.mu.Unlock()
}

// Warn records a warning.
func (l *Ledger) Warn(warning Warning) {
	if warning.At.IsZero() {
		warning.At = time.Now().UTC()
	}

	l.mu.Lock()
	l.warnings = append(l.warnings, warning)
	l.mu.Unlock()
}

// Absent records that an expected artefact was not present. This is reported,
// never treated as an error: an absence is itself evidence about the collection.
func (l *Ledger) Absent(artefact, path, message string) {
	l.Warn(Warning{
		Artefact: artefact,
		Path:     path,
		Severity: "absent",
		Message:  message,
	})
}

// Sources returns a copy of the recorded sources.
func (l *Ledger) Sources() []Source {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Source, len(l.sources))
	copy(out, l.sources)
	return out
}

// Observations returns a copy of the recorded observations.
func (l *Ledger) Observations() []Observation {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Observation, len(l.observations))
	copy(out, l.observations)
	return out
}

// Warnings returns a copy of the recorded warnings.
func (l *Ledger) Warnings() []Warning {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Warning, len(l.warnings))
	copy(out, l.warnings)
	return out
}

// Counts reports ledger size, for progress and summary reporting.
func (l *Ledger) Counts() (sources, observations, warnings int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.sources), len(l.observations), len(l.warnings)
}

// HashFile returns the SHA-256 of a file. Outputs are hashed with the same
// function as evidence, so a quoted export can be shown to be what the run
// wrote just as an evidence file can.
func HashFile(path string) (string, error) { return hashFile(path) }

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
