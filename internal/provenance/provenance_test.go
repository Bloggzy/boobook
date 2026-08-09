package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAddSourceHashesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SYSTEM")
	content := []byte("regf pretend hive")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	ledger := NewLedger()
	source, err := ledger.AddSource(path, "SYSTEM")
	if err != nil {
		t.Fatalf("AddSource: %v", err)
	}

	digest := sha256.Sum256(content)
	if want := hex.EncodeToString(digest[:]); source.SHA256 != want {
		t.Errorf("SHA256 = %s, want %s", source.SHA256, want)
	}
	if source.SizeBytes != int64(len(content)) {
		t.Errorf("SizeBytes = %d, want %d", source.SizeBytes, len(content))
	}
	if source.ID == "" {
		t.Error("source must be given an ID")
	}
	if got := len(ledger.Sources()); got != 1 {
		t.Errorf("ledger holds %d sources, want 1", got)
	}
}

func TestAddSourceReportsMissingFile(t *testing.T) {
	ledger := NewLedger()
	if _, err := ledger.AddSource(filepath.Join(t.TempDir(), "absent"), "SYSTEM"); err == nil {
		t.Error("expected an error for a file that does not exist")
	}
}

// Parsers run one goroutine per artefact, so IDs must stay unique under
// concurrency. A duplicated observation ID would silently make two different
// facts resolve to the same provenance record.
func TestObservationIDsAreUniqueUnderConcurrency(t *testing.T) {
	ledger := NewLedger()

	const writers = 8
	const perWriter = 500

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				ledger.Observe(Observation{
					SourceID: "src-0001",
					Kind:     "devnode.value",
					Field:    fmt.Sprintf("w%d-%d", worker, i),
				})
			}
		}(w)
	}
	wg.Wait()

	observations := ledger.Observations()
	if len(observations) != writers*perWriter {
		t.Fatalf("recorded %d observations, want %d",
			len(observations), writers*perWriter)
	}

	seen := make(map[string]bool, len(observations))
	for _, observation := range observations {
		if observation.ID == "" {
			t.Fatal("observation recorded without an ID")
		}
		if seen[observation.ID] {
			t.Fatalf("duplicate observation ID %s", observation.ID)
		}
		seen[observation.ID] = true
	}
}

func TestObserveBatchAssignsIDsAndKeepsSuppliedOnes(t *testing.T) {
	ledger := NewLedger()
	ledger.ObserveBatch([]Observation{
		{Kind: "a"},
		{ID: "obs-supplied", Kind: "b"},
		{Kind: "c"},
	})

	observations := ledger.Observations()
	if len(observations) != 3 {
		t.Fatalf("got %d observations, want 3", len(observations))
	}
	if observations[1].ID != "obs-supplied" {
		t.Errorf("a supplied ID must be kept, got %q", observations[1].ID)
	}
	for _, observation := range observations {
		if observation.ID == "" {
			t.Error("every observation must carry an ID")
		}
	}
}

// An absent artefact is a finding about the collection, not an error. It must
// be recorded and must not stop a run.
func TestAbsentIsRecordedAsAWarning(t *testing.T) {
	ledger := NewLedger()
	ledger.Absent("setupapi", `C:\x\Windows\INF\setupapi.dev.log`, "not collected")

	warnings := ledger.Warnings()
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want 1", len(warnings))
	}
	if warnings[0].Severity != "absent" {
		t.Errorf("Severity = %q, want %q", warnings[0].Severity, "absent")
	}
	if warnings[0].At.IsZero() {
		t.Error("a warning must be timestamped")
	}
}

// Callers must not be able to mutate ledger state through a returned slice.
func TestAccessorsReturnCopies(t *testing.T) {
	ledger := NewLedger()
	ledger.Observe(Observation{Kind: "devnode.value", Field: "ContainerID"})

	observations := ledger.Observations()
	observations[0].Field = "mutated"

	if again := ledger.Observations(); again[0].Field != "ContainerID" {
		t.Errorf("ledger state was mutated through a returned slice: %q",
			again[0].Field)
	}
}

func TestUpdateSourceReplacesInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SYSTEM")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	ledger := NewLedger()
	source, err := ledger.AddSource(path, "SYSTEM")
	if err != nil {
		t.Fatal(err)
	}

	replayed := true
	source.Replayed = &replayed
	source.ReplayLogs = []string{"SYSTEM.LOG1"}
	ledger.UpdateSource(source)

	sources := ledger.Sources()
	if len(sources) != 1 {
		t.Fatalf("update created a duplicate: %d sources", len(sources))
	}
	if sources[0].Replayed == nil || !*sources[0].Replayed ||
		len(sources[0].ReplayLogs) != 1 {
		t.Error("replay detail was not recorded against the source")
	}
}

// Replay applies to a registry hive and to nothing else. An event log stored as
// "not replayed" reads as a hive whose transaction logs were skipped, which
// attaches a caveat to evidence it has nothing to do with.
func TestReplayIsUnsetWhereItDoesNotApply(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "Security.evtx")
	if err := os.WriteFile(path, []byte("record"), 0o644); err != nil {
		t.Fatal(err)
	}

	ledger := NewLedger()
	source, err := ledger.AddSource(path, "EVTX")
	if err != nil {
		t.Fatal(err)
	}
	if source.Replayed != nil {
		t.Errorf("replayed = %v, want unset for an event log", *source.Replayed)
	}
}

// A file that changed under the run must be reported, not attested.
//
// Ledger.AddSource hashes a path and every parser opens that path again, so
// nothing tied the digest and the parse to one immutable stream. On a mounted
// image that is academic; Boobook also accepts a directory of evidence, which
// can be a live host, a network share, or a collection still being written. A
// file that moved in between would leave every observation from it carrying the
// digest of bytes nobody read, and the report would print a hash an examiner
// could not reproduce with nothing to explain the difference.
func TestAFileThatChangedUnderTheRunIsReportedRatherThanAttested(t *testing.T) {
	dir := t.TempDir()
	steady := filepath.Join(dir, "steady.evtx")
	moving := filepath.Join(dir, "moving.evtx")
	for _, path := range []string{steady, moving} {
		if err := os.WriteFile(path, []byte("as collected"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ledger := NewLedger()
	if _, err := ledger.AddSource(steady, "EVTX"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AddSource(moving, "EVTX"); err != nil {
		t.Fatal(err)
	}

	// The same length, so a check on size alone would pass it. That is the
	// reason this re-hashes rather than comparing size and modification time:
	// those are what an inadvertent change disturbs and exactly what anything
	// deliberate would preserve.
	if err := os.WriteFile(moving, []byte("as amended!!"), 0o644); err != nil {
		t.Fatal(err)
	}

	if moved := ledger.Reverify(); moved != 1 {
		t.Fatalf("Reverify reported %d changed files, want 1", moved)
	}

	byPath := map[string]Source{}
	for _, source := range ledger.Sources() {
		byPath[source.Path] = source
	}

	if got := byPath[steady]; got.Verified == nil || !*got.Verified {
		t.Errorf("the unchanged file is not marked verified: %+v", got.Verified)
	} else if got.VerifyNote != "" {
		t.Errorf("the unchanged file carries a note: %q", got.VerifyNote)
	}

	changed := byPath[moving]
	if changed.Verified == nil || *changed.Verified {
		t.Fatal("a file whose bytes changed under the run was still attested")
	}
	if !strings.Contains(changed.VerifyNote, "SHA-256") {
		t.Errorf("the note does not say what changed: %q", changed.VerifyNote)
	}

	// A finding about the evidence, so it has to reach the report's
	// limitations rather than only the source row.
	var reported bool
	for _, warning := range ledger.Warnings() {
		if warning.Path == moving && warning.Severity == "failed" {
			reported = true
		}
	}
	if !reported {
		t.Error("no warning was raised, so the report would carry a digest " +
			"that does not attest the bytes that were parsed and say nothing")
	}
}

// The observations are kept. The record is real and only the attestation is in
// doubt, and discarding what was read would lose evidence to tidy away a fact
// the analyst needs to see.
func TestAChangedSourceKeepsItsObservations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SYSTEM")
	if err := os.WriteFile(path, []byte("as collected"), 0o644); err != nil {
		t.Fatal(err)
	}

	ledger := NewLedger()
	source, err := ledger.AddSource(path, "SYSTEM")
	if err != nil {
		t.Fatal(err)
	}
	ledger.Observe(Observation{SourceID: source.ID, Kind: "device", Value: "kept"})

	if err := os.WriteFile(path, []byte("as amended!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	ledger.Reverify()

	if got := len(ledger.Observations()); got != 1 {
		t.Errorf("got %d observations, want 1: a source that moved is a "+
			"finding, not a reason to delete what was read from it", got)
	}
}
