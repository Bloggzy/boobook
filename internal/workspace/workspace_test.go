package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bloggzy/boobook/internal/provenance"
)

// regparser.RecoverHive writes its recovered hive to os.TempDir(). If that is
// not redirected, a run's staged evidence scatters through the system temp
// folder instead of sitting in the caller's working root.
func TestRedirectProcessTempDir(t *testing.T) {
	// t.Setenv registers the restore the test framework needs; the redirect
	// then overwrites these values and must put them back.
	original := t.TempDir()
	for _, key := range []string{"TMP", "TEMP", "TMPDIR"} {
		t.Setenv(key, original)
	}

	root := t.TempDir()
	workspace, err := New(root, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Creating the workspace must not, on its own, move the process temp dir:
	// that is a global side effect and belongs to the program entry point.
	if os.TempDir() != original {
		t.Errorf("New() mutated the process temp dir to %q", os.TempDir())
	}

	restore, err := workspace.RedirectProcessTempDir()
	if err != nil {
		t.Fatalf("RedirectProcessTempDir: %v", err)
	}

	if got := os.TempDir(); got != workspace.TempDir() {
		t.Errorf("os.TempDir() = %q, want the workspace working dir %q",
			got, workspace.TempDir())
	}

	// A file created the way RecoverHive creates one must land in the workspace.
	temp, err := os.CreateTemp(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	temp.Close()
	if !strings.HasPrefix(temp.Name(), workspace.TempDir()) {
		t.Errorf("temp file %q was not created inside the workspace %q",
			temp.Name(), workspace.TempDir())
	}

	restore()
	if got := os.TempDir(); got != original {
		t.Errorf("restore left the temp dir at %q, want %q", got, original)
	}
}

func TestNewCreatesRunScopedDirectory(t *testing.T) {
	root := t.TempDir()
	workspace, err := New(root, "")
	if err != nil {
		t.Fatal(err)
	}

	if workspace.RunID == "" {
		t.Error("a run must be identified")
	}
	if !strings.Contains(workspace.Dir, workspace.RunID) {
		t.Errorf("run directory %q does not carry the run ID %q",
			workspace.Dir, workspace.RunID)
	}
	if info, err := os.Stat(workspace.TempDir()); err != nil || !info.IsDir() {
		t.Errorf("working directory was not created: %v", err)
	}
}

func TestStageCopiesFileIntoWorkspace(t *testing.T) {
	root := t.TempDir()
	workspace, err := New(root, "")
	if err != nil {
		t.Fatal(err)
	}

	sourceDir := t.TempDir()
	sourcePath := filepath.Join(sourceDir, "SYSTEM")
	content := []byte("regf pretend hive")
	if err := os.WriteFile(sourcePath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	stagedPath, err := workspace.Stage(sourcePath, "SYSTEM")
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if !strings.HasPrefix(stagedPath, workspace.TempDir()) {
		t.Errorf("staged copy %q is outside the workspace", stagedPath)
	}

	staged, err := os.ReadFile(stagedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(staged) != string(content) {
		t.Error("staged copy does not match the source")
	}

	// The source must be untouched.
	original, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != string(content) {
		t.Error("the source file was modified by staging")
	}
}

// The results are what the examiner named a directory for, so they go straight
// into the run directory. Scratch lives underneath it and leaves with it.
//
// This was once the other way round — the working root was the required flag
// and the output was nested inside it at Boobook/<runID>/output — which named
// the parameter after the byproduct rather than after what the analyst chose.
func TestTheRunDirectoryHoldsTheResultsAndScratchSitsUnderIt(t *testing.T) {
	root := t.TempDir()
	workspace, err := New(root, "")
	if err != nil {
		t.Fatal(err)
	}

	output, err := workspace.OutputDir()
	if err != nil {
		t.Fatal(err)
	}
	if output != workspace.Dir {
		t.Errorf("output %q is not the run directory %q", output, workspace.Dir)
	}
	if want := filepath.Join(root, workspace.RunID); workspace.Dir != want {
		t.Errorf("run directory %q, want %q", workspace.Dir, want)
	}
	if !strings.HasPrefix(workspace.TempDir(), workspace.Dir) {
		t.Errorf("scratch %q is not inside the run directory %q",
			workspace.TempDir(), workspace.Dir)
	}
}

// Scratch on its own root is still scoped by run id. Two runs sharing one
// scratch directory would have the second delete the first's recovered hives
// while it was still reading them.
func TestASeparateScratchRootIsStillScopedByRun(t *testing.T) {
	output, scratch := t.TempDir(), t.TempDir()
	workspace, err := New(output, scratch)
	if err != nil {
		t.Fatal(err)
	}

	if strings.HasPrefix(workspace.TempDir(), workspace.Dir) {
		t.Errorf("scratch %q landed inside the output despite a separate root",
			workspace.TempDir())
	}
	if !strings.HasPrefix(workspace.TempDir(), filepath.Join(scratch, workspace.RunID)) {
		t.Errorf("scratch %q is not under the run's own directory in %q",
			workspace.TempDir(), scratch)
	}

	// And discarding it takes the run's directory with it rather than leaving
	// an empty shell per run on a disk nobody looks at.
	if err := workspace.DiscardScratch(); err != nil {
		t.Fatalf("DiscardScratch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scratch, workspace.RunID)); !os.IsNotExist(err) {
		t.Errorf("the run's scratch directory survived: %v", err)
	}
	// The output must be untouched by any of that.
	if _, err := os.Stat(workspace.Dir); err != nil {
		t.Errorf("discarding scratch removed the output directory: %v", err)
	}
}

// A recovered hive is derived, and referenced by no source record; the hive
// and each of its logs are hashed in the ledger, so the run stays reproducible
// once scratch is gone. That is what makes removing it safe. The count is taken
// first because files vanishing without a word invites the question of what
// they were — and because a non-empty scratch tree means a previous run ended
// early, which is worth saying rather than tidying away.
func TestScratchIsCountedBeforeItIsDiscardedAndTheOutputSurvives(t *testing.T) {
	workspace, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	// A directory with no file in it holds nothing: staging creates a folder
	// per artefact kind before it knows whether it will put anything there.
	if err := os.MkdirAll(filepath.Join(workspace.TempDir(), "staged", "SYSTEM"),
		0o755); err != nil {
		t.Fatal(err)
	}
	held, err := workspace.ScratchFiles()
	if err != nil {
		t.Fatal(err)
	}
	if held != 0 {
		t.Errorf("ScratchFiles = %d for empty directories, want 0", held)
	}

	sourcePath := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(sourcePath, []byte("regf pretend hive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := workspace.Stage(sourcePath, "SYSTEM"); err != nil {
		t.Fatal(err)
	}

	held, err = workspace.ScratchFiles()
	if err != nil {
		t.Fatal(err)
	}
	if held != 1 {
		t.Errorf("ScratchFiles = %d, want 1", held)
	}

	// The results have to survive a discard, which is the whole point of the
	// scratch directory being a subdirectory rather than the parent.
	marker := filepath.Join(workspace.Dir, "report.html")
	if err := os.WriteFile(marker, []byte("<html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := workspace.DiscardScratch(); err != nil {
		t.Fatalf("DiscardScratch: %v", err)
	}
	if _, err := os.Stat(workspace.TempDir()); !os.IsNotExist(err) {
		t.Errorf("scratch survived the discard: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("discarding scratch took the report with it: %v", err)
	}
}

func TestManifestRecordsToolRunAndCounts(t *testing.T) {
	root := t.TempDir()
	workspace, err := New(root, "")
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now().UTC()
	manifest := workspace.NewManifest(started)
	manifest.Case = CaseInfo{Reference: "OP-2026-001", Examiner: "A. Analyst"}
	manifest.AddTiming("registry", 250*time.Millisecond, "SYSTEM")

	ledger := provenance.NewLedger()
	ledger.Observe(provenance.Observation{Kind: "devnode.value"})
	ledger.Absent("SETUPAPI", "x", "not collected")
	manifest.Finalise(ledger, started.Add(3*time.Second))

	path, err := workspace.WriteManifest(manifest)
	if err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)

	for _, want := range []string{
		"Boobook", "OP-2026-001", "A. Analyst", "registry", "not collected",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("manifest does not record %q", want)
		}
	}

	if manifest.Counts.Observations != 1 {
		t.Errorf("Observations = %d, want 1", manifest.Counts.Observations)
	}
	if manifest.Counts.Warnings != 1 {
		t.Errorf("Warnings = %d, want 1", manifest.Counts.Warnings)
	}
	if manifest.Run.DurationMS != 3000 {
		t.Errorf("DurationMS = %d, want 3000", manifest.Run.DurationMS)
	}
}

// A run directory is what keeps one run's results from being overwritten by the
// next, and the id it is named after is a UTC timestamp to the second. Two runs
// started in one second therefore asked for the same directory, and MkdirAll
// gave it to both: a review's five parallel reference runs all received
// 20260808T171306Z, and only separate output roots kept them from contending
// for one database, one set of exports and one scratch tree.
//
// The claim being made is exclusivity, so it comes from the filesystem — one
// os.Mkdir, which either creates the directory or says somebody has it. A
// finer-grained timestamp would have made the ids unique without making them
// exclusive, and two processes can format the same string however many digits
// it has.
func TestTwoRunsInOneSecondNeverShareADirectory(t *testing.T) {
	root := t.TempDir()

	first, err := New(root, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, err := New(root, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The test is worthless if the clock ticked between the two calls, and it
	// would pass silently. Say so instead.
	if !strings.HasPrefix(second.RunID, first.RunID) {
		t.Skipf("the clock advanced between the two runs (%s then %s), so "+
			"they did not contend for one id", first.RunID, second.RunID)
	}

	if second.RunID == first.RunID {
		t.Fatalf("both runs took the id %s", first.RunID)
	}
	if second.Dir == first.Dir {
		t.Fatalf("both runs took the directory %s", first.Dir)
	}
	if second.RunID != first.RunID+"-2" {
		t.Errorf("the second run is %s, want %s-2: a collision is settled by "+
			"counting, so the id says on its face that it is the second",
			second.RunID, first.RunID)
	}
	if second.TempDir() == first.TempDir() {
		t.Errorf("both runs share the scratch directory %s: one would delete "+
			"the other's recovered hives mid-read", first.TempDir())
	}
}

// The same claim where scratch is on a root of its own, which is the case that
// can half-collide: the output id is free and the working id is not, or the
// reverse. Taking one and not the other would give two runs one scratch tree.
func TestARunNeverSharesAScratchDirectoryWithAnother(t *testing.T) {
	output, working := t.TempDir(), t.TempDir()

	first, err := New(output, working)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Free the output id and leave the working id taken, which is the shape a
	// half-check would accept.
	if err := os.RemoveAll(first.Dir); err != nil {
		t.Fatal(err)
	}

	second, err := New(output, working)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(second.RunID, first.RunID) {
		t.Skipf("the clock advanced between the two runs (%s then %s)",
			first.RunID, second.RunID)
	}
	if second.WorkingRoot == first.WorkingRoot {
		t.Errorf("both runs took the working directory %s, because the output "+
			"id was free: a run directory is claimed on both roots or on "+
			"neither", first.WorkingRoot)
	}
	// And the id it gave back is free again, rather than an empty directory
	// left standing in the output root that no run will ever write into.
	if _, err := os.Stat(first.Dir); !os.IsNotExist(err) {
		t.Errorf("%s was left behind by the run that could not claim its "+
			"scratch directory", first.Dir)
	}
}
