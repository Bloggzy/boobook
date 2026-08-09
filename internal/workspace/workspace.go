// Package workspace owns the directories a run writes into, and the manifest
// that records what the run did.
//
// Nothing is ever written below the evidence root. Everything a run produces —
// recovered hives, staged copies, outputs — lands beneath caller-controlled
// roots.
//
// There are two, and they are not equals. The output root is where the results
// go and is what the examiner names; the working root is scratch, sits inside
// the run's output directory unless the caller puts it elsewhere, and is
// removed at the end of the run unless it is asked for. Scratch was once the
// primary parameter with the results nested inside it, which inverted what an
// analyst is actually choosing when they run the tool.
package workspace

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Workspace is the set of directories one run writes into.
type Workspace struct {
	// OutputRoot is the caller-supplied root the results go beneath.
	OutputRoot string
	// WorkingRoot is where scratch goes. It equals Dir unless the caller named
	// a separate root, which is worth doing when the output is on a network
	// share and staging a hive across it would be slow.
	WorkingRoot string
	// RunID identifies this run within the output root.
	RunID string
	// Dir is this run's output directory: OutputRoot/RunID. Every result the
	// run produces is written directly into it.
	//
	// Run-scoped rather than written straight into the output root, because a
	// second run must never overwrite the first: a report already cited in a
	// case note is not something to quietly replace.
	Dir string
	// tempDir holds recovered hives and staged copies.
	tempDir string
}

// maxRunAttempts bounds the search for a free run id. A hundred runs starting
// against one output root inside one second is not a case being worked, so
// exhausting it is reported rather than retried for ever.
const maxRunAttempts = 100

// New creates the directories for a run.
//
// workingRoot may be empty, which is the ordinary case: scratch then lives
// inside the run's own output directory and is cleaned up with it.
func New(outputRoot, workingRoot string) (*Workspace, error) {
	// The roots themselves are made first so that the run directory beneath
	// them can be claimed with os.Mkdir, which fails on an existing directory.
	// MkdirAll would not: it treats one as success, which is the whole defect.
	if err := os.MkdirAll(outputRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create output root %s: %w", outputRoot, err)
	}
	if workingRoot != "" {
		if err := os.MkdirAll(workingRoot, 0o755); err != nil {
			return nil, fmt.Errorf("create working root %s: %w", workingRoot, err)
		}
	}

	// The run id is a UTC timestamp to the second, which two runs started in
	// one second share — five parallel reference runs in a review all received
	// 20260808T171306Z, and only separate output roots kept them apart. Against
	// one root they would have contended for one database, one set of exports
	// and one scratch tree, which is precisely what a run-scoped directory
	// exists to prevent.
	//
	// The stamp is kept, because it is what an examiner sorts and cites, and a
	// collision is settled by counting rather than by widening the clock: a
	// second run in the same second is -2, and it says on its face that it is
	// the second. Sub-second precision would make the ids unique and would not
	// make them exclusive — two processes can still format the same string —
	// and the claim being made here is exclusivity, so it has to come from the
	// filesystem.
	stamp := time.Now().UTC().Format("20060102T150405Z")

	for attempt := 1; ; attempt++ {
		runID := stamp
		if attempt > 1 {
			runID = fmt.Sprintf("%s-%d", stamp, attempt)
		}

		workspace := &Workspace{
			OutputRoot: outputRoot,
			RunID:      runID,
			Dir:        filepath.Join(outputRoot, runID),
		}

		// A separate working root is still scoped by run id. Two runs sharing a
		// scratch directory would have one delete the other's recovered hives.
		workspace.WorkingRoot = workspace.Dir
		if workingRoot != "" {
			workspace.WorkingRoot = filepath.Join(workingRoot, runID)
		}
		workspace.tempDir = filepath.Join(workspace.WorkingRoot, "working")

		taken, err := claim(workspace.Dir)
		if err != nil {
			return nil, err
		}
		if taken {
			if attempt >= maxRunAttempts {
				return nil, fmt.Errorf(
					"no free run directory under %s after %d attempts at %s",
					outputRoot, maxRunAttempts, stamp)
			}
			continue
		}

		if workspace.WorkingRoot != workspace.Dir {
			taken, err := claim(workspace.WorkingRoot)
			if err != nil {
				return nil, err
			}
			if taken {
				// The output directory was claimed and is still empty, so give
				// the id back whole rather than leaving a run directory behind
				// that no run will ever write into.
				os.Remove(workspace.Dir)
				if attempt >= maxRunAttempts {
					return nil, fmt.Errorf(
						"no free run directory under %s after %d attempts at %s",
						workingRoot, maxRunAttempts, stamp)
				}
				continue
			}
		}

		// Both, and not only the scratch directory. Where scratch is on a
		// separate root it does not sit under the output, so creating it alone
		// left the output directory to be made later by whoever happened to
		// write first — and a run that failed early produced no directory at
		// all to explain itself in.
		if err := os.MkdirAll(workspace.tempDir, 0o755); err != nil {
			return nil, fmt.Errorf(
				"create working area %s: %w", workspace.tempDir, err)
		}

		return workspace, nil
	}
}

// claim creates a directory and reports whether somebody else already had it.
//
// os.Mkdir is the whole of the exclusion: it is one filesystem operation that
// either creates the directory or says it exists, so two processes racing for
// one id cannot both believe they won. Checking with os.Stat first and creating
// afterwards would reintroduce the gap.
func claim(dir string) (taken bool, err error) {
	switch err := os.Mkdir(dir, 0o755); {
	case err == nil:
		return false, nil
	case errors.Is(err, fs.ErrExist):
		return true, nil
	default:
		return false, fmt.Errorf("create run directory %s: %w", dir, err)
	}
}

// RedirectProcessTempDir points os.TempDir() at this workspace.
//
// This is not housekeeping: regparser.RecoverHive writes its recovered hive
// copy to os.TempDir(), and a run's staged evidence must sit in one controlled,
// caller-known location rather than scattered through the system temp folder.
//
// It mutates process-global environment, so only a program entry point should
// call it — never a library path, where it would surprise an unrelated caller.
// The returned function restores the previous values.
func (w *Workspace) RedirectProcessTempDir() (restore func(), err error) {
	keys := []string{"TMP", "TEMP", "TMPDIR"}
	previous := make(map[string]string, len(keys))

	for _, key := range keys {
		previous[key] = os.Getenv(key)
		if err := os.Setenv(key, w.tempDir); err != nil {
			return func() {}, fmt.Errorf(
				"redirect %s into the working area: %w", key, err)
		}
	}

	return func() {
		for key, value := range previous {
			if value == "" {
				os.Unsetenv(key)
				continue
			}
			os.Setenv(key, value)
		}
	}, nil
}

// TempDir is where recovered hives and staged copies land.
func (w *Workspace) TempDir() string { return w.tempDir }

// OutputDir returns the directory a run writes its results to, creating it.
//
// It is the run directory itself. There is no output/ beneath it: once the
// caller names an output root, a folder called output inside the folder they
// chose is a level of nesting that says nothing.
func (w *Workspace) OutputDir() (string, error) {
	if err := os.MkdirAll(w.Dir, 0o755); err != nil {
		return "", fmt.Errorf("create output directory %s: %w", w.Dir, err)
	}
	return w.Dir, nil
}

// Stage copies a source file into the working area and returns the copy's path.
//
// Staging is only needed where a file must be opened by something that may
// write to it, or where the evidence source is not stable for the life of the
// run. Read-only parsing of a mounted image does not require it.
func (w *Workspace) Stage(sourcePath, artefactKind string) (string, error) {
	stagedDir := filepath.Join(w.tempDir, "staged", artefactKind)
	if err := os.MkdirAll(stagedDir, 0o755); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}

	stagedPath := filepath.Join(stagedDir, filepath.Base(sourcePath))
	if err := copyFile(sourcePath, stagedPath); err != nil {
		return "", fmt.Errorf("stage %s: %w", sourcePath, err)
	}
	return stagedPath, nil
}

// ScratchFiles counts the files the working area holds.
//
// Directories alone do not count: staging creates a folder per artefact kind
// before it knows whether it will put anything in it, and an empty tree is a
// run that read everything in place.
func (w *Workspace) ScratchFiles() (int, error) {
	held := 0
	err := filepath.WalkDir(w.tempDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			held++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("inspect working area %s: %w", w.tempDir, err)
	}
	return held, nil
}

// DiscardScratch removes the working area.
//
// Usually there is nothing in it. A hive recovered by replaying transaction
// logs is written here — os.TempDir() is redirected so it cannot land anywhere
// else — but registry.LoadHive returns a cleanup that removes each one as soon
// as the hive is read, so on a run that completes the tree is empty. What
// survives is what a run that ended early left behind.
//
// Removing it is safe either way, which was not obvious until the question was
// asked. A recovered hive is a derived intermediate rather than evidence: no
// source record points at it, and the inputs it was rebuilt from — the hive and
// each of its transaction logs — are hashed in the ledger, so what was read
// stays reproducible once this is gone. Keeping it is a debugging convenience,
// which is what -keep-working is for.
//
// Where the caller put scratch on a separate root, the run-scoped directory
// around it goes too, rather than leaving an empty shell per run on a disk
// nobody is looking at.
func (w *Workspace) DiscardScratch() error {
	target := w.tempDir
	if w.WorkingRoot != w.Dir {
		target = w.WorkingRoot
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("remove working area %s: %w", target, err)
	}
	return nil
}

func copyFile(sourcePath, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(destinationPath)
	if err != nil {
		return err
	}
	defer destination.Close()

	if _, err := io.Copy(destination, source); err != nil {
		return err
	}
	return destination.Sync()
}
