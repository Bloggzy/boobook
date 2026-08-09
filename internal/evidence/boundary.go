package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Boundary enforces that nothing outside the evidence root is ever read.
//
// This is not theoretical. A collection can contain a directory junction, and
// following one would pull an unrelated file into the run and report it as
// evidence from this host.
type Boundary struct {
	// root is the evidence root with symlinks resolved.
	root string
	// declared is the root as the caller gave it, for messages.
	declared string
}

// NewBoundary resolves an evidence root and returns a boundary over it.
func NewBoundary(root string) (*Boundary, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve evidence root %s: %w", root, err)
	}

	resolved, err := resolvePath(absolute)
	if err != nil {
		// A root that cannot be resolved cannot be bounded, and reading
		// anything beneath it would be unbounded by definition.
		return nil, fmt.Errorf("evidence root %s is not readable: %w", root, err)
	}
	if _, err := os.Stat(resolved); err != nil {
		return nil, fmt.Errorf("evidence root %s is not readable: %w", root, err)
	}

	return &Boundary{root: resolved, declared: absolute}, nil
}

// Root returns the resolved evidence root.
func (b *Boundary) Root() string { return b.root }

// Contains reports whether a path resolves to somewhere inside the evidence
// root, following any junction or symlink first.
//
// A path that cannot be resolved is not inside: an unreadable target is not a
// reason to assume it was safe.
func (b *Boundary) Contains(path string) (bool, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", path, err)
	}

	resolved, err := resolvePath(absolute)
	if err != nil {
		return false, fmt.Errorf("resolve %s: %w", path, err)
	}
	// The path has to be there. Resolution alone no longer establishes it —
	// resolvePath deliberately carries components that do not exist, so that a
	// directory a run is about to create can be tested — and an unreadable or
	// dangling target is not a reason to assume it was safe.
	if _, err := os.Lstat(resolved); err != nil {
		return false, fmt.Errorf("resolve %s: %w", path, err)
	}

	return within(b.root, resolved), nil
}

// Check returns an error naming the escape if the path leaves the root.
func (b *Boundary) Check(path string) error {
	inside, err := b.Contains(path)
	if err != nil {
		return err
	}
	if !inside {
		resolved, _ := filepath.EvalSymlinks(path)
		return fmt.Errorf(
			"path escapes the evidence root: %s resolves to %s, outside %s",
			path, resolved, b.root)
	}
	return nil
}

// RefuseWrite returns an error if a directory the run intends to write into
// sits at or beneath the evidence root.
//
// The first standing rule is that the source is never modified, and read-only
// opens are not the whole of it. Nothing stopped an examiner passing the same
// path to -evidence and -output: the run created its output directory inside
// the collection and wrote case.duckdb, thirty-odd exports, the report and the
// manifest into the evidence tree. It exited zero. Reported by a review that
// simply tried it.
//
// The check must happen before the first MkdirAll, so the path it is given does
// not exist yet — which is why it cannot go through Contains. flag names the
// command-line flag in the error, because "refused" without naming which of two
// roots is the offender leaves the examiner to guess.
func (b *Boundary) RefuseWrite(flag, path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s %s cannot be resolved: %w", flag, path, err)
	}
	resolved, err := resolvePath(absolute)
	if err != nil {
		return fmt.Errorf("%s %s cannot be resolved: %w", flag, path, err)
	}
	if !within(b.root, resolved) {
		return nil
	}
	// The commonest way to hit this is passing one path to both flags, and
	// there the general form prints the same directory three times. Say the
	// short thing when it is the whole of the truth.
	if resolved == b.root {
		return fmt.Errorf(
			"%s %s is the evidence root. Nothing a run produces may be written "+
				"into the evidence — name a directory outside the collection",
			flag, path)
	}
	return fmt.Errorf(
		"%s %s is inside the evidence root: it resolves to %s, beneath %s. "+
			"Nothing a run produces may be written into the evidence — name a "+
			"directory outside the collection",
		flag, path, resolved, b.root)
}

// resolvePath expands every reparse point in an absolute path, including
// components that do not exist yet.
//
// This replaced filepath.EvalSymlinks and it is not a refactor.
// **EvalSymlinks does not resolve a Windows directory junction**: given the
// junction itself it returns the path unchanged, and given a path through one
// it fails outright. Measured on go1.26.5, which is the toolchain this builds
// with. Junctions are the reparse point that actually turns up in a collection
// — mklink /J needs no elevation where a symlink does — so the boundary was
// resolving the one construct it was written against by not resolving it.
//
// What saved it was luck of a useful kind. A file *through* a junction failed
// to resolve at all, Contains turned that into an error, and Check refuses on
// an error — so the tool fail-closed on the contents and the junction tests
// passed. But the junction *directory* resolved to itself and was therefore
// admitted, which is why collectUserHives had to comment that a refused Users
// junction names one file at a time instead of naming the directory: the
// directory check it added could never fire. And RefuseWrite would have
// accepted an output root that was a junction into the evidence, which is the
// hole the whole check exists to close.
//
// os.Readlink does read a junction's target, so the walk is done a component at
// a time. A component that is not a reparse point, or is not there, is carried
// as written — which is what lets a directory the run is about to create be
// tested before it exists.
func resolvePath(absolute string) (string, error) {
	return resolveWalk(filepath.Clean(absolute), 0)
}

// maxReparseDepth bounds the expansion. A junction may point at a path that
// crosses another junction, and two pointing at each other would otherwise
// loop for ever on a file the examiner has no reason to distrust.
const maxReparseDepth = 32

func resolveWalk(absolute string, depth int) (string, error) {
	if depth > maxReparseDepth {
		return "", fmt.Errorf(
			"%s passes through more than %d reparse points, which is a loop",
			absolute, maxReparseDepth)
	}

	separator := string(filepath.Separator)
	volume := filepath.VolumeName(absolute)
	rest := strings.TrimPrefix(absolute[len(volume):], separator)

	resolved := volume + separator
	for _, part := range strings.Split(rest, separator) {
		if part == "" {
			continue
		}
		candidate := filepath.Join(resolved, part)

		target, err := os.Readlink(candidate)
		if err != nil {
			// Not a reparse point, or not there. Either way it stands as it is.
			resolved = candidate
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(resolved, target)
		}
		// The target is resolved in full rather than spliced in, because it can
		// itself sit behind another junction.
		expanded, err := resolveWalk(filepath.Clean(target), depth+1)
		if err != nil {
			return "", err
		}
		resolved = expanded
	}
	return resolved, nil
}

// within reports whether child sits at or beneath parent, comparing whole path
// components. A prefix comparison alone would treat "C:\Eviden" as containing
// "C:\Evidence2".
func within(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	if relative == "." {
		return true
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(relative)
}
