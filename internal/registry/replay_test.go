package registry

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Bloggzy/boobook/internal/evidence"
)

// hiveWithNoDirtyPages writes a hive regparser will copy and find nothing to
// apply to. It is the shape that matters here: recovery succeeds, and succeeds
// having done nothing.
func hiveWithNoDirtyPages(t *testing.T, dir string) string {
	t.Helper()

	hive := make([]byte, 0x2000)
	copy(hive, "regf")
	binary.LittleEndian.PutUint32(hive[4:], 1)  // primary sequence
	binary.LittleEndian.PutUint32(hive[8:], 1)  // secondary sequence
	binary.LittleEndian.PutUint32(hive[36:], 0) // root cell
	binary.LittleEndian.PutUint32(hive[40:], 0x1000)

	path := filepath.Join(dir, "SYSTEM")
	if err := os.WriteFile(path, hive, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A recovery that ran and changed nothing is not a replay.
//
// regparser.RecoverHive copies the hive to a temporary file, applies whatever
// dirty pages it finds, and returns that file — successfully, when there were
// no logs at all, when every log was empty, when every log was a format version
// it does not support, and when every log's sequence was already behind the
// hive. Boobook read that success as "transaction logs were applied" and then
// listed every log found beside the hive in replay_logs, which reads as an
// assertion that those logs are behind the values in the report.
//
// The claim rests on the hive rather than on the library's return value:
// recovery copies first and writes pages second, so a recovered copy identical
// to the hive as stored is a replay that did nothing.
func TestARecoveryThatChangedNothingIsNotAReplay(t *testing.T) {
	dir := t.TempDir()
	path := hiveWithNoDirtyPages(t, dir)

	_, cleanup, replay, err := LoadHive(evidence.Artefact{Path: path})
	if err != nil {
		t.Fatalf("loading the hive: %v", err)
	}
	defer cleanup()

	if replay.Applied() {
		t.Error("a hive no log touched was reported as replayed, so every " +
			"value read from it carries a claim the evidence does not support")
	}
	if logs := replay.AppliedLogs(); len(logs) != 0 {
		t.Errorf("AppliedLogs = %v, want none: naming a log that supplied no "+
			"page asserts it is behind the values in the report", logs)
	}
	if !strings.Contains(replay.Describe(), "no transaction log was found") {
		t.Errorf("Describe = %q, which does not say why nothing was applied",
			replay.Describe())
	}
}

// A log that is present and contributed nothing is named as such, not as one
// that applied and not by its absence.
//
// Three states used to be indistinguishable: a log that was applied, a log that
// could not be, and a log that was never there. The first was asserted for all
// three. An empty .LOG1 is the ordinary case — Windows leaves one behind after
// a clean shutdown — so this is not an exotic collection.
func TestALogThatContributedNothingIsNamedRatherThanCredited(t *testing.T) {
	dir := t.TempDir()
	path := hiveWithNoDirtyPages(t, dir)

	empty := filepath.Join(dir, "SYSTEM.LOG1")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "SYSTEM.LOG2")

	_, cleanup, replay, err := LoadHive(evidence.Artefact{
		Path: path, LogPaths: []string{empty, missing}})
	if err != nil {
		t.Fatalf("loading the hive: %v", err)
	}
	defer cleanup()

	if replay.Applied() {
		t.Error("an empty log and a missing one were read as a replay")
	}
	if len(replay.Logs) != 2 {
		t.Fatalf("got %d log records, want 2: a log the run could not open "+
			"used to be skipped in silence, which made it indistinguishable "+
			"from one that was never there", len(replay.Logs))
	}

	states := map[string]string{}
	for _, log := range replay.Logs {
		states[filepath.Base(log.Path)] = log.State
		if log.Detail == "" {
			t.Errorf("%s: no reason recorded, so the state cannot be checked "+
				"against the artefact", log.Path)
		}
	}
	if states["SYSTEM.LOG1"] != LogEmpty {
		t.Errorf("the empty log is %q, want %q", states["SYSTEM.LOG1"], LogEmpty)
	}
	if states["SYSTEM.LOG2"] != LogUnreadable {
		t.Errorf("the missing log is %q, want %q",
			states["SYSTEM.LOG2"], LogUnreadable)
	}
	if !strings.Contains(replay.Describe(), "changed nothing") {
		t.Errorf("Describe = %q, which does not say that recovery ran and did "+
			"nothing — the case a boolean cannot express", replay.Describe())
	}

	// regparser announces the empty log with fmt.Printf, straight to the
	// process standard output, which the redirect behind -quiet does not cover
	// because it is not the standard logger. A run asked to be silent printed
	// it into whatever was consuming its output. It belongs in the case, not on
	// the terminal.
	if !strings.Contains(replay.Note, "SYSTEM.LOG1") {
		t.Errorf("the recovery's own output was not captured (%q), so either "+
			"it escaped to stdout under -quiet or it was thrown away",
			replay.Note)
	}
	if !strings.Contains(replay.Account(), "the recovery reported:") {
		t.Errorf("Account = %q, which does not carry what the recovery said",
			replay.Account())
	}
}

// filesDiffer decides whether a page was applied, so it has to be right about
// equality rather than approximately right. A hive is tens of megabytes and it
// reads in chunks, so the interesting cases are a difference in the last chunk
// and a difference in length alone.
func TestFilesDifferComparesEveryByte(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	body := make([]byte, 3<<20)
	for i := range body {
		body[i] = byte(i)
	}
	same := append([]byte(nil), body...)
	tail := append([]byte(nil), body...)
	tail[len(tail)-1] ^= 0xFF
	shorter := body[:len(body)-1]

	cases := []struct {
		name       string
		left, righ []byte
		differ     bool
	}{
		{"identical", body, same, false},
		{"last byte", body, tail, true},
		{"one byte shorter", body, shorter, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := filesDiffer(write("a-"+c.name, c.left),
				write("b-"+c.name, c.righ))
			if err != nil {
				t.Fatal(err)
			}
			if got != c.differ {
				t.Errorf("filesDiffer = %t, want %t", got, c.differ)
			}
		})
	}
}
