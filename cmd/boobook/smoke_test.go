package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Bloggzy/boobook/internal/classify"
	"github.com/Bloggzy/boobook/internal/fixture"
	"github.com/Bloggzy/boobook/internal/provenance"
	"github.com/Bloggzy/boobook/internal/workspace"
)

// The whole run, end to end, over a tree this repository builds.
//
// Every other check on this tool is a person running it by hand against five
// collections that live outside the repository and that nobody else can run.
// That is the thinnest part of the project: a change that makes the tool fall
// over on a sparse collection would be caught by an examiner, on a case, rather
// than here.
//
// The fixture is deliberately incomplete. It has no registry hives and no event
// logs, which is what a triage collection taken with the wrong profile looks
// like, and it is the shape most likely to find a nil where a device was
// assumed. A run over it has to finish, write its outputs, and say what was
// missing.
func TestARunOverASparseCollectionCompletesAndSaysWhatWasMissing(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.Write(evidence); err != nil {
		t.Fatalf("building the evidence tree: %v", err)
	}
	output := t.TempDir()

	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		caseRef:      "SMOKE-1",
		examiner:     "CI",
		quiet:        true,
	}); err != nil {
		t.Fatalf("the run failed over %s: %v", fixture.Describe(), err)
	}

	dir := onlyRunDir(t, output)
	manifest := readManifest(t, filepath.Join(dir, "manifest.json"))

	// The manifest is the chain-of-custody document. A run that produced data
	// files and no manifest has produced a set of claims with nothing tying
	// them to the evidence.
	if manifest.Tool.Version == "" {
		t.Error("the manifest records no tool version")
	}
	if manifest.Evidence.Root == "" {
		t.Error("the manifest does not name the evidence it read")
	}
	if manifest.Counts.Sources == 0 {
		t.Error("no source was hashed, so nothing in the output can be attested")
	}

	// Every output the manifest claims must be on disk with a hash. A dead
	// citation in a forensic report is the failure this guards against.
	if len(manifest.Outputs) == 0 {
		t.Fatal("the manifest names no outputs")
	}
	for _, out := range manifest.Outputs {
		if out.SHA256 == "" {
			t.Errorf("%s was written without a hash", out.Name)
		}
		if _, err := os.Stat(out.Path); err != nil {
			t.Errorf("%s is in the manifest and not on disk: %v", out.Name, err)
		}
	}

	// The artefacts the fixture does carry have to have been read. Their
	// absence would mean the run completed by doing nothing, which is the way
	// a smoke test passes without testing anything.
	if manifest.Counts.ShellLinks == 0 {
		t.Error("the shell link was not read")
	}
	if manifest.Counts.PrefetchRuns == 0 {
		t.Error("the prefetch record was not read")
	}
	if manifest.Counts.RemovableTargets == 0 {
		t.Error("the link records a removable volume and nothing counted it")
	}

	// The join the fixture exists for. The shell link records a volume serial
	// against a letter and a label; the prefetch record names the same serial
	// and nothing else. Reaching the letter from the serial is the chain the
	// whole tool is about, and a smoke test that only asserted "it did not
	// crash" would pass with that chain broken.
	assertPrefetchReachedTheVolume(t, dir)

	// And the ones it does not carry have to be reported as absent rather than
	// as nothing. "There was no SYSTEM hive" and "no device was found" are
	// different statements, and only one of them is true here.
	if manifest.Counts.Warnings == 0 {
		t.Error("a collection with no hives and no event logs produced no " +
			"warning, so its report claims a completeness it does not have")
	}
	if len(manifest.Evidence.NotCollected) == 0 {
		t.Error("nothing was recorded as not collected")
	}
}

// The report is the document an analyst reads, so a run that writes data files
// and an unusable report has failed. The standing constraints it has to meet
// are structural and can be checked here: nothing fetched, nothing scripted,
// and every fold forced open on paper.
func TestTheReportFromASparseCollectionIsSelfContainedAndPrintsWhole(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.Write(evidence); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()

	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		quiet:        true,
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(onlyRunDir(t, output), "report.html")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no report was written: %v", err)
	}
	document := string(body)

	// A report that reaches for anything at run time is a report that behaves
	// differently on the machine it is read on, months later, with no network.
	for _, forbidden := range []string{
		"<script", "http://", "https://", "@import", "src=",
	} {
		if strings.Contains(document, forbidden) {
			t.Errorf("the report contains %q, so it is not self-contained",
				forbidden)
		}
	}

	// Printing carries everything: the folds are checkboxes and a rule rather
	// than <details>, because a closed <details> cannot be forced open by a
	// stylesheet.
	if !strings.Contains(document,
		".disclose-body { display: block !important; }") {
		t.Error("printing would omit every folded section")
	}
	if strings.Contains(document, `disclose-toggle" type="checkbox" id="disc-summary" checked`) {
		t.Error("the report opens a fold by default")
	}
}

// A second run over one evidence tree writes the same bytes. The manifest
// records a SHA-256 per output file, so an examiner who reruns a case and gets
// different hashes has to explain why — and "the rows come out in a different
// order each time" is a bad answer in a report.
//
// provenance/sources.csv is the exception and is meant to be: its read_at
// column is when this run hashed each file, which is a custody record and not a
// finding.
func TestTwoRunsOverOneTreeWriteTheSameBytes(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.Write(evidence); err != nil {
		t.Fatal(err)
	}

	first := runInto(t, evidence)
	second := runInto(t, evidence)

	names := dataFileNames(t, first)
	if len(names) == 0 {
		t.Fatal("no data files were written, so this compares nothing")
	}

	for _, name := range names {
		if name == filepath.Join("provenance", "sources.csv") {
			continue
		}
		before := readFile(t, filepath.Join(first, name))
		after := readFile(t, filepath.Join(second, name))
		if before != after {
			t.Errorf("%s differs between two runs over the same evidence", name)
		}
	}
}

func assertPrefetchReachedTheVolume(t *testing.T, dir string) {
	t.Helper()

	rows := readCSV(t, filepath.Join(dir, "data", "prefetch-runs.csv"))
	if len(rows) != 1 {
		t.Fatalf("got %d prefetch runs, want the one the fixture wrote", len(rows))
	}
	row := rows[0]

	if row["ran_from_serial"] != fixture.VolumeSerialHex {
		t.Errorf("prefetch names serial %q, want %q",
			row["ran_from_serial"], fixture.VolumeSerialHex)
	}
	// Reached through the shell link, which is the only artefact in this tree
	// that ties a serial to a letter.
	if row["removable_letter"] != fixture.DriveLetter {
		t.Errorf("the serial reached letter %q, want %q — the link and the "+
			"prefetch record agree on the serial and the join is not being made",
			row["removable_letter"], fixture.DriveLetter)
	}
	if row["removable_label"] != fixture.VolumeLabel {
		t.Errorf("the volume label came out %q, want %q",
			row["removable_label"], fixture.VolumeLabel)
	}
	if row["ran_from_removable"] != "true" {
		t.Errorf("ran_from_removable = %q; the executable is in the volume "+
			"the record names", row["ran_from_removable"])
	}
}

func readCSV(t *testing.T, path string) []map[string]string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		return nil
	}
	header := records[0]

	var rows []map[string]string
	for _, record := range records[1:] {
		row := make(map[string]string, len(header))
		for i, name := range header {
			if i < len(record) {
				row[name] = record[i]
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func runInto(t *testing.T, evidence string) string {
	t.Helper()
	output := t.TempDir()
	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		quiet:        true,
	}); err != nil {
		t.Fatal(err)
	}
	return onlyRunDir(t, output)
}

// onlyRunDir returns the run directory, and insists there is exactly one.
// Results are run-scoped so a second run cannot overwrite a report already
// cited in a case note, and a test that picked the first of several would be
// reading whichever the filesystem happened to list first.
func onlyRunDir(t *testing.T, output string) string {
	t.Helper()
	entries, err := os.ReadDir(output)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, entry.Name())
		}
	}
	if len(dirs) != 1 {
		t.Fatalf("got %d run directories under the output root, want 1: %v",
			len(dirs), dirs)
	}
	return filepath.Join(output, dirs[0])
}

func dataFileNames(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".csv", ".jsonl":
			relative, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			names = append(names, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func readManifest(t *testing.T, path string) workspace.Manifest {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no manifest was written: %v", err)
	}
	var manifest workspace.Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("the manifest is not readable JSON: %v", err)
	}
	return manifest
}

// A run over a collection where nothing parses.
//
// Every other check on malformed input in this project is a unit test asserting
// that a function returns an error. Those cannot say whether a *run* survives
// one, reports it, and refuses to turn it into a finding — and that is what
// matters, because damaged evidence is routine: a hive from a live acquisition,
// a prefetch file from a machine that lost power, a shortcut a collector copied
// mid-write.
//
// Three claims, and the third is worth the most.
func TestARunOverACollectionWhereNothingParsesSurvivesAndSaysSo(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.WriteAdversarial(evidence); err != nil {
		t.Fatalf("building the broken tree: %v", err)
	}
	output := t.TempDir()

	// One. It must not crash. A single unreadable artefact in a collection of
	// thousands must cost that artefact, not the case — and the event log
	// reader hands chunks to several goroutines, where an unrecovered panic
	// takes the process down rather than the file.
	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		caseRef:      "SMOKE-ADVERSARIAL",
		examiner:     "CI",
		quiet:        true,
	}); err != nil {
		t.Fatalf("the run failed over %s: %v", fixture.DescribeAdversarial(), err)
	}

	dir := onlyRunDir(t, output)
	manifest := readManifest(t, filepath.Join(dir, "manifest.json"))

	// Two. It must say so. A file that could not be read and a file that held
	// nothing produce the same silence otherwise, and "absence is reported as
	// absence" is worthless if a parse failure is indistinguishable from an
	// empty artefact.
	if manifest.Counts.Warnings == 0 {
		t.Error("a collection in which no artefact parses produced no warning, " +
			"so the report claims a completeness it does not have")
	}
	for _, out := range manifest.Outputs {
		if _, err := os.Stat(out.Path); err != nil {
			t.Errorf("%s is in the manifest and not on disk: %v", out.Name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "report.html")); err != nil {
		t.Errorf("no report was written for a damaged collection: %v", err)
	}

	// And the other half of the same rule, which matters as much: what *did*
	// parse must survive.
	//
	// The setupapi log's section header is intact and names a device; only the
	// section's end is missing. Reporting that device is correct — the log
	// said it, and a file being cut short later is not a reason to discard what
	// was read before the cut. The standing rule is that a damaged record is
	// kept and labelled, never dropped, and a test that demanded silence from
	// a damaged collection would be asking the tool to break that rule.
	//
	// This assertion is here because the first version of this test got it
	// wrong: it listed the device among the things that must not appear, and
	// the tool was right and the test was wrong.
	assertPartialEvidenceSurvived(t, dir)

	// Three. None of it may become evidence.
	//
	// Every parser here has a comment somewhere saying that a structure read at
	// the wrong offset does not fail but produces plausible values. The volume
	// serial below is written into a prefetch block whose device path offset
	// points outside itself, into a link truncated before its volume ID, and
	// into a file claiming an undocumented format version. If it reaches any
	// output, something read past a structure and believed what it found — and
	// a device invented that way arrives in the report at full confidence with
	// nothing marking it as fabricated.
	assertNothingWasInventedFrom(t, dir)
}

// assertPartialEvidenceSurvived checks that the readable part of a damaged
// artefact still reached the output.
//
// Refusing everything from a file with one broken structure would be the easy
// way to pass the test below it, and it would be wrong: it would throw away
// evidence to tidy up a parse failure, which is the failure mode this whole
// project was written against.
func assertPartialEvidenceSurvived(t *testing.T, dir string) {
	t.Helper()

	// The device the intact setupapi section header names, from a section that
	// never ends.
	const named = "PHANTOM0001"

	body, err := os.ReadFile(filepath.Join(dir, "data", "devices.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), named) {
		t.Errorf("the device named by an intact setupapi section header is "+
			"absent from devices.csv. The section never ends, which is a fact "+
			"about the log rather than about the device, and discarding what "+
			"was read before the cut loses evidence to tidy away a parse "+
			"failure. Wanted %q.", named)
	}
}

// assertNothingWasInventedFrom checks that no identifier only present in the
// damaged structures reached any output file.
func assertNothingWasInventedFrom(t *testing.T, dir string) {
	t.Helper()

	// Rendered the way each output would show them. The serial appears in
	// prefetch as a formatted volume serial and in a link as a raw value, so
	// both spellings are checked.
	forbidden := map[string]string{
		"BADF-BADF": "a volume serial from a prefetch entry that declares its " +
			"device path outside its own block",
		"BADFBADF": "the same serial, unformatted",
		fixture.AdversarialLabel: "a volume label from a link truncated before " +
			"the label was written",
		`E:\phantom\`: "a path from a link that ends before its LinkInfo does",
	}

	var checked int
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		switch filepath.Ext(path) {
		case ".csv", ".jsonl", ".html", ".json":
		default:
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		relative, _ := filepath.Rel(dir, path)
		text := string(body)
		for needle, what := range forbidden {
			if strings.Contains(text, needle) {
				t.Errorf("%s contains %q — %s. Something read past a structure "+
					"and reported what it found there as evidence.",
					relative, needle, what)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no output files were examined, so this asserts nothing")
	}
}

// And the damaged collection must not be mistaken for a rich one.
//
// The complement of the test above: as well as inventing nothing, the run has
// to reach the end with the counts a collection of unreadable files earns. A
// tool that reported four devices here would be reporting its own parse
// failures.
func TestNothingIsCountedFromACollectionThatDoesNotParse(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.WriteAdversarial(evidence); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()

	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		quiet:        true,
	}); err != nil {
		t.Fatal(err)
	}

	manifest := readManifest(t, filepath.Join(onlyRunDir(t, output), "manifest.json"))

	// Devices is deliberately not asserted at zero: the setupapi section header
	// parses and legitimately names one, and demanding silence would ask the
	// tool to discard evidence it read correctly. What follows are the counts
	// that can only come from structures that did not parse at all.
	if manifest.Counts.Devnodes != 0 {
		t.Errorf("%d devnodes came out of two truncated hives",
			manifest.Counts.Devnodes)
	}
	if manifest.Counts.EventRecords != 0 {
		t.Errorf("%d event records came out of a headerless log",
			manifest.Counts.EventRecords)
	}
	// The sources are still hashed and recorded: the files exist and were read
	// from, and the custody record covers what was opened rather than what
	// parsed. A run that hashed nothing would mean discovery had not found the
	// damaged files at all, which would make the rest of this test vacuous.
	if manifest.Counts.Sources == 0 {
		t.Error("no source was hashed, so nothing was actually attempted")
	}
}

// A recorder puts the stored form in raw and its narration in summary.
//
// The two are different claims and they were sharing a column. Observation.Raw
// is documented as "the stored form, unaltered", and eight recorders put a
// joined description there — "version=30 run_count=3 times=1 volumes=2" — while
// two more put the value in Field and a registry key name in Raw. So a consumer
// of observations.jsonl had no way to know whether a row's raw held bytes,
// decoded text or a sentence, which makes the column useless for the only thing
// it exists for: checking a derived value against what the artefact holds.
//
// This runs over the well-formed fixture and reads what actually came out, so
// it fails on a recorder that regresses rather than on a grep of the source.
func TestAnObservationsRawIsTheStoredFormAndNotADescriptionOfIt(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.Write(evidence); err != nil {
		t.Fatalf("building the evidence tree: %v", err)
	}
	output := t.TempDir()

	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		caseRef:      "SMOKE-RAW",
		examiner:     "CI",
		quiet:        true,
	}); err != nil {
		t.Fatalf("the run failed over %s: %v", fixture.Describe(), err)
	}

	body, err := os.ReadFile(filepath.Join(onlyRunDir(t, output),
		"provenance", "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}

	// The shapes a description takes and a stored value does not. "key=value;
	// key=value" is what the joined details look like; a stored registry value
	// or a device path is never written that way.
	narration := regexp.MustCompile(`\w+=[^;]*;\s*\w+=`)

	var checked int
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var row struct {
			ID    string `json:"observation_id"`
			Kind  string `json:"kind"`
			Field string `json:"field"`
			Raw   string `json:"raw"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatalf("observations.jsonl is not JSON lines: %v", err)
		}
		checked++

		if narration.MatchString(row.Raw) {
			t.Errorf("%s (%s): raw is a description, not the stored form: %q",
				row.ID, row.Kind, row.Raw)
		}
		// Field names which fact within the kind. A field holding a path, a
		// drive letter or a device identity is a value in the name's place,
		// which is the inversion this test was written for.
		if strings.ContainsAny(row.Field, `\/:`) {
			t.Errorf("%s (%s): field holds a value rather than the name of a "+
				"fact: %q", row.ID, row.Kind, row.Field)
		}
	}
	if checked == 0 {
		t.Fatal("no observations were written, so this test proves nothing")
	}
}

// The manifest says Outputs names every file the run wrote with its hash, and
// case.duckdb was the one it did not: the exports and the report were appended
// as they were written, the database was left to a deferred close, and the
// manifest was finalised while it was still open. All five reference runs
// listed 34 hashed outputs beside an unhashed database.
//
// That matters because the database is not a byproduct. The exporter says in as
// many words that the whole prefetch loaded-file list exists only there, so the
// run's own evidence included a file nothing in the custody record tied to it,
// and a copy produced months later could not be shown to be this run's.
//
// The claim is made over the directory rather than over a name, because the
// defect was a file nobody had thought to look for. Anything the run leaves
// behind — a database, a write-ahead log that should not have survived the
// close, whatever is added next — is either in the manifest or is a hole in it.
func TestEveryFileTheRunLeavesBehindIsHashedIntoTheManifest(t *testing.T) {
	evidence := t.TempDir()
	if err := fixture.Write(evidence); err != nil {
		t.Fatalf("building the evidence tree: %v", err)
	}
	output := t.TempDir()

	if err := run(options{
		evidenceRoot: evidence,
		outputRoot:   output,
		profile:      classify.DefaultProfile,
		caseRef:      "SMOKE-DB",
		examiner:     "CI",
		quiet:        true,
	}); err != nil {
		t.Fatalf("the run failed over %s: %v", fixture.Describe(), err)
	}

	dir := onlyRunDir(t, output)
	manifest := readManifest(t, filepath.Join(dir, "manifest.json"))

	manifested := map[string]string{}
	for _, out := range manifest.Outputs {
		absolute, err := filepath.Abs(out.Path)
		if err != nil {
			t.Fatal(err)
		}
		manifested[absolute] = out.SHA256
	}

	var found int
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		// The manifest cannot contain its own hash, and it is the one file
		// whose absence from Outputs says nothing.
		if path == filepath.Join(dir, "manifest.json") {
			return nil
		}
		found++

		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		recorded, ok := manifested[absolute]
		if !ok {
			t.Errorf("the run wrote %s and the manifest does not name it: a "+
				"copy of it made later cannot be tied back to this run",
				filepath.Base(path))
			return nil
		}

		// And the hash has to be of the file that settled. A digest taken
		// while the database was still open attests bytes the next writer
		// changes, which is worse than no digest: it looks checkable.
		digest, err := provenance.HashFile(path)
		if err != nil {
			return err
		}
		if digest != recorded {
			t.Errorf("%s hashes to %s and the manifest records %s",
				filepath.Base(path), digest, recorded)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("the run directory holds no files at all")
	}

	// Named outright as well, because the walk would go quiet if the database
	// ever stopped being written rather than stopping being manifested.
	if _, err := os.Stat(filepath.Join(dir, "case.duckdb")); err != nil {
		t.Fatalf("the run wrote no case database: %v", err)
	}
	var database bool
	for _, out := range manifest.Outputs {
		if out.Name == "case.duckdb" {
			database = true
			if out.Bytes == 0 {
				t.Error("case.duckdb is manifested with a size of zero")
			}
		}
	}
	if !database {
		t.Error("case.duckdb is not in the manifest")
	}
}
