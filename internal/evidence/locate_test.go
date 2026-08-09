package evidence

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDecodeChannelHandlesBothEscapings(t *testing.T) {
	cases := map[string]string{
		"Microsoft-Windows-Kernel-PnP%4Configuration.evtx":   "Microsoft-Windows-Kernel-PnP/Configuration",
		"Microsoft-Windows-Kernel-PnP%254Configuration.evtx": "Microsoft-Windows-Kernel-PnP/Configuration",
		"Microsoft-Windows-Partition%254Diagnostic.evtx":     "Microsoft-Windows-Partition/Diagnostic",
		"System.evtx":   "System",
		"Security.evtx": "Security",
	}
	for filename, want := range cases {
		if got := DecodeChannel(filename); got != want {
			t.Errorf("DecodeChannel(%q) = %q, want %q", filename, got, want)
		}
	}
}

func TestDecodeDriveLetter(t *testing.T) {
	cases := map[string]string{
		"C%3A":           "C",
		"C":              "C",
		"c%3a":           "C",
		"%5C%5C.%5CC%3A": "C",
		"D%3A":           "D",
		"uploads":        "",
		"NotAVolumeName": "",
		"%5C%5C.%5CE%3A": "E",
	}
	for name, want := range cases {
		if got := decodeDriveLetter(name); got != want {
			t.Errorf("decodeDriveLetter(%q) = %q, want %q", name, got, want)
		}
	}
}

// buildVolume creates the minimum tree Locate recognises as a Windows volume.
func buildVolume(t *testing.T, volumeRoot string) {
	t.Helper()

	dirs := []string{
		filepath.Join(volumeRoot, "Windows", "System32", "config"),
		filepath.Join(volumeRoot, "Windows", "System32", "winevt", "Logs"),
		filepath.Join(volumeRoot, "Windows", "INF"),
		filepath.Join(volumeRoot, "Users", "Analyst", "AppData", "Local", "Microsoft", "Windows"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string]string{
		filepath.Join(volumeRoot, "Windows", "System32", "config", "SYSTEM"):                                      "regf",
		filepath.Join(volumeRoot, "Windows", "System32", "config", "SYSTEM.LOG1"):                                 "log1",
		filepath.Join(volumeRoot, "Windows", "System32", "config", "SOFTWARE"):                                    "regf",
		filepath.Join(volumeRoot, "Windows", "INF", "setupapi.dev.log"):                                           "setupapi",
		filepath.Join(volumeRoot, "Users", "Analyst", "NTUSER.DAT"):                                               "regf",
		filepath.Join(volumeRoot, "Users", "Analyst", "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"): "regf",
		filepath.Join(volumeRoot, "Windows", "System32", "winevt", "Logs", "System.evtx"):                         "evtx",
		filepath.Join(volumeRoot, "Windows", "System32", "winevt", "Logs",
			"Microsoft-Windows-Kernel-PnP%254Configuration.evtx"): "evtx",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocatePlainVolume(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, root)

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}

	if len(set.Volumes) != 1 {
		t.Fatalf("found %d volumes, want 1", len(set.Volumes))
	}
	if set.Volumes[0].Layout != LayoutPlain {
		t.Errorf("Layout = %q, want %q", set.Volumes[0].Layout, LayoutPlain)
	}

	wantKinds := map[string]int{
		"SYSTEM": 1, "SOFTWARE": 1, "NTUSER": 1,
		"USRCLASS": 1, "SETUPAPI": 1, "EVTX": 2,
	}
	for kind, want := range wantKinds {
		if got := len(set.ByKind(kind)); got != want {
			t.Errorf("%s: found %d, want %d", kind, got, want)
		}
	}

	// The hive must carry its transaction logs, or replay cannot happen.
	system := set.ByKind("SYSTEM")[0]
	if len(system.LogPaths) != 1 {
		t.Errorf("SYSTEM has %d transaction logs, want 1", len(system.LogPaths))
	}

	if profile := set.ByKind("NTUSER")[0].Profile; profile != "Analyst" {
		t.Errorf("Profile = %q, want %q", profile, "Analyst")
	}
}

func TestLocateVelociraptorLayout(t *testing.T) {
	root := t.TempDir()
	volumeRoot := filepath.Join(root, "uploads", "auto", "C%3A")
	buildVolume(t, volumeRoot)

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}

	if len(set.Volumes) != 1 {
		t.Fatalf("found %d volumes, want 1", len(set.Volumes))
	}
	if set.Volumes[0].Layout != LayoutVelociraptor {
		t.Errorf("Layout = %q, want %q", set.Volumes[0].Layout, LayoutVelociraptor)
	}
	if set.Volumes[0].DriveLetter != "C" {
		t.Errorf("DriveLetter = %q, want %q", set.Volumes[0].DriveLetter, "C")
	}
	if len(set.ByKind("SYSTEM")) != 1 {
		t.Error("SYSTEM hive was not found in a Velociraptor layout")
	}
}

func TestLocateKAPELayout(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, filepath.Join(root, "C"))

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(set.Volumes) != 1 || set.Volumes[0].Layout != LayoutKAPE {
		t.Fatalf("expected one KAPE volume, got %+v", set.Volumes)
	}
	if set.Volumes[0].DriveLetter != "C" {
		t.Errorf("DriveLetter = %q, want %q", set.Volumes[0].DriveLetter, "C")
	}
}

// An absence is a finding about the collection, not an error that stops a run.
func TestLocateReportsMissingArtefacts(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, root)

	if err := os.Remove(filepath.Join(root, "Windows", "INF", "setupapi.dev.log")); err != nil {
		t.Fatal(err)
	}

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("a missing artefact must not fail the run: %v", err)
	}

	var found bool
	for _, missing := range set.Missing {
		if strings.HasPrefix(missing, "SETUPAPI") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing setupapi.dev.log was not reported, got %v", set.Missing)
	}
}

func TestLocateRejectsRootWithNoWindowsVolume(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Documents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Locate(root); err == nil {
		t.Error("expected an error when no Windows volume is present")
	}
}

func TestBoundaryContainsAndRejects(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}

	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}

	if err := boundary.Check(inside); err != nil {
		t.Errorf("a path inside the root was rejected: %v", err)
	}

	outside := t.TempDir()
	if err := boundary.Check(outside); err == nil {
		t.Error("a path outside the root was accepted")
	}
}

// A prefix comparison would treat a sibling directory sharing a name prefix as
// being inside the root.
func TestBoundaryComparesWholeComponents(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "Evidence")
	sibling := filepath.Join(parent, "Evidence2")
	for _, dir := range []string{root, sibling} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.Check(sibling); err == nil {
		t.Error("Evidence2 must not be treated as inside Evidence")
	}
}

// Nothing a run produces may be written into the evidence.
//
// The first standing rule, and read-only opens are not the whole of it: an
// examiner passing one path to -evidence and -output got a run that created its
// output directory inside the collection, wrote the case database, every export
// and the report into it, and exited zero. The check has to work on a directory
// that does not exist yet, because it must happen before the first MkdirAll.
func TestNothingARunProducesMayBeWrittenIntoTheEvidence(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "Evidence")
	if err := os.MkdirAll(filepath.Join(root, "Cases"), 0o755); err != nil {
		t.Fatal(err)
	}

	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}

	refused := map[string]string{
		"the evidence root itself":    root,
		"an existing directory in it": filepath.Join(root, "Cases"),
		"a directory not yet created": filepath.Join(root, "output", "run"),
		// Windows compares case-insensitively and accepts either separator, and
		// a check that did not would be trivial to walk around by accident.
		"a differently cased path": filepath.Join(parent, "evidence", "out"),
		"a forward-slash path":     root + "/out",
	}
	for name, path := range refused {
		if err := boundary.RefuseWrite("-output", path); err == nil {
			t.Errorf("%s (%s) was accepted as an output root", name, path)
		}
	}

	// And the other direction stays allowed. Evidence sitting inside the output
	// root is an ordinary arrangement — the run directory is a sibling of the
	// collection, not inside it — and refusing it would be a false positive
	// that stops people using the tool as they reasonably do.
	if err := boundary.RefuseWrite("-output", parent); err != nil {
		t.Errorf("an output root containing the evidence was refused: %v", err)
	}
	if err := boundary.RefuseWrite("-output", filepath.Join(parent, "Evidence2")); err != nil {
		t.Errorf("a sibling sharing a name prefix was refused: %v", err)
	}
}

// The junction case for the write check, which is the one a path comparison
// alone cannot see: an output directory anywhere on the machine that resolves
// back into the collection.
func TestAnOutputRootThatResolvesIntoTheEvidenceIsRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("directory junctions are a Windows construct")
	}

	parent := t.TempDir()
	root := filepath.Join(parent, "Evidence")
	if err := os.MkdirAll(filepath.Join(root, "Inner"), 0o755); err != nil {
		t.Fatal(err)
	}

	junction := filepath.Join(parent, "Output")
	cmd := exec.Command("cmd", "/c", "mklink", "/J", junction,
		filepath.Join(root, "Inner"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not create a junction in this environment: %v (%s)",
			err, output)
	}

	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.RefuseWrite("-output", junction); err == nil {
		t.Error("an output root that resolves into the evidence was accepted")
	}
	// And the same through a run directory below it that does not exist yet,
	// which is the shape the tool actually passes.
	if err := boundary.RefuseWrite(
		"-working", filepath.Join(junction, "scratch")); err == nil {
		t.Error("a working root resolving into the evidence was accepted")
	}
}

// The junction case is the one that matters, and it is tested against a real
// one rather than a simulation: a collection can contain a directory junction,
// and following it would pull an unrelated file in and report it as evidence
// from this host.
func TestBoundaryRefusesRealDirectoryJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("directory junctions are a Windows construct")
	}

	root := t.TempDir()
	target := t.TempDir()

	secret := filepath.Join(target, "elsewhere.txt")
	if err := os.WriteFile(secret, []byte("not from this host"), 0o600); err != nil {
		t.Fatal(err)
	}

	junction := filepath.Join(root, "junction")
	// mklink is a cmd builtin; a junction needs no elevation, unlike a symlink.
	cmd := exec.Command("cmd", "/c", "mklink", "/J", junction, target)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not create a junction in this environment: %v (%s)",
			err, output)
	}

	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}

	throughJunction := filepath.Join(junction, "elsewhere.txt")
	if err := boundary.Check(throughJunction); err == nil {
		t.Error("a file reached through a junction out of the root was accepted")
	}
}

// A directory that could not be read is not a directory that held nothing.
//
// Every walker used to discard its errors and every boundary refusal returned
// nil, so the two produced the same silence. That is the failure mode this
// whole project is written against, arriving through the one door nothing else
// guarded: a Prefetch directory the run could not follow looked exactly like
// one holding no prefetch files, and the report's silence then reads as
// nothing having been executed from a removable device when it means nobody
// looked.
//
// A junction is what makes this checkable without depending on permissions:
// os.ReadDir follows one, so the files are enumerated, and the boundary then
// refuses each of them for resolving outside the evidence root. That is a real
// refusal on a real path rather than a simulated error, and it is a realistic
// collection: a reparse point captured in place of the directory it pointed at.
func TestAPlaceThatCouldNotBeLookedAtIsNotReportedAsEmpty(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("directory junctions are a Windows construct")
	}

	root := t.TempDir()
	buildVolume(t, root)

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "ELSEWHERE.EXE-11111111.pf"),
		[]byte("not from this host"), 0o600); err != nil {
		t.Fatal(err)
	}

	junction := filepath.Join(root, "Windows", "Prefetch")
	cmd := exec.Command("cmd", "/c", "mklink", "/J", junction, outside)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not create a junction in this environment: %v (%s)",
			err, output)
	}

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}

	// The refusal itself is the standing rule and is not what is being tested.
	for _, artefact := range set.Artefacts {
		if strings.Contains(artefact.Path, "ELSEWHERE") {
			t.Fatal("a prefetch file reached through a junction out of the " +
				"evidence root was collected")
		}
	}

	// The failure names the directory, not the files inside it.
	//
	// It used to name the files: the junction resolved to itself, so the
	// directory was admitted, os.ReadDir followed it and each prefetch file was
	// refused in turn. That produced one failure per file and none naming the
	// cause. Now the directory is refused, which is what collectPrefetch's own
	// comment always said it was doing.
	var reported bool
	for _, failure := range set.Failures {
		if failure.Path != junction {
			continue
		}
		reported = true
		if failure.Why != FailureBoundaryRefused {
			t.Errorf("Why = %q, want %q", failure.Why, FailureBoundaryRefused)
		}
		if failure.Kind != "PREFETCH" {
			t.Errorf("Kind = %q, want PREFETCH: without it a reader cannot "+
				"tell what class of evidence the run is missing", failure.Kind)
		}
	}
	if !reported {
		t.Error("the refusal was not recorded, so the report would be silent " +
			"about a place it could not look, which is indistinguishable from " +
			"a place that held nothing")
	}
}

// An unreadable directory that is genuinely absent must not be reported as
// unlooked-at. "Not there" is a fact about the host and belongs in Missing;
// inventing a failure for it would fill the limitations with noise on every
// ordinary collection and make the real cases harder to see.
func TestAnAbsentDirectoryIsMissingRatherThanUnreadable(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, root)

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}

	// buildVolume writes no Prefetch directory, so it is absent.
	var missing bool
	for _, entry := range set.Missing {
		if strings.HasPrefix(entry, "PREFETCH") {
			missing = true
		}
	}
	if !missing {
		t.Fatal("an absent Prefetch directory was not recorded as missing")
	}
	for _, failure := range set.Failures {
		t.Errorf("an ordinary collection recorded a discovery failure: %+v",
			failure)
	}
}

// The same claim for the two directories a review found still silent: Users,
// which every per-user artefact hangs off, and Windows\INF, which holds the
// setupapi log.
//
// Both were checked with `boundary.Check(path) == nil` inline and dropped in
// silence when it failed, so a collection whose Users directory was captured as
// a junction pointing elsewhere produced a run with no NTUSER, no UsrClass, no
// shortcuts, no jump lists — and a manifest naming neither a missing artefact
// nor a failure. The whole of a host's file activity, absent behind a clean
// exit code.
func TestAJunctionedUsersOrINFDirectoryIsReportedRatherThanSkipped(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("directory junctions are a Windows construct")
	}

	for _, directory := range []struct {
		name     string
		path     []string
		kind     string
		populate func(t *testing.T, outside string)
	}{
		{
			name: "Users", path: []string{"Users"}, kind: "NTUSER",
			populate: func(t *testing.T, outside string) {
				profile := filepath.Join(outside, "Analyst")
				if err := os.MkdirAll(profile, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(profile, "NTUSER.DAT"),
					[]byte("regf"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "INF", path: []string{"Windows", "INF"}, kind: "SETUPAPI",
			populate: func(t *testing.T, outside string) {
				if err := os.WriteFile(
					filepath.Join(outside, "setupapi.dev.log"),
					[]byte(">>>  [Device Install]"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		// These two were enumerated before their root was admitted, so the
		// files below were refused one at a time and an empty junction produced
		// neither an artefact nor a failure. A run over such a collection said
		// nothing about event logs or prefetch, which reads as a host that
		// logged nothing and ran nothing.
		{
			name: "Logs",
			path: []string{"Windows", "System32", "winevt", "Logs"},
			kind: "EVTX",
			populate: func(t *testing.T, outside string) {
				if err := os.WriteFile(filepath.Join(outside, "System.evtx"),
					[]byte("evtx"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "Prefetch", path: []string{"Windows", "Prefetch"},
			kind: "PREFETCH",
			populate: func(t *testing.T, outside string) {
				if err := os.WriteFile(filepath.Join(outside, "CMD.EXE-1234.pf"),
					[]byte("MAM"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(directory.name, func(t *testing.T) {
			root := t.TempDir()
			buildVolume(t, root)

			outside := t.TempDir()
			directory.populate(t, outside)

			target := filepath.Join(append([]string{root}, directory.path...)...)
			if err := os.RemoveAll(target); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("cmd", "/c", "mklink", "/J", target, outside)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("could not create a junction in this environment: "+
					"%v (%s)", err, output)
			}

			set, err := Locate(root)
			if err != nil {
				t.Fatalf("Locate: %v", err)
			}

			for _, artefact := range set.Artefacts {
				if strings.HasPrefix(artefact.Path, outside) {
					t.Fatalf("%s was collected from outside the evidence root",
						artefact.Path)
				}
			}

			var reported bool
			for _, failure := range set.Failures {
				if failure.Why == FailureBoundaryRefused &&
					failure.Kind == directory.kind {
					reported = true
				}
			}
			if !reported {
				t.Errorf("a %s directory resolving outside the evidence root "+
					"was skipped with no failure recorded. The run then "+
					"reports no %s artefacts, which reads as the host having "+
					"none", directory.name, directory.kind)
			}
		})
	}
}

// An empty directory pointing out of the evidence is a failure, not a silence.
//
// This is the case the per-file refusal cannot reach, and it is the one a
// review reproduced: where the junction's target holds nothing, there are no
// files to refuse, so a run over it recorded no artefact and no failure at all.
// The report then says nothing about event logs or prefetch, and nothing about
// why — which reads as a host that logged nothing and ran nothing.
//
// The directory is admitted before it is enumerated, so the refusal names the
// cause whether or not anything was inside.
func TestAnEmptyDirectoryOutsideTheEvidenceIsAFailureNotASilence(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("directory junctions are a Windows construct")
	}

	for _, directory := range []struct {
		name string
		path []string
		kind string
	}{
		{"Logs", []string{"Windows", "System32", "winevt", "Logs"}, "EVTX"},
		{"Prefetch", []string{"Windows", "Prefetch"}, "PREFETCH"},
		{"Users", []string{"Users"}, "NTUSER"},
		{"INF", []string{"Windows", "INF"}, "SETUPAPI"},
	} {
		t.Run(directory.name, func(t *testing.T) {
			root := t.TempDir()
			buildVolume(t, root)

			// Empty on purpose: nothing inside to be refused one at a time.
			outside := t.TempDir()

			target := filepath.Join(append([]string{root}, directory.path...)...)
			if err := os.RemoveAll(target); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("cmd", "/c", "mklink", "/J", target, outside)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Skipf("could not create a junction in this environment: "+
					"%v (%s)", err, output)
			}

			set, err := Locate(root)
			if err != nil {
				t.Fatalf("Locate: %v", err)
			}

			for _, failure := range set.Failures {
				if failure.Why == FailureBoundaryRefused &&
					failure.Path == target {
					return
				}
			}
			t.Errorf("an empty %s directory resolving outside the evidence "+
				"root produced no failure naming it. The run reports no %s "+
				"artefacts and no reason, which is indistinguishable from a "+
				"host that had none", directory.name, directory.kind)
		})
	}
}

// A transaction log is an input to what was read, so it is bounded like one.
//
// The hive above it was admitted and its logs were not. They went straight into
// LogPaths, where the run hashes each as a source of its own and regparser
// opens it to replay pages into the recovered copy every device fact is then
// read from — so a log resolving outside the collection could change reported
// values while the manifest attested the run was bounded to the evidence.
//
// No reparse point is needed to prove it: the boundary compares resolved paths,
// so a hive directory that is simply somewhere else is the same test without
// requiring a privilege CI may not have.
func TestATransactionLogOutsideTheEvidenceIsRefusedRatherThanReplayed(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, root)

	elsewhere := t.TempDir()
	for _, name := range []string{"SYSTEM", "SYSTEM.LOG1", "SYSTEM.LOG2"} {
		if err := os.WriteFile(filepath.Join(elsewhere, name),
			[]byte("regf"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}
	set := &Set{Root: boundary.Root()}

	logs := transactionLogs(set, boundary, elsewhere, "SYSTEM")
	if len(logs) != 0 {
		t.Errorf("transaction logs outside the evidence root reached LogPaths: "+
			"%v. They are hashed as sources and replayed into the hive, so a "+
			"log from outside the collection can change what the report says",
			logs)
	}

	var refused int
	for _, failure := range set.Failures {
		if failure.Why == FailureBoundaryRefused &&
			failure.Kind == "TRANSACTION_LOG" {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("%d transaction logs were recorded as boundary refusals, "+
			"want 2. A log dropped in silence leaves a hive that says it was "+
			"read with no logs applied", refused)
	}
}

// And the same claim made over a whole run rather than one function.
//
// TestOnlyOneFunctionDecidesWhetherAPathIsInsideTheEvidence proves every call to
// Boundary.Check is inside admit. It does not prove every path reaches admit,
// which is the gap the transaction logs went through for the whole life of the
// project. This asks the other question: of everything Locate handed back, is
// any of it outside?
//
// Like the export-ordering invariants it cannot fail on a clean tree. It fails
// the moment a collector is added that resolves a path and does not admit it.
func TestEveryPathDiscoveryReturnsIsInsideTheEvidence(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, root)

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	boundary, err := NewBoundary(root)
	if err != nil {
		t.Fatal(err)
	}

	if len(set.Artefacts) == 0 {
		t.Fatal("no artefacts were located, so this proves nothing")
	}
	var logs int
	for _, artefact := range set.Artefacts {
		if err := boundary.Check(artefact.Path); err != nil {
			t.Errorf("%s artefact is outside the evidence root: %v",
				artefact.Kind, err)
		}
		for _, log := range artefact.LogPaths {
			logs++
			if err := boundary.Check(log); err != nil {
				t.Errorf("a transaction log of the %s hive is outside the "+
					"evidence root: %v", artefact.Kind, err)
			}
		}
	}
	if logs == 0 {
		t.Error("no transaction log was located, so the LogPaths half of this " +
			"proves nothing")
	}
}

// A directory that could not be read is not a collection that lacks the hive.
//
// resolveInsensitive returned a bare false for both, so a config directory the
// run could not read reported SYSTEM and SOFTWARE as missing from the
// collection — an absence, stated about evidence nobody had seen. That is the
// confusion Set.Failures exists to prevent, one level below where it was being
// watched for.
//
// A file standing where the directory should be is the unreadable case without
// needing a permission or an elevation: os.ReadDir returns a not-a-directory
// error, which is not os.IsNotExist.
func TestADirectoryThatCouldNotBeReadIsNotAMissingHive(t *testing.T) {
	root := t.TempDir()
	buildVolume(t, root)

	configDir := filepath.Join(root, "Windows", "System32", "config")
	if err := os.RemoveAll(configDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	set, err := Locate(root)
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}

	for _, missing := range set.Missing {
		if strings.HasPrefix(missing, "SYSTEM") ||
			strings.HasPrefix(missing, "SOFTWARE") {
			t.Errorf("%q reports a hive as absent from the collection when "+
				"the directory holding it could not be read", missing)
		}
	}

	var unreadable bool
	for _, failure := range set.Failures {
		if failure.Why == FailureUnreadable &&
			(failure.Kind == "SYSTEM" || failure.Kind == "SOFTWARE") {
			unreadable = true
		}
	}
	if !unreadable {
		t.Error("a config directory that could not be read was not recorded " +
			"as a failure, so the run says nothing about it at all")
	}
}

// One function decides whether a path is inside the evidence, and every other
// place asks it.
//
// This is the shape the failure kept taking: `boundary.Check(path) == nil` is
// the natural thing to write, it compiles, it fails closed on the file — and it
// records nothing, so a refusal becomes an absence. Three call sites had it and
// two of them covered the artefacts a whole host's activity depends on.
//
// Like the export-ordering and catalogue invariants, this cannot fail as
// written. It fails the moment somebody adds the fourth.
func TestOnlyOneFunctionDecidesWhetherAPathIsInsideTheEvidence(t *testing.T) {
	source, err := os.ReadFile("locate.go")
	if err != nil {
		t.Fatal(err)
	}

	var offenders []int
	for number, line := range strings.Split(string(source), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if !strings.Contains(trimmed, "boundary.Check(") {
			continue
		}
		// The one permitted caller, which records the refusal.
		if strings.HasPrefix(trimmed, "if err := boundary.Check(path); err != nil {") {
			continue
		}
		offenders = append(offenders, number+1)
	}
	if len(offenders) != 0 {
		t.Errorf("locate.go calls boundary.Check outside admit at line(s) %v. "+
			"A boundary test that is not admit refuses the path and records "+
			"nothing, so the run reports an absence where it means it could "+
			"not look", offenders)
	}
}
