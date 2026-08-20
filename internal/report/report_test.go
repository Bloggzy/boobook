package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bloggzy/boobook/internal/classify"
	"github.com/Bloggzy/boobook/internal/eventlog"
	"github.com/Bloggzy/boobook/internal/prefetch"
	"github.com/Bloggzy/boobook/internal/provenance"
	"github.com/Bloggzy/boobook/internal/registry"
	"github.com/Bloggzy/boobook/internal/setupapi"
	"github.com/Bloggzy/boobook/internal/store"
	"github.com/Bloggzy/boobook/internal/workspace"
)

func caseWith(t *testing.T, devnodes []registry.Devnode) *store.Store {
	return caseLoading(t, devnodes, nil)
}

// prepared holds a case database that has been built once, as bytes, so that
// every test after the first can have one by copying rather than by creating.
//
// Creating the views is the whole cost of opening a store: three and a half
// seconds, because DuckDB checks all 84 of them and views.sql is the largest
// file in the project. Paid once per test across the 44 in this file it is
// about two and a half minutes of setup before any test does any work. Copying
// the finished file instead costs 0.19s, and the database a test gets is the
// same one, made the same way, by the same store.Open. The store package holds
// the same helper, and the duplication is deliberate: a shared one would have
// to live in a package that imports store, which store's own internal test
// cannot import back.
//
// The template is a variable rather than a file on disk kept between runs. A
// cached one would be a copy of views.sql that nothing updates, and a test
// suite silently checking last week's views is worse than a slow one.
var prepared struct {
	once  sync.Once
	bytes []byte
	err   error
}

func preparedCase() ([]byte, error) {
	prepared.once.Do(func() {
		dir, err := os.MkdirTemp("", "boobook-template")
		if err != nil {
			prepared.err = err
			return
		}
		defer os.RemoveAll(dir)

		path := filepath.Join(dir, "template.duckdb")
		db, err := store.Open(path)
		if err != nil {
			prepared.err = err
			return
		}
		// Without this the views are still in the write-ahead log and the copy
		// is a database that has none of them.
		if err := db.Checkpoint(); err != nil {
			db.Close()
			prepared.err = err
			return
		}
		if err := db.Close(); err != nil {
			prepared.err = err
			return
		}
		prepared.bytes, prepared.err = os.ReadFile(path)
	})
	return prepared.bytes, prepared.err
}

// openCase gives a test its own copy of the prepared database.
func openCase(t *testing.T) *store.Store {
	t.Helper()

	bytes, err := preparedCase()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "case.duckdb")
	if err := os.WriteFile(path, bytes, 0o644); err != nil {
		t.Fatal(err)
	}

	db, err := store.OpenExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// caseLoading builds a case and lets a test add whatever else it needs, against
// the same hashed source, before the consolidation runs.
func caseLoading(t *testing.T, devnodes []registry.Devnode,
	extra func(db *store.Store, sourceID string)) *store.Store {
	t.Helper()

	db := openCase(t)

	rules, err := classify.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.LoadRules(rules, classify.DefaultProfile); err != nil {
		t.Fatal(err)
	}

	// A real source, hashed, because the report's claim is that every value can
	// be followed to a file — and a fixture with no source would let a citation
	// to nothing pass.
	hive := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(hive, []byte("hive"), 0o644); err != nil {
		t.Fatal(err)
	}
	ledger := provenance.NewLedger()
	source, err := ledger.AddSource(hive, "SYSTEM")
	if err != nil {
		t.Fatal(err)
	}

	if err := db.LoadDevnodes(source.ID, devnodes); err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		extra(db, source.ID)
	}
	if err := db.LoadLedger(ledger); err != nil {
		t.Fatal(err)
	}
	if err := db.Consolidate(); err != nil {
		t.Fatal(err)
	}
	return db
}

func manifest() *workspace.Manifest {
	return &workspace.Manifest{
		Tool: workspace.ToolInfo{Name: "Boobook", Version: "test"},
		Run:  workspace.RunInfo{ID: "20260801T000000Z", StartedAt: time.Now().UTC()},
		Evidence: workspace.EvidenceInfo{
			Root: `C:\Evidence`, Layout: "plain_volume",
		},
		Classification: workspace.ClassificationInfo{
			RuleSetVersion: "1", Profile: "general",
		},
		// The manifest is what the report links citations against: it is the
		// record of what was written, so a link can only point at a file this
		// run produced.
		Outputs: []workspace.OutputFile{
			{Name: "data/devices.csv", Format: "csv"},
			{Name: "data/timeline.csv", Format: "csv"},
			{Name: "data/timeline-significant.csv", Format: "csv"},
			{Name: "data/file-attribution.csv", Format: "csv"},
			{Name: "data/file-attribution-summary.csv", Format: "csv"},
		},
	}
}

func render(t *testing.T, db *store.Store) string {
	t.Helper()

	gathered, err := Gather(db, manifest())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path, err := Write(gathered, directory)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "report.html" {
		t.Errorf("wrote %s, want report.html", filepath.Base(path))
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func at(text string) time.Time {
	moment, err := time.Parse(time.RFC3339, text)
	if err != nil {
		panic(err)
	}
	return moment
}

// prefetchRun builds a .pf record. ranFrom is the distinction the section under
// test turns on: a programme's own executable appears in its file list wherever
// it lives, and that is what says which volume it ran from.
func prefetchRun(executable, devicePath, serial string, ranFrom bool,
	when time.Time) *prefetch.Run {

	run := &prefetch.Run{
		SourceFile: `C:\Windows\Prefetch\` + executable + "-DEADBEEF.pf",
		Executable: executable,
		Version:    "Win10",
		RunCount:   3,
		RunTimes:   []time.Time{when},
		Volumes: []prefetch.Volume{
			{DevicePath: devicePath, SerialHex: serial},
		},
		Files: []string{devicePath + `\DOCUMENT.DOCX`},
	}
	if ranFrom {
		run.Files = append(run.Files, devicePath+`\`+executable)
	} else {
		run.ExecutablePath = `\DEVICE\HARDDISKVOLUME3\WINDOWS\` + executable
	}
	return run
}

func storageNode(deviceID, instanceID, name string) registry.Devnode {
	node := registry.Devnode{
		ControlSet: "ControlSet001", Enumerator: "USB",
		DeviceID: deviceID, InstanceID: instanceID,
		DeviceInstanceID: `USB\` + deviceID + `\` + instanceID,
		FriendlyName:     name,
		CompatibleIDs:    `USB\Class_08&SubClass_06&Prot_50|USB\Class_08`,
		Service:          "USBSTOR",
	}
	return node
}

// The report has to open with the answer. A storage device that was attached to
// the host belongs above the fold, in a sentence, with the file a reader can
// open to argue with it.
func TestTheReportLeadsWithTheAnswer(t *testing.T) {
	db := caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	})

	document := render(t, db)

	if !strings.Contains(document, "1 storage device was attached to this host") {
		t.Error("the headline finding is missing from the report")
	}
	if !strings.Contains(document, "SanDisk Ultra") {
		t.Error("the finding does not name the device")
	}
	if !strings.Contains(document, ">devices.csv</a>, category Storage") {
		t.Error("the finding does not say what it rests on")
	}

	// Answer first: the finding has to precede the coverage and the caveats,
	// or the report is Boodie's again — epistemology before answers.
	finding := strings.Index(document, "storage device was attached")
	coverage := strings.Index(document, `id="coverage"`)
	if finding < 0 || coverage < 0 || finding > coverage {
		t.Error("the coverage section comes before the finding")
	}
}

// A report that fetches anything is a report that renders as unformatted text
// on the air-gapped machine it will eventually be opened on.
func TestTheReportIsSelfContained(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	for _, forbidden := range []string{
		"http://", "https://", "//cdn", "<script", "src=", "@import",
	} {
		if strings.Contains(strings.ToLower(document), forbidden) {
			t.Errorf("the report reaches outside itself: found %q", forbidden)
		}
	}
	if !strings.Contains(document, "<style>") {
		t.Error("the stylesheet was not inlined")
	}
}

// Evidence text is evidence, not markup. A device whose friendly name carries
// a tag must not be able to close one.
func TestEvidenceTextCannotBecomeMarkup(t *testing.T) {
	db := caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537",
			`<script>alert(1)</script> stick`),
	})

	document := render(t, db)

	if strings.Contains(document, "<script>alert(1)</script>") {
		t.Fatal("a device name was rendered as markup")
	}
	if !strings.Contains(document, "&lt;script&gt;") {
		t.Error("the device name is missing from the report entirely")
	}
}

// A report should not spend the top of its page saying what it did not find.
func TestAFindingWithNothingBehindItIsAbsentRatherThanZero(t *testing.T) {
	document := render(t, caseWith(t, nil))

	for _, zero := range []string{"0 storage device", "0 device", "0 file record"} {
		if strings.Contains(document, zero) {
			t.Errorf("the report reports an absence as a count of zero: %q", zero)
		}
	}

	// What does appear is the one finding an empty case genuinely supports:
	// that no connection window could be derived. Absence of the arrival
	// records is a fact about the collection, and a silent report would let it
	// read as "nothing was ever connected".
	if !strings.Contains(document, "no connection window could be derived") {
		t.Error("the report is silent about having no connection evidence")
	}
}

// The limits are part of the report, not an appendix to it. A report that does
// not say what it could not see invites its silences to be read as absences of
// evidence.
func TestTheReportStatesWhatItDoesNotClaim(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	for _, claim := range []string{
		"What this report does not claim",
		"a letter is reused",
		"the absence of a record is the absence of an event",
	} {
		if !strings.Contains(document, claim) {
			t.Errorf("the report does not state its limits: %q is missing", claim)
		}
	}
}

// The whole point of the card is that a value can be followed to the record
// that carried it. A citation pointing at a value the card does not show is
// worse than no citation, because it looks checked.
func TestACardsValuesAgreeWithItsCitations(t *testing.T) {
	// Two identities of one device, disagreeing about the friendly name — the
	// shape the reference evidence has, where a WPDBUSENUM node stores a
	// shorter name than the USBSTOR node it shadows.
	storage := storageNode("VID_24A9&PID_205A", "24111912130128", "PATRIOT USB Device")
	storage.ContainerID = "{5b7dd1bc-b582-5b39-b1b6-1a15d74a6372}"

	shadow := registry.Devnode{
		ControlSet: "ControlSet001", Enumerator: "SWD",
		DeviceID: "WPDBUSENUM", InstanceID: "24111912130128",
		DeviceInstanceID: `SWD\WPDBUSENUM\24111912130128`,
		FriendlyName:     "PATRIOT",
		ContainerID:      "{5b7dd1bc-b582-5b39-b1b6-1a15d74a6372}",
	}

	db := caseWith(t, []registry.Devnode{storage, shadow})
	cards, err := db.Cards(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 {
		t.Fatalf("got %d cards, want 1: the container id groups these", len(cards))
	}

	card := cards[0]
	for _, field := range card.Fields {
		var shown string
		switch field.Field {
		case "friendly_name":
			shown = card.FriendlyName
		case "serial":
			shown = card.Serial
		case "manufacturer":
			shown = card.Mfg
		case "device_class":
			shown = card.Class
		default:
			continue
		}
		if field.Value != shown {
			t.Errorf("the card shows %s = %q and cites a record holding %q",
				field.Field, shown, field.Value)
		}
		if field.Locator == "" || field.SourcePath == "" {
			t.Errorf("%s is cited to nothing: locator %q, source %q",
				field.Field, field.Locator, field.SourcePath)
		}
	}

	// Where the identities disagreed, the card has to say a choice was made.
	var flagged bool
	for _, field := range card.Fields {
		if field.Field == "friendly_name" && field.Disputed() {
			flagged = true
		}
	}
	if !flagged {
		t.Error("two identities carry different friendly names and the card " +
			"does not say so")
	}
}

// A card is the physical device, not the devnode, and has to show what it
// grouped and by what route — or the grouping is an assertion.
func TestACardShowsWhatItGrouped(t *testing.T) {
	storage := storageNode("VID_24A9&PID_205A", "24111912130128", "PATRIOT")
	storage.ContainerID = "{5b7dd1bc-b582-5b39-b1b6-1a15d74a6372}"
	shadow := registry.Devnode{
		ControlSet: "ControlSet001", Enumerator: "USBSTOR",
		DeviceID: "Disk&Ven_PATRIOT", InstanceID: "24111912130128&0",
		DeviceInstanceID: `USBSTOR\Disk&Ven_PATRIOT\24111912130128&0`,
		ContainerID:      "{5b7dd1bc-b582-5b39-b1b6-1a15d74a6372}",
	}

	document := render(t, caseWith(t, []registry.Devnode{storage, shadow}))

	if !strings.Contains(document, "Identities grouped into this device (2)") {
		t.Error("the card does not say how many identities it grouped")
	}
	if !strings.Contains(document, "Grouped by: container_id") {
		t.Error("the card does not name the route that grouped them")
	}
	if !strings.Contains(document, "Why this classification:") {
		t.Error("the card does not say why it was classified as it was")
	}
}

// A storage device that no file record reached is a finding about that device.
// Hiding the zero would make it read as not having been looked at.
func TestACardShowsACountOfZero(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document, "file paths linked") {
		t.Error("the file count is missing from the card")
	}
	if !strings.Contains(document, "connection windows") {
		t.Error("the connection count is missing from the card")
	}
}

// Times are truncated rather than rounded: rounding a timestamp up can place a
// record after an event it actually preceded.
func TestAnInstantIsTruncatedNotRounded(t *testing.T) {
	moment := time.Date(2026, 7, 26, 10, 0, 59, 900_000_000, time.UTC)
	if got := instant(moment); got != "2026-07-26 10:00:59" {
		t.Errorf("instant = %s, want 2026-07-26 10:00:59", got)
	}
	if got := instant((*time.Time)(nil)); got != "not recorded" {
		t.Errorf("a missing time reads as %q, want \"not recorded\"", got)
	}
}

// ---- the timeline ----------------------------------------------------------

// installed builds a case whose timeline holds one setupapi section: a local
// wall clock with no zone, on a host that observes daylight saving, which is the
// hardest kind of timestamp the report has to present honestly.
func installed(t *testing.T, devnodes []registry.Devnode) *store.Store {
	t.Helper()
	return caseLoading(t, devnodes, func(db *store.Store, sourceID string) {
		// The transition months are what make this a daylight saving host. A
		// daylight bias alone is not: Windows stores one for every zone that
		// has ever had daylight saving, including the ones that no longer take
		// it, so without the rules this host writes in one season only.
		host := registry.TimeZone{
			KeyName: "W. Europe Standard Time", StandardName: "CET",
			BiasMinutes: -60, DaylightBiasMinutes: -60,
			StandardStartMonth: 10, DaylightStartMonth: 3,
			Found: true,
		}
		if err := db.LoadTimeZone(sourceID, "ControlSet001", host); err != nil {
			t.Fatal(err)
		}
		for _, node := range devnodes {
			if err := db.LoadSetupSections(sourceID, []setupapi.Section{{
				SourceFile:       "setupapi.dev.log",
				Kind:             setupapi.KindInstall,
				Operation:        "Device Install (Hardware initiated)",
				DeviceInstanceID: node.DeviceInstanceID,
				StartLocal:       "2026/07/26 12:00:00.000",
				LineNumber:       1,
			}}); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// A date that is only a storage format's zero must not read as a date, and must
// not set the edge of the span the report opens with.
//
// This is what a real report got wrong: a shell item's wall clock of
// 1980-01-01 00:00, read on a host east of UTC, surfaced as 1979-12-31 14:00 and
// became the moment "the evidence reaches from". The row is still listed — the
// record is real and only its timestamp is not — and it is labelled where every
// other row carries a unit.
func TestAnEpochDefaultIsLabelledAndDoesNotOpenTheReport(t *testing.T) {
	node := storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra")
	db := caseLoading(t, []registry.Devnode{node},
		func(db *store.Store, sourceID string) {
			host := registry.TimeZone{
				KeyName: "AUS Eastern Standard Time", StandardName: "AEST",
				// East of UTC, which is the arrangement that hides the
				// sentinel: Windows records bias as minutes west, so the FAT
				// epoch converts backwards into 1979 and stops equalling
				// anything wintime is in a position to refuse.
				BiasMinutes: -600, DaylightBiasMinutes: 0, Found: true,
			}
			if err := db.LoadTimeZone(sourceID, "ControlSet001", host); err != nil {
				t.Fatal(err)
			}
			// Two sections: one dated, one whose date is the epoch. A wall
			// clock carrying a device is what puts the row in the section an
			// analyst reads, rather than only in the span.
			if err := db.LoadSetupSections(sourceID, []setupapi.Section{
				{
					SourceFile: "setupapi.dev.log", Kind: setupapi.KindInstall,
					Operation:        "Device Install (Hardware initiated)",
					DeviceInstanceID: node.DeviceInstanceID,
					StartLocal:       "2026/07/26 12:00:00.000", LineNumber: 1,
				},
				{
					SourceFile: "setupapi.dev.log", Kind: setupapi.KindInstall,
					Operation:        "Device Install (Hardware initiated)",
					DeviceInstanceID: node.DeviceInstanceID,
					StartLocal:       "1980/01/01 00:00:00.000", LineNumber: 2,
				},
			}); err != nil {
				t.Fatal(err)
			}
		})

	document := render(t, db)

	if !strings.Contains(document, `<span class="unit epoch">`) {
		t.Error("the epoch default is not marked in the unit column")
	}
	if !strings.Contains(document, "the FAT epoch, 1980-01-01") {
		t.Error("the row does not name which epoch its date is")
	}
	if strings.Contains(document, "The evidence reaches from 1979") {
		t.Error("a sentinel is still setting the start of the evidence span")
	}
	// And the reader is told it happened, above the fold. A span quietly
	// narrowed is a span nobody can check.
	if !strings.Contains(document, "clock's default") {
		t.Error("the summary does not say that entries were set aside")
	}
}

// A time this run worked out and a time an artefact recorded are different kinds
// of claim, and a timeline that prints them alike invites the weaker one to be
// quoted as the stronger.
func TestAConvertedWallClockIsMarkedApartFromARecordedInstant(t *testing.T) {
	document := render(t, installed(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document, `<span class="unit converted">`) {
		t.Error("the converted wall clock is not marked as converted")
	}
	if !strings.Contains(document, "Recorded as local wall clock 2026/07/26 12:00:00.000") {
		t.Error("the row does not show the wall clock as the artefact wrote it")
	}
}

// Where a wall clock has two readings, both are shown. Picking one would be
// this tool asserting a season the record does not record.
func TestBothSeasonalReadingsAreShownWhereTheSeasonIsUnrecorded(t *testing.T) {
	document := render(t, installed(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document, "either 2026-07-26 11:00:00 or 2026-07-26 10:00:00 UTC") {
		t.Error("the row does not offer both seasonal readings")
	}
	if !strings.Contains(document, "does not say which season") {
		t.Error("the row does not say why there are two readings")
	}
}

// At a glance the analyst needs to know that a converted time is not a recorded
// one, and where the second reading is. Why there are two belongs beside the
// timeline, where the two readings are actually shown: three sentences of time
// zone mechanics at the top of the report is the summary explaining itself
// instead of summarising.
func TestTheSummaryNamesTheSecondReadingWithoutExplainingIt(t *testing.T) {
	document := render(t, installed(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	summary := document[:strings.Index(document, `<ul class="findings"`)]

	if !strings.Contains(summary, "rest on a local time") ||
		!strings.Contains(summary, "time_utc_alt") {
		t.Errorf("the summary does not say the second reading exists:\n%s", summary)
	}
	for _, aside := range []string{
		"could be either of two instants",
		"observes daylight saving",
		"never counted or listed twice",
		"standard-time reading",
	} {
		if strings.Contains(summary, aside) {
			t.Errorf("the summary carries the explanation rather than the fact: %q", aside)
		}
	}
	// And it is still explained, further down, where the readings are shown.
	if !strings.Contains(document, "does not say which season") {
		t.Error("the explanation was dropped rather than moved")
	}
}

// Two sticks of one model carry one friendly name. A filter offering that name
// twice cannot answer the question it exists to answer.
func TestTheTimelineFilterNamesEachDeviceDistinctly(t *testing.T) {
	document := render(t, installed(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
		storageNode("VID_0781&PID_5581", "0401B570C999", "SanDisk Ultra"),
	}))

	timeline := document[strings.Index(document, `aria-label="Filter the timeline by device"`):]
	timeline = timeline[:strings.Index(timeline, "</nav>")]

	if strings.Count(timeline, `<label for="f-timeline-`) != 3 {
		t.Fatalf("want an all chip and one per device, got:\n%s", timeline)
	}
	if !strings.Contains(timeline, "0401B570C537") ||
		!strings.Contains(timeline, "0401B570C999") {
		t.Error("two devices of one model are offered under one indistinguishable name")
	}

	// And the rows say the same thing the chips do. Two rows a second apart,
	// worded identically, describing two different devices, is the same failure
	// one level down.
	if !strings.Contains(document,
		`<span class="entry-label">SanDisk Ultra · 0401B570C999`) {
		t.Error("a timeline row names a device by a name it shares with another")
	}
}

// The filter is CSS. Nothing on this page may depend on script running, and a
// filter that fails must fail towards showing everything rather than hiding it.
func TestTheTimelineFilterFailsTowardsShowingEverything(t *testing.T) {
	document := render(t, installed(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document, `id="f-timeline-0" checked`) {
		t.Error("the page does not open with every entry shown")
	}
	if !strings.Contains(document,
		`#f-timeline-1:checked ~ .filter-targets > :not(.fx-timeline-1){display:none}`) {
		t.Error("the generated filter rule is missing")
	}
	// The only rules that hide anything are the per-device ones. Nothing hides
	// an entry by default, so a stylesheet that failed to apply, or a rule this
	// code never generated, leaves the timeline complete.
	if strings.Contains(document, ".timeline-entries > .entry{display:none}") {
		t.Error("entries are hidden by default")
	}
}

// The cap is a rendering limit, not a filter on the evidence. A page that shows
// the first few hundred entries of several thousand without saying so misleads
// about the shape of the case.
func TestACappedTimelineSaysWhatItLeftOut(t *testing.T) {
	timeline := Timeline{Rows: make([]TimelineRow, 750), Total: 1200}

	if !timeline.Capped() {
		t.Error("a timeline longer than the page does not report itself capped")
	}
	if timeline.Omitted() != 450 {
		t.Errorf("omitted = %d, want 450", timeline.Omitted())
	}
}

// The confidence on a timeline row is about the tie between the record and the
// device, not about whether the event happened. Printing "confirmed" on every
// registry row would say nothing and would teach the reader to skip the chip
// that matters.
func TestOnlyAnUncertainLinkIsFlaggedOnATimelineRow(t *testing.T) {
	certain := TimelineRow{TimelineRow: store.TimelineRow{
		TimelineEntry: store.TimelineEntry{Confidence: "confirmed"}}}
	weak := TimelineRow{TimelineRow: store.TimelineRow{
		TimelineEntry: store.TimelineEntry{Confidence: "probable"}}}

	if certain.Uncertain() {
		t.Error("a confirmed link is flagged as uncertain")
	}
	if !weak.Uncertain() {
		t.Error("a probable link is not flagged")
	}

	document := render(t, installed(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))
	if strings.Contains(document, "confirmed link to") {
		t.Error("every row carries a confidence, so none of them stands out")
	}
}

// And where a row does carry one, it says which device it is about.
//
// "probable link to this device" was reported from real evidence as unreadable,
// and it is: every other word on a file row names a file, so "this device"
// points at nothing the eye has passed. The device was in hand all along -- the
// chip above the list is built from it -- and the row now carries the same name
// that chip does, so filtering to a device and reading a row agree.
func TestAnUncertainRowNamesTheDeviceItIsUncertainAbout(t *testing.T) {
	document := render(t, withFiles(t))

	if strings.Contains(document, "link to this device") {
		t.Error("a row leaves the reader asking which device it means")
	}
	if !strings.Contains(document, "probable link to SanDisk Ultra") {
		t.Error("the confidence does not name the device it is about")
	}
}

// ---- file activity ---------------------------------------------------------

// withFiles builds a case where one storage device is reached by two file
// records: one the connection windows cover, and one they do not. That is the
// shape the disclosure exists for — the same device, two strengths of link.
func withFiles(t *testing.T) *store.Store {
	t.Helper()
	const stick = `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\0401B570C537&0`

	node := storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra")
	// A tier 3 device too, so a fixture used to check the page's structure
	// carries every section the page has.
	keyboard := hidNode("VID_046D&PID_C31C", "KBD0001", "USB Keyboard")

	return caseLoading(t, []registry.Devnode{node, keyboard},
		func(db *store.Store, sourceID string) {
			if err := db.LoadPortableDevices(sourceID,
				[]registry.PortableDevice{
					{FriendlyName: "FIELDWORK", DeviceInstanceID: stick},
				}); err != nil {
				t.Fatal(err)
			}

			// A window from 10:00 to 11:00. The first record falls inside it and
			// the second an hour after it closed.
			if err := db.LoadEvents(map[string]string{"state.evtx": sourceID},
				[]eventlog.Record{
					{
						Channel:    "Microsoft-Windows-StorageVolume/Operational",
						SourceFile: "state.evtx", RecordID: 1, EventID: 1001,
						TimeUTC: time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC),
						RuleID:  "Microsoft-Windows-StorageVolume/Operational:1001",
						Kind:    eventlog.KindConnect,
						Fields: []eventlog.Field{{
							Name: "DeviceInstanceId",
							Role: eventlog.RoleDeviceInstanceID, Value: stick,
						}},
					},
					{
						Channel:    "Microsoft-Windows-StorageVolume/Operational",
						SourceFile: "state.evtx", RecordID: 2, EventID: 1002,
						TimeUTC: time.Date(2026, 7, 26, 11, 0, 0, 0, time.UTC),
						RuleID:  "Microsoft-Windows-StorageVolume/Operational:1002",
						Kind:    eventlog.KindDisconnect,
						Fields: []eventlog.Field{{
							Name: "DeviceInstanceId",
							Role: eventlog.RoleDeviceInstanceID, Value: stick,
						}},
					},
				}); err != nil {
				t.Fatal(err)
			}

			covered := time.Date(2026, 7, 26, 10, 30, 0, 0, time.UTC)
			after := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
			if err := db.LoadFileTargets([]store.FileTarget{
				fileTarget(sourceID, "FIELDWORK", `E:\covered.docx`, covered),
				fileTarget(sourceID, "FIELDWORK", `E:\after.docx`, after),
				// And one on the system drive, which reaches no device at all.
				{
					SourceID: sourceID, SourceFile: "local.lnk",
					Origin: "shell_link", Path: `C:\Users\a\local.txt`,
					DriveLetter: "C", LastAccessUTC: &covered,
				},
			}); err != nil {
				t.Fatal(err)
			}
		})
}

// withFilesOnTwoAlikeDevices is the shape reported from real evidence: two
// sticks of one model, neither carrying a FriendlyName on its own storage node,
// each mounted on D: at a different time, and each on a volume with no label —
// so the portable-device node holds the drive path where a label would be.
func withFilesOnTwoAlikeDevices(t *testing.T) *store.Store {
	t.Helper()

	stick := func(serial string) []registry.Devnode {
		const model = `Disk&Ven_Vendor&Prod_Product&Rev_2.00`
		container := "{aabbccdd-1111-2222-3333-4444" + serial[4:] + "}"

		disk := registry.Devnode{
			ControlSet: "ControlSet001", Enumerator: "USBSTOR",
			DeviceID: model, InstanceID: serial + "&0",
			DeviceInstanceID: `USBSTOR\` + model + `\` + serial + "&0",
			DeviceDesc:       "@disk.inf,%disk_devdesc%;Disk drive",
			Service:          "disk", ContainerID: container,
		}
		// The volume node. Windows writes the volume's label into its
		// FriendlyName, and the drive path where there is no label.
		volume := registry.Devnode{
			ControlSet: "ControlSet001", Enumerator: "SWD",
			DeviceID: "WPDBUSENUM", InstanceID: "_??_" + serial,
			DeviceInstanceID: `SWD\WPDBUSENUM\_??_` + serial,
			FriendlyName:     `D:\`, ContainerID: container,
		}
		return []registry.Devnode{disk, volume}
	}

	nodes := append(stick("9207AAAA"), stick("9207BBBB")...)

	return caseLoading(t, nodes, func(db *store.Store, sourceID string) {
		// A window each, an hour apart, so every record reaches exactly one of
		// them and both devices end up with file activity.
		var records []eventlog.Record
		for index, serial := range []string{"9207AAAA", "9207BBBB"} {
			path := `USBSTOR\Disk&Ven_Vendor&Prod_Product&Rev_2.00\` +
				serial + "&0"
			hour := 10 + index*2
			records = append(records,
				volumeEvent(uint64(index*2+1), 1001, eventlog.KindConnect, path,
					time.Date(2026, 7, 26, hour, 0, 0, 0, time.UTC)),
				volumeEvent(uint64(index*2+2), 1002, eventlog.KindDisconnect, path,
					time.Date(2026, 7, 26, hour+1, 0, 0, 0, time.UTC)))
		}
		if err := db.LoadEvents(
			map[string]string{"state.evtx": sourceID}, records); err != nil {
			t.Fatal(err)
		}

		firstUse := time.Date(2026, 7, 26, 10, 30, 0, 0, time.UTC)
		secondUse := time.Date(2026, 7, 26, 12, 30, 0, 0, time.UTC)
		if err := db.LoadFileTargets([]store.FileTarget{
			onDriveD(sourceID, `D:\first.docx`, firstUse),
			onDriveD(sourceID, `D:\second.docx`, secondUse),
		}); err != nil {
			t.Fatal(err)
		}
	})
}

func volumeEvent(recordID uint64, eventID int64, kind eventlog.Kind,
	instanceID string, when time.Time) eventlog.Record {

	return eventlog.Record{
		Channel:    "Microsoft-Windows-StorageVolume/Operational",
		SourceFile: "state.evtx", RecordID: recordID, EventID: eventID,
		TimeUTC: when,
		RuleID: "Microsoft-Windows-StorageVolume/Operational:" +
			map[int64]string{1001: "1001", 1002: "1002"}[eventID],
		Kind: kind,
		Fields: []eventlog.Field{{
			Name: "DeviceInstanceId",
			Role: eventlog.RoleDeviceInstanceID, Value: instanceID,
		}},
	}
}

// A record on an unlabelled removable volume: a letter, and nothing else that
// could reach a device.
func onDriveD(sourceID, path string, opened time.Time) store.FileTarget {
	return store.FileTarget{
		SourceID: sourceID, SourceFile: path + ".lnk", Origin: "shell_link",
		Path: path, DriveLetter: "D", VolumePresent: true,
		DriveType: "removable", Removable: true, LastAccessUTC: &opened,
	}
}

func fileTarget(sourceID, label, path string, opened time.Time) store.FileTarget {
	return store.FileTarget{
		SourceID: sourceID, SourceFile: path + ".lnk", Origin: "shell_link",
		Path: path, DriveLetter: "E", VolumePresent: true,
		DriveType: "removable", VolumeSerialHex: "E607-9156", VolumeLabel: label,
		Removable: true, LastAccessUTC: &opened,
	}
}

// The split is per device, not against a fixed bar. On current Windows nothing
// is confirmed, so a fixed bar would hide every file record in the case — and
// file activity is the question a USB case is usually asked to answer.
func TestTheFirmestLinksAreShownWhateverTheyAre(t *testing.T) {
	db := withFiles(t)

	files, err := gatherFiles(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(files.Devices) != 1 {
		t.Fatalf("got %d devices with file activity, want 1", len(files.Devices))
	}

	device := files.Devices[0]
	if device.Best != "probable" {
		t.Errorf("best = %q, want probable: no route here reaches higher", device.Best)
	}
	if len(device.Strongest) == 0 {
		t.Fatal("every link is behind the disclosure, so the section shows nothing")
	}
	for _, row := range device.Strongest {
		if row.Confidence != device.Best {
			t.Errorf("a %s link is shown among the firmest", row.Confidence)
		}
	}
	for _, row := range device.Weaker {
		if row.Confidence == device.Best {
			t.Errorf("a %s link is hidden behind the disclosure", row.Confidence)
		}
	}
}

// A weaker link is disclosed with what makes it weak. The word alone is a
// ranking; the reason is what an analyst can act on or argue with.
func TestAWeakerLinkIsDisclosedWithItsReasoning(t *testing.T) {
	document := render(t, withFiles(t))

	if !strings.Contains(document, "Weaker associations") {
		t.Fatal("the weaker links are not behind a disclosure")
	}
	if !strings.Contains(document,
		"nothing places the device on the machine at this time") {
		t.Error("a weaker link does not say what makes it weaker")
	}
	// And the firmer one says what lifted it, which is a different claim.
	if !strings.Contains(document,
		"a connection window independently places it on the machine") {
		t.Error("the firmer link does not say what lifted it")
	}
}

// A record that reached no device is a gap in what the evidence can link, and a
// gap that is not shown reads as an absence of activity.
func TestARecordThatReachedNoDeviceSaysWhy(t *testing.T) {
	document := render(t, withFiles(t))

	if !strings.Contains(document, "Records that reached no device") {
		t.Fatal("the unattributed records are not shown at all")
	}
	// Capitalised and stopped, which is the rendering and not the view: the
	// reason is written as a fragment because it is also joined into longer
	// strings, and stands alone here as a sentence.
	if !strings.Contains(document,
		"Drive letter C is linked to no USB device in this evidence.") {
		t.Error("an unattributed record does not say what stopped it")
	}
}

// ---- tier 3 ----------------------------------------------------------------

func hidNode(deviceID, instanceID, name string) registry.Devnode {
	return registry.Devnode{
		ControlSet: "ControlSet001", Enumerator: "USB",
		DeviceID: deviceID, InstanceID: instanceID,
		DeviceInstanceID: `USB\` + deviceID + `\` + instanceID,
		FriendlyName:     name,
		CompatibleIDs:    `USB\Class_03&SubClass_01&Prot_01|USB\Class_03`,
		Service:          "kbdhid",
	}
}

// A tier is a ranking, not a filter. The low-value devices are all present and
// collapsed by category, because a report that dropped them could not be
// checked and one that listed them flat would bury the two that matter.
func TestTierThreeIsPresentInFullAndCollapsed(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
		hidNode("VID_04F3&PID_0001", "5&1a89cd96&0&1", "Keyboard"),
		hidNode("VID_04F3&PID_0002", "5&1a89cd96&0&2", "Mouse"),
	}))

	if !strings.Contains(document, `StandardHID — 2 devices`) {
		t.Error("the tier 3 devices are not grouped by category with a count")
	}
	if !strings.Contains(document, "Keyboard") || !strings.Contains(document, "Mouse") {
		t.Error("a tier 3 device was dropped from the report entirely")
	}

	// And they are not among the cards, which are the answer to the case.
	cards := document[strings.Index(document, `id="significant"`):strings.Index(document, `id="timeline"`)]
	if strings.Contains(cards, "Keyboard") {
		t.Error("a tier 3 device is shown among the significant devices")
	}
}

// Review is a flag, not a tier. A tier 3 device asking for attention is lifted
// out of the collapsed group rather than buried among seventy siblings.
func TestATierThreeDeviceFlaggedForReviewIsLiftedOut(t *testing.T) {
	// Two devices sharing one serial: a finding at any class.
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
		hidNode("VID_04F3&PID_0001", "SHARED123", "Keyboard"),
		hidNode("VID_04F3&PID_0002", "SHARED123", "Keypad"),
	}))

	flagged := strings.Index(document, "Flagged for review")
	collapsed := strings.Index(document, `class="other-group"`)
	if flagged < 0 {
		t.Fatal("a tier 3 device needing review is not surfaced")
	}
	if collapsed >= 0 && flagged > collapsed {
		t.Error("the review list is below the collapsed groups it exists to escape")
	}
	if !strings.Contains(document, "shared with another physical device") {
		t.Error("the review list does not say what is being flagged")
	}
}

// The flag has to mean something. Raised on every keyboard and hub, which never
// carry serials, it is raised on nothing.
func TestAClassThatNeverCarriesASerialIsNotFlagged(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		hidNode("VID_04F3&PID_0001", "5&1a89cd96&0&1", "Keyboard"),
	}))

	if strings.Contains(document, "Flagged for review") {
		t.Error("a keyboard with no serial is flagged, which flags every keyboard")
	}
}

func printerNode(deviceID, instanceID, name string) registry.Devnode {
	return registry.Devnode{
		ControlSet: "ControlSet001", Enumerator: "USB",
		DeviceID: deviceID, InstanceID: instanceID,
		DeviceInstanceID: `USB\` + deviceID + `\` + instanceID,
		FriendlyName:     name,
		CompatibleIDs:    `USB\Class_07&SubClass_01&Prot_02|USB\Class_07`,
		Service:          "usbprint",
	}
}

// Four devices joined into a paragraph have to be read before they can be
// counted, and the headline above has already counted them.
func TestAFindingNamingSeveralDevicesGivesEachItsOwnRow(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
		storageNode("VID_13FE&PID_4200", "24111912130128", "PATRIOT USB Device"),
	}))

	list := document[strings.Index(document, `<ul class="detail-list">`):]
	list = list[:strings.Index(list, "</ul>")]

	if strings.Count(list, "<li>") != 2 {
		t.Fatalf("want one row per device, got:\n%s", list)
	}
	if !strings.Contains(list, "SanDisk Ultra") ||
		!strings.Contains(list, "PATRIOT USB Device") {
		t.Errorf("the rows do not name the devices:\n%s", list)
	}
}

// A finding whose detail is a sentence is a sentence, not a one-item list.
func TestAFindingWhoseDetailIsASentenceStaysASentence(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if strings.Contains(document, `<ul class="detail-list">`) {
		t.Error("a single device is rendered as a list of one")
	}
	if !strings.Contains(document, `<div class="detail">`) {
		t.Error("the detail is missing entirely")
	}
}

// The file a finding rests on is a click away. The link is relative, so the
// report and its data directory move together.
func TestACitedFileLinksToTheFileTheRunWrote(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document,
		`<a class="cite" href="data/devices.csv">devices.csv</a>, category Storage`) {
		t.Error("the cited file is not linked to the file beside the report")
	}
	if strings.Contains(document, `href="http`) {
		t.Error("a citation reaches off the machine")
	}
}

// Only files the manifest records as written are linked. A report that offered
// a path to something that is not there would be worse than one offering none.
func TestOnlyAFileTheRunWroteIsLinked(t *testing.T) {
	report := &Report{Manifest: manifest()}

	linked := string(report.Cite("devices.csv and invented.csv"))
	if !strings.Contains(linked, `href="data/devices.csv"`) {
		t.Errorf("a file the run wrote is not linked: %s", linked)
	}
	if strings.Contains(linked, `href="data/invented.csv"`) ||
		strings.Contains(linked, `href="invented.csv"`) {
		t.Errorf("a file the run never wrote is linked: %s", linked)
	}
	if !strings.Contains(linked, "invented.csv") {
		t.Errorf("the name was dropped rather than left as text: %s", linked)
	}
}

// A source path names the artefact, not where the examiner mounted it.
//
// The same SYSTEM hive is E:\Windows\System32\config\SYSTEM from a mounted
// image and F:\Sources\HOST01\Windows\System32\config\SYSTEM from a collector
// pack. Repeating that prefix on every row of every table costs a line of
// reading each time and identifies nothing: the root is stated once, in the
// masthead, and the paths hang off it.
func TestASourcePathIsRelativeToTheEvidenceRoot(t *testing.T) {
	report := &Report{Manifest: manifest()}

	for _, want := range []struct{ path, rendered string }{
		{`C:\Evidence\Windows\System32\config\SYSTEM`,
			`\Windows\System32\config\SYSTEM`},
		// Case and separator both vary in practice: a root recorded as C:\
		// against a path built with forward slashes has to still match.
		{`c:/evidence/Windows/Prefetch/EXCEL.EXE-1234.pf`,
			`/Windows/Prefetch/EXCEL.EXE-1234.pf`},
		// Outside the root, so it stays whole. This should not happen — the
		// boundary check refuses it — and inventing a relative form for the one
		// path worth noticing would hide it.
		{`D:\Elsewhere\SYSTEM`, `D:\Elsewhere\SYSTEM`},
		// A prefix that matches mid-segment is not containment.
		{`C:\Evidence2\SYSTEM`, `C:\Evidence2\SYSTEM`},
		{"", ""},
	} {
		if got := report.evidenceRelative(want.path); got != want.rendered {
			t.Errorf("evidenceRelative(%q) = %q, want %q",
				want.path, got, want.rendered)
		}
	}
}

// The report is a document to read, and a SHA-256 beside every one of five
// hundred rows is not something anybody reads — it is something they scroll
// past, pushing the finding off the line.
//
// Nothing is lost by leaving it out. The hash of every file the run read is in
// provenance/sources.csv and the manifest, once per file, where it can actually
// be compared against a hash somebody else computed.
func TestTheReportDoesNotRepeatAHashOnEveryRow(t *testing.T) {
	document := render(t, withFiles(t))

	if strings.Contains(document, "sha256") ||
		strings.Contains(document, "SHA256") {
		t.Error("a hash is printed on the page")
	}
	// The claim it replaces still has to be made, or a reader has no idea the
	// hashes exist at all.
	if !strings.Contains(document, "provenance/sources.csv") {
		t.Error("the report does not say where the hashes are")
	}
}

// An explanatory line is rendered as a sentence. The views write these as
// fragments because they are also joined into longer strings, and a column of
// uncapitalised unterminated text reads as debug output rather than a document.
func TestAnExplanatoryLineIsRenderedAsASentence(t *testing.T) {
	for _, want := range []struct{ given, rendered string }{
		{"the time the target was last opened",
			"The time the target was last opened."},
		// Already a sentence, and gaining a second full stop would be worse
		// than gaining none.
		{"It is one stored state.", "It is one stored state."},
		// A trailing colon introduces the list that follows and must not be
		// stopped; one mid-line is just punctuation and changes nothing.
		{"grouped by:", "Grouped by:"},
		{"grouped by: container id", "Grouped by: container id."},
		{"  spaced  ", "Spaced."},
		{"", ""},
	} {
		if got := sentence(want.given); got != want.rendered {
			t.Errorf("sentence(%q) = %q, want %q",
				want.given, got, want.rendered)
		}
	}
}

// A citation is still evidence text passing through a renderer.
func TestACitationCannotCarryMarkup(t *testing.T) {
	report := &Report{Manifest: manifest()}

	linked := string(report.Cite(`<script>alert(1)</script> devices.csv`))
	if strings.Contains(linked, "<script>") {
		t.Errorf("markup survived the citation: %s", linked)
	}
	if !strings.Contains(linked, `href="data/devices.csv"`) {
		t.Errorf("the citation stopped working: %s", linked)
	}
}

// Tier 1 is what the report is for, so it opens with the report. Tier 2 is
// there in full behind one click, with its devices named outside the fold so
// the section can be dismissed without opening it.
func TestEveryTierFoldsWithItsDevicesNamed(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
		printerNode("VID_03F0&PID_0024", "CN12345678", "HP LaserJet"),
	}))

	// Tier 1 included. A report that opens with one section already filling the
	// screen does not show the analyst what else is in it.
	for tier, name := range map[string]string{
		"disc-tier1": "SanDisk Ultra",
		"disc-tier2": "HP LaserJet",
	} {
		if strings.Contains(document, `id="`+tier+`" checked`) {
			t.Errorf("%s opens by default", tier)
		}
		// Folded is not hidden: the label names every device in the group, so a
		// group can be dismissed, or opened, without being opened first.
		label := document[strings.Index(document, `for="`+tier+`"`):]
		label = label[:strings.Index(label, "</label>")]
		if !strings.Contains(label, name) {
			t.Errorf("the %s label does not name what it holds:\n%s", tier, label)
		}
	}
}

// The counts and the span are what the summary shows before it is opened. An
// analyst meeting the report should see its shape in one screen — which
// sections exist, and how much is in each — rather than the first section
// already filling it.
func TestTheSummaryShowsItsNumbersAndFoldsTheRest(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document, "Summary: At a glance") {
		t.Error("the summary is not named as a summary")
	}

	open := document[:strings.Index(document, `id="disc-summary"`)]
	// The tiles say what they are counting. "5" beside "tier 1" is a number
	// beside a word the reader has not met yet.
	if !strings.Contains(open, "tier 1 device") ||
		!strings.Contains(open, "tier 2 device") {
		t.Errorf("the tier tiles do not say they count devices:\n%s", open)
	}
	if !strings.Contains(open, "The evidence reaches from") {
		t.Error("the span is behind the fold")
	}

	// And the fold says how many findings are behind it, so the report still
	// answers "is there anything here" without being opened.
	label := document[strings.Index(document, `for="disc-summary"`):]
	label = label[:strings.Index(label, "</label>")]
	if !strings.Contains(label, "2 findings") {
		t.Errorf("the fold does not say how many findings it holds:\n%s", label)
	}
	if strings.Contains(open, "storage device was attached") {
		t.Error("the findings are outside the fold they were put behind")
	}
}

// The long sections fold. The timeline is most of the document's height, and
// with it open the file activity below it is far enough down to be missed.
func TestTheLongSectionsFoldAndPrintOpen(t *testing.T) {
	document := render(t, withFiles(t))

	for _, fold := range []string{
		"disc-summary", "disc-tier1", "disc-timeline", "disc-files",
		"disc-others", "disc-coverage", "disc-limitations",
	} {
		if !strings.Contains(document, `id="`+fold+`"`) {
			t.Errorf("%s is not behind a fold", fold)
		}
		if strings.Contains(document, `id="`+fold+`" checked`) {
			t.Errorf("%s opens by default", fold)
		}
	}

	// A closed <details> cannot be forced open by any stylesheet, which is why
	// these are a checkbox and a rule. Print overrides the rule, so nothing is
	// dropped off the paper without the paper saying so.
	if !strings.Contains(document, ".disclose-body { display: block !important; }") {
		t.Error("printing would omit every folded section")
	}
	if !strings.Contains(document,
		"Printed with every collapsible section expanded") {
		t.Error("the printed page does not say the folds were opened")
	}
}

// The masthead's claim covers the whole document, so one <details> anywhere in
// it makes the claim false. The card drill-downs, the gap table, the weaker
// associations and the tier 3 groups were all <details> for a long time while
// the tiers around them were checkboxes: the reasoning had been written down
// and applied only where it was written. A print stylesheet cannot open them,
// so a printed report was quietly missing the evidence behind every device.
//
// Structural, and cheap: it fails the moment the next fold is written the easy
// way rather than waiting for somebody to print a populated report.
func TestNoFoldInTheDocumentIsA_DetailsElement(t *testing.T) {
	document := render(t, withFiles(t))

	if strings.Contains(document, "<details") || strings.Contains(document, "<summary") {
		t.Error("a fold in this report cannot be forced open for printing")
	}

	// Every fold must be a label pointing at its own input, or the id collision
	// makes two folds open together and the second one's label opens the first.
	ids := regexp.MustCompile(`id="(fold-\d+|disc-[a-z0-9]+)"`).FindAllString(document, -1)
	if len(ids) < 8 {
		t.Fatalf("only %d folds rendered; this report should hold more", len(ids))
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Errorf("%s is used twice, so two folds share one checkbox", id)
		}
		seen[id] = true
	}
}

// A shortcut to a drive root stores the FAT epoch in place of a timestamp. Read
// as a write time it puts a file record in 1980 and drags the reported span of
// the whole case back forty years, which is what the top of the report says the
// evidence reaches across.
func TestTheFATEpochIsReportedAsTheAbsenceItIs(t *testing.T) {
	const stick = `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00 1B570C537&0`

	db := caseLoading(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}, func(db *store.Store, sourceID string) {
		if err := db.LoadPortableDevices(sourceID, []registry.PortableDevice{
			{FriendlyName: "FIELDWORK", DeviceInstanceID: stick},
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.LoadFileTargets([]store.FileTarget{{
			SourceID: sourceID, SourceFile: `E (root).lnk`,
			Origin: "shell_link", Path: `E:\`, DriveLetter: "E",
			VolumePresent: true, DriveType: "removable", Removable: true,
			VolumeLabel: "FIELDWORK",
			// What Explorer wrote: no derived time, and the stored value kept.
			RawTargetWritten: 119600064000000000,
		}}); err != nil {
			t.Fatal(err)
		}
	})

	document := render(t, db)

	if strings.Contains(document, "reaches from 1980-01-01") {
		t.Error("the reported span of the case starts at the FAT epoch")
	}
	files := document[strings.Index(document, `id="file-activity"`):]
	if !strings.Contains(files, `<span class="unit absent">no time</span>`) {
		t.Error("the record is not marked as carrying no time")
	}
	if !strings.Contains(document, "the record stores the FAT epoch") {
		t.Error("the report does not say why the record has no time")
	}

	// On no timeline, because it has no time — and still in the file activity
	// section, because it is still a record that a drive root was opened.
	entries, _, err := db.SignificantTimeline(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.SortUTC != nil && entry.SortUTC.Year() == 1980 {
			t.Errorf("a timeline entry is dated %s", entry.SortUTC)
		}
	}
}

// A host that keeps one offset all year has no season to be unsure about, and a
// report that raised the ambiguity anyway would be describing a difficulty the
// case does not have.
func TestTheSeasonalReadingIsOnlyRaisedWhereTheHostHasTwo(t *testing.T) {
	db := caseLoading(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}, func(db *store.Store, sourceID string) {
		// UTC: one offset all year, which is what the Lenovo collections hold.
		if err := db.LoadTimeZone(sourceID, "ControlSet001", registry.TimeZone{
			Found: true, KeyName: "UTC", StandardName: "UTC",
		}); err != nil {
			t.Fatal(err)
		}
	})

	document := render(t, db)

	if strings.Contains(document, "could be either of two instants") {
		t.Error("a host with one offset all year is told its records are ambiguous")
	}

	// And the qualification is its own paragraph, so the two counts do not run
	// into one another.
	span := strings.Index(document, "The evidence reaches from")
	note := strings.Index(document, "<strong>Note:</strong>")
	if note < 0 {
		t.Fatal("the qualification is not labelled")
	}
	if between := document[span:note]; !strings.Contains(between, "</p>") {
		t.Error("the note runs on from the span rather than starting a paragraph")
	}
}

// Prefetch reached the report through the headline findings, the device facts,
// the file activity and the timeline. That is enough to be found and not enough
// to be read as a body of evidence: an analyst asking what ran off a stick,
// when, and what those programmes touched on it had to assemble the answer from
// four places.
//
// The section has to keep the two claims apart. A programme executed off a
// device and one on the system disk that merely opened a file on it reach the
// device through the same chain, and a table holding both would let a reader
// count four programmes as having run from a stick when one did.
func TestTheReportShowsWhatRanOffADeviceApartFromWhatMerelyReadFromIt(t *testing.T) {
	const stick = `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\0401B570C537&0`
	const volume = `\VOLUME{01dc0f73-00c90010}`
	ran := at("2026-08-04T02:28:19Z")

	db := caseLoading(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}, func(db *store.Store, sourceID string) {
		if err := db.LoadMountEntries(sourceID, []registry.MountEntry{{
			ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
			DriveLetter: "E", TargetKind: registry.TargetDevicePath,
			DeviceInstanceID: stick,
		}}); err != nil {
			t.Fatal(err)
		}
		// A shell link is what states the volume serial against a letter, which
		// is the only route prefetch has to a device.
		if err := db.LoadFileTargets([]store.FileTarget{{
			SourceID: sourceID, SourceFile: "notes.lnk", Origin: "shell_link",
			Path: `E:\notes.txt`, DriveLetter: "E", VolumePresent: true,
			DriveType: "removable", VolumeSerialHex: "00C9-0010",
			VolumeLabel: "FIELDWORK", Removable: true,
		}}); err != nil {
			t.Fatal(err)
		}

		collector := prefetchRun("COLLECTOR.EXE", volume, "00C9-0010", true, ran)
		reader := prefetchRun("NOTEPAD.EXE", volume, "00C9-0010", false, ran)
		if err := db.LoadPrefetchRuns(
			[]*prefetch.Run{collector, reader},
			map[string]string{
				collector.SourceFile: sourceID,
				reader.SourceFile:    sourceID,
			}); err != nil {
			t.Fatal(err)
		}
	})

	document := render(t, db)

	if !strings.Contains(document, "Programmes and the devices they touched") {
		t.Fatal("the section is absent")
	}
	// Behind a fold like every other long section, and closed, so printing has
	// something to force open rather than a section that was never rendered.
	if !strings.Contains(document, `id="disc-executions"`) {
		t.Error("the section is not behind a fold")
	}
	if strings.Contains(document, `id="disc-executions" checked`) {
		t.Error("the section opens by default")
	}

	if !strings.Contains(document, "1 programme ran from a device") {
		t.Error("the label does not say how many ran from a device: a reader " +
			"has to be able to dismiss the section without opening it")
	}
	if !strings.Contains(document, "Read from this device, but ran from "+
		"somewhere else") {
		t.Error("the weaker claim is not kept apart from the stronger one")
	}

	// The execution itself, and what the programme touched on the device.
	if !strings.Contains(document, "2026-08-04 02:28:19") {
		t.Error("the execution time is not shown")
	}
	if !strings.Contains(document, "DOCUMENT.DOCX") {
		t.Error("what the programme read from the device is not shown")
	}
	// Both counts. Windows counted three runs and this file holds one of them,
	// and either number alone misleads.
	if !strings.Contains(document, "still recorded") {
		t.Error("the surviving execution count is not shown beside the tally")
	}

	// And none of it is in a table.
	//
	// It was five columns wide and every cell held a paragraph, a file list or a
	// sentence of reasoning, so a prefetch record naming eight files by device
	// path wrapped to twenty lines in a two-inch column while the programme the
	// row was about was the narrowest thing on the screen. A table is for values
	// that line up and can be compared down a column, and nothing here does —
	// the same reasoning that took the file activity section out of one.
	section := document[strings.Index(document, `id="disc-executions"`):]
	section = section[:strings.Index(section, `id="other-devices"`)]
	if strings.Contains(section, "<table") {
		t.Error("the executions are laid out as a table; every column here " +
			"holds a paragraph or a file list, and none of them compare")
	}
	if !strings.Contains(section, `class="run-list"`) {
		t.Error("the executions are not laid out as a list")
	}
}

// A collection whose prefetch reaches no device gets a stated absence, not a
// missing section. "No programme ran from a device" and "nobody looked" read
// very differently, and only one of them is true.
func TestNoPrefetchReachingADeviceIsSaidRatherThanLeftOut(t *testing.T) {
	document := render(t, caseWith(t, []registry.Devnode{
		storageNode("VID_0781&PID_5581", "0401B570C537", "SanDisk Ultra"),
	}))

	if !strings.Contains(document, "Programmes and the devices they touched") {
		t.Fatal("the section heading is absent")
	}
	if !strings.Contains(document,
		"No prefetch record in this evidence names a volume that reached a device") {
		t.Error("the absence is not stated")
	}
}

// The same claim as the timeline filter, one section along, and this is where
// it was reported from real evidence: two device cards in the file activity
// section both headed "D:\", and the chip row above them reading "D:\ D:\".
//
// Two causes, and both are here. A portable-device node's FriendlyName is the
// volume label, and an unlabelled volume gets the drive path written into it
// instead -- so a name that identifies nothing beat the vendor and product
// sitting in the instance id. And the disambiguation existed only in Go, and
// only for the timeline chips, so every other place a device is named went on
// repeating one label. It is in v_device_label now, which is what all of them
// read.
func TestTwoDevicesOfOneModelAreNamedApartInFileActivityToo(t *testing.T) {
	document := render(t, withFilesOnTwoAlikeDevices(t))

	chips := document[strings.Index(document, `for="disc-files"`):]
	chips = chips[:strings.Index(chips, "</label>")]

	first := strings.Index(chips, `class="name-chip"`)
	second := strings.Index(chips[first+1:], `class="name-chip"`)
	if first < 0 || second < 0 {
		t.Fatalf("want a chip per device, got:\n%s", chips)
	}
	if strings.Contains(chips, `D:\`) {
		t.Error("a device is named after the letter it was mounted on")
	}
	if !strings.Contains(chips, "9207AAAA") || !strings.Contains(chips, "9207BBBB") {
		t.Errorf("the two devices are not told apart:\n%s", chips)
	}
}

// Every section that draws a row of device pills filters with them.
//
// The timeline had a working filter. The significant-device tiers and the file
// activity section drew the same row of names inside their fold's label, so
// pressing one opened the section rather than narrowing it — reported by an
// examiner as the control not working the same way across the report, which is
// exactly what it was. A pill that looks like a filter and toggles a fold is
// worse than no pill at all, because the gesture is learnt in one section and
// mislearnt everywhere else.
//
// The claim here is structural and covers all three: a bar, a radio group of
// its own, and a rule that hides what the selected pill does not name.
func TestEverySectionWithDevicePillsFiltersWithThem(t *testing.T) {
	document := render(t, withFilesOnTwoAlikeDevices(t))

	// Two sticks, which this fixture classifies as tier 1, so the tier bar it
	// exercises is tier1. The claim is about every section that draws pills,
	// and tier 2 renders from the same template with the same group name shape.
	for _, group := range []string{"timeline", "tier1", "files"} {
		// The pill that shows everything, checked, so the section opens
		// complete and a filter that failed to apply leaves it that way.
		if !strings.Contains(document, `id="f-`+group+`-0" checked`) {
			t.Errorf("the %s section has no all-devices pill selected", group)
		}
		// Its own radio group. Sharing one would make selecting a device in one
		// section silently clear the filter in another.
		if !strings.Contains(document, `name="fg-`+group+`"`) {
			t.Errorf("the %s section has no radio group of its own", group)
		}
		// And a rule that actually hides something.
		if !strings.Contains(document, `#f-`+group+
			`-1:checked ~ .filter-targets > :not(.fx-`+group+`-1){display:none}`) {
			t.Errorf("the %s pills highlight but do not filter", group)
		}
		// The items the rule reaches have to exist and carry the class, or the
		// rule hides every one of them.
		if !strings.Contains(document, `fx-`+group+`-1`) {
			t.Errorf("nothing in the %s section carries a filter class", group)
		}
	}
}

// A device name in a fold's label must not be a filter control.
//
// This is the defect itself rather than the fix: the names stay, because a
// collapsed section reading "2 devices" says nothing about whether it is worth
// opening. What they must not be is a label pointing at the fold's checkbox
// while looking like the timeline's pills.
func TestADeviceNameInAFoldLabelDoesNotPretendToFilter(t *testing.T) {
	document := render(t, withFilesOnTwoAlikeDevices(t))

	for _, label := range []string{"disc-tier1", "disc-files"} {
		section := document[strings.Index(document, `for="`+label+`"`):]
		section = section[:strings.Index(section, "</label>")]

		if strings.Contains(section, `<label for="f-`) {
			t.Errorf("the %s fold label contains a filter pill; pressing it "+
				"would toggle the fold rather than filter", label)
		}
		// The names are still there, as plain text.
		if !strings.Contains(section, "name-chip") {
			t.Errorf("the %s fold no longer names what it holds", label)
		}
	}

	// And they are drawn once. Open, the filter bar names the same devices an
	// inch below, and a reader looking at two rows of one list has to work out
	// which of them does anything — the confusion this whole control was
	// straightened out to remove, reintroduced a row higher up. The stylesheet
	// withdraws them exactly where the bar arrives.
	if !strings.Contains(document,
		".disclose-toggle:checked ~ .disclose-label .disclose-names") {
		t.Error("an open fold draws its device names twice: once as plain text " +
			"in the label and again as the filter bar below it")
	}
}

// Printing carries every row, whatever the reader had selected on screen.
//
// The rules are generated inside @media screen, which is the whole of the
// guarantee: print cannot apply them, so there is nothing for the print
// stylesheet to undo. It used to undo them by naming the element being hidden —
// display:grid for a timeline entry — so every new filtered element needed
// somebody to remember to add an override in a different file, and a report
// printed with a device selected would have been missing the rest with nothing
// on the paper saying so.
//
// Structural and cheap, like the no-<details> check beside it: it fails the
// moment a hiding rule is written outside the screen scope.
func TestTheDeviceFilterCannotHideAnythingOnPaper(t *testing.T) {
	document := render(t, withFilesOnTwoAlikeDevices(t))

	style := document[strings.Index(document, "<style>"):]
	style = style[:strings.Index(style, "</style>")]

	generated := style[strings.Index(style, "/* generated: one rule per filter pill"):]
	screen := generated[strings.Index(generated, "@media screen {"):]
	screen = screen[:strings.Index(screen, "\n}\n")]

	// Every rule that hides anything is inside that block.
	hiding := strings.Count(style, "{display:none}")
	if hiding == 0 {
		t.Fatal("no filter rule hides anything, so this proves nothing")
	}
	if inside := strings.Count(screen, "{display:none}"); inside != hiding {
		t.Errorf("%d of %d hiding rules are outside @media screen and would "+
			"apply on paper", hiding-inside, hiding)
	}

	// And the paper says the filter was ignored, rather than leaving a reader
	// to wonder whether what they selected is what they printed.
	if !strings.Contains(document,
		"Printed with the device filter ignored") {
		t.Error("the printed page does not say the filter was ignored")
	}
}
