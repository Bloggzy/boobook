package store

import (
	"fmt"
	"strings"
	"time"
)

// The report's figures and its sentences are read from views, exactly as the
// console summary and the CSVs are. Nothing here works anything out: a number
// in the report's prose and a number in a data file have one query behind them,
// so they cannot drift apart.

// ReportSummary is the headline accounting for a case.
type ReportSummary struct {
	Devices        int
	Tier1          int
	Tier2          int
	Tier3          int
	ReviewRequired int
	Identities     int

	Connections       int
	FileRecords       int
	AttributedRecords int
	RemovableVolumes  int

	TimelineEntries int
	// WallClockEntries is how much of the timeline is placed by converting a
	// local wall clock rather than by a recorded instant. It qualifies every
	// time in the report and so is carried beside the total, not buried.
	WallClockEntries int
	// AmbiguousEntries is how many of those have two readings an hour apart,
	// because the host observes daylight saving and the record does not say
	// which season it was written in. On a host that keeps one offset all year
	// this is zero, and the report then has no reason to raise it.
	AmbiguousEntries int
	// EpochDefaultEntries is how many entries are placed by a storage format's
	// zero rather than by a recorded moment. They are kept on the timeline and
	// left out of the span: one shortcut carrying the FAT epoch is enough to
	// report a case as beginning in 1979.
	EpochDefaultEntries int
	EarliestUTC         *time.Time
	LatestUTC           *time.Time

	// HostStarts and HostStops are the host's own boots and shutdowns. They
	// qualify every silence in the report: an hour with no records is a quiet
	// hour or an hour switched off, and only these tell the two apart. Stated
	// even when zero, because a reader has to know whether the evidence was
	// there to be read.
	HostStarts int
	HostStops  int
	// HostStopsUnexpected counts shutdowns that closed no logs — a power loss
	// or a hard stop. Absent from all five reference collections.
	HostStopsUnexpected int
	// ConnectionsEndedByShutdown counts windows with no removal recorded where
	// the host was later recorded going off, which is the ordinary reason a
	// window never closed.
	ConnectionsEndedByShutdown int

	Sources         int
	FailedSources   int
	AbsentArtefacts int
}

// Significant counts the devices the report leads with.
func (s ReportSummary) Significant() int { return s.Tier1 + s.Tier2 }

// Summary reads the headline counts.
func (s *Store) Summary() (ReportSummary, error) {
	var summary ReportSummary
	err := s.db.QueryRow(`
        SELECT devices, tier_1, tier_2, tier_3, review_required, identities,
               connections, file_records, attributed_records, removable_volumes,
               timeline_entries, wall_clock_entries, ambiguous_entries,
               epoch_default_entries, earliest_utc, latest_utc,
               host_starts, host_stops, host_stops_unexpected,
               connections_ended_by_shutdown,
               sources, failed_sources, absent_artefacts
        FROM v_report_summary`).Scan(
		&summary.Devices, &summary.Tier1, &summary.Tier2, &summary.Tier3,
		&summary.ReviewRequired, &summary.Identities,
		&summary.Connections, &summary.FileRecords, &summary.AttributedRecords,
		&summary.RemovableVolumes,
		&summary.TimelineEntries, &summary.WallClockEntries,
		&summary.AmbiguousEntries, &summary.EpochDefaultEntries,
		&summary.EarliestUTC, &summary.LatestUTC,
		&summary.HostStarts, &summary.HostStops,
		&summary.HostStopsUnexpected, &summary.ConnectionsEndedByShutdown,
		&summary.Sources, &summary.FailedSources, &summary.AbsentArtefacts)
	if err != nil {
		return summary, fmt.Errorf("report summary: %w", err)
	}
	return summary, nil
}

// Finding is one headline answer, in a sentence, with what it rests on.
type Finding struct {
	FindingID int
	Rank      int
	// Kind names the shape of the finding so the renderer can style it without
	// matching on the wording, which is data and will change.
	Kind     string
	Headline string
	Detail   string
	// Basis names the file a reader can open to argue with the finding.
	Basis string
}

// Items is the detail as the lines it was written as.
//
// A finding that names devices writes one per line, so the renderer can give
// each its own row: four devices joined into a paragraph have to be read to be
// counted. A finding whose detail is a sentence is one item, and reads as the
// sentence it is. Nothing is decided here — the view chose the wording, the
// order and the breaks, and this only hands them on.
func (f Finding) Items() []string {
	if f.Detail == "" {
		return nil
	}
	return strings.Split(f.Detail, "\n")
}

// Findings returns the headline answers, most important first.
//
// A finding with nothing behind it is absent rather than zero: a report should
// not spend the top of its page saying what it did not find.
func (s *Store) Findings() ([]Finding, error) {
	rows, err := s.db.Query(`
        SELECT finding_id, rank, kind, headline, detail, basis
        FROM v_report_finding ORDER BY rank`)
	if err != nil {
		return nil, fmt.Errorf("report findings: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var finding Finding
		if err := rows.Scan(&finding.FindingID, &finding.Rank, &finding.Kind,
			&finding.Headline, &finding.Detail, &finding.Basis); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

// SignificantTimeline reads the timeline the report shows, oldest first, and
// reports how many entries the view holds in total.
//
// The total comes back even when the rows are capped, because a section that
// quietly shows the first few hundred of several thousand entries is a section
// that misleads about the shape of the case. The renderer says how many it left
// out, and every entry is in the exported file either way.
func (s *Store) SignificantTimeline(limit int) (
	entries []TimelineEntry, total int, err error) {

	entries, err = s.Timeline(true, limit)
	if err != nil {
		return nil, 0, err
	}
	// Short of the limit, the rows are the total, and counting again would mean
	// evaluating the timeline and the classification behind it a second time for
	// a number already in hand. Only a run that filled the page has to ask.
	if limit <= 0 || len(entries) < limit {
		return entries, len(entries), nil
	}
	if err := s.db.QueryRow(
		`SELECT count(*) FROM v_timeline_significant`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("significant timeline count: %w", err)
	}
	return entries, total, nil
}

// CardDevice is one physical device as the report presents it.
//
// It embeds the same Device the inventory and devices.csv carry, so the card
// and the file cannot describe a device differently, and adds only the counts
// that cross into the volume and file layers.
type CardDevice struct {
	Device

	LinkedDriveLetters string
	VolumeLabels       string
	VolumeLinks        int

	ConnectionWindows int
	// OpenEndedWindows counts arrivals with no removal after them, and
	// UnknownStartWindows removals with no arrival before them. Both are shapes
	// the evidence genuinely leaves, and tidying either away would manufacture
	// a boundary nothing recorded.
	OpenEndedWindows    int
	UnknownStartWindows int
	FirstStartedUTC     *time.Time
	LastEndedUTC        *time.Time

	FileRecords  int
	FilePaths    int
	FileLetters  int
	FirstFileUTC *time.Time
	LastFileUTC  *time.Time
	// FileConfidence is the strongest route that reached this device. A count
	// without it would say nothing about how firmly the files were linked.
	FileConfidence string

	// Fields, Facts and Sources are the drill-downs behind the card.
	Fields  []DeviceField
	Facts   []DeviceFact
	Sources []DeviceSource
}

// DeviceField is one value on a card with the record that carried it.
type DeviceField struct {
	Field string
	Value string
	// Note qualifies the value without altering it — a Windows-generated serial
	// is still what the evidence holds, and is shown rather than suppressed.
	Note     string
	Locator  string
	SourceID string
	// SourcePath and SourceSHA256 are what makes a card checkable: the file the
	// value came from, and the hash of that file as this run read it.
	SourcePath   string
	SourceSHA256 string
	// DistinctValues is how many different values the identities in the group
	// carried for this field. More than one means there was a choice.
	DistinctValues int
}

// Label renders a field name for display.
func (f DeviceField) Label() string {
	return strings.ReplaceAll(f.Field, "_", " ")
}

// Disputed reports whether the identities disagreed about this field.
func (f DeviceField) Disputed() bool { return f.DistinctValues > 1 }

// DeviceFact is one derived fact with the evidence that produced it.
type DeviceFact struct {
	Fact     string
	Evidence string
}

// DeviceSource is a file the evidence for a device was read from.
type DeviceSource struct {
	Evidence   string
	Artefact   string
	SourcePath string
	SHA256     string
	Records    int
}

// Cards returns the devices the report leads with, with their drill-downs.
//
// maxTier bounds what "leads with" means: 2 for the significant section, 3 for
// everything. Nothing is dropped from the exported files either way.
func (s *Store) Cards(maxTier int) ([]CardDevice, error) {
	rows, err := s.db.Query(deviceQueryFrom("v_report_device")+
		" AND tier <= ?"+deviceOrder, maxTier)
	if err != nil {
		return nil, fmt.Errorf("report cards: %w", err)
	}
	defer rows.Close()

	var cards []CardDevice
	for rows.Next() {
		var card CardDevice
		targets := append(deviceScanTargets(&card.Device),
			&card.LinkedDriveLetters, &card.VolumeLabels, &card.VolumeLinks,
			&card.ConnectionWindows, &card.OpenEndedWindows,
			&card.UnknownStartWindows, &card.FirstStartedUTC, &card.LastEndedUTC,
			&card.FileRecords, &card.FilePaths, &card.FileLetters,
			&card.FirstFileUTC, &card.LastFileUTC, &card.FileConfidence)
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		cards = append(cards, card)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return cards, s.fillCards(cards)
}

// fillCards attaches the drill-downs.
//
// Each relation is read once for every device and distributed here, rather than
// queried per card. Three queries per device is thirty round trips into a view
// that has to be planned each time, and it took a run from eight seconds to
// nineteen. Distributing rows is not deciding anything: the rows are what the
// views produced, in the order they produced them.
func (s *Store) fillCards(cards []CardDevice) error {
	index := make(map[string]*CardDevice, len(cards))
	for position := range cards {
		index[cards[position].PhysicalDeviceID] = &cards[position]
	}

	fields, err := s.db.Query(`
        SELECT physical_device_id, field, value, note, locator, source_id,
               source_path, source_sha256, distinct_values
        FROM v_report_device_field ORDER BY physical_device_id, ordinal`)
	if err != nil {
		return fmt.Errorf("device fields: %w", err)
	}
	for fields.Next() {
		var id string
		var field DeviceField
		if err := fields.Scan(&id, &field.Field, &field.Value, &field.Note,
			&field.Locator, &field.SourceID, &field.SourcePath,
			&field.SourceSHA256, &field.DistinctValues); err != nil {
			fields.Close()
			return err
		}
		// A row for a device outside the tier bound has no card. That is how
		// the bound is applied, and it is not a loss: every row is in the
		// exported files whatever the report shows.
		if card := index[id]; card != nil {
			card.Fields = append(card.Fields, field)
		}
	}
	fields.Close()
	if err := fields.Err(); err != nil {
		return err
	}

	facts, err := s.db.Query(`
        SELECT physical_device_id, fact, evidence FROM v_device_fact
        ORDER BY physical_device_id, fact, evidence`)
	if err != nil {
		return fmt.Errorf("device facts: %w", err)
	}
	for facts.Next() {
		var id string
		var fact DeviceFact
		if err := facts.Scan(&id, &fact.Fact, &fact.Evidence); err != nil {
			facts.Close()
			return err
		}
		if card := index[id]; card != nil {
			card.Facts = append(card.Facts, fact)
		}
	}
	facts.Close()
	if err := facts.Err(); err != nil {
		return err
	}

	sources, err := s.db.Query(`
        SELECT physical_device_id, evidence, artefact, source_path, sha256,
               records
        FROM v_report_device_source
        ORDER BY physical_device_id, evidence, source_path`)
	if err != nil {
		return fmt.Errorf("device sources: %w", err)
	}
	defer sources.Close()
	for sources.Next() {
		var id string
		var source DeviceSource
		if err := sources.Scan(&id, &source.Evidence, &source.Artefact,
			&source.SourcePath, &source.SHA256, &source.Records); err != nil {
			return err
		}
		if card := index[id]; card != nil {
			card.Sources = append(card.Sources, source)
		}
	}
	return sources.Err()
}

// OtherDevices returns the tier 3 devices, by category and then by score.
//
// They carry no drill-downs. Seventy devices with eleven cited fields each is a
// megabyte of page nobody opens, and the tier the classification put them in is
// the statement that they are unlikely to matter; devices.csv and
// device-facts.csv hold the same detail for the ones that do.
func (s *Store) OtherDevices() ([]Device, error) {
	rows, err := s.db.Query(deviceQueryFrom("v_device_classified") +
		" AND tier >= 3\nORDER BY category, score DESC, event_count DESC," +
		" physical_device_id")
	if err != nil {
		return nil, fmt.Errorf("other devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		if err := rows.Scan(deviceScanTargets(&device)...); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

// FileActivity is one file or folder record as it reached one device.
type FileActivity struct {
	PhysicalDeviceID string
	DeviceLabel      string
	Tier             int

	ActivityID int
	// Confidence is how firmly this record reached this device, and Route and
	// Reason say how it got there. The reason travels with the row because
	// "probable" means a different thing by each route, and a reader deciding
	// what to do with a link needs the route rather than the ranking word.
	Confidence       string
	ConfidenceRank   int
	Route            string
	Reason           string
	CandidateDevices int

	Artefact string
	Detail   string
	Path     string

	DriveLetter string
	VolumeLabel string
	Profile     string

	RecordedUTC     *time.Time
	RecordedMeaning string
	// EpochDefault names the format zero the recorded time turned out to be,
	// and is empty for a time that means something.
	EpochDefault string

	SourceID     string
	SourcePath   string
	SourceSHA256 string
}

// Contested reports that another device claims this record too.
func (f FileActivity) Contested() bool { return f.CandidateDevices > 1 }

// FileActivity reads the attributed records, strongest link first within each
// device, and reports how many the view holds in total.
func (s *Store) FileActivity(limit int) (rows []FileActivity, total int, err error) {
	statement := `
        SELECT physical_device_id, device_label, tier, activity_id,
               confidence, confidence_rank, route, reason, candidate_devices,
               artefact, detail, path, drive_letter, volume_label, profile,
               recorded_utc, recorded_meaning, epoch_default,
               source_id, source_path, source_sha256
        FROM v_report_file_activity`
	if limit > 0 {
		statement += fmt.Sprintf(" LIMIT %d", limit)
	}

	result, err := s.db.Query(statement)
	if err != nil {
		return nil, 0, fmt.Errorf("report file activity: %w", err)
	}
	defer result.Close()

	for result.Next() {
		var row FileActivity
		if err := result.Scan(&row.PhysicalDeviceID, &row.DeviceLabel, &row.Tier,
			&row.ActivityID, &row.Confidence, &row.ConfidenceRank, &row.Route,
			&row.Reason, &row.CandidateDevices, &row.Artefact, &row.Detail,
			&row.Path, &row.DriveLetter, &row.VolumeLabel, &row.Profile,
			&row.RecordedUTC, &row.RecordedMeaning, &row.EpochDefault,
			&row.SourceID, &row.SourcePath, &row.SourceSHA256); err != nil {
			return nil, 0, err
		}
		rows = append(rows, row)
	}
	if err := result.Err(); err != nil {
		return nil, 0, err
	}

	// Short of the limit the rows are the total; see SignificantTimeline.
	if limit <= 0 || len(rows) < limit {
		return rows, len(rows), nil
	}
	if err := s.db.QueryRow(
		`SELECT count(*) FROM v_report_file_activity`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("file activity count: %w", err)
	}
	return rows, total, nil
}

// FileGap is a file or folder record that reached no device, and why.
type FileGap struct {
	ActivityID      int
	Artefact        string
	Detail          string
	Path            string
	DriveLetter     string
	Profile         string
	RecordedUTC     *time.Time
	RecordedMeaning string
	// Reason is what stopped the record reaching a device. A gap with no reason
	// beside it reads as a failure of this tool rather than of the evidence.
	Reason string
	// EpochDefault names the format zero the recorded time turned out to be.
	EpochDefault string
	SourceID     string
	SourcePath   string
	SourceSHA256 string
}

// FileGaps reads the records that reached no device.
func (s *Store) FileGaps(limit int) (rows []FileGap, total int, err error) {
	statement := `
        SELECT activity_id, artefact, detail, path, drive_letter, profile,
               recorded_utc, recorded_meaning, reason, epoch_default,
               source_id, source_path, source_sha256
        FROM v_report_file_unattributed`
	if limit > 0 {
		statement += fmt.Sprintf(" LIMIT %d", limit)
	}

	result, err := s.db.Query(statement)
	if err != nil {
		return nil, 0, fmt.Errorf("report file gaps: %w", err)
	}
	defer result.Close()

	for result.Next() {
		var row FileGap
		if err := result.Scan(&row.ActivityID, &row.Artefact, &row.Detail,
			&row.Path, &row.DriveLetter, &row.Profile, &row.RecordedUTC,
			&row.RecordedMeaning, &row.Reason, &row.EpochDefault, &row.SourceID,
			&row.SourcePath, &row.SourceSHA256); err != nil {
			return nil, 0, err
		}
		rows = append(rows, row)
	}
	if err := result.Err(); err != nil {
		return nil, 0, err
	}

	if limit <= 0 || len(rows) < limit {
		return rows, len(rows), nil
	}
	if err := s.db.QueryRow(
		`SELECT count(*) FROM v_report_file_unattributed`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("file gap count: %w", err)
	}
	return rows, total, nil
}

// Coverage is what was read of one artefact kind.
type Coverage struct {
	Artefact string
	Sources  int
	Bytes    int64
	Replayed int
	// NotReplayed counts hives parsed without their transaction logs, which may
	// be missing their most recent writes — the window an examiner cares about
	// most.
	NotReplayed int
	Failed      int
	Malformed   int
}

// Coverage reports what the run read, by artefact.
func (s *Store) Coverage() ([]Coverage, error) {
	rows, err := s.db.Query(`
        SELECT artefact, sources, coalesce(bytes, 0), replayed, not_replayed,
               failed, malformed
        FROM v_report_coverage`)
	if err != nil {
		return nil, fmt.Errorf("report coverage: %w", err)
	}
	defer rows.Close()

	var coverage []Coverage
	for rows.Next() {
		var row Coverage
		if err := rows.Scan(&row.Artefact, &row.Sources, &row.Bytes,
			&row.Replayed, &row.NotReplayed, &row.Failed,
			&row.Malformed); err != nil {
			return nil, err
		}
		coverage = append(coverage, row)
	}
	return coverage, rows.Err()
}

// PrefetchSetting returns the host's prefetcher configuration as one sentence,
// or empty where no SYSTEM hive was read.
//
// It is a limitation rather than a finding: it says what the absence of
// prefetch evidence is allowed to mean. On a host with prefetching disabled,
// "nothing ran from this device" is not something the evidence can support.
func (s *Store) PrefetchSetting() (string, error) {
	var description string
	err := s.db.QueryRow(`
        SELECT coalesce(min(description), '') FROM v_host_prefetch_setting`).
		Scan(&description)
	if err != nil {
		return "", fmt.Errorf("prefetch setting: %w", err)
	}
	return description, nil
}

// Limitation is something the run could not read, or that was not there.
type Limitation struct {
	Severity string
	Artefact string
	Path     string
	Message  string
}

// Limitations returns what the evidence did not yield.
//
// "The file was absent" and "the file was there and would not parse" are
// different claims about a collection, so the severity stays on the row.
func (s *Store) Limitations() ([]Limitation, error) {
	rows, err := s.db.Query(`
        SELECT severity, artefact, coalesce(path, ''), message
        FROM v_report_limitation`)
	if err != nil {
		return nil, fmt.Errorf("report limitations: %w", err)
	}
	defer rows.Close()

	var limitations []Limitation
	for rows.Next() {
		var row Limitation
		if err := rows.Scan(&row.Severity, &row.Artefact, &row.Path,
			&row.Message); err != nil {
			return nil, err
		}
		limitations = append(limitations, row)
	}
	return limitations, rows.Err()
}

// PrefetchRun is one programme a device carried, as the report groups it.
//
// RanFrom is the distinction the section turns on. A programme executed off a
// device and one on the system disk that merely opened a file on it reach the
// device through the same chain, and reporting them together would say four
// programmes ran from a stick when one did.
type PrefetchRun struct {
	PhysicalDeviceID string
	DeviceLabel      string
	Tier             int

	Executable string
	RanFrom    bool

	// RunCount is what Windows counted; TimesRecorded is how many of those
	// executions this file still holds. They are different numbers and both are
	// shown: Windows keeps the last eight and overwrites the rest, so the
	// second is a floor and the first is the tally.
	RunCount      int
	TimesRecorded int
	FirstRunUTC   *time.Time
	LastRunUTC    *time.Time
	// ExecutionTimes is the surviving executions, newest first, one per line.
	ExecutionTimes string

	// FilesLoaded counts what this programme read from *this* device, and Files
	// lists them. A prefetch file names every volume the loader touched, so the
	// count is per volume rather than the file list as a whole.
	FilesLoaded int
	Files       string

	DriveLetter      string
	VolumeLabel      string
	VolumeSerialHex  string
	VolumeRoute      string
	VolumeConfidence string
	// LetterContradicted is the record's own label naming a different device
	// than the letter reaches.
	LetterContradicted bool

	ParseWarnings string
	SourceID      string
	SourceFile    string
	SourcePath    string
	SourceSHA256  string
}

// Executions splits the recorded execution times into lines.
func (p PrefetchRun) Executions() []string {
	if p.ExecutionTimes == "" {
		return nil
	}
	return strings.Split(p.ExecutionTimes, "\n")
}

// LoadedFiles splits the files this programme read from the device.
func (p PrefetchRun) LoadedFiles() []string {
	if p.Files == "" {
		return nil
	}
	return strings.Split(p.Files, "\n")
}

// Prefetch reads the executions each device carried.
func (s *Store) Prefetch() ([]PrefetchRun, error) {
	result, err := s.db.Query(`
        SELECT physical_device_id, device_label, tier, executable, ran_from,
               run_count, times_recorded, first_run_utc, last_run_utc,
               execution_times, files_loaded, files, drive_letter, volume_label,
               volume_serial_hex, volume_route, volume_confidence,
               letter_contradicted, parse_warnings, source_id, source_file,
               source_path, source_sha256
        FROM v_report_prefetch`)
	if err != nil {
		return nil, fmt.Errorf("report prefetch: %w", err)
	}
	defer result.Close()

	var rows []PrefetchRun
	for result.Next() {
		var row PrefetchRun
		if err := result.Scan(&row.PhysicalDeviceID, &row.DeviceLabel,
			&row.Tier, &row.Executable, &row.RanFrom, &row.RunCount,
			&row.TimesRecorded, &row.FirstRunUTC, &row.LastRunUTC,
			&row.ExecutionTimes, &row.FilesLoaded, &row.Files,
			&row.DriveLetter, &row.VolumeLabel, &row.VolumeSerialHex,
			&row.VolumeRoute, &row.VolumeConfidence, &row.LetterContradicted,
			&row.ParseWarnings, &row.SourceID, &row.SourceFile,
			&row.SourcePath, &row.SourceSHA256); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, result.Err()
}
