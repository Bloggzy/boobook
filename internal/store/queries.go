package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Device is one physical device: every identity the evidence named it under,
// grouped into the thing an analyst would hold in their hand.
//
// Read from v_physical_device, the same view devices.csv is copied from, so the
// console summary and the exported file cannot report different numbers.
type Device struct {
	// PhysicalDeviceID is the identity that speaks for the group, chosen by a
	// total ordering so it is the same on every run over the same evidence.
	PhysicalDeviceID string
	IdentityCount    int
	Identities       string
	Enumerators      string
	// GroupingMethods names the routes that grouped the identities, so a reader
	// who disagrees with a grouping can see what made it.
	GroupingMethods string

	// Category, Tier and Score are the classification. Score is clamped to
	// 0-100 so two cases can be compared; the unclamped figure is in the
	// exported file beside it.
	Category  string
	Tier      int
	Relevance string
	Score     float64
	// ReviewRequired is a flag and not a tier. A tier 3 keyboard with a
	// duplicated serial still needs looking at, and demoting it would hide that.
	ReviewRequired       bool
	ClassificationReason string
	ReviewReason         string

	DeviceInstanceID string
	Serial           string
	// IdentityNotUnique means no identity in the group reported a serial, so
	// nothing here separates this device from another of the same model.
	IdentityNotUnique bool
	FriendlyName      string
	// DeviceLabel is v_device_label's answer: the name every part of the report
	// calls this device, with the serial appended where two devices would
	// otherwise share one. Label() prefers it.
	DeviceLabel     string
	DeviceDesc      string
	BusReportedDesc string
	Mfg             string
	Class           string

	// InRegistry false means the device was named only by event, SetupAPI or
	// portable-device evidence. Its registry key is not in this collection —
	// deleted, in a hive that was not collected, or never written.
	InRegistry          bool
	PortableNames       string
	CurrentDriveLetters string

	EventCount        int
	ConnectEvents     int
	DisconnectEvents  int
	SetupSections     int
	FirstSeenUTC      *time.Time
	LastSeenUTC       *time.Time
	FirstConnectUTC   *time.Time
	LastDisconnectUTC *time.Time
	EvidenceSources   string
}

// Label is the name this device is called wherever the report names it.
//
// DeviceLabel is v_device_label's answer and is preferred outright, because
// that view is the one place the project decides what a device is called — it
// refuses a drive path, prefers a product name from a software node over a
// generic description from the USB node above it, and appends the serial where
// two devices would otherwise share one name. A Go-side coalesce that did some
// of that was deleted once already; this is what remains of the one that got
// away, kept only for the case where the view has nothing.
//
// The fallback matters on that case alone. A stored description of the form
// "@oem47.inf,%DeviceName%" is an unresolved reference into a resource file,
// not a name. It is used only when nothing readable exists, because it is still
// what the hive holds.
func (d Device) Label() string {
	if d.DeviceLabel != "" {
		return d.DeviceLabel
	}
	candidates := []string{
		d.FriendlyName, d.BusReportedDesc, d.DeviceDesc, d.DeviceInstanceID,
	}

	for _, candidate := range candidates {
		if candidate != "" && !strings.HasPrefix(candidate, "@") {
			return candidate
		}
	}
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return d.PhysicalDeviceID
}

// IdentityList splits the grouped identities for display, in the order the
// grouping preferred them.
func (d Device) IdentityList() []string {
	if d.Identities == "" {
		return nil
	}
	return strings.Split(d.Identities, "; ")
}

// Columns are named rather than selected with *, so a change to the view's
// column order cannot silently shift values into the wrong fields.
const deviceColumns = `
       physical_device_id, identity_count, identities, enumerators,
       grouping_methods,
       category, tier, relevance, score, review_required,
       classification_reason, review_reason,
       device_instance_id, serial, identity_not_unique,
       friendly_name, device_label, device_desc, bus_reported_desc, mfg, class,
       in_registry, portable_names, current_drive_letters,
       event_count, connect_events, disconnect_events, setup_sections,
       first_seen_utc, last_seen_utc, first_connect_utc, last_disconnect_utc,
       evidence_sources`

// deviceScanTargets pairs with deviceColumns. They are written beside each
// other because the one way to get this wrong is to add a column to one and
// not the other, and the result is a report whose fields are shifted by one.
func deviceScanTargets(device *Device) []any {
	return []any{
		&device.PhysicalDeviceID, &device.IdentityCount, &device.Identities,
		&device.Enumerators, &device.GroupingMethods,
		&device.Category, &device.Tier, &device.Relevance, &device.Score,
		&device.ReviewRequired, &device.ClassificationReason, &device.ReviewReason,
		&device.DeviceInstanceID, &device.Serial, &device.IdentityNotUnique,
		&device.FriendlyName, &device.DeviceLabel, &device.DeviceDesc,
		&device.BusReportedDesc,
		&device.Mfg, &device.Class,
		&device.InRegistry, &device.PortableNames, &device.CurrentDriveLetters,
		&device.EventCount, &device.ConnectEvents, &device.DisconnectEvents,
		&device.SetupSections,
		&device.FirstSeenUTC, &device.LastSeenUTC,
		&device.FirstConnectUTC, &device.LastDisconnectUTC,
		&device.EvidenceSources,
	}
}

// deviceQueryFrom builds the inventory query over a view that carries the
// device columns, with the card columns after them where the view has any. It
// ends in a WHERE so a caller can bound it.
func deviceQueryFrom(view string) string {
	extra := ""
	if view != "v_device_classified" {
		extra = `,
       linked_drive_letters, volume_labels, volume_links,
       connection_windows, open_ended_windows, unknown_start_windows,
       first_started_utc, last_ended_utc,
       file_records, file_paths, file_letters,
       first_file_utc, last_file_utc, file_confidence`
	}
	return "SELECT" + deviceColumns + extra + "\nFROM " + view + "\nWHERE true"
}

const deviceOrder = `
ORDER BY tier, score DESC, event_count DESC, physical_device_id`

// Devices returns the device inventory.
func (s *Store) Devices() ([]Device, error) {
	rows, err := s.db.Query(deviceQueryFrom("v_device_classified") + deviceOrder)
	if err != nil {
		return nil, fmt.Errorf("device inventory: %w", err)
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

// CandidateLink is a link between two identities that was reported and not
// acted on, with whether the grouping reached the same conclusion by another
// route.
type CandidateLink struct {
	DeviceKey      string
	OtherDeviceKey string
	Method         string
	AlreadyGrouped bool
	Reason         string
}

// CandidateLinks returns the links Boobook declined to group on.
func (s *Store) CandidateLinks() ([]CandidateLink, error) {
	rows, err := s.db.Query(`
        SELECT device_key, other_device_key, method, already_grouped, reason
        FROM v_device_candidate_link`)
	if err != nil {
		return nil, fmt.Errorf("candidate links: %w", err)
	}
	defer rows.Close()

	var links []CandidateLink
	for rows.Next() {
		var link CandidateLink
		if err := rows.Scan(&link.DeviceKey, &link.OtherDeviceKey,
			&link.Method, &link.AlreadyGrouped, &link.Reason); err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// RemovableVolume is the file activity one removable volume recorded.
type RemovableVolume struct {
	VolumeSerialHex string
	VolumeLabel     string
	DriveLetter     string
	TargetCount     int
	DistinctPaths   int
	Profiles        int
	// FirstInteraction and LastInteraction span the times somebody used this
	// volume. Nil where no record on it carries an interaction time at all —
	// which is a finding, and used to be filled in with the earliest target
	// write time, a value that can predate the volume reaching this host.
	FirstInteraction *time.Time
	LastInteraction  *time.Time
	// UndatedRecords is how many records on this volume carry no time for
	// anybody having used them, so the range above does not cover them.
	UndatedRecords int
}

// RemovableVolumes returns file activity grouped by the volume that recorded
// it. Grouped by serial and not by drive letter: a letter is reused, and the
// reference evidence has one letter carrying two different volumes.
func (s *Store) RemovableVolumes() ([]RemovableVolume, error) {
	rows, err := s.db.Query(`
        SELECT volume_serial_hex, volume_label, drive_letter,
               target_count, distinct_paths, profiles,
               first_interaction_utc, last_interaction_utc, undated_records
        FROM v_removable_volume`)
	if err != nil {
		return nil, fmt.Errorf("removable volumes: %w", err)
	}
	defer rows.Close()

	var volumes []RemovableVolume
	for rows.Next() {
		var volume RemovableVolume
		if err := rows.Scan(&volume.VolumeSerialHex, &volume.VolumeLabel,
			&volume.DriveLetter, &volume.TargetCount, &volume.DistinctPaths,
			&volume.Profiles,
			&volume.FirstInteraction, &volume.LastInteraction,
			&volume.UndatedRecords,
		); err != nil {
			return nil, err
		}
		volumes = append(volumes, volume)
	}
	return volumes, rows.Err()
}

// Connection is one interval a device was connected.
type Connection struct {
	DeviceKey        string
	DeviceInstanceID string
	// StartedUTC is nil where the device was already connected when the
	// evidence begins. EndedUTC is nil where the evidence never says it was
	// removed — an open window, not a window that ends with the log.
	StartedUTC *time.Time
	EndedUTC   *time.Time
	// EndedBeforeUTC is set where the window was closed by the device arriving
	// again with no removal logged in between. It left at some point before
	// this and nothing says when, so this bounds the window rather than ending
	// it — the difference between a device that may still be attached and one
	// that certainly is not.
	EndedBeforeUTC *time.Time
	StartKnown     bool
	OpenEnded      bool
	// SpanSeconds is the distance between the opening and closing records, not
	// the time the device was connected. Nothing records whether it stayed
	// connected in between, and a log that rolled leaves this same shape.
	SpanSeconds       *int64
	OpenedBy          string
	ClosedBy          string
	SupportingRecords int
}

// Connections returns the connection windows, most recent first.
func (s *Store) Connections() ([]Connection, error) {
	rows, err := s.db.Query(`
        SELECT device_key, device_instance_id, started_utc, ended_utc,
               ended_before_utc, start_known, open_ended, span_seconds,
               coalesce(opened_by, ''), coalesce(closed_by, ''),
               supporting_records
        FROM v_connection
        ORDER BY coalesce(started_utc, ended_utc) DESC`)
	if err != nil {
		return nil, fmt.Errorf("connections: %w", err)
	}
	defer rows.Close()

	var connections []Connection
	for rows.Next() {
		var connection Connection
		if err := rows.Scan(&connection.DeviceKey, &connection.DeviceInstanceID,
			&connection.StartedUTC, &connection.EndedUTC,
			&connection.EndedBeforeUTC,
			&connection.StartKnown, &connection.OpenEnded,
			&connection.SpanSeconds, &connection.OpenedBy,
			&connection.ClosedBy, &connection.SupportingRecords,
		); err != nil {
			return nil, err
		}
		connections = append(connections, connection)
	}
	return connections, rows.Err()
}

// VolumeLink is one route from a volume to a device.
type VolumeLink struct {
	DeviceKey        string
	DeviceInstanceID string
	VolumeKind       string
	VolumeID         string
	DriveLetter      string
	VolumeLabel      string
	Route            string
	Confidence       string
	Detail           string
}

// VolumeLinks returns every device-volume link, strongest route first.
func (s *Store) VolumeLinks() ([]VolumeLink, error) {
	rows, err := s.db.Query(`
        SELECT device_key, device_instance_id, volume_kind, volume_id,
               drive_letter, volume_label, route, confidence, detail
        FROM v_device_volume_link
        ORDER BY CASE confidence
                     WHEN 'confirmed' THEN 0 WHEN 'strong' THEN 1
                     WHEN 'probable'  THEN 2 ELSE 3 END,
                 drive_letter, volume_id`)
	if err != nil {
		return nil, fmt.Errorf("device volume links: %w", err)
	}
	defer rows.Close()

	var links []VolumeLink
	for rows.Next() {
		var link VolumeLink
		if err := rows.Scan(&link.DeviceKey, &link.DeviceInstanceID,
			&link.VolumeKind, &link.VolumeID, &link.DriveLetter,
			&link.VolumeLabel, &link.Route, &link.Confidence, &link.Detail,
		); err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

// AmbiguousLabels returns volume labels recorded for more than one device.
//
// These are a finding rather than a failure: they are the reason a volume that
// looks identifiable by its label is not.
func (s *Store) AmbiguousLabels() (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT volume_label, device_count FROM v_ambiguous_label`)
	if err != nil {
		return nil, fmt.Errorf("ambiguous labels: %w", err)
	}
	defer rows.Close()

	labels := map[string]int{}
	for rows.Next() {
		var label string
		var count int
		if err := rows.Scan(&label, &count); err != nil {
			return nil, err
		}
		labels[label] = count
	}
	return labels, rows.Err()
}

// Attribution is one file record and the devices the evidence reaches from it.
type Attribution struct {
	Path             string
	DriveLetter      string
	VolumeLabel      string
	Artefact         string
	BestConfidence   string
	CandidateDevices int
	Devices          string
	RoutesUsed       string
}

// Attributions returns file records with more than one candidate device, or
// with none.
//
// These are the rows worth an analyst's attention: a record with two candidates
// is a question the evidence has not settled, and one with none is a gap that
// should be visible rather than absent from the output.
func (s *Store) Attributions() (contested, unattributed []Attribution, err error) {
	rows, err := s.db.Query(`
        SELECT path, drive_letter, volume_label, artefact, best_confidence,
               candidate_devices, coalesce(devices, ''), coalesce(routes_used, '')
        FROM v_file_attribution_summary
        WHERE candidate_devices <> 1
        ORDER BY candidate_devices DESC, drive_letter, path`)
	if err != nil {
		return nil, nil, fmt.Errorf("file attribution: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var row Attribution
		if err := rows.Scan(&row.Path, &row.DriveLetter, &row.VolumeLabel,
			&row.Artefact, &row.BestConfidence, &row.CandidateDevices,
			&row.Devices, &row.RoutesUsed); err != nil {
			return nil, nil, err
		}
		if row.CandidateDevices == 0 {
			unattributed = append(unattributed, row)
			continue
		}
		contested = append(contested, row)
	}
	return contested, unattributed, rows.Err()
}

// UnattributedByLetter counts file records that reached no device, by the drive
// letter they name.
//
// Grouped by letter because that is the explanation: a record reaches no device
// when nothing links its letter to one. Most are on the internal disk, and a
// bare total invites that to be read as a parsing failure.
func (s *Store) UnattributedByLetter() (map[string]int, error) {
	rows, err := s.db.Query(`
        SELECT CASE WHEN drive_letter = '' THEN '(no letter)' ELSE drive_letter END,
               count(*)
        FROM v_file_attribution_summary
        WHERE candidate_devices = 0
        GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return nil, fmt.Errorf("unattributed records: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var letter string
		var count int
		if err := rows.Scan(&letter, &count); err != nil {
			return nil, err
		}
		counts[letter] = count
	}
	return counts, rows.Err()
}

// AttributionCounts reports how many file records reached a device at each
// confidence.
func (s *Store) AttributionCounts() (map[string]int, error) {
	rows, err := s.db.Query(`
        SELECT best_confidence, count(*)
        FROM v_file_attribution_summary GROUP BY 1`)
	if err != nil {
		return nil, fmt.Errorf("attribution counts: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var confidence string
		var count int
		if err := rows.Scan(&confidence, &count); err != nil {
			return nil, err
		}
		counts[confidence] = count
	}
	return counts, rows.Err()
}

// LetterActivity counts what each drive letter carried, by artefact.
type LetterActivity struct {
	DriveLetter string
	Artefact    string
	Records     int
	FirstLocal  string
	LastLocal   string
}

// LetterActivity reports file and folder records per drive letter.
//
// A letter is not a device. This is the set of records that name a letter, from
// whichever artefact named it, so an analyst asking "what was on E:" does not
// have to know which of four registry keys and two file formats to look in.
func (s *Store) LetterActivity() ([]LetterActivity, error) {
	rows, err := s.db.Query(`
        SELECT drive_letter, artefact, count(*) AS records,
               coalesce(min(recorded_local), '') AS first_local,
               coalesce(max(recorded_local), '') AS last_local
        FROM v_letter_activity
        GROUP BY drive_letter, artefact
        ORDER BY drive_letter, artefact`)
	if err != nil {
		return nil, fmt.Errorf("letter activity: %w", err)
	}
	defer rows.Close()

	var activity []LetterActivity
	for rows.Next() {
		var row LetterActivity
		if err := rows.Scan(&row.DriveLetter, &row.Artefact, &row.Records,
			&row.FirstLocal, &row.LastLocal); err != nil {
			return nil, err
		}
		activity = append(activity, row)
	}
	return activity, rows.Err()
}

// TimelineEntry is one timestamped record, whatever artefact holds it.
//
// TimeUTC and TimeLocal are separate because the records are: an event log
// carries a UTC instant, a setupapi section and a shell item carry local wall
// clock with no zone. TimeBasis says which the row rests on, and TimeUTCAlt
// carries the other seasonal reading where the season is not recorded.
type TimelineEntry struct {
	EntryID    int
	SortUTC    *time.Time
	TimeUTC    *time.Time
	TimeUTCAlt *time.Time
	TimeLocal  string
	TimeBasis  string
	// TimeAmbiguous means the wall clock has two UTC readings and the record
	// does not say which season it was written in.
	TimeAmbiguous bool
	// EpochDefault names the format zero this row's time turned out to be —
	// the FAT epoch, FILETIME zero, the Unix epoch — and is empty for a time
	// that means something. The row is still shown, because the record is real
	// and only its timestamp is not, but it sets no edge of the evidence span.
	EpochDefault string

	Category string
	Event    string
	Meaning  string

	DeviceKey        string
	PhysicalDeviceID string
	DeviceLabel      string

	DriveLetter string
	Path        string
	Profile     string
	Confidence  string

	Artefact   string
	Detail     string
	SourceID   string
	SourcePath string
}

// Label is what a timeline row shows for the thing the entry concerns.
//
// A file entry names the file. The device it was attributed to is on the row
// beside it, but the file is what the entry is about, and showing the device
// instead makes six openings of six files read as six identical lines.
func (e TimelineEntry) Label() string {
	switch {
	case e.Category == "file" && e.Path != "":
		return e.Path
	case e.DeviceLabel != "":
		return e.DeviceLabel
	case e.Path != "":
		return e.Path
	case e.DriveLetter != "":
		return e.DriveLetter + ":"
	default:
		return e.Detail
	}
}

// Timeline returns the timeline, oldest first. Passing significantOnly reads
// the same view filtered to tier 1 and tier 2 devices; nothing is dropped from
// the exported file either way.
func (s *Store) Timeline(significantOnly bool, limit int) ([]TimelineEntry, error) {
	view := "v_timeline"
	if significantOnly {
		view = "v_timeline_significant"
	}
	statement := `
        SELECT entry_id, sort_utc, time_utc, time_utc_alt, time_local,
               time_basis, time_ambiguous, epoch_default, category, event, meaning,
               device_key, physical_device_id, device_label,
               drive_letter, path, profile, confidence,
               artefact, detail, source_id, source_path
        FROM ` + view + ` ORDER BY entry_id`
	if limit > 0 {
		statement += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := s.db.Query(statement)
	if err != nil {
		return nil, fmt.Errorf("timeline: %w", err)
	}
	defer rows.Close()

	var entries []TimelineEntry
	for rows.Next() {
		var entry TimelineEntry
		if err := rows.Scan(&entry.EntryID, &entry.SortUTC, &entry.TimeUTC,
			&entry.TimeUTCAlt, &entry.TimeLocal, &entry.TimeBasis,
			&entry.TimeAmbiguous, &entry.EpochDefault, &entry.Category,
			&entry.Event, &entry.Meaning,
			&entry.DeviceKey, &entry.PhysicalDeviceID, &entry.DeviceLabel,
			&entry.DriveLetter, &entry.Path, &entry.Profile, &entry.Confidence,
			&entry.Artefact, &entry.Detail, &entry.SourceID, &entry.SourcePath,
		); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// TimelineSpan reports how many entries the timeline holds, how many rest on a
// wall clock rather than a recorded instant, and the instants it runs between.
func (s *Store) TimelineSpan() (entries, wallClock, ambiguous int,
	earliest, latest *time.Time, err error) {

	err = s.db.QueryRow(`
        SELECT count(*),
               count(*) FILTER (WHERE time_basis <> 'recorded_utc'),
               count(*) FILTER (WHERE time_ambiguous),
               -- The span excludes rows placed by a format's zero, exactly as
               -- v_report_summary does. The console line and the report head
               -- have to say the same thing about when the evidence begins.
               min(sort_utc) FILTER (WHERE epoch_default = ''),
               max(sort_utc) FILTER (WHERE epoch_default = '')
        FROM v_timeline`).Scan(&entries, &wallClock, &ambiguous, &earliest, &latest)
	if err != nil {
		return 0, 0, 0, nil, nil, fmt.Errorf("timeline span: %w", err)
	}
	return entries, wallClock, ambiguous, earliest, latest, nil
}

// HostTimeZone reports the host zone the timeline converts wall clocks with.
// Found is false where none was recovered, in which case a wall clock has no
// UTC reading at all.
//
// Observes is whether the host actually changes its clock. It is reported
// separately from the daylight offset because the two disagree: Windows stores
// a daylight bias for a zone whether or not the transitions are ever taken, so
// naming that offset on a host that never takes it describes a season the
// evidence cannot have been written in.
func (s *Store) HostTimeZone() (name string, standardOffset, daylightOffset int,
	observes, found bool, err error) {

	row := s.db.QueryRow(`
        SELECT key_name, standard_offset_minutes, daylight_offset_minutes,
               observes_daylight_saving
        FROM v_host_time_zone LIMIT 1`)
	switch err := row.Scan(&name, &standardOffset, &daylightOffset, &observes); err {
	case nil:
		return name, standardOffset, daylightOffset, observes, true, nil
	case sql.ErrNoRows:
		return "", 0, 0, false, false, nil
	default:
		return "", 0, 0, false, false, fmt.Errorf("host time zone: %w", err)
	}
}

// CountByEnumerator reports how many devnodes each enumerator contributed.
func (s *Store) CountByEnumerator() (map[string]int, error) {
	rows, err := s.db.Query(
		`SELECT enumerator, count(*) FROM devnode GROUP BY 1 ORDER BY 2 DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var enumerator string
		var count int
		if err := rows.Scan(&enumerator, &count); err != nil {
			return nil, err
		}
		counts[enumerator] = count
	}
	return counts, rows.Err()
}

// ParseWarning is one reason a parser could not fully read records of one
// artefact, and how many records carry it.
type ParseWarning struct {
	Artefact    string
	Reason      string
	Records     int
	SourceFiles int
	Example     string
}

// ParseWarnings returns the row-local parser warnings, gathered by artefact and
// reason.
//
// These live in a semicolon-joined column on the record that carries them,
// where nothing counts them: the run's warning ledger is mostly whole-file
// failures, so a manifest could say "1 warning" with three hundred partially
// read shortcuts behind it. The caller turns each of these into a ledger
// warning, which is what puts them in the manifest count and in the report's
// limitations — where a reader is looking for exactly this.
func (s *Store) ParseWarnings() ([]ParseWarning, error) {
	rows, err := s.db.Query(
		`SELECT artefact, reason, records, source_files, example
		 FROM v_parse_warning`)
	if err != nil {
		return nil, fmt.Errorf("parse warnings: %w", err)
	}
	defer rows.Close()

	var warnings []ParseWarning
	for rows.Next() {
		var warning ParseWarning
		if err := rows.Scan(&warning.Artefact, &warning.Reason,
			&warning.Records, &warning.SourceFiles, &warning.Example); err != nil {
			return nil, err
		}
		warnings = append(warnings, warning)
	}
	return warnings, rows.Err()
}
