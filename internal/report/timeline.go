package report

import (
	"fmt"
	"strings"

	"github.com/Bloggzy/boobook/internal/store"
)

// TimelineLimit caps how many entries the section renders.
//
// The cap exists because a page with ten thousand list items stops being read,
// not because the rest is unimportant: timeline-significant.csv holds every
// entry, and the section says how many it left out and where they are.
const TimelineLimit = 750

// TimelineRow is one entry as the section renders it.
//
// It adds one thing to what the view produced: the index of the filter chip the
// row belongs to. That index is a property of this document — which chips it
// drew, in what order — rather than of the evidence, which is why it is the
// only thing assigned here.
type TimelineRow struct {
	store.TimelineRow
	DeviceIndex int
	// Members are the records a moment gathered, rendered inside its fold. Empty
	// on an ordinary row, and on a moment they are the whole of what it rests
	// on: the summary above them is a statement about these records and nothing
	// else, so a reader who opens the fold sees exactly what was counted.
	Members []TimelineRow
	// Name is what the row calls the thing it concerns: the file for a file
	// record, and otherwise the device under the same name its filter chip
	// carries. Three sticks of one model would otherwise produce three rows a
	// second apart, worded identically, describing three different devices.
	Name string
	// Device is the device this row was filed under, under the same name its
	// filter chip carries. It is what the confidence phrase names: "probable
	// link to this device" leaves a reader asking which device, on a row whose
	// other words are all about a file, and the answer was already in hand.
	Device string
}

// Timeline is the section: the rows, the chips that filter them, and what the
// times on them rest on.
type Timeline struct {
	Rows    []TimelineRow
	Filters []Filter

	// Total is every entry the view holds; len(Rows) is what fitted.
	Total int
	// WallClock and Ambiguous count, among the rows shown, those placed by
	// converting a local wall clock and those whose wall clock has two readings.
	WallClock int
	Ambiguous int
	// EpochDefault counts, among the rows shown, those whose time is a storage
	// format's zero rather than a moment. They are listed, because the record is
	// real and only its timestamp is not, and they set no edge of the span.
	EpochDefault int

	// Zone is the host zone the conversions used. Where none was recovered a
	// wall clock has no UTC reading at all, and the rows say so individually.
	Zone      string
	ZoneFound bool
}

// Bar is the timeline's filter, which is the one every other section's copies.
func (t Timeline) Bar() FilterBar {
	return FilterBar{
		Group:    "timeline",
		AllLabel: "All devices",
		AllCount: len(t.Rows),
		Filters:  t.Filters,
		Legend:   "Filter the timeline by device",
	}
}

// Capped reports whether entries were left out of the page.
func (t Timeline) Capped() bool { return t.Total > len(t.Rows) }

// Omitted is how many entries the page does not show.
func (t Timeline) Omitted() int { return t.Total - len(t.Rows) }

// gatherTimeline reads the significant timeline and works out the chips.
//
// The chips are the distinct devices of the rows that were actually rendered,
// in the order those rows first appear. Building them from anything wider would
// offer a filter that selects nothing, and building them from a separate query
// would let the chip counts and the list disagree.
func gatherTimeline(db *store.Store) (Timeline, error) {
	entries, total, err := db.SignificantTimeline(TimelineLimit)
	if err != nil {
		return Timeline{}, err
	}
	members, err := db.TimelineMomentMembers()
	if err != nil {
		return Timeline{}, err
	}
	zone, _, _, _, found, err := db.HostTimeZone()
	if err != nil {
		return Timeline{}, err
	}

	timeline := Timeline{Total: total, Zone: zone, ZoneFound: found}
	index := map[string]int{}

	for _, entry := range entries {
		key := entry.PhysicalDeviceID
		position, seen := index[key]
		if !seen {
			timeline.Filters = append(timeline.Filters, Filter{
				Index:            len(timeline.Filters) + 1,
				Label:            timelineFilterLabel(entry),
				PhysicalDeviceID: key,
			})
			position = len(timeline.Filters)
			index[key] = position
		}
		timeline.Filters[position-1].Count++

		row := TimelineRow{TimelineRow: entry, DeviceIndex: position}
		for _, member := range members[entry.MomentID] {
			// A member's chip index is its moment's: it is the same device, and
			// the filter has to hide a fold's contents with the fold.
			row.Members = append(row.Members,
				TimelineRow{TimelineRow: member, DeviceIndex: position})
		}
		timeline.Rows = append(timeline.Rows, row)

		// Counted over the folded records too. They are on the page — the print
		// stylesheet forces every fold open — so a count of what rests on a
		// converted wall clock that ignored them would understate the part of
		// the document it exists to qualify.
		timeline.count(row)
		for _, member := range row.Members {
			timeline.count(member)
		}
	}

	// Naming happens after the chips, so a row and the chip that selects it say
	// the same thing about the same device.
	for position := range timeline.Rows {
		row := &timeline.Rows[position]
		row.name(timeline.Filters[row.DeviceIndex-1].Label)
		for member := range row.Members {
			row.Members[member].name(timeline.Filters[row.DeviceIndex-1].Label)
		}
	}
	return timeline, nil
}

func (t *Timeline) count(row TimelineRow) {
	if row.TimeBasis != "recorded_utc" {
		t.WallClock++
	}
	if row.TimeAmbiguous {
		t.Ambiguous++
	}
	if row.EpochDefault != "" {
		t.EpochDefault++
	}
}

func (r *TimelineRow) name(device string) {
	r.Device = device
	r.Name = r.Label()
	if r.DeviceLabel != "" && r.Name == r.DeviceLabel {
		r.Name = r.Device
	}
}

// IsMoment reports whether the row stands for the records it gathered rather
// than being one of them.
func (r TimelineRow) IsMoment() bool { return r.RowKind == "moment" }

func timelineFilterLabel(entry store.TimelineRow) string {
	switch {
	case entry.DeviceLabel != "":
		return entry.DeviceLabel
	case entry.PhysicalDeviceID != "":
		return entry.PhysicalDeviceID
	default:
		return "no device named"
	}
}

// Recorded reports whether the row rests on an instant the artefact recorded,
// rather than on a wall clock this run converted.
func (r TimelineRow) Recorded() bool { return r.TimeBasis == "recorded_utc" }

// Uncertain reports that the tie between this record and the device it is filed
// under is less than certain. It is what decides whether the row carries a
// confidence at all: every registry and event-log branch of the timeline is
// confirmed by construction, because the record names the device, and a page of
// "confirmed" chips would drown the handful that are genuinely weaker.
func (r TimelineRow) Uncertain() bool {
	return r.Confidence != "" && r.Confidence != "confirmed"
}

// LinkedTo is the device the confidence is about, or empty where the row was
// filed under no device at all — in which case the chip label is a placeholder
// and naming it would put "link to no device named" on the page.
func (r TimelineRow) LinkedTo() string {
	if r.PhysicalDeviceID == "" {
		return ""
	}
	return r.Device
}

// Unconverted reports a wall clock with no UTC reading at all, which is what a
// collection with no recoverable host time zone leaves. The row is still placed
// in the list, by reading its wall clock as though it were UTC, because sending
// it to the end would hide it. When and Qualifier both say that is what it is.
func (r TimelineRow) Unconverted() bool { return r.TimeUTC == nil }

// When is the time shown at the head of the row.
func (r TimelineRow) When() string {
	if r.Unconverted() {
		return strings.TrimSpace(r.TimeLocal)
	}
	return instant(r.TimeUTC)
}

// Unit names what When is measured in, so a converted wall clock and a
// recorded instant are never printed as if they were the same kind of thing.
func (r TimelineRow) Unit() string {
	if r.Unconverted() {
		return "local"
	}
	return "UTC"
}

// Sentinel reports that the time on this row is a storage format's zero rather
// than a moment anything happened at.
//
// The row keeps its place in the list and keeps showing the value, because the
// value is what the artefact holds and an examiner checking the row has to be
// able to find it. What changes is that it is labelled, and that the summary
// does not let it set the edge of the evidence span.
func (r TimelineRow) Sentinel() bool { return r.EpochDefault != "" }

// Qualifier is the sentence a row needs before its time can be relied on. It is
// empty for a recorded instant, which needs none.
func (r TimelineRow) Qualifier() string {
	switch {
	// First, because it overrides everything else the time could be said to
	// be: a converted wall clock that turns out to be the FAT epoch was never
	// a wall clock worth converting, and explaining the conversion would dress
	// a sentinel up as a measurement.
	case r.Sentinel():
		return fmt.Sprintf("This date is %s, not a moment anything is recorded "+
			"as happening at. The record is real; its timestamp is not, so it "+
			"is listed here and excluded from the span the evidence is reported "+
			"to reach across.", r.EpochDefault)
	case r.Recorded():
		return ""
	case r.Unconverted():
		return fmt.Sprintf("Recorded as local wall clock %s with no time zone, "+
			"and no host time zone was recovered from this evidence, so it has "+
			"no UTC reading. It is placed here by reading it as UTC.",
			strings.TrimSpace(r.TimeLocal))
	case r.TimeAmbiguous:
		return fmt.Sprintf("Recorded as local wall clock %s with no time zone. "+
			"The host zone observes daylight saving and the record does not say "+
			"which season it was written in, so it is either %s or %s UTC.",
			strings.TrimSpace(r.TimeLocal), instant(r.TimeUTC),
			instant(r.TimeUTCAlt))
	default:
		return fmt.Sprintf("Recorded as local wall clock %s with no time zone, "+
			"converted with the host zone.", strings.TrimSpace(r.TimeLocal))
	}
}
