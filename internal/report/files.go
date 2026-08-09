package report

import (
	"github.com/Bloggzy/boobook/internal/store"
)

// FileLimit and GapLimit cap what the section renders. Both are rendering
// limits: file-attribution.csv and file-attribution-summary.csv hold every row
// either way, and the section says how many it left out.
const (
	FileLimit = 500
	GapLimit  = 200
)

// FileDevice is one device's file and folder activity.
//
// Strongest holds the records that reached this device by the firmest route the
// evidence offered for it, and Weaker the rest. The split is per device rather
// than against a fixed threshold, for a reason the reference collections made
// plain: on current Windows the EMDMgmt key is gone, so nothing is confirmed and
// almost nothing is strong. A section that showed only confirmed and strong
// links inline would have shown nothing at all in three of the four reference
// collections, and file activity is the whole question in a USB case.
type FileDevice struct {
	PhysicalDeviceID string
	Label            string
	Tier             int
	// Index is the filter pill that shows this device's card. A property of the
	// document — which pills it drew, in what order — not of the evidence.
	Index int

	// Best is the confidence Strongest is at, so the section can say what the
	// firmest link to this device actually is rather than implying it is firm.
	Best      string
	Strongest []store.FileActivity
	Weaker    []store.FileActivity
}

// Records is how many records reached this device.
func (d FileDevice) Records() int { return len(d.Strongest) + len(d.Weaker) }

// Files is the section.
type Files struct {
	Devices []FileDevice
	// Records and Total account for the attributed rows; Gaps and GapTotal for
	// the records that reached no device.
	Records  int
	Total    int
	Gaps     []store.FileGap
	GapTotal int
}

// Bar filters the section down to one device's card.
//
// The section already drew this row of names, inside the fold's label, where
// pressing one opened the fold instead of narrowing it. On a host with six
// devices the section is most of the document's height and finding one stick's
// activity meant scrolling past five other cards — which is the question this
// section exists to answer, made harder by the control that looked like it
// would answer it.
func (f Files) Bar() FilterBar {
	filters := make([]Filter, 0, len(f.Devices))
	for _, device := range f.Devices {
		filters = append(filters, Filter{
			Index:            device.Index,
			Label:            device.Label,
			PhysicalDeviceID: device.PhysicalDeviceID,
			Count:            device.Records(),
		})
	}
	return FilterBar{
		Group:    "files",
		AllLabel: "All devices",
		AllCount: f.Records,
		Filters:  filters,
		Legend:   "Filter the file activity by device",
	}
}

// Any reports whether the section has anything to show.
func (f Files) Any() bool { return len(f.Devices) > 0 || len(f.Gaps) > 0 }

// Capped and GapsCapped report whether rows were left off the page.
func (f Files) Capped() bool     { return f.Total > f.Records }
func (f Files) Omitted() int     { return f.Total - f.Records }
func (f Files) GapsCapped() bool { return f.GapTotal > len(f.Gaps) }
func (f Files) GapsOmitted() int { return f.GapTotal - len(f.Gaps) }

// gatherFiles reads the attributed records and groups them by device.
//
// The grouping is distribution, not decision: the rows arrive in the order the
// view produced them — device by device in the order the cards use, strongest
// link first — and this walks them once.
func gatherFiles(db *store.Store) (Files, error) {
	rows, total, err := db.FileActivity(FileLimit)
	if err != nil {
		return Files{}, err
	}
	gaps, gapTotal, err := db.FileGaps(GapLimit)
	if err != nil {
		return Files{}, err
	}

	files := Files{Records: len(rows), Total: total, Gaps: gaps, GapTotal: gapTotal}
	index := map[string]int{}

	for _, row := range rows {
		position, seen := index[row.PhysicalDeviceID]
		if !seen {
			files.Devices = append(files.Devices, FileDevice{
				PhysicalDeviceID: row.PhysicalDeviceID,
				Label:            row.DeviceLabel,
				Tier:             row.Tier,
				Best:             row.Confidence,
				Index:            len(files.Devices) + 1,
			})
			position = len(files.Devices) - 1
			index[row.PhysicalDeviceID] = position
		}

		device := &files.Devices[position]
		if row.Confidence == device.Best {
			device.Strongest = append(device.Strongest, row)
		} else {
			device.Weaker = append(device.Weaker, row)
		}
	}
	return files, nil
}
