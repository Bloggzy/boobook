package report

import (
	"github.com/Bloggzy/boobook/internal/store"
)

// OtherCategory is one group of low-value devices, collapsed behind a summary.
type OtherCategory struct {
	Category string
	Devices  []store.Device
	// Events is how many event records the group accounts for, so the summary
	// line says how much evidence is behind the collapsed group rather than
	// only how many devices are in it.
	Events int
}

// Others is the tier 3 section.
//
// The tier is a statement that these are unlikely to matter, not that they are
// unimportant, so they are all here and none is dropped — collapsed by category
// so the page stays readable with seventy of them.
type Others struct {
	Categories []OtherCategory
	Devices    int
	Events     int

	// Review is the tier 3 devices flagged for review, lifted out of the
	// collapsed groups. Review is not a tier: a keyboard with a duplicated
	// serial is still a keyboard, and still the thing an examiner has to look
	// at. Folding it into a group called "other" would hide the one row in
	// seventy that was asking for attention.
	Review []store.Device
}

// Any reports whether there is anything to show.
func (o Others) Any() bool { return o.Devices > 0 }

// gatherOthers reads the tier 3 devices and groups them by category.
//
// The rows arrive ordered by category and then by score, so this walks them
// once. Nothing is decided here: the category, the tier and the review flag are
// all the classification's, read from the same view devices.csv is copied from.
func gatherOthers(db *store.Store) (Others, error) {
	devices, err := db.OtherDevices()
	if err != nil {
		return Others{}, err
	}

	others := Others{Devices: len(devices)}
	index := map[string]int{}

	for _, device := range devices {
		position, seen := index[device.Category]
		if !seen {
			others.Categories = append(others.Categories,
				OtherCategory{Category: device.Category})
			position = len(others.Categories) - 1
			index[device.Category] = position
		}

		group := &others.Categories[position]
		group.Devices = append(group.Devices, device)
		group.Events += device.EventCount
		others.Events += device.EventCount

		if device.ReviewRequired {
			others.Review = append(others.Review, device)
		}
	}
	return others, nil
}
