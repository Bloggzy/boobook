package report

import (
	"github.com/Bloggzy/boobook/internal/store"
)

// PrefetchDevice is one device's programme executions.
//
// RanFrom and Loaded are kept apart because they are different claims. A
// programme executed off the device is the finding; a programme on the system
// disk that opened one file on it reaches the device through the same chain and
// is a weaker, separate statement. Folding them together would report four
// programmes as having run from a stick when one did.
type PrefetchDevice struct {
	PhysicalDeviceID string
	Label            string
	Tier             int

	RanFrom []store.PrefetchRun
	Loaded  []store.PrefetchRun
}

// Programmes is how many prefetch records name this device.
func (d PrefetchDevice) Programmes() int { return len(d.RanFrom) + len(d.Loaded) }

// Prefetch is the section.
type Prefetch struct {
	Devices []PrefetchDevice
	// RanFrom and Loaded are the totals across every device, so the section's
	// label can say what it holds without the reader opening it.
	RanFrom int
	Loaded  int
}

// Any reports whether the section has anything to show. A collection with no
// prefetch, or none of it touching a removable volume, gets no section rather
// than an empty one saying nothing was found.
func (p Prefetch) Any() bool { return len(p.Devices) > 0 }

// gatherPrefetch groups the executions by device.
//
// Distribution, not decision: the rows arrive in the order the view produced
// them — by tier, then device, ran-from first, then most recent — and this walks
// them once.
func gatherPrefetch(db *store.Store) (Prefetch, error) {
	rows, err := db.Prefetch()
	if err != nil {
		return Prefetch{}, err
	}

	var section Prefetch
	index := map[string]int{}
	for _, row := range rows {
		position, seen := index[row.PhysicalDeviceID]
		if !seen {
			position = len(section.Devices)
			index[row.PhysicalDeviceID] = position
			section.Devices = append(section.Devices, PrefetchDevice{
				PhysicalDeviceID: row.PhysicalDeviceID,
				Label:            row.DeviceLabel,
				Tier:             row.Tier,
			})
		}
		device := &section.Devices[position]
		if row.RanFrom {
			device.RanFrom = append(device.RanFrom, row)
			section.RanFrom++
			continue
		}
		device.Loaded = append(device.Loaded, row)
		section.Loaded++
	}

	return section, nil
}
