package report

import (
	"fmt"

	"github.com/Bloggzy/boobook/internal/store"
)

// TierGroup is one tier's significant devices, behind one disclosure.
//
// The cards are long — eleven cited fields and four drill-downs each — and a
// host with three sticks and seven tier 2 devices runs to a page and a half
// before the timeline starts. Grouping by tier puts the ranking the
// classification already made to work on the page.
//
// Every tier starts collapsed, tier 1 included. An analyst opening the report
// should meet its structure — which sections exist and what is in them — and
// then choose where to dig, which they cannot do if the first section has
// already pushed the rest off the screen. Nothing is hidden by this: the label
// names every device in the group, and the print stylesheet opens all of them.
type TierGroup struct {
	Tier    int
	Devices []store.CardDevice
}

// TierCard is one device card and the index of the pill that selects it.
//
// The index belongs to this document rather than to the evidence, which is why
// it is the only thing added: the card itself is what the store produced.
type TierCard struct {
	store.CardDevice
	Index int
}

// Cards is the group's devices, each carrying the pill index that shows it.
func (g TierGroup) Cards() []TierCard {
	cards := make([]TierCard, 0, len(g.Devices))
	for position, device := range g.Devices {
		cards = append(cards, TierCard{CardDevice: device, Index: position + 1})
	}
	return cards
}

// Group is the tier's filter-bar name, and is why the tier number has to be a
// number: it prefixes every id and class the bar generates.
func (g TierGroup) Group() string { return fmt.Sprintf("tier%d", g.Tier) }

// Bar filters this tier's cards down to one device.
//
// The pills were already here and did nothing but open the fold they sat in,
// because they were inside its label. An examiner who had learnt the gesture on
// the timeline pressed one here and got a section expanding rather than
// narrowing. They are a filter now, and the fold's own label is a separate bar
// above them.
//
// "All tier 1 devices" rather than "All devices": three bars on one page all
// reading the same thing give a reader no way to tell which list a pill
// belongs to.
func (g TierGroup) Bar() FilterBar {
	filters := make([]Filter, 0, len(g.Devices))
	for position, device := range g.Devices {
		filters = append(filters, Filter{
			Index:            position + 1,
			Label:            device.Label(),
			PhysicalDeviceID: device.PhysicalDeviceID,
			// No count. Every other bar's pill counts the items it selects, and
			// here that is always one device — a column of pills each reading
			// "1" says nothing. The score would fill the space and be read as a
			// count of something, which is worse than a gap.
		})
	}
	return FilterBar{
		Group:    g.Group(),
		AllLabel: fmt.Sprintf("All tier %d devices", g.Tier),
		AllCount: len(g.Devices),
		Filters:  filters,
		Legend:   fmt.Sprintf("Filter the tier %d devices", g.Tier),
	}
}

// Names is what the group holds, for the label.
//
// The names show whether the group is open or shut, which is the point: a
// collapsed section reading "7 devices" tells a reader nothing about whether it
// is worth opening, and one naming them can be dismissed without opening it.
func (g TierGroup) Names() []string {
	names := make([]string, 0, len(g.Devices))
	for _, device := range g.Devices {
		names = append(names, device.Label())
	}
	return names
}

// tierGroups splits the significant devices by the tier they were put in.
//
// The order within a tier is the order the classification ranked them in, and
// nothing is re-sorted here: this walks the rows once and cuts them where the
// tier changes.
func tierGroups(devices []store.CardDevice) []TierGroup {
	var groups []TierGroup
	for _, device := range devices {
		if len(groups) == 0 || groups[len(groups)-1].Tier != device.Tier {
			groups = append(groups, TierGroup{Tier: device.Tier})
		}
		group := &groups[len(groups)-1]
		group.Devices = append(group.Devices, device)
	}
	return groups
}
