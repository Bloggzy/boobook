package report

import (
	"fmt"
	"regexp"
	"strings"
)

// The device filter, shared by every section that has one.
//
// The timeline had this and nothing else did. The significant-device tiers and
// the file activity section drew the same row of device names and clicking one
// only opened the fold it sat in, which is worse than having no filter: it
// looks like the timeline's control, so a reader learns the gesture in one
// section and finds it does something else in the next. Reported by an examiner
// as "it doesn't work the same across the report", which is exactly right.
//
// One mechanism now, generated in one place. Each bar is a group of radio
// buttons and a row of labels; a checked radio hides the items that do not
// carry its class. The alternative — a click handler — is not available and
// should not be: the report fetches nothing and runs no script, so what an
// examiner opens in five years is what was written today.
//
// A filter that fails must fail towards showing everything. With no rule
// matching at all, or a stylesheet that did not load, every item stays visible.

// Filter is one pill: a device, and how many of this section's items carry it.
type Filter struct {
	// Index is 1-based and is a property of this document — which pills it drew
	// and in what order — rather than of the evidence.
	Index int
	Label string
	// PhysicalDeviceID goes in the pill's title so a reader can check which
	// device a shortened label means without opening anything.
	PhysicalDeviceID string
	Count            int
}

// FilterBar is one row of pills over one list of items.
//
// Group names the radio group and prefixes every id and class the bar
// generates. It must be unique on the page, or two bars share a radio group and
// selecting a device in one clears the other.
type FilterBar struct {
	Group string
	// AllLabel is the pill that selects everything. Each section words it for
	// what it holds — "All devices" over the timeline, "All tier 1 devices"
	// over a tier — because a page with three bars all reading "All devices"
	// gives a reader no way to tell which list a pill belongs to.
	AllLabel string
	AllCount int
	Filters  []Filter
	// Legend is the accessible name of the bar, for the same reason.
	Legend string
}

// Any reports whether the bar is worth drawing.
//
// One device is enough. Suppressing the bar there was tried and is wrong: the
// two pills do select the same rows, but a section that sometimes has a filter
// and sometimes does not is the inconsistency this work exists to remove, and a
// reader who has learnt where the control lives should find it in the same
// place on the next report. The bar also states the count, which a single pill
// reading "1 device" says plainly enough.
func (b FilterBar) Any() bool { return len(b.Filters) > 0 }

// safeGroup is what a group name may contain.
//
// Group names are written by this package — "timeline", "files", "tier1" — and
// never come from the evidence. This is not defence against a hostile device
// name reaching the stylesheet, because none can get here; it is so that the
// claim stays true if somebody later builds a group name from something read
// off a disk. A rule is dropped rather than written, so the worst case is a
// filter that shows everything.
var safeGroup = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// filterStyle generates the rules that make every bar on the page work.
//
// Nothing from the evidence reaches these rules. The only values interpolated
// are a group name this package chose and an index it counted.
//
// The whole of it is inside @media screen, and that is the load-bearing part
// rather than a tidy-up. Printing carries everything: a printed report that
// silently dropped the rows a reader had filtered out would lie by omission,
// with nothing on the paper to say so. The rules used to apply on paper too and
// were undone by a print rule naming the element being hidden —
// `.timeline-entries > .entry { display: grid !important }` — which meant every
// new filtered element type needed somebody to remember to add its own
// override, in a different file, with the failure invisible until a populated
// report was actually printed. Scoped to the screen, print never applies the
// filter at all and there is nothing to remember.
func filterStyle(bars []FilterBar) string {
	var rules strings.Builder
	rules.WriteString("\n/* generated: one rule per filter pill. " +
		"Screen only, so paper always carries every row. */\n")
	rules.WriteString("@media screen {\n")

	for _, bar := range bars {
		if !bar.Any() || !safeGroup.MatchString(bar.Group) {
			continue
		}
		rules.WriteString(selected(bar.Group, 0))
		for _, filter := range bar.Filters {
			// The hiding rule and the pill's own lit state. Both are needed:
			// a bar that filters without showing which pill is active leaves a
			// reader looking at a short list with no idea why.
			rules.WriteString(fmt.Sprintf(
				"#f-%s-%d:checked ~ .filter-targets > :not(.fx-%s-%d)"+
					"{display:none}\n",
				bar.Group, filter.Index, bar.Group, filter.Index))
			rules.WriteString(selected(bar.Group, filter.Index))
		}
	}

	rules.WriteString("}\n")
	return rules.String()
}

func selected(group string, index int) string {
	return fmt.Sprintf(
		"#f-%s-%d:checked ~ .filter-chips label[for=\"f-%s-%d\"]"+
			"{--chip-face:var(--chip-on);--chip-ink:var(--chip-on-ink)}\n",
		group, index, group, index)
}

// bars is every filter bar the document draws, in the order it draws them.
//
// One list, so the stylesheet is generated from the same thing the template
// renders. Built separately, a bar could be drawn with no rules behind it —
// pills that highlight nothing and filter nothing.
func (r *Report) bars() []FilterBar {
	bars := []FilterBar{r.Timeline.Bar()}
	for _, tier := range r.Tiers {
		bars = append(bars, tier.Bar())
	}
	return append(bars, r.Files.Bar())
}
