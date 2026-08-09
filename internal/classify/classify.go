// Package classify holds the device classification rule set.
//
// The rules are data. They are loaded into the case database as tables and the
// classification itself is a view over them, so an analyst can read the rule
// that fired, change a weight, and re-run — without a Go build and without a
// second implementation of the same logic to disagree with the first.
package classify

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

//go:embed rules.json
var builtinRules []byte

// DefaultProfile is the weighting used when no case profile is chosen.
const DefaultProfile = "general"

// SetupClass names a Windows device setup class GUID.
type SetupClass struct {
	GUID string `json:"guid"`
	Name string `json:"name"`
}

// Category is one investigative category with the tier it defaults to.
type Category struct {
	Category  string `json:"category"`
	Tier      int    `json:"tier"`
	Relevance string `json:"relevance"`
	Note      string `json:"note"`
}

// Condition is one fact a rule requires, or requires to be absent.
type Condition struct {
	Fact   string `json:"fact"`
	Negate bool   `json:"negate"`
}

// Rule assigns a category and tier when every one of its conditions holds.
//
// Tier sits on the rule rather than only on the category because the same
// category can mean different things: a dock exposing Ethernet and storage is
// tier 1, and a bare hub with no child functions recorded is tier 2.
type Rule struct {
	ID         string      `json:"id"`
	Category   string      `json:"category"`
	Tier       int         `json:"tier"`
	Priority   int         `json:"priority"`
	Conditions []Condition `json:"conditions"`
	Note       string      `json:"note"`
}

// Indicator is one fact's contribution to the relevance score.
type Indicator struct {
	Fact   string  `json:"fact"`
	Weight float64 `json:"weight"`
	Group  string  `json:"group"`
	Note   string  `json:"note"`
}

// ReviewFact is a fact that raises review_required, with what it means.
type ReviewFact struct {
	Fact string `json:"fact"`
	Note string `json:"note"`
	// Unless names facts that make this one normal rather than notable. A
	// keyboard has no serial and never did; flagging every such device buries
	// the ones where the absence means something. UnlessNote records why the
	// exception exists, in the rule set rather than in code, so it can be
	// argued with.
	Unless     []string `json:"unless,omitempty"`
	UnlessNote string   `json:"unless_note,omitempty"`
}

// Rules is the whole rule set.
type Rules struct {
	Version      string                        `json:"version"`
	SetupClasses []SetupClass                  `json:"setup_classes"`
	Categories   []Category                    `json:"categories"`
	Rules        []Rule                        `json:"rules"`
	Indicators   []Indicator                   `json:"indicators"`
	ReviewFacts  []ReviewFact                  `json:"review_facts"`
	Profiles     map[string]map[string]float64 `json:"profiles"`
}

// Load returns the built-in rule set.
func Load() (Rules, error) {
	return parse(builtinRules, "built-in rules")
}

// LoadFile returns a rule set read from disk, for a case that needs weights the
// built-in set does not carry.
func LoadFile(path string) (Rules, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Rules{}, fmt.Errorf("read rules: %w", err)
	}
	return parse(raw, path)
}

func parse(raw []byte, origin string) (Rules, error) {
	var rules Rules
	if err := json.Unmarshal(raw, &rules); err != nil {
		return Rules{}, fmt.Errorf("parse %s: %w", origin, err)
	}
	if err := rules.validate(); err != nil {
		return Rules{}, fmt.Errorf("%s: %w", origin, err)
	}
	return rules, nil
}

// validate rejects a rule set that would classify silently wrongly: a rule
// naming a category that does not exist, or a duplicate rule id, would produce
// devices with an empty category and no way to see why.
func (r Rules) validate() error {
	categories := make(map[string]bool, len(r.Categories))
	for _, category := range r.Categories {
		if categories[category.Category] {
			return fmt.Errorf("category %q is defined twice", category.Category)
		}
		categories[category.Category] = true
	}

	seen := make(map[string]bool, len(r.Rules))
	for _, rule := range r.Rules {
		if seen[rule.ID] {
			return fmt.Errorf("rule id %q is used twice", rule.ID)
		}
		seen[rule.ID] = true
		if !categories[rule.Category] {
			return fmt.Errorf("rule %q names unknown category %q", rule.ID, rule.Category)
		}
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("rule %q has no conditions and would match everything", rule.ID)
		}
		// A rule defined only by what is absent would match every device that
		// happens to lack that fact, including devices nothing is known about.
		// That is almost always a mistake, and a silent one.
		positive := false
		for _, condition := range rule.Conditions {
			if !condition.Negate {
				positive = true
			}
		}
		if !positive {
			return fmt.Errorf("rule %q has only negated conditions and would "+
				"match every device lacking them", rule.ID)
		}
	}

	if _, ok := r.Profiles[DefaultProfile]; !ok {
		return fmt.Errorf("no %q profile is defined", DefaultProfile)
	}
	return nil
}

// ProfileNames lists the profiles the rule set defines, for the CLI help and
// for the error a mistyped -profile produces.
func (r Rules) ProfileNames() []string {
	names := make([]string, 0, len(r.Profiles))
	for name := range r.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Weights returns the fact weights a profile applies, with every fact the rule
// set knows about present. A profile multiplies the facts it names and leaves
// the rest alone, so the returned table is complete rather than a delta — the
// case database then holds exactly the numbers that were used.
func (r Rules) Weights(profile string) (map[string]float64, error) {
	multipliers, ok := r.Profiles[profile]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q, choose one of %v",
			profile, r.ProfileNames())
	}

	for fact := range multipliers {
		if !r.knowsFact(fact) {
			return nil, fmt.Errorf("profile %q reweights unknown fact %q", profile, fact)
		}
	}

	weights := make(map[string]float64, len(r.Indicators))
	for _, indicator := range r.Indicators {
		weight := indicator.Weight
		if multiplier, ok := multipliers[indicator.Fact]; ok {
			weight *= multiplier
		}
		weights[indicator.Fact] = weight
	}
	return weights, nil
}

func (r Rules) knowsFact(fact string) bool {
	for _, indicator := range r.Indicators {
		if indicator.Fact == fact {
			return true
		}
	}
	return false
}
