package classify

import (
	"strings"
	"testing"
)

// The rule set ships inside the binary, so a rule set that does not parse or
// does not validate is a broken build rather than a broken run.
func TestBuiltInRulesLoad(t *testing.T) {
	rules, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Rules) == 0 || len(rules.Categories) == 0 {
		t.Fatal("the built-in rule set is empty")
	}

	// The eighteen investigative categories from the reference document. A
	// category quietly dropped from the set would silently stop being assigned.
	if len(rules.Categories) != 18 {
		t.Errorf("got %d categories, want the 18 from the reference document",
			len(rules.Categories))
	}
}

// Every profile has to apply cleanly, because a profile that names a fact the
// indicator table does not carry would silently weight nothing.
func TestEveryProfileApplies(t *testing.T) {
	rules, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	for _, profile := range rules.ProfileNames() {
		weights, err := rules.Weights(profile)
		if err != nil {
			t.Errorf("profile %s: %v", profile, err)
			continue
		}
		if len(weights) != len(rules.Indicators) {
			t.Errorf("profile %s returned %d weights for %d indicators",
				profile, len(weights), len(rules.Indicators))
		}
	}
}

// A profile multiplies the facts it names and leaves the rest alone. It changes
// placement and score only — never what was extracted or what a rule assigned.
func TestProfileReweightsOnlyTheFactsItNames(t *testing.T) {
	rules, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	general, err := rules.Weights(DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	bypass, err := rules.Weights("network-bypass")
	if err != nil {
		t.Fatal(err)
	}

	if bypass["network_interface"] <= general["network_interface"] {
		t.Errorf("network-bypass should raise network_interface: %v then %v",
			general["network_interface"], bypass["network_interface"])
	}
	if bypass["printer_interface"] != general["printer_interface"] {
		t.Error("network-bypass reweighted a fact it does not name")
	}
}

func TestUnknownProfileIsRejected(t *testing.T) {
	rules, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Weights("nonesuch"); err == nil {
		t.Fatal("an unknown profile was accepted")
	}
}

// A rule naming a category that does not exist would produce devices with an
// empty category and nothing to say why.
func TestRuleNamingAnUnknownCategoryIsRejected(t *testing.T) {
	_, err := parse([]byte(`{
        "categories": [{"category": "Storage", "tier": 1}],
        "rules": [{"id": "r", "category": "Nope",
                   "conditions": [{"fact": "storage_identity"}]}],
        "indicators": [], "profiles": {"general": {}}
    }`), "test")
	if err == nil || !strings.Contains(err.Error(), "unknown category") {
		t.Fatalf("error = %v, want a complaint about the unknown category", err)
	}
}

// A rule defined only by absence matches every device that lacks the fact,
// including devices nothing at all is known about.
func TestRuleWithOnlyNegatedConditionsIsRejected(t *testing.T) {
	_, err := parse([]byte(`{
        "categories": [{"category": "Storage", "tier": 1}],
        "rules": [{"id": "r", "category": "Storage",
                   "conditions": [{"fact": "storage_identity", "negate": true}]}],
        "indicators": [], "profiles": {"general": {}}
    }`), "test")
	if err == nil || !strings.Contains(err.Error(), "only negated") {
		t.Fatalf("error = %v, want a complaint about the negated-only rule", err)
	}
}

func TestDuplicateRuleIDIsRejected(t *testing.T) {
	_, err := parse([]byte(`{
        "categories": [{"category": "Storage", "tier": 1}],
        "rules": [
            {"id": "r", "category": "Storage", "conditions": [{"fact": "a"}]},
            {"id": "r", "category": "Storage", "conditions": [{"fact": "b"}]}],
        "indicators": [], "profiles": {"general": {}}
    }`), "test")
	if err == nil || !strings.Contains(err.Error(), "used twice") {
		t.Fatalf("error = %v, want a complaint about the duplicate id", err)
	}
}
