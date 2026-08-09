package store

import (
	"fmt"

	"github.com/Bloggzy/boobook/internal/classify"
)

// LoadRules writes the classification rule set into the case database with the
// chosen profile's weights already applied.
//
// The rules go into the database rather than staying in Go because the
// classification is a view over them. A run therefore carries the rule set that
// produced its answers, and an analyst can re-run a query against a changed
// weight without a rebuild.
func (s *Store) LoadRules(rules classify.Rules, profile string) error {
	weights, err := rules.Weights(profile)
	if err != nil {
		return err
	}

	if err := s.insert("rule_setup_class", "class_guid,class_name",
		len(rules.SetupClasses), func(add func(...any) error) error {
			for _, class := range rules.SetupClasses {
				// Lower cased on the way in: the hives write the GUID both ways
				// and a class that failed to match on casing would silently
				// become an unknown class and a review flag.
				if err := add(lowerText(class.GUID), class.Name); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}

	if err := s.insert("rule_category", "category,default_tier,relevance,note",
		len(rules.Categories), func(add func(...any) error) error {
			for _, category := range rules.Categories {
				if err := add(category.Category, category.Tier,
					category.Relevance, category.Note); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}

	conditions := 0
	for _, rule := range rules.Rules {
		conditions += len(rule.Conditions)
	}

	if err := s.insert("rule", "rule_id,category,tier,priority,note",
		len(rules.Rules), func(add func(...any) error) error {
			for _, rule := range rules.Rules {
				tier := rule.Tier
				if tier == 0 {
					tier = defaultTier(rules, rule.Category)
				}
				if err := add(rule.ID, rule.Category, tier,
					rule.Priority, rule.Note); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}

	if err := s.insert("rule_condition", "rule_id,fact,negate",
		conditions, func(add func(...any) error) error {
			for _, rule := range rules.Rules {
				for _, condition := range rule.Conditions {
					if err := add(rule.ID, condition.Fact,
						condition.Negate); err != nil {
						return err
					}
				}
			}
			return nil
		}); err != nil {
		return err
	}

	if err := s.insert("rule_indicator",
		"fact,weight,base_weight,indicator_group,profile,note",
		len(rules.Indicators), func(add func(...any) error) error {
			for _, indicator := range rules.Indicators {
				if err := add(indicator.Fact, weights[indicator.Fact],
					indicator.Weight, indicator.Group, profile,
					indicator.Note); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}

	if err := s.insert("rule_review_fact", "fact,note",
		len(rules.ReviewFacts), func(add func(...any) error) error {
			for _, review := range rules.ReviewFacts {
				if err := add(review.Fact, review.Note); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}

	exceptions := 0
	for _, review := range rules.ReviewFacts {
		exceptions += len(review.Unless)
	}
	return s.insert("rule_review_exception", "fact,unless_fact,note",
		exceptions, func(add func(...any) error) error {
			for _, review := range rules.ReviewFacts {
				for _, unless := range review.Unless {
					if err := add(review.Fact, unless,
						review.UnlessNote); err != nil {
						return err
					}
				}
			}
			return nil
		})
}

func defaultTier(rules classify.Rules, category string) int {
	for _, defined := range rules.Categories {
		if defined.Category == category {
			return defined.Tier
		}
	}
	// validate() rejects a rule naming an undefined category, so this is
	// unreachable; returning the lowest tier rather than zero keeps a future
	// change from producing a device in tier 0.
	return 3
}

func lowerText(text string) string {
	lowered := make([]byte, 0, len(text))
	for index := 0; index < len(text); index++ {
		character := text[index]
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		lowered = append(lowered, character)
	}
	return string(lowered)
}

// Consolidate writes the derived layers that everything downstream reads.
//
// It must run after all evidence is loaded and before anything reads a device:
// the grouping is a recursive closure over every identity, and the facts are a
// wide union over the grouping. Computing them once here rather than per reader
// is the difference between a four second run and one that does not finish.
//
// The reasoning is unchanged — these are copies of v_device_grouping and
// v_device_fact_computed — so there is still one place where each is decided.
func (s *Store) Consolidate() error {
	steps := []struct{ table, view string }{
		{"device_group", "v_device_grouping"},
		{"device_fact", "v_device_fact_computed"},
		// After the facts: the attribution's confidence depends on the
		// connection windows, which depend on nothing above, but the order is
		// fixed so a reader does not have to work out that it is free.
		{"file_attribution", "v_file_attribution_computed"},
		// Last, and the order is not free here: the membership joins the whole
		// timeline against every connection endpoint, and the timeline reads
		// the attribution above it.
		{"timeline_moment_member", "v_timeline_moment_member_computed"},
	}

	for _, step := range steps {
		// Deleted first so a second call is not a second set of rows. A run
		// calls this once, but a duplicated grouping would silently double
		// every count built on it.
		if _, err := s.db.Exec("DELETE FROM " + step.table); err != nil {
			return fmt.Errorf("clear %s: %w", step.table, err)
		}
		if _, err := s.db.Exec(fmt.Sprintf(
			"INSERT INTO %s SELECT * FROM %s", step.table, step.view)); err != nil {
			return fmt.Errorf("consolidate %s from %s: %w", step.table, step.view, err)
		}
	}
	return nil
}

// RuleSummary reports what was loaded, for the run's console line.
func (s *Store) RuleSummary() (rules, conditions, indicators int, err error) {
	row := s.db.QueryRow(`
        SELECT (SELECT count(*) FROM rule),
               (SELECT count(*) FROM rule_condition),
               (SELECT count(*) FROM rule_indicator)`)
	if err := row.Scan(&rules, &conditions, &indicators); err != nil {
		return 0, 0, 0, fmt.Errorf("rule summary: %w", err)
	}
	return rules, conditions, indicators, nil
}
