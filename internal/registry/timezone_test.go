package registry

import "testing"

// Windows stores a daylight bias for every zone that has ever had daylight
// saving, and says "but not here" by leaving the transition rules empty. Read
// from the bias alone, a Perth host looks seasonally ambiguous and every wall
// clock on it gains a second reading an hour out — 88 entries on
// USB-LENOVO-Multi-USBs, none of which the evidence supports.
func TestAStoredDaylightBiasIsNotADaylightSavingHost(t *testing.T) {
	perth := TimeZone{
		KeyName:             "W. Australia Standard Time",
		BiasMinutes:         -480,
		DaylightBiasMinutes: -60,
		// Both SYSTEMTIME rules are sixteen zero bytes.
		StandardStartMonth: 0,
		DaylightStartMonth: 0,
		Found:              true,
	}
	if perth.ObservesDaylightSaving() {
		t.Error("a zone with no transition rules must not observe daylight saving")
	}

	pacific := TimeZone{
		KeyName:             "Pacific Standard Time",
		BiasMinutes:         480,
		DaylightBiasMinutes: -60,
		StandardStartMonth:  11,
		DaylightStartMonth:  3,
		Found:               true,
	}
	if !pacific.ObservesDaylightSaving() {
		t.Error("a zone with both transition rules does observe daylight saving")
	}
}

// The user switch is a second, independent way for the answer to be no. A host
// with the rules present but the switch set does not change its clock, and
// offering a seasonal alternative for it would describe a season that host
// never entered.
func TestTheDynamicDaylightSwitchOverridesThePresentRules(t *testing.T) {
	zone := TimeZone{
		DaylightBiasMinutes:     -60,
		StandardStartMonth:      11,
		DaylightStartMonth:      3,
		DynamicDaylightDisabled: true,
	}
	if zone.ObservesDaylightSaving() {
		t.Error("DynamicDaylightTimeDisabled must turn daylight saving off")
	}
}

// wMonth is the second field of a SYSTEMTIME, not the first, and a rule that is
// absent or short reads as zero — which is the safe answer, because it makes
// the timeline offer one reading rather than invent a second.
func TestTheTransitionMonthIsReadFromTheSecondField(t *testing.T) {
	// wYear 0, wMonth 3, wDayOfWeek 0, wDay 2, then the time fields.
	march := []byte{
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if got := transitionMonth(march); got != 3 {
		t.Errorf("month = %d, want 3", got)
	}

	empty := make([]byte, 16)
	if got := transitionMonth(empty); got != 0 {
		t.Errorf("an empty rule gave month %d, want 0", got)
	}
	if got := transitionMonth(nil); got != 0 {
		t.Errorf("an absent rule gave month %d, want 0", got)
	}
	if got := transitionMonth([]byte{0x00, 0x00}); got != 0 {
		t.Errorf("a short rule gave month %d, want 0", got)
	}
}
