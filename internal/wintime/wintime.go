// Package wintime converts Windows time values to UTC.
//
// Every derived UTC value in Boobook comes through here, for one reason: a
// timeline whose channels spell UTC differently sorts wrongly. The stored form
// is always kept beside the derived one so a conversion can be checked.
package wintime

import (
	"time"
)

// epochDelta is the number of 100-nanosecond intervals between the FILETIME
// epoch (1601-01-01) and the Unix epoch (1970-01-01).
const epochDelta = 116444736000000000

// maxReasonable guards against a garbage FILETIME being rendered as a date in
// the year 30000. Values beyond it are treated as unreadable rather than shown.
const maxReasonable = 0x7FFFFFFFFFFFFFFF

// FATEpoch is the FILETIME for 1980-01-01 00:00:00 UTC.
//
// It is the earliest date the FAT date format can express, and it is what a
// zeroed DOS date becomes when Windows widens one into a FILETIME. Explorer
// writes it into a shortcut whose target has no timestamps of its own — a
// shortcut to a drive root carries it in all three header times at once, to the
// tick, beside a file size of zero and the directory attribute.
//
// So the value means "nothing was recorded", and reading it as a write time
// puts a file record in 1980 and drags the whole reported span back with it.
const FATEpoch = 119600064000000000

// IsFATEpoch reports whether a FILETIME is the FAT epoch exactly.
//
// Exactly, and not "some time in 1980": this is a sentinel, and matching a
// range would throw away a genuine timestamp that happened to be old. A real
// write time also carries sub-second precision, which this never does.
func IsFATEpoch(filetime uint64) bool { return filetime == FATEpoch }

// dosEpoch is the packed FAT date and time for 1980-01-01 00:00:00: year 0,
// month 1, day 1, and a zeroed time word.
//
// It is the same sentinel as FATEpoch in the format a shell item stores rather
// than the widened FILETIME, and it means the same thing — nothing was
// recorded. Read as a wall clock and converted with the host offset it lands
// somewhere in December 1979, which is how it announces itself: no timestamp a
// Windows machine ever wrote falls before the epoch its own format starts at.
const dosEpoch = 0x00000021

// FromFileTime converts a Windows FILETIME to UTC.
//
// The second return value is false where the value is zero, implausible, or the
// FAT epoch sentinel; the caller keeps the raw value and reports no derived
// time, rather than showing a converted nonsense date.
func FromFileTime(filetime uint64) (time.Time, bool) {
	if filetime == 0 || filetime < epochDelta || filetime > maxReasonable ||
		IsFATEpoch(filetime) {
		return time.Time{}, false
	}

	intervals := int64(filetime - epochDelta)
	seconds := intervals / 10000000
	nanos := (intervals % 10000000) * 100

	return time.Unix(seconds, nanos).UTC(), true
}

// FromDOSDateTime converts the FAT date and time a shell item stores.
//
// The returned time is a wall clock reading with no zone: FAT records local
// time and nothing beside it says which offset was in force. It is returned in
// UTC only because Go needs a location, and callers must not present it as a
// UTC instant — pass it through SeasonalCandidates where the host offset is
// known, and report it as local where it is not.
//
// The low 16 bits hold the date and the high 16 bits the time, as shell items
// store them.
func FromDOSDateTime(value uint32) (time.Time, bool) {
	// Exactly the epoch, for the same reason FromFileTime refuses the widened
	// form exactly: a range would discard a genuine old timestamp, and FAT
	// stores seconds in twos, so a real time that happened to fall on the first
	// tick of 1980 is not something this format can distinguish anyway.
	if value == 0 || value == dosEpoch {
		return time.Time{}, false
	}

	date := uint16(value)
	clock := uint16(value >> 16)

	year := 1980 + int(date>>9)
	month := int(date>>5) & 0x0F
	day := int(date) & 0x1F

	hour := int(clock >> 11)
	minute := int(clock>>5) & 0x3F
	second := (int(clock) & 0x1F) * 2

	// A misread offset produces month 0 or hour 31 far more often than it
	// produces a plausible date, so the implausible ones are refused rather
	// than normalised into a date that never existed.
	if month < 1 || month > 12 || day < 1 || day > 31 ||
		hour > 23 || minute > 59 || second > 59 || year > 2100 {
		return time.Time{}, false
	}

	when := time.Date(year, time.Month(month), day, hour, minute, second, 0,
		time.UTC)

	// `day <= 31` is not the same as the day existing in that month, and
	// time.Date normalises rather than refusing: 31 February becomes 2 or 3
	// March, and 31 September becomes 1 October. So a corrupt or misaligned
	// field produced a date that is not merely wrong but *plausible* — it
	// sorts correctly, prints correctly, and is a couple of days from what the
	// field claimed with nothing to show for it. The whole reason the checks
	// above exist is that a structure read at the wrong offset yields
	// plausible values, and normalisation hands that failure a clean-looking
	// result.
	//
	// Round-tripping is the cheapest complete check: where the calendar Go
	// built disagrees with the one the field described, the field did not
	// describe a date. It keeps 29 February in a leap year, which a rule
	// written from a table of month lengths would have to special-case.
	if when.Year() != year || int(when.Month()) != month || when.Day() != day {
		return time.Time{}, false
	}
	return when, true
}

// FromUnixFloat converts the float seconds an EVTX record carries in
// TimeCreated.SystemTime, which holds sub-second precision the record header
// does not.
func FromUnixFloat(seconds float64) (time.Time, bool) {
	if seconds <= 0 {
		return time.Time{}, false
	}
	whole := int64(seconds)
	nanos := int64((seconds - float64(whole)) * 1e9)
	return time.Unix(whole, nanos).UTC(), true
}

// Format renders a time in the one form every Boobook timeline uses. These sort
// correctly as text, which a mixture of offset spellings does not: with
// "+00:00" and "Z" mixed, 09:00+00:00 sorts before 08:00Z despite being an hour
// later.
func Format(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

// SeasonalCandidates returns both UTC readings of a local time recorded without
// a zone — as SetupAPI writes them — given the standard and daylight biases in
// minutes.
//
// Which applies depends on whether daylight saving was in force at that moment,
// which the log does not record. Both are offered rather than one being guessed.
type SeasonalCandidate struct {
	// Basis names which bias produced this reading.
	Basis string
	// BiasMinutes is the total offset applied, west of UTC being positive as
	// Windows records it.
	BiasMinutes int
	UTC         time.Time
}

// SeasonalCandidates converts a recorded local time under both biases.
//
// Windows stores Bias as minutes west of UTC, so UTC = local + bias.
func SeasonalCandidates(local time.Time, standardBias, daylightBias int) []SeasonalCandidate {
	standard := standardBias
	daylight := standardBias + daylightBias

	candidates := []SeasonalCandidate{{
		Basis:       "standard_time",
		BiasMinutes: standard,
		UTC:         local.Add(time.Duration(standard) * time.Minute).UTC(),
	}}

	// Where the two biases agree there is only one reading, and offering it
	// twice would imply an ambiguity that does not exist.
	if daylight != standard {
		candidates = append(candidates, SeasonalCandidate{
			Basis:       "daylight_time",
			BiasMinutes: daylight,
			UTC:         local.Add(time.Duration(daylight) * time.Minute).UTC(),
		})
	}

	return candidates
}
