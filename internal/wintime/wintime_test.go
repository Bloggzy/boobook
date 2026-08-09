package wintime

import (
	"testing"
	"time"
)

func TestFromFileTimeKnownValues(t *testing.T) {
	cases := []struct {
		name     string
		filetime uint64
		want     string
		ok       bool
	}{
		{
			// The Unix epoch expressed as a FILETIME.
			name:     "unix epoch",
			filetime: 116444736000000000,
			want:     "1970-01-01T00:00:00.000000000Z",
			ok:       true,
		},
		{
			// Verified independently: (133700000000000000 - 116444736000000000)
			// / 1e7 = 1725526400 unix seconds.
			name:     "known instant",
			filetime: 133700000000000000,
			want:     "2024-09-05T08:53:20.000000000Z",
			ok:       true,
		},
		{
			// Sub-second precision must survive: a FILETIME is 100ns intervals.
			name:     "sub-second precision retained",
			filetime: 116444736000000001,
			want:     "1970-01-01T00:00:00.000000100Z",
			ok:       true,
		},
		{name: "zero is not a time", filetime: 0, ok: false},
		{name: "before the unix epoch is rejected", filetime: 1000, ok: false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := FromFileTime(testCase.filetime)
			if ok != testCase.ok {
				t.Fatalf("ok = %v, want %v", ok, testCase.ok)
			}
			if !ok {
				return
			}
			if formatted := Format(got); formatted != testCase.want {
				t.Errorf("= %s, want %s", formatted, testCase.want)
			}
		})
	}
}

// A timeline sorts as text. If one channel spells UTC "+00:00" and another "Z",
// 09:00+00:00 sorts before 08:00Z despite being an hour later — so every
// derived time must render identically.
func TestFormatIsTextSortable(t *testing.T) {
	earlier := time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)
	later := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	// Same instant as `later`, expressed in a non-UTC zone.
	zone := time.FixedZone("AWST", 8*3600)
	laterElsewhere := later.In(zone)

	if Format(earlier) >= Format(later) {
		t.Errorf("earlier %s should sort before later %s",
			Format(earlier), Format(later))
	}
	if Format(laterElsewhere) != Format(later) {
		t.Errorf("a zoned time must render identically to its UTC form: %s vs %s",
			Format(laterElsewhere), Format(later))
	}
}

func TestSeasonalCandidates(t *testing.T) {
	// Perth: UTC+8, no daylight saving. Windows records minutes west of UTC.
	local := time.Date(2026, 3, 1, 17, 0, 0, 0, time.UTC)

	candidates := SeasonalCandidates(local, -480, 0)
	if len(candidates) != 1 {
		t.Fatalf("no daylight bias should give one candidate, got %d",
			len(candidates))
	}
	if want := "2026-03-01T09:00:00.000000000Z"; Format(candidates[0].UTC) != want {
		t.Errorf("= %s, want %s", Format(candidates[0].UTC), want)
	}

	// A zone that does observe daylight saving has two readings, and the log
	// does not record which applied.
	candidates = SeasonalCandidates(local, 300, -60)
	if len(candidates) != 2 {
		t.Fatalf("expected two candidates, got %d", len(candidates))
	}
	if candidates[0].Basis != "standard_time" || candidates[1].Basis != "daylight_time" {
		t.Errorf("candidates must name their basis, got %q and %q",
			candidates[0].Basis, candidates[1].Basis)
	}
	if !candidates[1].UTC.Before(candidates[0].UTC) {
		t.Error("the daylight reading should be an hour earlier in UTC")
	}
}

// 1980-01-01 00:00:00 is the FAT epoch: the earliest date a DOS date can
// express, and what a zeroed one becomes when Windows widens it into a
// FILETIME. Explorer writes it into a shortcut whose target has no timestamps
// of its own. Read as a write time it puts a file record in 1980 and drags the
// reported span of a whole case back forty years with it.
func TestTheFATEpochIsNotATime(t *testing.T) {
	if _, ok := FromFileTime(FATEpoch); ok {
		t.Error("the FAT epoch converts to a time, so a zeroed date reads as 1980")
	}

	// Exactly the sentinel, and not a range. A genuine timestamp that happens
	// to be old is still a timestamp, and refusing a whole year would throw one
	// away.
	nextTick := uint64(FATEpoch + 1)
	converted, ok := FromFileTime(nextTick)
	if !ok {
		t.Fatal("a real timestamp one tick after the sentinel was refused")
	}
	if converted.Year() != 1980 {
		t.Errorf("converted to %s, want 1980", converted)
	}
}

// The same sentinel in the packed form a shell item stores. Read as a wall clock
// and converted with a host offset east of UTC it lands in December 1979, and a
// report that took it for a timestamp said the evidence reached back to
// 1979-12-31 14:00:00 — a date before the format's own epoch, on a machine
// whose oldest real record was two years old.
func TestTheFATEpochInAShellItemIsNotATime(t *testing.T) {
	// Year 0, month 1, day 1, and a zeroed time word.
	const packed = uint32(0x00000021)

	if _, ok := FromDOSDateTime(packed); ok {
		t.Error("the packed FAT epoch converts to a time")
	}

	// Exactly the sentinel. The next expressible instant is two seconds later,
	// because FAT stores seconds in twos, and it is a time like any other.
	converted, ok := FromDOSDateTime(packed | (1 << 16))
	if !ok {
		t.Fatal("a real timestamp on the first day of 1980 was refused")
	}
	if converted.Year() != 1980 || converted.Second() != 2 {
		t.Errorf("converted to %s, want 1980-01-01 00:00:02", converted)
	}
}

// A day number inside a month that has no such day is not a date.
//
// The check was `day <= 31`, which passes 31 February — and time.Date
// normalises rather than refusing, so it became 2 or 3 March. That is the worst
// possible outcome for a forensic tool: not an obvious error but a plausible
// one, two days from where the field claimed, sorting and printing like any
// other timestamp.
//
// The whole reason the surrounding checks exist is that a structure read at the
// wrong offset produces plausible values rather than failing. Normalisation
// hands exactly that failure a clean-looking result.
func TestADayThatDoesNotExistInItsMonthIsNotATime(t *testing.T) {
	pack := func(year, month, day, hour, minute, second int) uint32 {
		date := uint16((year-1980)<<9 | month<<5 | day)
		clock := uint16(hour<<11 | minute<<5 | second/2)
		return uint32(clock)<<16 | uint32(date)
	}

	for _, impossible := range []struct {
		name                 string
		year, month, day     int
		hour, minute, second int
	}{
		{"31 February", 2026, 2, 31, 12, 0, 0},
		{"30 February", 2026, 2, 30, 12, 0, 0},
		{"29 February in a common year", 2026, 2, 29, 12, 0, 0},
		{"31 September", 2026, 9, 31, 12, 0, 0},
		{"31 April", 2026, 4, 31, 12, 0, 0},
		{"31 November", 2026, 11, 31, 12, 0, 0},
	} {
		got, ok := FromDOSDateTime(pack(impossible.year, impossible.month,
			impossible.day, impossible.hour, impossible.minute, impossible.second))
		if ok {
			t.Errorf("%s was accepted and became %v — a normalised date is "+
				"worse than a refused one, because nothing downstream can tell "+
				"it from a real timestamp", impossible.name, got)
		}
	}

	// And the real dates near them still parse, including the leap day in a
	// year that has one. A check that refuses 29 February 2024 would lose a
	// genuine timestamp to catch a corrupt one.
	for _, real := range []struct {
		name                 string
		year, month, day     int
		hour, minute, second int
	}{
		{"29 February in a leap year", 2024, 2, 29, 12, 0, 0},
		{"28 February", 2026, 2, 28, 23, 58, 58},
		{"30 September", 2026, 9, 30, 0, 0, 0},
		{"31 December", 2026, 12, 31, 23, 58, 58},
	} {
		got, ok := FromDOSDateTime(pack(real.year, real.month, real.day,
			real.hour, real.minute, real.second))
		if !ok {
			t.Errorf("%s was refused; it is a real date", real.name)
			continue
		}
		if got.Year() != real.year || int(got.Month()) != real.month ||
			got.Day() != real.day {
			t.Errorf("%s came back as %v", real.name, got)
		}
	}
}
