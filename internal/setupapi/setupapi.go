// Package setupapi parses the Windows device installation log.
//
// setupapi.dev.log records every device install the PnP manager performed, and
// it survives in rotated copies after the registry has moved on. It is the one
// Tier A source that predates the current SYSTEM hive, which makes it the place
// a device that has since been removed still shows up.
//
// Its timestamps are local, written with no zone and no offset. Boobook does
// not guess which one applied: it keeps the local time as written and offers
// both seasonal readings, labelled. A single converted timestamp here would be
// a fabrication dressed as a fact.
package setupapi

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Bloggzy/boobook/internal/devid"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// Kind is what the section did.
type Kind string

const (
	KindInstall Kind = "install"
	KindDelete  Kind = "delete"
	KindOther   Kind = "other"
)

// Section is one logged operation.
type Section struct {
	SourceFile string
	// LineNumber is where the section header sits, so a finding can be checked
	// against the file directly.
	LineNumber int

	// Operation is the bracketed heading as written: "Device Install (Hardware
	// initiated)", "Delete Device", and so on.
	Operation string
	Kind      Kind
	// Target is the identifier the heading named, unaltered.
	Target string
	// DeviceInstanceID is Target in canonical form, where it named a device.
	DeviceInstanceID string

	// StartLocal and EndLocal are as written: local time, no zone.
	StartLocal string
	EndLocal   string
	// StartUTC and EndUTC are both readings of the local time, labelled by the
	// bias each assumed. Empty where no time zone was available.
	StartUTC []wintime.SeasonalCandidate
	EndUTC   []wintime.SeasonalCandidate

	ExitStatus   string
	ParentDevice string
	DriverINF    string
	ClassGUID    string
	// Problem is the problem code that prompted the install, where one is given.
	Problem string
}

// Stats accounts for what a file contributed.
type Stats struct {
	Path         string
	Bytes        int64
	LinesRead    int
	Sections     int
	Retained     int
	NotUSB       int
	Unterminated int
	Err          error
}

var (
	sectionHeader = regexp.MustCompile(`^>>>\s+\[(.+?)\]\s*$`)
	sectionStart  = regexp.MustCompile(`^>>>\s+Section start\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)`)
	sectionEnd    = regexp.MustCompile(`^<<<\s+Section end\s+(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)`)
	exitStatus    = regexp.MustCompile(`^<<<\s+\[Exit status:\s*(.+?)\]`)

	parentDevice = regexp.MustCompile(`Parent Device:\s*(\S+)`)
	driverINF    = regexp.MustCompile(`Driver INF\s+-\s+(\S+)`)
	classGUID    = regexp.MustCompile(`Class GUID\s+-\s+(\{[0-9A-Fa-f-]+\})`)
	problemCode  = regexp.MustCompile(`problem code (CM_PROB_\w+)`)
)

// localLayout is how the log writes a timestamp. It carries no zone, which is
// the whole difficulty.
const localLayout = "2006/01/02 15:04:05.000"

// TimeZone is the host's offset, in minutes west of UTC, as the registry
// records it. Found is false where no time zone could be read, in which case
// the local times are kept and no UTC reading is offered.
type TimeZone struct {
	BiasMinutes         int
	StandardBiasMinutes int
	DaylightBiasMinutes int
	Found               bool
	// Observes is whether the host actually changes its clock, decided from the
	// zone's transition rules rather than from the bias.
	//
	// The bias alone is not the question and answering it that way was wrong on
	// real evidence: W. Australia Standard Time carries DaylightBias -60 with
	// both transition rules empty, because Western Australia abolished daylight
	// saving in 2009. The registry reader has read the rules for a long time
	// and the SQL has acted on them; this adapter was still handed the biases
	// alone, so every SetupAPI section on a Perth host recorded a UTC+9
	// alternative in provenance that no evidence supported — suppressed later
	// in the timeline, and present in the file an analyst checks a reading
	// against.
	Observes bool
}

// Parse reads one setupapi log and returns the sections naming a USB device.
func Parse(path string, zone TimeZone) ([]Section, Stats) {
	stats := Stats{Path: path}
	if info, err := os.Stat(path); err == nil {
		stats.Bytes = info.Size()
	}

	file, err := os.Open(path)
	if err != nil {
		stats.Err = err
		return nil, stats
	}
	defer file.Close()

	var sections []Section
	var current *Section

	scanner := bufio.NewScanner(file)
	// Some driver lines are very long, and the default 64 KB limit would end
	// the scan mid-file with an error that reads like a truncated log.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		stats.LinesRead++
		line := scanner.Text()

		if matches := sectionHeader.FindStringSubmatch(line); matches != nil {
			// A section that never closed is still evidence of what started.
			if current != nil {
				stats.Unterminated++
				sections = appendIfRelevant(sections, current, &stats)
			}
			current = newSection(path, lineNumber, matches[1])
			continue
		}

		if current == nil {
			continue
		}

		switch {
		case sectionStart.MatchString(line):
			current.StartLocal = sectionStart.FindStringSubmatch(line)[1]
			current.StartUTC = candidates(current.StartLocal, zone)
		case sectionEnd.MatchString(line):
			current.EndLocal = sectionEnd.FindStringSubmatch(line)[1]
			current.EndUTC = candidates(current.EndLocal, zone)
		case exitStatus.MatchString(line):
			current.ExitStatus = exitStatus.FindStringSubmatch(line)[1]
			sections = appendIfRelevant(sections, current, &stats)
			current = nil
		default:
			readBodyLine(current, line)
		}
	}

	if current != nil {
		stats.Unterminated++
		sections = appendIfRelevant(sections, current, &stats)
	}

	if err := scanner.Err(); err != nil {
		stats.Err = err
	}

	stats.Sections = stats.Retained + stats.NotUSB
	return sections, stats
}

func newSection(path string, lineNumber int, heading string) *Section {
	section := &Section{
		SourceFile: path,
		LineNumber: lineNumber,
		Operation:  heading,
		Kind:       KindOther,
	}

	// "Device Install (Hardware initiated) - USBSTOR\..." — the operation and
	// its target, separated by the first " - ".
	if index := strings.Index(heading, " - "); index > 0 {
		section.Operation = strings.TrimSpace(heading[:index])
		section.Target = strings.TrimSpace(heading[index+3:])
		section.DeviceInstanceID = devid.Normalise(section.Target)
	}

	switch {
	case strings.Contains(section.Operation, "Device Install"):
		section.Kind = KindInstall
	case strings.Contains(section.Operation, "Delete Device"):
		section.Kind = KindDelete
	}

	return section
}

func readBodyLine(section *Section, line string) {
	if section.ParentDevice == "" {
		if matches := parentDevice.FindStringSubmatch(line); matches != nil {
			section.ParentDevice = matches[1]
		}
	}
	if section.DriverINF == "" {
		if matches := driverINF.FindStringSubmatch(line); matches != nil {
			section.DriverINF = matches[1]
		}
	}
	if section.ClassGUID == "" {
		if matches := classGUID.FindStringSubmatch(line); matches != nil {
			section.ClassGUID = strings.ToLower(matches[1])
		}
	}
	if section.Problem == "" {
		if matches := problemCode.FindStringSubmatch(line); matches != nil {
			section.Problem = matches[1]
		}
	}
}

// appendIfRelevant keeps a section only where it names a USB device, and counts
// the rest. Every install on the machine passes through this log, so without
// the gate the output would be a driver history rather than a device history.
func appendIfRelevant(sections []Section, section *Section, stats *Stats) []Section {
	if !devid.IsUSB(section.Target) && !devid.IsUSB(section.ParentDevice) {
		stats.NotUSB++
		return sections
	}
	stats.Retained++
	return append(sections, *section)
}

func candidates(local string, zone TimeZone) []wintime.SeasonalCandidate {
	if !zone.Found || local == "" {
		return nil
	}
	parsed, err := time.Parse(localLayout, local)
	if err != nil {
		return nil
	}
	// A host that never changes its clock has one reading, and offering a
	// second states an ambiguity the evidence does not contain.
	daylight := zone.DaylightBiasMinutes
	if !zone.Observes {
		daylight = 0
	}
	return wintime.SeasonalCandidates(parsed,
		zone.BiasMinutes+zone.StandardBiasMinutes, daylight)
}

// Describe renders the time of a section for display: the local time as
// written, then the readings it could correspond to.
//
// Where the two readings differ the ambiguity is shown rather than resolved.
// An hour is the difference between a device being connected during business
// hours and outside them, which is exactly the sort of claim an analyst should
// not have decided for them.
func Describe(local string, candidates []wintime.SeasonalCandidate) string {
	if local == "" {
		return ""
	}
	if len(candidates) == 0 {
		return local + " (local, no time zone available)"
	}
	if len(candidates) == 1 {
		return fmt.Sprintf("%s (%s)",
			wintime.Format(candidates[0].UTC), candidates[0].Basis)
	}

	parts := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		parts = append(parts, fmt.Sprintf("%s if %s",
			wintime.Format(candidate.UTC), strings.ReplaceAll(candidate.Basis, "_", " ")))
	}
	return local + " local = " + strings.Join(parts, ", or ")
}
