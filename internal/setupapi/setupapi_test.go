package setupapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A log fragment in the form Windows writes, taken from the shape of the
// reference collections.
const sample = `[Device Install Log]
     OS Version = 10.0.26100
>>>  [Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00#04010d18a394#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}]
>>>  Section start 2026/07/26 10:00:06.987
     ump: Install needed due to device having problem code CM_PROB_NOT_CONFIGURED
     dvi:           Parent Device: STORAGE\Volume\_??_USBSTOR#Disk&Ven__USB#04010d18a394#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
     utl:           Driver INF     - wpdfs.inf (C:\WINDOWS\System32\DriverStore\wpdfs.inf)
     utl:           Class GUID     - {EEC5AD98-8080-425F-922A-DABF3DE3F69A}
<<<  Section end 2026/07/26 10:00:07.318
<<<  [Exit status: SUCCESS]

>>>  [Device Install (Hardware initiated) - PCI\VEN_8086&DEV_9A0D\3&11583659&0&B0]
>>>  Section start 2026/07/26 09:13:01.081
<<<  Section end 2026/07/26 09:13:01.116
<<<  [Exit status: SUCCESS]

>>>  [Delete Device - STORAGE\VOLUME\_??_USBSTOR#DISK&VEN_PATRIOT&PROD_&REV_#24111912130128&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}]
>>>  Section start 2026/07/26 09:13:47.495
<<<  Section end 2026/07/26 09:13:47.497
<<<  [Exit status: SUCCESS]
`

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "setupapi.dev.log")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSelectsUSBSectionsOnly(t *testing.T) {
	// UTC+8, no daylight saving, as Western Australia keeps it.
	zone := TimeZone{BiasMinutes: -480, Found: true}

	sections, stats := Parse(write(t, sample), zone)

	if len(sections) != 2 {
		t.Fatalf("got %d sections, want 2: %+v", len(sections), sections)
	}
	// Every install on the machine passes through this log. Without the gate
	// the result is a driver history, not a device history.
	if stats.NotUSB != 1 {
		t.Errorf("NotUSB = %d, want 1 (the PCI device)", stats.NotUSB)
	}
	if stats.Sections != 3 {
		t.Errorf("Sections = %d, want 3", stats.Sections)
	}

	install := sections[0]
	if install.Kind != KindInstall {
		t.Errorf("Kind = %q, want install", install.Kind)
	}
	if want := `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\04010d18a394`; install.DeviceInstanceID != want {
		t.Errorf("DeviceInstanceID = %q, want %q", install.DeviceInstanceID, want)
	}
	if install.Problem != "CM_PROB_NOT_CONFIGURED" {
		t.Errorf("Problem = %q", install.Problem)
	}
	if install.DriverINF != "wpdfs.inf" {
		t.Errorf("DriverINF = %q", install.DriverINF)
	}
	if install.ExitStatus != "SUCCESS" {
		t.Errorf("ExitStatus = %q", install.ExitStatus)
	}
	if install.LineNumber != 3 {
		t.Errorf("LineNumber = %d, want 3", install.LineNumber)
	}

	if sections[1].Kind != KindDelete {
		t.Errorf("second section Kind = %q, want delete", sections[1].Kind)
	}
}

// The log writes local time with no zone. A single UTC value would be a guess
// presented as a measurement, so both readings are offered whenever daylight
// saving could apply — and only one where it could not.
func TestLocalTimesAreConvertedUnderBothSeasons(t *testing.T) {
	sections, _ := Parse(write(t, sample),
		TimeZone{BiasMinutes: 300, DaylightBiasMinutes: -60, Found: true,
			Observes: true})

	if len(sections) == 0 {
		t.Fatal("no sections")
	}
	candidates := sections[0].StartUTC
	if len(candidates) != 2 {
		t.Fatalf("got %d readings, want 2", len(candidates))
	}
	if candidates[0].UTC.Sub(candidates[1].UTC).Hours() != 1 {
		t.Errorf("the two readings should differ by an hour: %v vs %v",
			candidates[0].UTC, candidates[1].UTC)
	}

	described := Describe(sections[0].StartLocal, candidates)
	if !strings.Contains(described, "or") {
		t.Errorf("an ambiguous time must be shown as ambiguous: %q", described)
	}

	// A zone with no daylight saving has one reading, and offering two would
	// imply an ambiguity that does not exist.
	sections, _ = Parse(write(t, sample), TimeZone{BiasMinutes: -480, Found: true})
	if len(sections[0].StartUTC) != 1 {
		t.Errorf("got %d readings for a zone without daylight saving, want 1",
			len(sections[0].StartUTC))
	}
}

// Without the host offset there is nothing to convert with, and the local time
// must be reported as written rather than treated as UTC.
func TestNoTimeZoneMeansNoConvertedTime(t *testing.T) {
	sections, _ := Parse(write(t, sample), TimeZone{})

	if len(sections[0].StartUTC) != 0 {
		t.Error("a converted time was produced with no time zone")
	}
	if sections[0].StartLocal != "2026/07/26 10:00:06.987" {
		t.Errorf("StartLocal = %q", sections[0].StartLocal)
	}
	if described := Describe(sections[0].StartLocal, nil); !strings.Contains(described, "no time zone") {
		t.Errorf("the absence must be stated: %q", described)
	}
}

// A log that ends mid-section still evidences what started.
func TestUnterminatedSectionIsKeptAndCounted(t *testing.T) {
	truncated := `>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_X\SERIAL&0]
>>>  Section start 2026/07/26 10:00:06.987
     ump: Install needed
`
	sections, stats := Parse(write(t, truncated), TimeZone{})

	if len(sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(sections))
	}
	if stats.Unterminated != 1 {
		t.Errorf("Unterminated = %d, want 1", stats.Unterminated)
	}
	if sections[0].EndLocal != "" {
		t.Error("an end time was reported for a section that never ended")
	}
}

// A zone that stores a daylight bias and never takes it observes nothing, and
// the bias alone does not say which it is.
//
// W. Australia Standard Time carries DaylightBias -60 with both transition
// rules empty: Western Australia abolished daylight saving in 2009 and the
// zone's definition kept the field. The registry reader has decided this from
// the rules for a long time and the SQL has acted on it — this adapter was
// still handed the biases alone, so every SetupAPI section on a Perth host
// recorded a UTC+9 alternative in provenance that nothing supported. It was
// suppressed downstream, which made it invisible in the report and present in
// the file an analyst goes to when checking a reading.
func TestAZoneThatStoresADaylightBiasItNeverTakesHasOneReading(t *testing.T) {
	sections, _ := Parse(write(t, sample), TimeZone{
		BiasMinutes:         -480,
		DaylightBiasMinutes: -60,
		Found:               true,
		Observes:            false,
	})

	if len(sections) == 0 {
		t.Fatal("no sections")
	}
	if got := len(sections[0].StartUTC); got != 1 {
		t.Errorf("got %d readings, want 1: the host does not change its clock, "+
			"so the second reading names an hour no evidence puts anything in",
			got)
	}
}
