package progress

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// live returns a reporter that believes it is writing to a terminal, which is
// the only way to exercise the rewritten line from a test.
func live(out *bytes.Buffer) *Reporter {
	reporter := New(out, 10, false)
	reporter.width = 100
	return reporter
}

// livePhase starts a phase and only then turns the terminal on, so that no
// ticking goroutine is drawing into the buffer while the test reads it. The
// tick is what keeps elapsed time moving in a real run; here it would be a race
// between the test and its own subject.
func livePhase(r *Reporter, index int, name string) *Phase {
	phase := r.Phase(index, name)
	r.live = true
	return phase
}

// unthrottle lets the next draw through. The throttle exists so that a phase
// finishing files faster than the terminal can scroll does not spend the run
// drawing, and in a test it would swallow the very line being asserted on.
func unthrottle(r *Reporter) { r.last = time.Time{} }

func TestARedirectedRunWritesOneLinePerPhase(t *testing.T) {
	var out bytes.Buffer
	reporter := New(&out, 10, false)

	phase := reporter.Phase(2, "Registry")
	phase.Expect(2, 2048)
	phase.Item("SYSTEM", `C:\evidence\SYSTEM`, 1024)
	phase.Read("SYSTEM", `C:\evidence\SYSTEM`, 1024, 40)
	phase.Finish("%d devnode(s)", 40)

	written := out.String()
	if strings.Contains(written, "\r") {
		t.Fatalf("a redirected run rewrote its line: %q", written)
	}
	if lines := strings.Count(written, "\n"); lines != 1 {
		t.Fatalf("want one line for the phase, got %d: %q", lines, written)
	}
	if !strings.Contains(written, "[2/10]") ||
		!strings.Contains(written, "Registry") ||
		!strings.Contains(written, "40 devnode(s)") {
		t.Fatalf("the phase line does not carry the phase or its finding: %q", written)
	}
}

func TestQuietWritesNothingAtAll(t *testing.T) {
	var out bytes.Buffer
	reporter := New(&out, 10, true)

	reporter.Printf("something\n")
	phase := livePhase(reporter, 1, "Discovery")
	phase.Expect(4, 4096)
	phase.Item("EVTX", `C:\evidence\System.evtx`, 1024)
	phase.Read("EVTX", `C:\evidence\System.evtx`, 1024, 12)
	phase.Records(3)
	phase.Finish("done")

	if out.Len() != 0 {
		t.Fatalf("a quiet run wrote %q", out.String())
	}
}

func TestTheProgressLineNamesTheArtefactAndWhatItHasRead(t *testing.T) {
	var out bytes.Buffer
	reporter := live(&out)

	phase := livePhase(reporter, 5, "Event logs")
	phase.Expect(4, 4096)
	unthrottle(reporter)
	phase.Item("EVTX", `C:\evidence\Windows\System32\winevt\Logs\System.evtx`, 1024)
	unthrottle(reporter)
	phase.Read("EVTX", `C:\evidence\Windows\System32\winevt\Logs\System.evtx`,
		1024, 1200)

	written := out.String()
	for _, want := range []string{"[5/10]", "Event logs", "1/4 file(s)",
		"1,200 record(s)", "System.evtx"} {
		if !strings.Contains(written, want) {
			t.Fatalf("the progress line is missing %q: %q", want, written)
		}
	}
	// The full path would push everything that moves off the end of the line.
	if strings.Contains(written, `C:\evidence`) {
		t.Fatalf("the progress line carries the whole path: %q", written)
	}
}

func TestTheProgressLineIsErasedBeforeAnythingElseIsWritten(t *testing.T) {
	var out bytes.Buffer
	reporter := live(&out)

	phase := livePhase(reporter, 2, "Registry")
	phase.Expect(1, 1024)
	unthrottle(reporter)
	phase.Item("SYSTEM", `C:\evidence\SYSTEM`, 1024)

	drawn := out.String()
	if !strings.Contains(drawn, "\r") {
		t.Fatalf("nothing was drawn to erase: %q", drawn)
	}
	out.Reset()

	reporter.Printf("      device links:\n")
	written := out.String()
	// The erase has to come first, or the note is printed over the top of a
	// line that is still on the screen.
	if !strings.HasPrefix(written, "\r") {
		t.Fatalf("the line was not erased first: %q", written)
	}
	if !strings.HasSuffix(written, "      device links:\n") {
		t.Fatalf("the note was not written after the erase: %q", written)
	}
}

func TestNoEstimateIsOfferedUntilSomethingHasBeenMeasured(t *testing.T) {
	var out bytes.Buffer
	reporter := live(&out)

	phase := livePhase(reporter, 5, "Event logs")
	phase.Expect(4, 4096)
	unthrottle(reporter)
	phase.Item("EVTX", `C:\evidence\System.evtx`, 1024)

	// Nothing has been read, so nothing has been measured, and an estimate here
	// could only be a guess dressed as a measurement.
	if strings.Contains(out.String(), "ETA") {
		t.Fatalf("an estimate was offered before anything was read: %q", out.String())
	}
}

func TestTheEstimateFollowsTheMeasuredRate(t *testing.T) {
	var out bytes.Buffer
	reporter := New(&out, 10, false)

	phase := reporter.Phase(5, "Event logs")
	phase.Expect(2, 4<<20)
	phase.Item("EVTX", `C:\evidence\System.evtx`, 2<<20)

	// Two megabytes read in a second, two still to go: one second left.
	phase.work["EVTX"].started = time.Now().Add(-time.Second)
	phase.work["EVTX"].bytes = 2 << 20
	phase.bytesDone = 2 << 20

	remaining, ok := reporter.eta(phase)
	if !ok {
		t.Fatal("no estimate was offered from a measured rate")
	}
	if remaining < 900*time.Millisecond || remaining > 1200*time.Millisecond {
		t.Fatalf("estimate %s is not the second the measured rate implies", remaining)
	}
}

func TestARateMeasuredInOnePhaseEstimatesTheNext(t *testing.T) {
	var out bytes.Buffer
	reporter := New(&out, 10, false)

	first := reporter.Phase(4, "User hives")
	first.Expect(1, 1<<20)
	first.Item("NTUSER", `C:\evidence\NTUSER.DAT`, 1<<20)
	first.work["NTUSER"].started = time.Now().Add(-time.Second)
	first.work["NTUSER"].bytes = 1 << 20
	first.Finish("read")

	// The second phase has read nothing of its own. Without the rate carried
	// from the first it could say nothing about how long it has left.
	second := reporter.Phase(5, "User hives")
	second.Expect(1, 2<<20)
	second.Item("NTUSER", `C:\evidence\NTUSER.DAT`, 2<<20)

	remaining, ok := reporter.eta(second)
	if !ok {
		t.Fatal("the rate measured in the first phase was not carried to the second")
	}
	if remaining < 1500*time.Millisecond || remaining > 2500*time.Millisecond {
		t.Fatalf("estimate %s does not follow the rate the first phase measured",
			remaining)
	}
}

func TestAnArtefactThatFailedStillCountsAsHandled(t *testing.T) {
	var out bytes.Buffer
	reporter := live(&out)

	phase := livePhase(reporter, 2, "Registry")
	phase.Expect(2, 2048)
	phase.Read("SYSTEM", `C:\evidence\SYSTEM`, 1024, 0)
	unthrottle(reporter)
	phase.Read("SYSTEM", `C:\evidence\SYSTEM2`, 1024, 20)

	// A hive that could not be read is still a hive the phase has finished
	// with. Counted otherwise, a run with one failure never reaches its total
	// and reads as stalled at the end.
	if !strings.Contains(out.String(), "2/2 file(s)") {
		t.Fatalf("the failed artefact was not counted: %q", out.String())
	}
}

func TestTheLineIsKeptInsideTheTerminal(t *testing.T) {
	var out bytes.Buffer
	reporter := live(&out)
	reporter.width = 40

	phase := livePhase(reporter, 5, "Event logs")
	phase.Expect(2, 2048)
	unthrottle(reporter)
	phase.Item("EVTX", strings.Repeat("a", 200)+".evtx", 1024)

	// A line longer than the terminal wraps, and a wrapped line cannot be
	// rewritten: the carriage return only reaches the start of the last row.
	for _, line := range strings.Split(out.String(), "\r") {
		if columns := len([]rune(line)); columns >= reporter.width {
			t.Fatalf("a line of %d columns exceeds the %d column terminal: %q",
				columns, reporter.width, line)
		}
	}
}

func TestDurationsReadTheWayAProgressLineIsRead(t *testing.T) {
	for _, test := range []struct {
		given time.Duration
		want  string
	}{
		{1500 * time.Millisecond, "1.5s"},
		{45 * time.Second, "45.0s"},
		{95 * time.Second, "1m35s"},
		{3 * time.Hour, "3h00m"},
	} {
		if got := brief(test.given); got != test.want {
			t.Errorf("brief(%s) = %q, want %q", test.given, got, test.want)
		}
	}
}

func TestCountsAreGroupedSoSixFiguresCanBeRead(t *testing.T) {
	for _, test := range []struct {
		given int
		want  string
	}{{7, "7"}, {999, "999"}, {1000, "1,000"}, {1234567, "1,234,567"}} {
		if got := thousands(test.given); got != test.want {
			t.Errorf("thousands(%d) = %q, want %q", test.given, got, test.want)
		}
	}
}
