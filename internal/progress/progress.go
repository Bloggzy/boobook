// Package progress reports what a run is doing while it does it.
//
// A collection can hold several gigabytes and take minutes to read, and a tool
// that says nothing until it finishes is indistinguishable from one that has
// hung. What is reported is the phase, the artefact in hand, the records read
// so far, the elapsed time and an estimate of the time remaining.
//
// The estimate is projected from throughput this run has measured, held
// separately per artefact class, because the classes differ by more than an
// order of magnitude: a registry hive and an event log of the same size take
// very different times to read, and one rate across both would predict neither.
// Until something has been measured no estimate is offered, rather than a
// guess dressed as a measurement.
//
// Everything here goes to stderr. Findings go to the report and the data files,
// and the manifest path goes to stdout, so a caller can pipe the run without
// having to filter the narration out of it.
package progress

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reporter is the run's narration.
//
// It is safe for concurrent use: the event log phase parses several files at
// once, and each worker reports the file it finished.
type Reporter struct {
	out   io.Writer
	quiet bool
	// live is whether the destination is a terminal. Redirected, each phase
	// writes one line and nothing is ever rewritten: a log file full of
	// carriage returns is worse than no progress at all.
	live    bool
	width   int
	total   int
	started time.Time

	mu    sync.Mutex
	rates map[string]*rate
	phase *Phase
	// drawn is whether a progress line is currently on the terminal and has to
	// be erased before anything else is written over it.
	drawn bool
	last  time.Time
}

// rate is the throughput measured for one artefact class.
type rate struct {
	bytes   int64
	elapsed time.Duration
}

// New returns a reporter writing to out, narrating a run of total phases.
func New(out io.Writer, total int, quiet bool) *Reporter {
	return &Reporter{
		out:     out,
		quiet:   quiet,
		live:    !quiet && isTerminal(out),
		width:   terminalWidth(),
		total:   total,
		started: time.Now(),
		rates:   map[string]*rate{},
	}
}

// Printf writes a line, erasing any progress line first so that the two never
// interleave into an unreadable one.
func (r *Reporter) Printf(format string, args ...any) {
	if r.quiet {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.erase()
	fmt.Fprintf(r.out, format, args...)
}

// Writer returns an io.Writer that puts what is written to it through the
// reporter.
//
// It is meant for the standard logger, which a dependency may write to. Left
// alone, those lines go straight to stderr: they land in the middle of the
// progress line and stay there, and they are printed even under -quiet, which
// promised silence.
func (r *Reporter) Writer() io.Writer { return writer{reporter: r} }

type writer struct{ reporter *Reporter }

func (w writer) Write(line []byte) (int, error) {
	w.reporter.Printf("%s", line)
	return len(line), nil
}

// Close erases any progress line left on the terminal. Deferred by the caller,
// it also runs on the way out of a failed run, so an error message is not
// printed on top of a half-drawn line.
func (r *Reporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.erase()
}

// Elapsed is how long the run has been going.
func (r *Reporter) Elapsed() time.Duration { return time.Since(r.started) }

// Phase begins a phase and returns it. Only one phase runs at a time.
func (r *Reporter) Phase(index int, name string) *Phase {
	phase := &Phase{
		reporter: r,
		index:    index,
		name:     name,
		started:  time.Now(),
		work:     map[string]*classWork{},
	}
	if r.quiet {
		return phase
	}

	r.mu.Lock()
	r.phase = phase
	r.mu.Unlock()

	if r.live {
		// A phase that reads one large file, or that spends its time inside
		// DuckDB, reports nothing between its start and its end. The tick is
		// what keeps the elapsed time moving there, which is the difference
		// between a progress display and a counter.
		phase.stop = make(chan struct{})
		go phase.tick(phase.stop)
	}
	return phase
}

// Phase is one step of the run.
type Phase struct {
	reporter *Reporter
	index    int
	name     string
	started  time.Time

	// files and bytes are the work the phase expects to do, where it knows in
	// advance. Bytes rather than records: how many records an artefact holds is
	// not known until it has been read, and an estimate has to divide something
	// known by a measured rate.
	files int
	bytes int64

	filesDone int
	bytesDone int64
	records   int
	item      string
	class     string
	work      map[string]*classWork

	stop chan struct{}
}

// classWork is what one artefact class has cost so far in this phase. The
// elapsed time is the phase's wall clock rather than the sum of the individual
// files, which would count the same seconds several times over where files are
// read in parallel and understate the rate accordingly.
type classWork struct {
	bytes   int64
	started time.Time
}

// Expect declares the work the phase is about to do. Without it the phase still
// reports elapsed time; with it, it can also say how far through it is and how
// much longer it has to go.
func (p *Phase) Expect(files int, bytes int64) {
	if p.reporter.quiet {
		return
	}
	p.reporter.mu.Lock()
	p.files, p.bytes = files, bytes
	p.reporter.mu.Unlock()
	p.reporter.draw(p)
}

// Item announces the artefact now being read. It is what the line names, and it
// starts the clock for that artefact's class.
//
// Where files are read in parallel the name shown is simply the last one
// started, which is what a reader of a moving line wants: evidence that work is
// going on and roughly where it has got to.
func (p *Phase) Item(class, path string, size int64) {
	if p.reporter.quiet {
		return
	}
	p.reporter.mu.Lock()
	p.item, p.class = base(path), class
	if p.work[class] == nil {
		p.work[class] = &classWork{started: time.Now()}
	}
	p.reporter.mu.Unlock()
	p.reporter.draw(p)
}

// Read reports one artefact finished: its size, and the records it yielded.
//
// Size and records are given here rather than remembered from Item because
// several artefacts can be in hand at once, and a phase that remembered only
// the last one started would credit its records to the wrong file.
func (p *Phase) Read(class, path string, size int64, records int) {
	if p.reporter.quiet {
		return
	}
	p.reporter.mu.Lock()
	p.filesDone++
	p.bytesDone += size
	p.records += records
	if p.work[class] == nil {
		p.work[class] = &classWork{started: p.started}
	}
	p.work[class].bytes += size
	p.reporter.mu.Unlock()
	p.reporter.draw(p)
}

// Advance reports bytes finished inside an artefact that is not finished.
//
// It exists because an event log large enough to matter is read in pieces, and
// crediting the bytes only when the whole file lands would leave the line still
// for as long as that file took — on the multi-gigabyte logs this is for, that
// is a minute of a run that looks hung. The file count is not touched: the
// artefact is not done, and saying it was would be the same lie in the other
// direction.
func (p *Phase) Advance(class string, bytes int64) {
	if p.reporter.quiet {
		return
	}
	p.reporter.mu.Lock()
	p.bytesDone += bytes
	if p.work[class] == nil {
		p.work[class] = &classWork{started: p.started}
	}
	p.work[class].bytes += bytes
	p.reporter.mu.Unlock()
	p.reporter.draw(p)
}

// Records adds records read from something with no file of its own.
func (p *Phase) Records(records int) {
	if p.reporter.quiet {
		return
	}
	p.reporter.mu.Lock()
	p.records += records
	p.reporter.mu.Unlock()
	p.reporter.draw(p)
}

// Finish ends the phase and writes its summary in place of the progress line.
//
// The summary is what survives in a redirected log, so it carries the counts
// rather than the progress: what the phase found, not how fast it went.
func (p *Phase) Finish(format string, args ...any) {
	if p.stop != nil {
		close(p.stop)
		p.stop = nil
	}
	if p.reporter.quiet {
		return
	}

	r := p.reporter
	r.mu.Lock()
	defer r.mu.Unlock()

	// The rates measured here are carried to the rest of the run, so a class
	// read again in a later phase is estimated from what it actually cost.
	for class, work := range p.work {
		elapsed := time.Since(work.started)
		if work.bytes <= 0 || elapsed <= 0 {
			continue
		}
		if r.rates[class] == nil {
			r.rates[class] = &rate{}
		}
		r.rates[class].bytes += work.bytes
		r.rates[class].elapsed += elapsed
	}

	r.erase()
	r.phase = nil
	fmt.Fprintf(r.out, "%s%s\n", r.prefix(p), fmt.Sprintf(format, args...))
}

// tick redraws the line while the phase is working, so the elapsed time moves
// even where the phase has nothing to announce.
// The channel is passed rather than read from the phase, so that ending the
// phase and this goroutine's next look at it are not a race.
func (p *Phase) tick(stop <-chan struct{}) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			p.reporter.draw(p)
		}
	}
}

// draw rewrites the progress line, at most a few times a second. The throttle
// is not cosmetic: the event log phase finishes files faster than a terminal
// can scroll, and drawing each one would cost more than the parse.
func (r *Reporter) draw(p *Phase) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.live || r.phase != p || time.Since(r.last) < 100*time.Millisecond {
		return
	}
	r.last = time.Now()

	line := truncate(r.render(p), r.width-1)
	fmt.Fprintf(r.out, "\r%s\r%s", strings.Repeat(" ", r.width-1), line)
	r.drawn = true
}

// render builds the progress line. Held by the caller: reads phase counters.
func (r *Reporter) render(p *Phase) string {
	parts := []string{}
	if p.files > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d file(s)", p.filesDone, p.files))
	}
	if p.records > 0 {
		parts = append(parts, thousands(p.records)+" record(s)")
	}
	parts = append(parts, brief(time.Since(p.started)))
	if remaining, ok := r.eta(p); ok {
		parts = append(parts, "ETA "+brief(remaining))
	}

	line := r.prefix(p) + strings.Join(parts, "  ")
	if p.item != "" {
		line += "  " + p.item
	}
	return line
}

// eta estimates the time the phase has left.
//
// It is deliberately conservative: the artefact in hand counts as unread until
// it is finished, so a phase reading one large file estimates from the files
// behind it rather than from a guess at how far into this one it has got.
func (r *Reporter) eta(p *Phase) (time.Duration, bool) {
	remaining := p.bytes - p.bytesDone
	if p.bytes <= 0 || remaining <= 0 {
		return 0, false
	}
	perSecond := r.throughput(p)
	if perSecond <= 0 {
		return 0, false
	}
	return time.Duration(float64(remaining) / perSecond * float64(time.Second)), true
}

// throughput is bytes per second for the class in hand: what this phase has
// measured for it, then what the run measured for it earlier, and finally what
// the phase has managed across every class. Nothing is assumed. A class nobody
// has read yet yields no rate, and the line then shows no estimate.
func (r *Reporter) throughput(p *Phase) float64 {
	if work := p.work[p.class]; work != nil && work.bytes > 0 {
		if elapsed := time.Since(work.started); elapsed > 0 {
			return float64(work.bytes) / elapsed.Seconds()
		}
	}
	if measured := r.rates[p.class]; measured != nil && measured.elapsed > 0 {
		return float64(measured.bytes) / measured.elapsed.Seconds()
	}
	if elapsed := time.Since(p.started); p.bytesDone > 0 && elapsed > 0 {
		return float64(p.bytesDone) / elapsed.Seconds()
	}
	return 0
}

func (r *Reporter) prefix(p *Phase) string {
	return fmt.Sprintf("%-8s%-10s ",
		fmt.Sprintf("[%d/%d]", p.index, r.total), p.name)
}

// erase removes the progress line from the terminal. Held by the caller.
func (r *Reporter) erase() {
	if !r.drawn {
		return
	}
	fmt.Fprintf(r.out, "\r%s\r", strings.Repeat(" ", r.width-1))
	r.drawn = false
}

// brief renders a duration the way a person reads one off a progress line.
func brief(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// thousands groups a count so six figures can be read at a glance.
func thousands(n int) string {
	digits := strconv.Itoa(n)
	if n < 0 {
		return digits
	}
	var out strings.Builder
	for index, digit := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(digit)
	}
	return out.String()
}

// base is the file name alone. The full path is in the manifest; on a progress
// line it would push everything that changes off the end.
func base(path string) string {
	if index := strings.LastIndexAny(path, `\/`); index >= 0 {
		return path[index+1:]
	}
	return path
}

// truncate cuts a line to a column count. Columns, not bytes: a path holding a
// character that takes three bytes to write still takes one column to print,
// and cutting by byte would both mangle the character and leave the line short.
func truncate(text string, size int) string {
	runes := []rune(text)
	if size < 4 || len(runes) <= size {
		return text
	}
	return string(runes[:size-1]) + "…"
}

// isTerminal reports whether out is a console rather than a file or a pipe.
func isTerminal(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// terminalWidth is how wide the line may be. A line longer than the terminal
// wraps, and a wrapped line cannot be rewritten in place: the carriage return
// returns to the start of the last row and the rest is left behind.
func terminalWidth() int {
	if columns := os.Getenv("COLUMNS"); columns != "" {
		if width, err := strconv.Atoi(columns); err == nil && width > 20 {
			return width
		}
	}
	return 80
}
