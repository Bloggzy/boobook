// Package report renders the case report.
//
// The report is a document rather than a data file, so it is assembled here
// rather than copied from a view. What is not assembled here is any finding:
// every figure and every headline sentence is read from a view, the same view
// the corresponding CSV is copied from, so the prose and the data cannot
// disagree about the evidence.
//
// The output is one self-contained file. No stylesheet, script, font or image
// is fetched from anywhere: an examiner opens a report on a machine with no
// network, often years later, and a report that degrades without one is a
// report that cannot be relied on. Every value from the evidence is escaped by
// html/template, so a device name carrying markup stays a device name.
package report

import (
	"embed"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Bloggzy/boobook/internal/store"
	"github.com/Bloggzy/boobook/internal/workspace"
)

//go:embed templates/*.html templates/*.css
var assets embed.FS

// Report is everything the document needs, gathered before rendering so a
// failed query fails the report rather than leaving a half-written file.
type Report struct {
	Manifest *workspace.Manifest
	Summary  store.ReportSummary
	Findings []store.Finding

	// Significant is the tier 1 and tier 2 devices, in the order the
	// classification ranked them. They are the body of the report.
	Significant []store.CardDevice

	// Tiers is the same devices cut into their tiers, which is how the section
	// is laid out: tier 1 open, tier 2 behind a disclosure that names what it
	// holds.
	Tiers []TierGroup

	// Timeline is the significant events in order, with the chips that filter
	// them. It follows the cards because a reader asks which devices matter
	// before asking when they were seen.
	Timeline Timeline

	// Files is the file and folder activity, grouped by the device it reached.
	// It follows the timeline because it answers a narrower question than
	// "when was this device on the machine": what was done with it.
	Files Files

	// Prefetch is what ran off each device and what those programmes read from
	// it. It follows the file activity because it answers the same question one
	// step further on: not what was opened, but what was executed.
	Prefetch Prefetch

	// OptInSkipped is the channels Boobook reads that this run did not ask for.
	// It is a limitation and not an omission, and the report has to say so: the
	// absence of a logon beside a connection otherwise reads as evidence there
	// was none.
	OptInSkipped []workspace.SkippedFile

	// Others is everything the classification put in tier 3, collapsed. It
	// comes last of the evidence sections because that is what its tier says
	// about it, and it is present in full because a tier is a ranking and not
	// a filter.
	Others Others

	Coverage []store.Coverage

	// Limitations is what the run could not read and what was not there. It is
	// a section of the report, not a log: a report that does not say what it
	// could not see invites its silences to be read as absences of evidence.
	Limitations []store.Limitation

	// PrefetchSetting is the host's EnablePrefetcher setting as a sentence, or
	// empty where no SYSTEM hive was read. It belongs among the limitations
	// because it governs what the absence of prefetch evidence is allowed to
	// mean: on a host that was not prefetching, "no programme ran from this
	// device" is not a finding the evidence can support.
	PrefetchSetting string

	// GeneratedAt is when the document was written, which is not when the
	// evidence was collected and is labelled as such.
	GeneratedAt time.Time
}

// Gather reads everything the report shows.
func Gather(db *store.Store, manifest *workspace.Manifest) (*Report, error) {
	summary, err := db.Summary()
	if err != nil {
		return nil, err
	}
	findings, err := db.Findings()
	if err != nil {
		return nil, err
	}
	significant, err := db.Cards(2)
	if err != nil {
		return nil, err
	}
	timeline, err := gatherTimeline(db)
	if err != nil {
		return nil, err
	}
	files, err := gatherFiles(db)
	if err != nil {
		return nil, err
	}
	prefetch, err := gatherPrefetch(db)
	if err != nil {
		return nil, err
	}
	others, err := gatherOthers(db)
	if err != nil {
		return nil, err
	}
	coverage, err := db.Coverage()
	if err != nil {
		return nil, err
	}
	limitations, err := db.Limitations()
	if err != nil {
		return nil, err
	}
	prefetchSetting, err := db.PrefetchSetting()
	if err != nil {
		return nil, err
	}

	return &Report{
		Manifest:        manifest,
		Summary:         summary,
		Findings:        findings,
		Significant:     significant,
		Tiers:           tierGroups(significant),
		Timeline:        timeline,
		Files:           files,
		Prefetch:        prefetch,
		OptInSkipped:    optInSkipped(manifest),
		Others:          others,
		Coverage:        coverage,
		Limitations:     limitations,
		PrefetchSetting: prefetchSetting,
		GeneratedAt:     time.Now().UTC(),
	}, nil
}

// Cite renders a sentence that names a data file, linking every file this run
// actually wrote to the copy of it sitting beside the report.
//
// Only names the manifest holds are linked. The manifest is the record of what
// was written, with each file's hash, so a link can only ever point at a file
// this run produced: a report that offered a path to something that is not
// there would be worse than one that offered none. The paths are relative, so
// the report and its data directory move together.
//
// The text is escaped before any of this, and the only markup inserted is built
// here from file names this package's own export table defines. Nothing from
// the evidence reaches the markup.
func (r *Report) Cite(text string) template.HTML {
	escaped := template.HTMLEscapeString(text)

	// Substituted in two passes through a sentinel, so that a file name
	// appearing inside an anchor written by an earlier pass cannot be matched
	// and wrapped a second time.
	anchors := []string{}
	for _, output := range r.dataFiles() {
		if !strings.Contains(escaped, output.name) {
			continue
		}
		sentinel := "\x00" + strconv.Itoa(len(anchors)) + "\x00"
		anchors = append(anchors, fmt.Sprintf(`<a class="cite" href="%s">%s</a>`,
			template.HTMLEscapeString(output.href),
			template.HTMLEscapeString(output.name)))
		escaped = strings.ReplaceAll(escaped, output.name, sentinel)
	}
	for index, anchor := range anchors {
		escaped = strings.ReplaceAll(escaped, "\x00"+strconv.Itoa(index)+"\x00",
			anchor)
	}
	return template.HTML(escaped)
}

type dataFile struct{ name, href string }

// optInSkipped pulls the channels this run chose not to read out of the run's
// own accounting. Only those: a channel nothing reads at all is a fact about
// the tool and is already in the capability catalogue, while this is a fact
// about the run and belongs in its limitations.
func optInSkipped(manifest *workspace.Manifest) []workspace.SkippedFile {
	if manifest == nil || manifest.EventSelection == nil {
		return nil
	}
	var skipped []workspace.SkippedFile
	for _, file := range manifest.EventSelection.SkippedFiles {
		if file.OptIn {
			skipped = append(skipped, file)
		}
	}
	return skipped
}

// dataFiles is what the run wrote, longest name first.
//
// Longest first because the names overlap at their tails, and replacing a short
// name before a long one would linkify the middle of the long one.
func (r *Report) dataFiles() []dataFile {
	files := make([]dataFile, 0, len(r.Manifest.Outputs))
	for _, output := range r.Manifest.Outputs {
		name := path.Base(filepath.ToSlash(output.Name))
		if name == "" || name == "report.html" {
			continue
		}
		files = append(files, dataFile{name: name,
			href: filepath.ToSlash(output.Name)})
	}
	sort.Slice(files, func(i, j int) bool {
		if len(files[i].name) != len(files[j].name) {
			return len(files[i].name) > len(files[j].name)
		}
		return files[i].name < files[j].name
	})
	return files
}

// Write renders the report into dir and returns the path it wrote.
func Write(report *Report, dir string) (string, error) {
	document, err := template.New("report.html").Funcs(functions(report)).ParseFS(
		assets, "templates/*.html")
	if err != nil {
		return "", fmt.Errorf("parse report template: %w", err)
	}

	style, err := assets.ReadFile("templates/report.css")
	if err != nil {
		return "", fmt.Errorf("read report stylesheet: %w", err)
	}

	path := filepath.Join(dir, "report.html")
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create report: %w", err)
	}
	defer file.Close()

	data := struct {
		*Report
		// Style is marked safe because it is the embedded stylesheet plus the
		// filter rules, which are generated from a count this package made.
		// Neither carries anything from the evidence.
		Style template.CSS
	}{report, template.CSS(string(style) + filterStyle(report.bars()))}

	if err := document.Execute(file, data); err != nil {
		return "", fmt.Errorf("render report: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}

// functions closes over the report because two of them need it.
//
// A method on Report would not do: inside {{template "filerows" .Strongest}}
// the root the template calls $ is the argument, not the document, so $.Source
// would not resolve where the file rows need it most.
func functions(report *Report) template.FuncMap {
	return template.FuncMap{
		"instant":  instant,
		"span":     span,
		"bytes":    humanBytes,
		"plural":   plural,
		"lower":    strings.ToLower,
		"sentence": sentence,
		"source":   report.evidenceRelative,
		"nonEmpty": func(values ...string) string { return firstNonEmpty(values) },
		"fold":     foldIDs(),
	}
}

// foldIDs hands out an id for each disclosure the template opens.
//
// A checkbox fold needs a label pointing at its own input, so every one of them
// needs an id nothing else on the page carries — and the folds inside a device
// card are written once in the template and rendered once per device, so the
// id cannot come from the markup. It counts instead. Rendering is sequential
// and the counter is created per Write, so the same evidence produces the same
// ids: a report whose ids moved between runs would change its own hash.
func foldIDs() func() string {
	next := 0
	return func() string {
		next++
		return "fold-" + strconv.Itoa(next)
	}
}

// evidenceRelative renders a source file's path as it sits inside the evidence
// root, so a report reads \Windows\System32\config\SYSTEM rather than
// F:\Sources\HOST01\Windows\System32\config\SYSTEM.
//
// The mount point is an accident of how the examiner attached the evidence, and
// repeating it on every row buries the part that identifies the artefact. It is
// not lost: the masthead names the root the paths are relative to, and
// provenance/sources.csv and the manifest keep the absolute path, which is
// where a chain of custody belongs.
//
// A path that is not beneath the root is returned as it stands. That should not
// happen — the boundary check refuses anything outside — and inventing a
// relative form for it would hide the one case worth seeing.
func (r *Report) evidenceRelative(sourcePath string) string {
	root := r.Manifest.Evidence.Root
	if root == "" || sourcePath == "" {
		return sourcePath
	}

	// Compared case-insensitively and separator-insensitively because Windows
	// is both, and a root recorded as E:\ against a path built with / would
	// otherwise fail to match and print in full.
	normalise := func(text string) string {
		return strings.ToLower(strings.ReplaceAll(text, "/", `\`))
	}
	trimmed := strings.TrimRight(normalise(root), `\`)
	if !strings.HasPrefix(normalise(sourcePath), trimmed) {
		return sourcePath
	}

	relative := sourcePath[len(trimmed):]
	if relative == "" {
		// The root itself, which is not a file but is worth naming as one.
		return `\`
	}
	if !strings.HasPrefix(relative, `\`) && !strings.HasPrefix(relative, "/") {
		// The prefix matched mid-segment: E:\Eviden matching E:\Evidence2 is
		// not containment, and trimming it would produce a nonsense path.
		return sourcePath
	}
	return relative
}

// sentence renders an explanatory line as a sentence.
//
// The views write these as fragments — "the time the MRU key was last written,
// which dates the most recent entry in the list" — because they are also joined
// into longer strings elsewhere, and a capital letter mid-clause reads wrongly.
// On the page they are standalone lines, and a column of uncapitalised,
// unterminated text reads as debug output rather than as a document.
//
// This is typography, not a finding: no word is changed, nothing is chosen, and
// the CSV keeps the fragment the view wrote.
func sentence(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ""
	}

	first, width := utf8.DecodeRuneInString(trimmed)
	trimmed = string(unicode.ToUpper(first)) + trimmed[width:]

	// Anything already closing itself is left alone, including a colon, which
	// introduces the list that follows it and must not gain a stop.
	switch trimmed[len(trimmed)-1] {
	case '.', '!', '?', ';', ':':
		return trimmed
	}
	return trimmed + "."
}

// instant renders a UTC instant to the second, truncated rather than rounded:
// rounding a timestamp up can place a record after an event it preceded.
//
// It takes either a time or a pointer to one, because a value read from the
// evidence is nullable — absent is a thing the evidence can say — while the
// run's own times always exist.
func instant(value any) string {
	switch moment := value.(type) {
	case time.Time:
		return format(moment)
	case *time.Time:
		if moment == nil {
			return "not recorded"
		}
		return format(*moment)
	default:
		return "not recorded"
	}
}

func format(moment time.Time) string {
	if moment.IsZero() {
		return "not recorded"
	}
	return moment.UTC().Truncate(time.Second).Format("2006-01-02 15:04:05")
}

// span renders the range the evidence reaches across.
func span(from, to *time.Time) string {
	switch {
	case from == nil && to == nil:
		return "no timestamped record was read"
	case from == nil:
		return "up to " + instant(to)
	case to == nil:
		return "from " + instant(from)
	default:
		return instant(from) + " to " + instant(to)
	}
}

func humanBytes(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	div, exponent := int64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %cB", float64(value)/float64(div), "KMGT"[exponent])
}

// plural picks the ending for a count, so a report never says "1 devices".
func plural(count int, singular, pluralForm string) string {
	if count == 1 {
		return singular
	}
	return pluralForm
}

func firstNonEmpty(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
