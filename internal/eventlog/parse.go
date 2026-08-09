// Package eventlog parses EVTX files and selects the records that evidence USB
// device activity.
//
// Selection is by catalogue, not by pattern match: see catalogue.go. What is
// read, what is skipped and why is accounted for record by record, so a claim
// that Boobook reported everything relevant can be checked against the source
// rather than taken on trust.
package eventlog

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"

	"github.com/Bloggzy/boobook/internal/devid"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// Field is one extracted value, with where it came from and what it means.
type Field struct {
	Name  string
	Role  Role
	Value string
	// Path is the element path within the record, so the value can be found
	// again in the source.
	Path string
}

// Record is one selected event.
type Record struct {
	Channel    string
	SourceFile string
	RecordID   uint64
	EventID    int64
	Provider   string
	// RawFileTime is the record header's stored time, kept beside the derived
	// one so the conversion can be checked.
	RawFileTime uint64
	TimeUTC     time.Time

	RuleID  string
	Kind    Kind
	Meaning string
	Fields  []Field
}

// Value returns the first value carrying a role, or "".
func (r *Record) Value(role Role) string {
	for _, field := range r.Fields {
		if field.Role == role && strings.TrimSpace(field.Value) != "" {
			return field.Value
		}
	}
	return ""
}

// DeviceInstanceID is the device the record names, in canonical form.
func (r *Record) DeviceInstanceID() string {
	return devid.Normalise(r.Value(RoleDeviceInstanceID))
}

// Exclusion reasons. Every record read is either retained or counted under one
// of these.
const (
	ReasonEventNotSelected = "event_not_selected"
	ReasonExcludedByRule   = "excluded_by_rule"
	ReasonNotUSB           = "no_usb_identity"
	ReasonMalformed        = "malformed_record"
)

// FileStats accounts for one file.
type FileStats struct {
	Path    string
	Channel string
	Bytes   int64
	// Skipped is set where the file was never parsed, and SkipReason says why.
	Skipped    bool
	SkipReason string
	// OptInSkipped narrows that: the channel is one Boobook reads, and this run
	// did not ask for it. A reader has to be able to tell that apart from a
	// channel nothing reads, because the two say opposite things about what the
	// silence in the report means.
	OptInSkipped bool

	ChunksRead    int
	ChunksFailed  int
	RecordsRead   int
	Retained      int
	ExcludedBy    map[string]int
	ChannelInFile string
	Err           error
}

// Stats is the whole-run accounting.
type Stats struct {
	Files []FileStats

	FilesParsed  int
	FilesSkipped int
	BytesParsed  int64
	BytesSkipped int64

	RecordsRead int
	Retained    int
	Failed      int

	// ExcludedByReason counts every record read and not retained.
	ExcludedByReason map[string]int
	// Unselected counts records by "channel:eventID" for events seen in a read
	// channel that no rule selects. This is the checkable part: an analyst can
	// see exactly what was passed over and argue with it.
	Unselected map[string]int
	// SelectedByRule counts retained records per rule.
	SelectedByRule map[string]int
	// ChannelMismatches counts records whose own channel differs from the one
	// the filename encodes, which would make file-level selection unsound.
	ChannelMismatches map[string]int
}

func newStats() *Stats {
	return &Stats{
		ExcludedByReason:  map[string]int{},
		Unselected:        map[string]int{},
		SelectedByRule:    map[string]int{},
		ChannelMismatches: map[string]int{},
	}
}

// ParseTree parses the EVTX files a rule reads and returns the selected records.
//
// Files on channels no rule reads are not parsed at all, and Security.evtx is
// the one that makes the difference. Measured against USB-LENOVO-Multi-USBs,
// adding a single rule to it moved this phase from 0.75 s to 1.49 s for 20 MB
// and 21,594 records — about 37 ms per megabyte.
//
// 20 MB is that channel's default cap and organisations raise it; a 2 GB
// Security.evtx has been seen in the field, which is roughly 76 seconds against
// a whole run of 22. Worse, it would not overlap with anything: the work below
// is split one file per goroutine, so one large log runs single-threaded on the
// critical path while every other channel finishes in under a second. The same
// would be true of any channel a host had grown, which is a defect in how the
// work is divided rather than a fact about Security.
//
// Each skipped file is reported with its size and the reason, so the omission
// is visible rather than implicit.
func ParseTree(paths []string) ([]Record, *Stats) {
	return ParseTreeReporting(paths, nil)
}

// Options is what a caller can ask for beyond the default selection.
type Options struct {
	// OptIn names the channels to read that are otherwise skipped, lower-cased.
	// Empty is the default and reads none of them.
	OptIn map[string]bool
}

func (o Options) wants(channel string) bool {
	return o.OptIn[strings.ToLower(channel)]
}

// Progress is what ParseTreeReporting tells a caller while it works.
//
// The selection is made in here, so only this can say how much work there
// actually is: a collection of three hundred logs where four are read is the
// normal case, and a caller counting the files it handed over would report a
// run that appeared to stall at four hundredths done.
//
// Files are parsed in parallel, so the calls come from several goroutines.
type Progress interface {
	// Expect is called once, with the files that will be read and their size.
	Expect(files int, bytes int64)
	// Item is called as each batch of a file is picked up. The same file is
	// announced several times where it is large enough to be split.
	Item(class, path string, size int64)
	// Advance reports bytes finished within a file that is not finished. It
	// exists because a large log is now parsed in batches: without it the line
	// would sit still for as long as that file took, which on the logs this
	// change is for is exactly when a reader wants to see movement.
	Advance(class string, bytes int64)
	// Read is called as each file is finished, with the records it yielded.
	// The size is zero where Advance has already accounted for the bytes.
	Read(class, path string, size int64, records int)
}

// ParseTreeReporting parses as ParseTree does, reporting its progress as it
// goes. A nil report is the plain parse.
func ParseTreeReporting(paths []string, report Progress) ([]Record, *Stats) {
	return ParseTreeWith(paths, report, Options{})
}

// ParseTreeWith parses with the caller's options.
func ParseTreeWith(paths []string, report Progress, options Options) (
	[]Record, *Stats) {

	stats := newStats()

	var selected []string
	for _, path := range paths {
		channel := channelName(path)
		optInReason, isOptIn := ChannelOptIn(channel)
		if ChannelSelected(channel) && (!isOptIn || options.wants(channel)) {
			selected = append(selected, path)
			continue
		}

		fileStats := FileStats{
			Path: path, Channel: channel, Bytes: fileSize(path),
			Skipped: true, SkipReason: "no rule reads this channel",
		}
		// An opt-in channel that was not asked for is skipped for a different
		// reason from one nothing reads, and the accounting has to say which.
		// "Boobook does not read this" and "this run did not ask for it" lead a
		// reader to opposite conclusions about what the silence means.
		if isOptIn {
			fileStats.SkipReason = "not read unless asked for: " + optInReason
			fileStats.OptInSkipped = true
		} else if rationale, ok := ChannelRationale(channel); ok {
			fileStats.SkipReason = rationale
		}
		stats.Files = append(stats.Files, fileStats)
		stats.FilesSkipped++
		stats.BytesSkipped += fileStats.Bytes
	}

	if report != nil {
		var bytes int64
		for _, path := range selected {
			bytes += fileSize(path)
		}
		report.Expect(len(selected), bytes)
	}

	// Two passes, because the unit of work is a batch of chunks and the batches
	// cannot be handed out until every file has been enumerated. Enumerating
	// touches a 128-byte header every 64 KB — 0.2% of a file — so the pass is
	// cheap even where the second one is not.
	plans := planFiles(selected, workerCount(len(selected)))

	var batches []chunkBatch
	for _, plan := range plans {
		batches = append(batches, plan.batches()...)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	records := []Record{}

	// Longest file first. The batches of one file are independent, so the only
	// thing left to get wrong is starting the biggest log last and finishing
	// alone on it — the very tail this change exists to remove.
	sort.SliceStable(batches, func(i, j int) bool {
		return len(batches[i].plan.chunks) > len(batches[j].plan.chunks)
	})

	batchCh := make(chan chunkBatch)
	for i := 0; i < workerCount(len(batches)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batchCh {
				if report != nil {
					report.Item("EVTX", batch.plan.path, batch.bytes())
				}
				batchRecords, batchStats := parseBatch(batch)
				if report != nil {
					report.Advance("EVTX", batch.bytes())
				}

				mu.Lock()
				records = append(records, batchRecords...)
				batch.plan.merge(batchStats)
				mu.Unlock()
			}
		}()
	}

	for _, batch := range batches {
		batchCh <- batch
	}
	close(batchCh)
	wg.Wait()

	for _, plan := range plans {
		fileStats := plan.fileStats()
		if report != nil {
			// A file that would not open, or that holds no readable chunk, has
			// no batch to announce it — and it is still an artefact the phase
			// attempted. Announcing it here keeps every selected file named
			// once, whatever came of it.
			if len(plan.chunks) == 0 {
				report.Item("EVTX", plan.path, plan.bytes)
			}
			// Zero bytes for the rest: Advance has already counted them batch
			// by batch. What this call is for is the file count and the
			// records, which belong to the file rather than to any batch of it.
			size := int64(0)
			if len(plan.chunks) == 0 {
				size = plan.bytes
			}
			report.Read("EVTX", plan.path, size, fileStats.Retained)
		}

		stats.Files = append(stats.Files, fileStats)
		stats.FilesParsed++
		stats.BytesParsed += fileStats.Bytes
		stats.RecordsRead += fileStats.RecordsRead
		stats.Retained += fileStats.Retained
		for reason, count := range fileStats.ExcludedBy {
			if strings.HasPrefix(reason, "unselected:") {
				stats.Unselected[strings.TrimPrefix(reason, "unselected:")] += count
				stats.ExcludedByReason[ReasonEventNotSelected] += count
				continue
			}
			if strings.HasPrefix(reason, "mismatch:") {
				stats.ChannelMismatches[strings.TrimPrefix(reason, "mismatch:")] += count
				continue
			}
			stats.ExcludedByReason[reason] += count
		}
		if fileStats.Err != nil {
			stats.Failed++
		}
	}

	for _, record := range records {
		stats.SelectedByRule[record.RuleID]++
	}

	sort.Slice(stats.Files, func(i, j int) bool { return stats.Files[i].Path < stats.Files[j].Path })
	// The order has to be total, and it was not. Time and record id tie across
	// files — a record id is unique within its log and nowhere else — and while
	// a file was one work item the ties fell out in a stable order by accident.
	// Batches are merged in whatever order they finish, so that accident is
	// gone and the tie-break has to be written down.
	sort.Slice(records, func(i, j int) bool {
		if !records[i].TimeUTC.Equal(records[j].TimeUTC) {
			return records[i].TimeUTC.Before(records[j].TimeUTC)
		}
		if records[i].SourceFile != records[j].SourceFile {
			return records[i].SourceFile < records[j].SourceFile
		}
		return records[i].RecordID < records[j].RecordID
	})

	return records, stats
}

// chunksPerBatch is how much of one log a worker takes at a time: 256 chunks of
// 64 KB, so 16 MB.
//
// The number trades the tail against the overhead. Too large and a worker is
// again alone on the last piece of a big file; too small and each batch pays
// for its own open and seek over a file the others are reading too. At 16 MB a
// 2 GB log is 128 batches, which spreads across any core count worth having,
// and every log in the reference collections is a single batch and so is parsed
// exactly as it was before.
const chunksPerBatch = 256

// filePlan is one file's chunks, enumerated once so they can be handed out.
type filePlan struct {
	path    string
	channel string
	bytes   int64
	chunks  []*evtx.Chunk

	// stats accumulates across the batches, under the caller's mutex.
	stats FileStats
}

// chunkBatch is a slice of one file's chunks, and the unit of work.
//
// It used to be a whole file. That meant one large log ran on a single
// goroutine while every other worker sat idle, so the phase took as long as its
// biggest file however many cores were free — the reason Security.evtx is
// unaffordable on a host that has raised its log cap, and the reason any other
// channel would be too.
type chunkBatch struct {
	plan   *filePlan
	chunks []*evtx.Chunk
}

func (b chunkBatch) bytes() int64 {
	// Chunks are a fixed 64 KB, so a batch's share of the file is countable
	// rather than estimated. The last batch is short and says so.
	return int64(len(b.chunks)) * evtxChunkSize
}

const evtxChunkSize = 0x10000

func (p *filePlan) batches() []chunkBatch {
	if len(p.chunks) == 0 {
		// A file that would not open, or holds no readable chunk. It still
		// needs a place in the accounting, and it has no work to hand out.
		return nil
	}
	var out []chunkBatch
	for start := 0; start < len(p.chunks); start += chunksPerBatch {
		end := start + chunksPerBatch
		if end > len(p.chunks) {
			end = len(p.chunks)
		}
		out = append(out, chunkBatch{plan: p, chunks: p.chunks[start:end]})
	}
	return out
}

// merge folds one batch's counts into the file's. Called under the caller's
// mutex, because batches of one file finish on different goroutines.
func (p *filePlan) merge(from FileStats) {
	p.stats.RecordsRead += from.RecordsRead
	p.stats.Retained += from.Retained
	p.stats.ChunksFailed += from.ChunksFailed
	for reason, count := range from.ExcludedBy {
		p.stats.ExcludedBy[reason] += count
	}
}

func (p *filePlan) fileStats() FileStats {
	stats := p.stats
	stats.Path, stats.Channel, stats.Bytes = p.path, p.channel, p.bytes
	stats.ChunksRead = len(p.chunks)
	return stats
}

func workerCount(items int) int {
	workers := runtime.NumCPU()
	if workers > items {
		workers = items
	}
	if workers < 1 {
		workers = 1
	}
	return workers
}

// planFiles enumerates every selected file's chunks, in parallel.
//
// Enumeration is a seek and a 128-byte header read per 64 KB, so it is a
// rounding error against the parse — but it is still per file, so it is spread
// the same way rather than leaving one goroutine walking a large log alone.
func planFiles(paths []string, workers int) []*filePlan {
	plans := make([]*filePlan, len(paths))
	pathCh := make(chan int)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range pathCh {
				plans[index] = planFile(paths[index])
			}
		}()
	}
	for i := range paths {
		pathCh <- i
	}
	close(pathCh)
	wg.Wait()

	return plans
}

func planFile(path string) *filePlan {
	plan := &filePlan{
		path: path, channel: channelName(path), bytes: fileSize(path),
		stats: FileStats{ExcludedBy: map[string]int{}},
	}

	fd, err := os.Open(path)
	if err != nil {
		plan.stats.Err = err
		return plan
	}
	defer fd.Close()

	chunks, err := evtx.GetChunks(fd)
	if err != nil {
		plan.stats.Err = err
		return plan
	}
	plan.chunks = chunks
	return plan
}

// parseBatch reads one slice of one file's chunks.
//
// The FileStats it returns holds only what this batch saw; the file's own
// totals are assembled from every batch by filePlan.merge.
func parseBatch(batch chunkBatch) ([]Record, FileStats) {
	path, channel := batch.plan.path, batch.plan.channel
	stats := FileStats{ExcludedBy: map[string]int{}}

	// A handle of this batch's own. Chunk.Parse seeks the reader it was built
	// with and then reads the whole 64 KB, so two goroutines sharing one handle
	// would race on the file offset and read each other's chunks. The chunk's
	// fields are exported, so rebinding it to a private handle costs nothing
	// and keeps the concurrency out of the library.
	fd, err := os.Open(path)
	if err != nil {
		stats.Err = err
		return nil, stats
	}
	defer fd.Close()

	var records []Record
	for _, planned := range batch.chunks {
		chunk := &evtx.Chunk{
			Header: planned.Header, Offset: planned.Offset, Fd: fd,
		}
		// A damaged chunk must not cost the rest of the file, but it must be
		// counted: records in it are unread, not absent.
		chunkRecords, err := chunk.Parse(0)
		if err != nil {
			stats.ChunksFailed++
			continue
		}

		for _, eventRecord := range chunkRecords {
			stats.RecordsRead++

			record, event, ok := header(eventRecord, channel, path)
			if !ok {
				stats.ExcludedBy[ReasonMalformed]++
				continue
			}

			// File-level selection used the filename. If the record disagrees
			// about its own channel that selection was made on a false premise,
			// so the disagreement is counted rather than smoothed over.
			if !strings.EqualFold(record.Channel, channel) {
				stats.ExcludedBy["mismatch:"+channel+" -> "+record.Channel]++
			}

			rule, rationale, ok := lookup(record.Channel, record.Provider,
				record.EventID)
			if !ok {
				if rationale != "" {
					stats.ExcludedBy[ReasonExcludedByRule]++
				} else {
					// The provider is named because the id alone is not the
					// thing that was passed over. Event 12 on the System
					// channel is read from Kernel-General and not from the
					// three other publishers that also write it, and an
					// accounting saying "System:12, unselected" while fifteen
					// of them were selected is one an analyst cannot argue
					// with, only be misled by.
					stats.ExcludedBy[fmt.Sprintf("unselected:%s:%s:%d",
						record.Channel, record.Provider, record.EventID)]++
				}
				continue
			}

			record.RuleID = rule.ID()
			record.Meaning = rule.Meaning
			record.Fields = extract(rule, event)
			// After extraction, because some events do not say what happened
			// in their ID: Kernel-PnP 420 is a removal only for a problem code
			// that means the device is gone, and is a fault otherwise.
			record.Kind = rule.KindOf(record.Fields)

			gate := rule.Gate
			if gate == nil {
				gate = usbIdentity
			}
			if !gate(record.Fields) {
				stats.ExcludedBy[ReasonNotUSB]++
				continue
			}

			records = append(records, record)
		}
	}

	stats.Retained = len(records)
	return records, stats
}

// header reads the parts every record has, and returns the Event element the
// field extraction works against.
func header(eventRecord *evtx.EventRecord, channel, path string) (Record, *ordereddict.Dict, bool) {
	dict, ok := eventRecord.Event.(*ordereddict.Dict)
	if !ok {
		return Record{}, nil, false
	}
	event, ok := getDict(dict, "Event")
	if !ok {
		return Record{}, nil, false
	}
	system, ok := getDict(event, "System")
	if !ok {
		return Record{}, nil, false
	}

	record := Record{
		Channel:     channel,
		SourceFile:  path,
		RecordID:    eventRecord.Header.RecordID,
		RawFileTime: eventRecord.Header.FileTime,
	}
	if converted, ok := wintime.FromFileTime(eventRecord.Header.FileTime); ok {
		record.TimeUTC = converted
	}

	// EventID is nested as {"Value": n}, not a bare integer. Read flat and every
	// record silently reports event 0.
	if eventID, ok := system.Get("EventID"); ok {
		if inner, ok := eventID.(*ordereddict.Dict); ok {
			if value, ok := inner.Get("Value"); ok {
				record.EventID = toInt(value)
			}
		} else {
			record.EventID = toInt(eventID)
		}
	}

	// The record names its own channel. Prefer that over the filename, which is
	// only an encoding of it and can be mangled by a collector.
	if channelValue, ok := system.Get("Channel"); ok {
		if text := fmt.Sprintf("%v", channelValue); text != "" {
			record.Channel = text
		}
	}

	// TimeCreated carries sub-second precision the record header does not.
	if timeCreated, ok := getDict(system, "TimeCreated"); ok {
		if systemTime, ok := timeCreated.Get("SystemTime"); ok {
			if seconds, ok := systemTime.(float64); ok {
				if converted, ok := wintime.FromUnixFloat(seconds); ok {
					record.TimeUTC = converted
				}
			}
		}
	}

	if provider, ok := getDict(system, "Provider"); ok {
		if name, ok := provider.Get("Name"); ok {
			record.Provider = fmt.Sprintf("%v", name)
		}
	}

	return record, event, true
}

// extract pulls the fields a rule names, and nothing else. Records carrying
// hundreds of fields — the partition and NTFS diagnostics run to ninety — are
// reduced to what was asked for, which is what keeps the output legible.
func extract(rule *Rule, event *ordereddict.Dict) []Field {
	if rule.NameValue {
		return extractNameValue(event)
	}

	var fields []Field
	for _, spec := range rule.Fields {
		value, path, ok := resolve(event, strings.Split(spec.Path, "."))
		if !ok {
			continue
		}
		text := render(value)
		if text == "" {
			continue
		}
		fields = append(fields, Field{
			Name: spec.Name, Role: spec.Role, Value: text, Path: path,
		})
	}
	return fields
}

// extractNameValue reads the EventData\Data {Name, Value} form, which some
// providers use in place of named elements. It appears as a single pair or as a
// list of them.
func extractNameValue(event *ordereddict.Dict) []Field {
	eventData, ok := getDict(event, "EventData")
	if !ok {
		return nil
	}
	data, ok := eventData.Get("Data")
	if !ok {
		return nil
	}

	var fields []Field
	for _, entry := range asList(data) {
		pair, ok := entry.(*ordereddict.Dict)
		if !ok {
			continue
		}
		name, hasName := pair.Get("Name")
		value, hasValue := pair.Get("Value")
		if !hasName || !hasValue {
			continue
		}

		fieldName := render(name)
		text := render(value)
		if fieldName == "" || text == "" {
			continue
		}

		role := RoleDetail
		if known, ok := dataNameRoles[strings.ToLower(fieldName)]; ok {
			role = known
		}
		fields = append(fields, Field{
			Name: fieldName, Role: role, Value: text,
			Path: "EventData.Data." + fieldName,
		})
	}
	return fields
}

// resolve walks a dotted path, where "*" matches any single element. The
// wildcard is what lets the UserData channels be read without assuming the
// element name a provider chose — the same event carries AddServiceID on one
// build and something else on another.
func resolve(dict *ordereddict.Dict, segments []string) (interface{}, string, bool) {
	if len(segments) == 0 || dict == nil {
		return nil, "", false
	}

	head, rest := segments[0], segments[1:]

	if head == "*" {
		for _, key := range dict.Keys() {
			value, _ := dict.Get(key)
			inner, ok := value.(*ordereddict.Dict)
			if !ok {
				continue
			}
			if found, path, ok := resolve(inner, rest); ok {
				return found, key + "." + path, true
			}
		}
		return nil, "", false
	}

	value, ok := dict.Get(head)
	if !ok {
		return nil, "", false
	}
	if len(rest) == 0 {
		return value, head, true
	}

	inner, ok := value.(*ordereddict.Dict)
	if !ok {
		return nil, "", false
	}
	found, path, ok := resolve(inner, rest)
	if !ok {
		return nil, "", false
	}
	return found, head + "." + path, true
}

// usbIdentity is the default gate: some field must name a USB or portable
// device, or the record must report the USB storage bus.
func usbIdentity(fields []Field) bool {
	for _, field := range fields {
		switch field.Role {
		case RoleDeviceInstanceID, RoleParentInstanceID:
			if devid.IsUSB(field.Value) {
				return true
			}
		case RoleBusType:
			if strings.TrimSpace(field.Value) == busTypeUSB {
				return true
			}
		case RoleVendor:
			// The storage channels report the SCSI inquiry vendor, and a USB
			// mass storage bridge reports "USB" there, padded.
			if strings.EqualFold(strings.TrimSpace(field.Value), "USB") {
				return true
			}
		}
	}
	return false
}

// render turns an extracted value into text, without deciding anything about
// it. Trailing NULs are stripped because a fixed-width string field keeps them
// and they break every later comparison; interior bytes are left alone.
func render(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimRight(typed, "\x00")
	case []byte:
		// Binary event data. Rendered as hex rather than through %v, which
		// would produce a Go slice literal that nothing can decode back.
		return hex.EncodeToString(typed)
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(reflected.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(reflected.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(reflected.Float(), 'f', -1, 64)
	}
	return strings.TrimRight(fmt.Sprintf("%v", value), "\x00")
}

// asList accepts either a single value or a list of them.
func asList(value interface{}) []interface{} {
	if list, ok := value.([]interface{}); ok {
		return list
	}
	return []interface{}{value}
}

func getDict(dict *ordereddict.Dict, key string) (*ordereddict.Dict, bool) {
	value, ok := dict.Get(key)
	if !ok {
		return nil, false
	}
	inner, ok := value.(*ordereddict.Dict)
	return inner, ok
}

// toInt reads an integer regardless of the width the binary XML parser chose.
// EventID arrives as uint16 on some channels and int64 on others; enumerating
// types by hand silently yields 0 for the ones missed.
func toInt(value interface{}) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case uint64:
		return int64(typed)
	case float64:
		return int64(typed)
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(reflected.Uint())
	case reflect.Float32, reflect.Float64:
		return int64(reflected.Float())
	case reflect.String:
		parsed, err := strconv.ParseInt(reflected.String(), 10, 64)
		if err == nil {
			return parsed
		}
	}
	return 0
}

func channelName(path string) string {
	name := filepath.Base(path)
	name = strings.TrimSuffix(name, filepath.Ext(name))
	// A collector that escapes the paths it writes turns the %4 Windows puts in
	// a channel name into %254; both forms name the same channel.
	name = strings.ReplaceAll(name, "%254", "/")
	name = strings.ReplaceAll(name, "%4", "/")
	return name
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
