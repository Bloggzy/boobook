package eventlog

import (
	"strings"
	"testing"

	"github.com/Velocidex/ordereddict"
	evtx "www.velocidex.com/golang/evtx"
)

// EventID arrives from the binary XML parser at whatever width the record used.
// A type switch that misses a width returns 0, which is indistinguishable from
// a genuine event 0 — so every width must be covered.
func TestToIntReadsAnyIntegerWidth(t *testing.T) {
	cases := []struct {
		name  string
		value interface{}
		want  int64
	}{
		{"int64", int64(400), 400},
		{"uint64", uint64(400), 400},
		{"int32", int32(400), 400},
		{"uint32", uint32(400), 400},
		{"int16", int16(400), 400},
		{"uint16", uint16(400), 400},
		{"uint8", uint8(200), 200},
		{"int", int(400), 400},
		{"float64", float64(400), 400},
		{"string", "400", 400},
		{"unparseable string", "not a number", 0},
		{"nil", nil, 0},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := toInt(testCase.value); got != testCase.want {
				t.Errorf("toInt(%#v) = %d, want %d",
					testCase.value, got, testCase.want)
			}
		})
	}
}

func TestChannelNameDecodesCollectorEscaping(t *testing.T) {
	cases := map[string]string{
		`C:\x\Microsoft-Windows-Kernel-PnP%254Configuration.evtx`: "Microsoft-Windows-Kernel-PnP/Configuration",
		`C:\x\Microsoft-Windows-Kernel-PnP%4Configuration.evtx`:   "Microsoft-Windows-Kernel-PnP/Configuration",
		`C:\x\System.evtx`: "System",
	}

	for path, want := range cases {
		if got := channelName(path); got != want {
			t.Errorf("channelName(%q) = %q, want %q", path, got, want)
		}
	}
}

// A rule whose fields can never satisfy its gate is dead: it selects records and
// then discards every one of them, and nothing in the output would say so. The
// catalogue is the tool's statement about what it looks at, so it has to hold
// together on its own terms.
func TestEveryRuleCanReachItsGate(t *testing.T) {
	gateable := map[Role]bool{
		RoleDeviceInstanceID: true,
		RoleParentInstanceID: true,
		RoleBusType:          true,
		RoleVendor:           true,
	}

	for _, rule := range Rules() {
		if rule.Gate != nil || rule.NameValue {
			continue
		}
		reachable := false
		for _, field := range rule.Fields {
			if gateable[field.Role] {
				reachable = true
				break
			}
		}
		if !reachable {
			t.Errorf("rule %s extracts nothing the default gate can act on, "+
				"so it can never retain a record", rule.ID())
		}
	}
}

func TestCatalogueIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range Rules() {
		if seen[rule.ID()] {
			t.Errorf("rule %s is defined twice; the second is unreachable", rule.ID())
		}
		seen[rule.ID()] = true

		if rule.Meaning == "" {
			t.Errorf("rule %s has no meaning: a record with no statement of what "+
				"it evidences cannot be reported responsibly", rule.ID())
		}
		// A device rule that extracts nothing has nothing to correlate on and
		// is dead weight. A session rule is the exception and not an oversight:
		// a boot names no device and carries no field worth keeping, and its
		// timestamp — which every record has — is the whole of the evidence.
		if len(rule.Fields) == 0 && !rule.NameValue && rule.Kind != KindSession {
			t.Errorf("rule %s extracts no fields", rule.ID())
		}
	}

	// An event cannot be both selected and deliberately excluded; if it is, one
	// of the two statements is a lie and which one wins is an accident of
	// lookup order.
	for _, exclusion := range Exclusions() {
		// Asked of every provider that has a rule for the id, not just of the
		// empty one: an exclusion is written per (channel, id) and a rule
		// naming a provider would otherwise slip past this check.
		for _, rule := range Rules() {
			if !strings.EqualFold(rule.Channel, exclusion.Channel) ||
				rule.EventID != exclusion.EventID {
				continue
			}
			if _, _, ok := lookup(exclusion.Channel, rule.Provider,
				exclusion.EventID); ok {
				t.Errorf("%s:%d is both selected and excluded",
					exclusion.Channel, exclusion.EventID)
			}
		}
		if _, _, ok := lookup(exclusion.Channel, "", exclusion.EventID); ok {
			t.Errorf("%s:%d is both selected and excluded",
				exclusion.Channel, exclusion.EventID)
		}
		if exclusion.Rationale == "" {
			t.Errorf("%s:%d is excluded with no reason given",
				exclusion.Channel, exclusion.EventID)
		}
	}

	// A channel cannot be both read and recorded as unread.
	for channel := range unreadChannels {
		if ChannelSelected(channel) {
			t.Errorf("channel %q is listed as unread but has rules", channel)
		}
	}
}

// Channel selection decides which files are opened at all, so the two forms a
// collector can write must both resolve.
func TestChannelSelectionMatchesEscapedFilenames(t *testing.T) {
	selected := []string{
		`C:\x\Microsoft-Windows-Kernel-PnP%4Configuration.evtx`,
		`C:\x\Microsoft-Windows-Kernel-PnP%254Configuration.evtx`,
		`C:\x\Microsoft-Windows-StorageVolume%4Operational.evtx`,
		`C:\x\System.evtx`,
	}
	for _, path := range selected {
		if !ChannelSelected(channelName(path)) {
			t.Errorf("%s should be read", path)
		}
	}

	// The channel that dominated the naive filter's output. It is not read, and
	// the reason is on the record.
	const appx = `C:\x\Microsoft-Windows-AppXDeploymentServer%4Operational.evtx`
	if ChannelSelected(channelName(appx)) {
		t.Error("the AppX deployment channel should not be read")
	}
	if _, ok := ChannelRationale(channelName(appx)); !ok {
		t.Error("a channel that is not read must say why")
	}
}

func TestResolveWalksWildcardPaths(t *testing.T) {
	// The System 20003 shape: the UserData element name is the provider's
	// choice, so the path must not assume it.
	inner := ordereddict.NewDict().
		Set("ServiceName", "WUDFWpdFs").
		Set("DeviceInstanceID", `SWD\WPDBUSENUM\{CE3E8F0E-7B66-11F0-A0A3-806E6F6E6963}#0000000E530F6E00`)
	event := ordereddict.NewDict().
		Set("UserData", ordereddict.NewDict().Set("AddServiceID", inner))

	value, path, ok := resolve(event, strings.Split("UserData.*.DeviceInstanceID", "."))
	if !ok {
		t.Fatal("the wildcard path did not resolve")
	}
	if want := "UserData.AddServiceID.DeviceInstanceID"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if !strings.Contains(render(value), "WPDBUSENUM") {
		t.Errorf("value = %q", render(value))
	}

	if _, _, ok := resolve(event, strings.Split("UserData.*.NoSuchField", ".")); ok {
		t.Error("a missing leaf must not resolve")
	}
}

func TestExtractReadsTheNameValueForm(t *testing.T) {
	// Kernel-PnP 430 and DeviceSetupManager 127 report a single pair.
	single := ordereddict.NewDict().Set("EventData",
		ordereddict.NewDict().Set("Data", ordereddict.NewDict().
			Set("Name", "DeviceInstanceId").
			Set("Value", `USB\VID_06CB&PID_009A\97cab486c67a`)))

	fields := extract(&Rule{NameValue: true}, single)
	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(fields))
	}
	if fields[0].Role != RoleDeviceInstanceID {
		t.Errorf("role = %q, want %q", fields[0].Role, RoleDeviceInstanceID)
	}
	if !usbIdentity(fields) {
		t.Error("a USB device instance id must pass the gate")
	}

	// The same form can arrive as a list.
	list := ordereddict.NewDict().Set("EventData",
		ordereddict.NewDict().Set("Data", []interface{}{
			ordereddict.NewDict().Set("Name", "Prop_DevnodeId").
				Set("Value", `USB\VID_8087&PID_0ACA\7&1e2cd3d3&0&0000`),
			ordereddict.NewDict().Set("Name", "SomethingUncatalogued").
				Set("Value", "42"),
		}))

	fields = extract(&Rule{NameValue: true}, list)
	if len(fields) != 2 {
		t.Fatalf("got %d fields, want 2", len(fields))
	}
	// An unrecognised name is kept as a detail rather than dropped: the record
	// said it, so the analyst gets to see it.
	if fields[1].Role != RoleDetail {
		t.Errorf("uncatalogued field role = %q, want %q", fields[1].Role, RoleDetail)
	}
}

// The gate is what stops the tool reporting the internal NVMe disk as a USB
// device, and what stops it discarding a USB disk that names no instance ID.
func TestUSBIdentityGate(t *testing.T) {
	cases := []struct {
		name   string
		fields []Field
		want   bool
	}{
		{
			"usb storage instance id",
			[]Field{{Name: "DeviceInstanceId", Role: RoleDeviceInstanceID,
				Value: `USBSTOR\Disk&Ven_X&Prod_Y\SERIAL&0`}},
			true,
		},
		{
			"volume node wrapping a usb device",
			[]Field{{Name: "DeviceInstanceId", Role: RoleDeviceInstanceID,
				Value: `STORAGE\VOLUME\_??_USBSTOR#DISK&VEN_PATRIOT#241119&0#{53F56307-B6BF-11D0-94F2-00A0C91EFB8B}`}},
			true,
		},
		{
			// The NTFS mount record names no device, only the bus. That is
			// still a statement that the volume was on USB.
			"usb storage bus with no instance id",
			[]Field{
				{Name: "VolumeId", Role: RoleVolumeGUID, Value: `\\?\Volume{fab6c968-0000-0000-0000-000000000000}`},
				{Name: "BusType", Role: RoleBusType, Value: "7"},
			},
			true,
		},
		{
			"usb mass storage bridge reporting itself as vendor",
			[]Field{{Name: "VendorId", Role: RoleVendor, Value: " USB"}},
			true,
		},
		{
			"internal nvme disk",
			[]Field{
				{Name: "ProductId", Role: RoleProduct, Value: "SAMSUNG MZVLB512HAJQ-000L7"},
				{Name: "BusType", Role: RoleBusType, Value: "17"},
			},
			false,
		},
		{
			"pci device",
			[]Field{{Name: "DeviceInstanceId", Role: RoleDeviceInstanceID,
				Value: `PCI\VEN_8086&DEV_9A0D\3&11583659&0&B0`}},
			false,
		},
		{
			// The naive filter kept this because the package path embeds the
			// system volume GUID. A volume GUID is not a device.
			"volume guid alone",
			[]Field{{Name: "VolumeId", Role: RoleVolumeGUID,
				Value: `\\?\Volume{d3c26787-16ab-4663-8b6d-20737e298b82}`}},
			false,
		},
		{"nothing", nil, false},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := usbIdentity(testCase.fields); got != testCase.want {
				t.Errorf("usbIdentity = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestUSBMiniportGate(t *testing.T) {
	usb := []Field{{Name: "MiniportName", Role: RoleDriverName, Value: "USBSTOR"}}
	if !usbMiniport(usb) {
		t.Error("a USBSTOR miniport is USB")
	}

	virtual := []Field{{Name: "MiniportName", Role: RoleDriverName, Value: "vhdmp"}}
	if usbMiniport(virtual) {
		t.Error("a virtual disk miniport is not USB")
	}
	// The default gate would have kept the virtual disk on its vendor string,
	// which is why this channel has its own.
	if usbMiniport(nil) {
		t.Error("no miniport name is not USB")
	}
}

func TestRenderKeepsValuesFaithful(t *testing.T) {
	cases := []struct {
		value interface{}
		want  string
	}{
		// A fixed-width string field keeps its terminator, and it breaks every
		// later comparison invisibly.
		{"USBSTOR\x00", "USBSTOR"},
		// SCSI inquiry padding is how the device reported itself, so it stays.
		{" SanDisk 3.2Gen1", " SanDisk 3.2Gen1"},
		{uint16(7), "7"},
		{int64(1048576), "1048576"},
		// The binary XML parser hands back whole numbers as floats; rendering
		// 1048576 as "1.048576e+06" would break every join on it.
		{float64(1048576), "1048576"},
		{true, "true"},
		{false, "false"},
		{nil, ""},
	}

	for _, testCase := range cases {
		if got := render(testCase.value); got != testCase.want {
			t.Errorf("render(%#v) = %q, want %q", testCase.value, got, testCase.want)
		}
	}
}

func TestProblemAndBusNamesDoNotInvent(t *testing.T) {
	if got := ProblemName("45"); got != "CM_PROB_DEVICE_DISCONNECTED" {
		t.Errorf("ProblemName(45) = %q", got)
	}
	// An unknown code is reported as itself rather than guessed at.
	if got := ProblemName("999"); got != "999" {
		t.Errorf("ProblemName(999) = %q, want the code back", got)
	}
	if got := BusTypeName("7"); got != "USB" {
		t.Errorf("BusTypeName(7) = %q", got)
	}
	if got := BusTypeName("99"); got != "99" {
		t.Errorf("BusTypeName(99) = %q, want the value back", got)
	}
}

// recorder is a Progress that keeps what it was told.
type recorder struct {
	files    int
	items    []string
	read     []string
	advanced int64
}

func (r *recorder) Expect(files int, bytes int64)             { r.files = files }
func (r *recorder) Item(class, path string, size int64)       { r.items = append(r.items, path) }
func (r *recorder) Advance(class string, bytes int64)         { r.advanced += bytes }
func (r *recorder) Read(class, path string, s int64, rec int) { r.read = append(r.read, path) }

// A collection holds a few hundred logs and a handful are read. The count of
// files handed to the parser would show a run stalled at four of three hundred
// for the whole phase, and then finish; only the parser knows which of them it
// is actually going to open.
func TestTheParserDeclaresOnlyTheFilesItWillRead(t *testing.T) {
	read := strings.ReplaceAll(Channels()[0], "/", "%4") + ".evtx"
	// The unread example was Security.evtx until Security acquired rules, at
	// which point this test skipped itself and stopped running. A test that
	// quietly does not run is worse than no test, so the example is now a
	// channel that is on the record as unread and stays that way.
	const unread = "Microsoft-Windows-Store%4Operational.evtx"
	if ChannelSelected(channelName(unread)) {
		t.Fatalf("%s is read now, so it is no longer the unread case", unread)
	}
	paths := []string{
		`C:\nowhere\` + read,
		`C:\nowhere\` + unread,
	}

	var progress recorder
	ParseTreeReporting(paths, &progress)

	if progress.files != 1 {
		t.Fatalf("the phase expects %d file(s), and one is read", progress.files)
	}
	if len(progress.items) != 1 || !strings.HasSuffix(progress.items[0], read) {
		t.Fatalf("the files picked up are %v, and only %s is read",
			progress.items, read)
	}
	if len(progress.read) != 1 {
		t.Fatalf("%d file(s) reported finished, and one was read", len(progress.read))
	}
}

// An event ID belongs to its provider, not to the channel it lands on. The
// System channel is shared by everything that has no log of its own, and on
// USB-LENOVO-Multi-USBs event 12 there is written by four publishers:
// Kernel-General fifteen times (the operating system starting),
// UserModePowerService forty-three, Wininit fifteen and a fingerprint reader's
// driver once. Keyed on the id alone, "the host booted" would be reported
// seventy-four times on a host that booted fifteen.
//
// A rule naming a different provider must not match at all — falling back to it
// is exactly the error this guards against.
func TestAnEventIDBelongsToItsProviderAndNotToTheChannel(t *testing.T) {
	rule, _, ok := lookup("System", "Microsoft-Windows-Kernel-General", 12)
	if !ok {
		t.Fatal("Kernel-General event 12 is the operating system starting")
	}
	if rule.Kind != KindSession {
		t.Errorf("kind = %q, want %q", rule.Kind, KindSession)
	}

	for _, impostor := range []string{
		"Microsoft-Windows-UserModePowerService",
		"Microsoft-Windows-Wininit",
		"Synaptics FPR",
		"",
	} {
		if _, _, ok := lookup("System", impostor, 12); ok {
			t.Errorf("event 12 from %q was read as the operating system "+
				"starting", impostor)
		}
	}
}

// A rule that names no provider still matches every one, because the dedicated
// channels have a single publisher and naming it on each rule would be noise
// that can drift out of date. Adding the field must not have changed them.
func TestARuleWithNoProviderStillMatchesAnyProvider(t *testing.T) {
	for _, provider := range []string{
		"Microsoft-Windows-StorageVolume", "something else entirely", "",
	} {
		rule, _, ok := lookup("Microsoft-Windows-StorageVolume/Operational",
			provider, 1001)
		if !ok {
			t.Fatalf("provider %q: a volume arrival went unread", provider)
		}
		if rule.Kind != KindConnect {
			t.Errorf("provider %q: kind = %q", provider, rule.Kind)
		}
	}
}

// System is the channel everything without a log of its own writes to, so a
// rule there that does not name its publisher will read another provider's
// event of the same number as though it were this one — which is exactly the
// error TestAnEventIDBelongsToItsProviderAndNotToTheChannel was written
// against, fixed for event 12 and left standing for four others.
//
// Like the exported-view order tests, this cannot fail as written. It fails
// the moment a System rule is added without a publisher.
func TestEveryRuleOnTheSharedChannelNamesItsPublisher(t *testing.T) {
	checked := 0
	for _, rule := range Rules() {
		if !strings.EqualFold(rule.Channel, "System") {
			continue
		}
		checked++
		if rule.Provider == "" {
			t.Errorf("System event %d matches any publisher; on a shared "+
				"channel that reads another provider's event of the same "+
				"number as this one", rule.EventID)
		}
	}
	if checked == 0 {
		t.Fatal("no System rules found: the check proved nothing")
	}
}

// The session rules are the only ones that describe the host rather than a
// device, so they are the only ones the USB gate would throw away. A boot names
// nothing; that is the point of it, and it must survive.
func TestARecordNamingNoDeviceSurvivesWhenItIsAboutTheHost(t *testing.T) {
	sessions := 0
	for _, rule := range Rules() {
		if rule.Kind != KindSession {
			continue
		}
		sessions++
		if rule.Gate == nil {
			t.Errorf("rule %s takes the default gate, which asks for a USB "+
				"identity it will never have", rule.ID())
			continue
		}
		if !rule.Gate(nil) {
			t.Errorf("rule %s discards a record carrying no fields, which is "+
				"every record it will ever see", rule.ID())
		}
	}
	if sessions == 0 {
		t.Error("no session rules: the host's own starts and stops are what " +
			"say whether a silence in the evidence is a quiet host or no host")
	}
}

// The unit of work is a batch of chunks rather than a whole file, so that one
// large log spreads across the workers instead of pinning a single goroutine
// while the rest idle. On a synthetic 1 GB System.evtx that took the parse from
// 41.5 s to 8.0 s on sixteen logical cores, reading the same 1,101,294 records.
//
// What this test covers is the arithmetic of the split, which is the part that
// can silently lose or repeat evidence: a chunk dropped between batches is a
// chunk of a Windows event log that no longer reaches the report, and a chunk
// handed out twice is every record in it counted twice. It does not test the
// parsing itself — every chunk is read exactly as it was before, from a handle
// of its batch's own.
func TestSplittingAFileHandsOutEveryChunkExactlyOnce(t *testing.T) {
	for _, count := range []int{
		1,
		chunksPerBatch - 1,
		chunksPerBatch,     // an exact multiple: no short batch at the end
		chunksPerBatch + 1, // a short final batch of one
		chunksPerBatch*3 + 7,
	} {
		plan := &filePlan{path: `C:\x\System.evtx`}
		for i := 0; i < count; i++ {
			plan.chunks = append(plan.chunks, &evtx.Chunk{Offset: int64(i)})
		}

		var seen []int64
		var bytes int64
		for _, batch := range plan.batches() {
			if len(batch.chunks) == 0 {
				t.Errorf("%d chunks: an empty batch was handed out", count)
			}
			if len(batch.chunks) > chunksPerBatch {
				t.Errorf("%d chunks: a batch of %d exceeds the limit",
					count, len(batch.chunks))
			}
			if batch.plan != plan {
				t.Errorf("%d chunks: a batch lost the file it came from", count)
			}
			for _, chunk := range batch.chunks {
				seen = append(seen, chunk.Offset)
			}
			bytes += batch.bytes()
		}

		if len(seen) != count {
			t.Errorf("%d chunks: %d were handed out", count, len(seen))
		}
		// In order and without repetition. The offsets were numbered 0..n-1, so
		// the sequence handed out must be exactly that.
		for i, offset := range seen {
			if offset != int64(i) {
				t.Errorf("%d chunks: position %d holds chunk %d",
					count, i, offset)
				break
			}
		}
		// The bytes reported to the progress line have to add up to the file,
		// or a run's completion percentage drifts as it goes.
		if want := int64(count) * evtxChunkSize; bytes != want {
			t.Errorf("%d chunks: batches account for %d bytes, want %d",
				count, bytes, want)
		}
	}
}

// A file that would not open, or that holds no readable chunk, has no work to
// hand out — and it is still an artefact the phase attempted, so it must keep
// its place in the accounting rather than vanishing from it. A log that failed
// to parse and a log that was never there read very differently in a report.
func TestAFileWithNoReadableChunkStillHasItsPlace(t *testing.T) {
	plan := &filePlan{
		path: `C:\x\System.evtx`, channel: "System", bytes: 4096,
		stats: FileStats{ExcludedBy: map[string]int{}},
	}
	if batches := plan.batches(); batches != nil {
		t.Errorf("got %d batches from a file with no chunks", len(batches))
	}

	stats := plan.fileStats()
	if stats.Path != plan.path || stats.Channel != "System" {
		t.Error("the file lost its identity in the accounting")
	}
	if stats.Bytes != 4096 {
		t.Errorf("bytes = %d, want the file's own size", stats.Bytes)
	}
	if stats.ChunksRead != 0 {
		t.Errorf("chunks read = %d, want 0", stats.ChunksRead)
	}
}

// One file's counts are now assembled from several goroutines, so the merge is
// the only place the totals exist. A count folded in twice, or not at all,
// would put a wrong number in the manifest's event accounting — which is the
// document an analyst uses to check that "these are the USB events" is true.
func TestAFilesCountsAreTheSumOfItsBatches(t *testing.T) {
	plan := &filePlan{
		path: `C:\x\System.evtx`, channel: "System",
		stats: FileStats{ExcludedBy: map[string]int{}},
	}
	plan.chunks = []*evtx.Chunk{{}, {}, {}}

	plan.merge(FileStats{
		RecordsRead: 10, Retained: 2, ChunksFailed: 1,
		ExcludedBy: map[string]int{"not_usb": 5, "unselected:System::9": 3},
	})
	plan.merge(FileStats{
		RecordsRead: 7, Retained: 1,
		ExcludedBy: map[string]int{"not_usb": 4},
	})

	stats := plan.fileStats()
	if stats.RecordsRead != 17 {
		t.Errorf("records read = %d, want 17", stats.RecordsRead)
	}
	if stats.Retained != 3 {
		t.Errorf("retained = %d, want 3", stats.Retained)
	}
	if stats.ChunksFailed != 1 {
		t.Errorf("chunks failed = %d, want 1", stats.ChunksFailed)
	}
	if stats.ExcludedBy["not_usb"] != 9 {
		t.Errorf("not_usb = %d, want 9", stats.ExcludedBy["not_usb"])
	}
	if stats.ExcludedBy["unselected:System::9"] != 3 {
		t.Errorf("unselected = %d, want 3",
			stats.ExcludedBy["unselected:System::9"])
	}
	// ChunksRead is the plan's own count, not a batch total: the chunks were
	// enumerated before any of them was handed out.
	if stats.ChunksRead != 3 {
		t.Errorf("chunks read = %d, want 3", stats.ChunksRead)
	}
}

// An opt-in channel is one Boobook reads and a run has to ask for. The two
// halves both matter: the catalogue must go on saying the channel is readable,
// so -sources and -rules describe the tool rather than one invocation, and the
// parser must not open the file unless asked.
//
// Security is the case it exists for. It holds a little worth having — 852
// logons and 10 logoffs on USB-LENOVO-Multi-USBs — and 82% of it is audit
// policy churn already excluded, and it costs the size of the file: nothing at
// the 20 MB default cap and about 76 seconds on the 2 GB a raised cap produces.
func TestAnOptInChannelIsReadableButNotReadUnlessAsked(t *testing.T) {
	if !ChannelSelected("Security") {
		t.Fatal("the catalogue no longer says Security can be read, so " +
			"-sources would stop describing what the tool is capable of")
	}
	reason, optIn := ChannelOptIn("Security")
	if !optIn {
		t.Fatal("Security is not marked opt-in, so every run would pay for it")
	}
	if reason == "" {
		t.Error("an opt-in channel must say why it is not read by default")
	}

	const path = `C:\nowhere\Security.evtx`

	var skipped recorder
	_, stats := ParseTreeWith([]string{path}, &skipped, Options{})
	if stats.FilesParsed != 0 {
		t.Errorf("%d file(s) parsed with no options; the channel must be "+
			"skipped unless asked for", stats.FilesParsed)
	}
	if len(stats.Files) != 1 || !stats.Files[0].Skipped {
		t.Fatal("the skipped file is not accounted for")
	}
	// Skipped for a different reason from a channel nothing reads, and the
	// accounting has to say which: "Boobook does not read this" and "this run
	// did not ask" lead a reader to opposite conclusions about the silence.
	if !stats.Files[0].OptInSkipped {
		t.Error("the file is not marked as skipped for want of asking, so a " +
			"reader cannot tell it from a channel nothing reads")
	}

	// Asked for, it is selected. The file does not exist, so it fails to parse
	// — what is being tested is that the parser reached for it at all.
	var asked recorder
	_, stats = ParseTreeWith([]string{path}, &asked,
		Options{OptIn: map[string]bool{"security": true}})
	if stats.FilesSkipped != 0 {
		t.Errorf("%d file(s) skipped when the channel was asked for",
			stats.FilesSkipped)
	}
}

// Lock and unlock need "Audit Other Logon/Logoff Events", which is not the
// default and is not set on any reference collection. They are selected anyway,
// because their presence is worth having where a host does audit them — and the
// catalogue has to say so, or their absence reads as the workstation never
// having been locked.
func TestLockAndUnlockSayTheyDependOnAnAuditPolicy(t *testing.T) {
	for _, id := range []int64{4800, 4801} {
		rule, _, ok := lookup("Security", "Microsoft-Windows-Security-Auditing", id)
		if !ok {
			t.Fatalf("event %d is not selected", id)
		}
		if rule.Kind != KindLogon {
			t.Errorf("event %d has kind %q, want %q", id, rule.Kind, KindLogon)
		}
		if rule.Note == "" {
			t.Errorf("event %d does not record that it depends on a "+
				"non-default audit policy, so its absence would read as the "+
				"workstation never having been locked", id)
		}
	}
}

// A Kernel-PnP 420 record is a removal only for a problem code that says the
// device is gone.
//
// The rule's Note had said exactly this for a long time — that 45 is
// CM_PROB_DEVICE_DISCONNECTED and that a record with another code is not a
// removal — and the rule then carried a fixed KindDisconnect, so every 420 that
// passed the USB gate closed a connection window whatever its problem code. The
// comment documented the defect it did not prevent.
//
// Nothing caught it because both 420 records in every reference collection
// carry problem 45. The happy path concealed it completely, which is the whole
// argument for a fixture: the evidence available cannot exercise the branch
// that is wrong.
//
// The field shape below is taken from a real record on
// USB-LENOVO-Multi-USBs — EventData.DeviceInstanceId, EventData.ClassGuid,
// EventData.Problem, EventData.Status, with the problem as a decimal string.
func TestAKernelPnPProblemIsADepartureOnlyWhenItSaysTheDeviceIsGone(t *testing.T) {
	rule, _, ok := lookup("Microsoft-Windows-Kernel-PnP/Configuration", "", 420)
	if !ok {
		t.Fatal("Kernel-PnP 420 is not in the catalogue")
	}

	record := func(problem string) []Field {
		return []Field{
			{Name: "DeviceInstanceId", Role: RoleDeviceInstanceID,
				Value: `STORAGE\VOLUME\_??_USBSTOR#DISK&VEN_PATRIOT&PROD_&REV_#24111912130128&0#`,
				Path:  "EventData.DeviceInstanceId"},
			{Name: "ClassGuid", Role: RoleClassGUID,
				Value: "71A27CDD-812A-11D0-BEC7-08002BE2092F",
				Path:  "EventData.ClassGuid"},
			{Name: "Problem", Role: RoleProblem, Value: problem,
				Path: "EventData.Problem"},
			{Name: "Status", Role: RoleStatus, Value: "0",
				Path: "EventData.Status"},
		}
	}

	for _, testCase := range []struct {
		problem string
		want    Kind
		why     string
	}{
		{"45", KindDisconnect,
			"CM_PROB_DEVICE_DISCONNECTED is a stick being pulled out, and is " +
				"the code on every 420 in every reference collection"},
		{"24", KindDisconnect,
			"CM_PROB_DEVICE_NOT_THERE is a devnode whose hardware has gone"},
		{"43", KindFault,
			"CM_PROB_FAILED_POST_START is a driver failing on a device that " +
				"is still in the port; read as a removal it would end a " +
				"connection window at the moment a driver crashed"},
		{"22", KindFault, "CM_PROB_DISABLED describes a device still attached"},
		{"28", KindFault, "CM_PROB_FAILED_INSTALL is not a departure"},
		{"21", KindFault,
			"CM_PROB_WILL_BE_REMOVED says a removal was asked for, not that " +
				"it happened; the removal writes its own record"},
		{"47", KindFault,
			"CM_PROB_HELD_FOR_EJECT is an intention too, and treating an " +
				"intention as the act closes the window before the device left"},
		{"", KindFault,
			"a record with no problem code at all must not be given the " +
				"strongest reading by default"},
	} {
		got := rule.KindOf(record(testCase.problem))
		if got != testCase.want {
			t.Errorf("problem %q (%s): kind = %q, want %q — %s",
				testCase.problem, ProblemName(testCase.problem),
				got, testCase.want, testCase.why)
		}
	}
}

// The three user-mode driver framework events say what operation they carry in
// their parameters, not in their event ID, so none of them is a removal on its
// own.
//
// Straight from the manifest installed on Windows, read with
// `wevtutil gp Microsoft-Windows-DriverFrameworks-UserMode /ge:true`:
//
//	2003  The UMDF Host Process (%1) has been asked to load drivers for device %2.
//	2100  Received a Pnp or Power operation (%3, %4) for device %2.
//	2102  Forwarded a finished Pnp or Power operation (%3, %4) to the lower
//	      driver for device %2 with status %9.
//
// Boobook read 2003 as an arrival and 2100 and 2102 as removals. A start, a
// query, a stop, a remove and a power transition are all the same event ID and
// differ only in %3 and %4, so a single retained 2100 would have ended a
// connection window at a power event — and 2003 fires at every boot for
// devices that were already attached.
//
// The channel is disabled by default on current Windows and no reference
// collection carries a record, so this could only ever have been found by
// reading the provider's own wording. That is what an independent review did.
func TestNoUserModeDriverFrameworkEventIsALifecycleTransitionOnItsOwn(t *testing.T) {
	const channel = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"

	for _, eventID := range []int64{2003, 2100, 2102} {
		rule, _, ok := lookup(channel, "", eventID)
		if !ok {
			t.Errorf("UMDF %d is no longer in the catalogue; it should be read "+
				"and reported, just not as an arrival or a departure", eventID)
			continue
		}
		if rule.Kind == KindConnect || rule.Kind == KindDisconnect {
			t.Errorf("UMDF %d is classified %q. The provider says this record "+
				"carries a PnP or power operation whose type is in its request "+
				"codes; the event ID cannot say what happened, and a record "+
				"read this way opens or closes a connection window on nothing.",
				eventID, rule.Kind)
		}
		// Kept, not dropped. The record is real evidence that something
		// happened to this device at this moment, and absence is reported as
		// absence — a rule removed entirely would make the channel silent.
		if rule.Meaning == "" {
			t.Errorf("UMDF %d says nothing about what it evidences", eventID)
		}
	}

	// And the channel therefore no longer claims to supply connection windows.
	for _, named := range StateChangeChannels() {
		if named == channel {
			t.Error("the UMDF channel is still declared as a state-change " +
				"channel, so a collection carrying only that channel would be " +
				"reported as able to yield connection windows it cannot")
		}
	}
}
