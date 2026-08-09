package store

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Bloggzy/boobook/internal/classify"
	"github.com/Bloggzy/boobook/internal/eventlog"
	"github.com/Bloggzy/boobook/internal/prefetch"
	"github.com/Bloggzy/boobook/internal/provenance"
	"github.com/Bloggzy/boobook/internal/registry"
	"github.com/Bloggzy/boobook/internal/setupapi"
	"github.com/Bloggzy/boobook/internal/wintime"
)

func open(t *testing.T) *Store {
	t.Helper()
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	rules, err := classify.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LoadRules(rules, classify.DefaultProfile); err != nil {
		t.Fatal(err)
	}
	return store
}

// consolidate runs the step a real run runs after its last load. The grouping
// and the facts are derived from everything above them, so a test that reads a
// device without it would read an empty inventory.
func consolidate(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Consolidate(); err != nil {
		t.Fatal(err)
	}
}

func at(text string) time.Time {
	moment, err := time.Parse(time.RFC3339, text)
	if err != nil {
		panic(err)
	}
	return moment
}

func devnode(enumerator, deviceID, instanceID, name string) registry.Devnode {
	return registry.Devnode{
		ControlSet:       "ControlSet001",
		Enumerator:       enumerator,
		DeviceID:         deviceID,
		InstanceID:       instanceID,
		DeviceInstanceID: enumerator + `\` + deviceID + `\` + instanceID,
		FriendlyName:     name,
	}
}

func event(recordID uint64, kind eventlog.Kind, instanceID string, when time.Time) eventlog.Record {
	return eventlog.Record{
		Channel:    "Microsoft-Windows-Kernel-PnP/Configuration",
		SourceFile: "pnp.evtx",
		RecordID:   recordID,
		EventID:    410,
		TimeUTC:    when,
		RuleID:     "Microsoft-Windows-Kernel-PnP/Configuration:410",
		Kind:       kind,
		Fields: []eventlog.Field{{
			Name: "DeviceInstanceId", Role: eventlog.RoleDeviceInstanceID,
			Value: instanceID,
		}},
	}
}

// stateEvent builds an arrival or departure record on a named channel, so the
// window logic is exercised against the shapes the catalogue produces.
func stateEvent(recordID uint64, channel string, eventID int64, kind eventlog.Kind,
	instanceID string, when time.Time, problem string) eventlog.Record {

	record := eventlog.Record{
		Channel:    channel,
		SourceFile: "state.evtx",
		RecordID:   recordID,
		EventID:    eventID,
		TimeUTC:    when,
		RuleID:     fmt.Sprintf("%s:%d", channel, eventID),
		Kind:       kind,
		Fields: []eventlog.Field{{
			Name: "DeviceInstanceId", Role: eventlog.RoleDeviceInstanceID,
			Value: instanceID,
		}},
	}
	if problem != "" {
		record.Fields = append(record.Fields, eventlog.Field{
			Name: "Problem", Role: eventlog.RoleProblem, Value: problem,
		})
	}
	return record
}

func loadState(t *testing.T, store *Store, records ...eventlog.Record) {
	t.Helper()
	if err := store.LoadEvents(map[string]string{"state.evtx": "src-1"}, records); err != nil {
		t.Fatal(err)
	}
}

func devices(t *testing.T, store *Store) map[string]Device {
	t.Helper()
	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	byKey := make(map[string]Device, len(rows))
	for _, device := range rows {
		byKey[device.PhysicalDeviceID] = device
	}
	return byKey
}

// The inventory is a union of every source, not a registry walk with extras
// attached. The reference evidence holds a device with event records and no
// registry key: starting from the registry loses it, and a device missing from
// the report looks exactly like a device that never existed.
func TestDeviceNamedOnlyByEventsIsInTheInventory(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USBSTOR", `Disk&Ven_PATRIOT&Prod_&Rev_`, "24111912130128&0", "PATRIOT USB Device"),
	}); err != nil {
		t.Fatal(err)
	}

	err := store.LoadEvents(map[string]string{"pnp.evtx": "src-2"}, []eventlog.Record{
		event(1, eventlog.KindConnect,
			`USBSTOR\Disk&Ven__USB&Prod__SanDisk&Rev_1.00\04010d18a394&0`,
			at("2026-07-26T08:28:25Z")),
		event(2, eventlog.KindDisconnect,
			`USBSTOR\Disk&Ven__USB&Prod__SanDisk&Rev_1.00\04010d18a394&0`,
			at("2026-07-26T10:03:12Z")),
	})
	if err != nil {
		t.Fatal(err)
	}

	found := devices(t, store)
	if len(found) != 2 {
		t.Fatalf("got %d devices, want 2: %v", len(found), found)
	}

	sandisk, ok := found[`USBSTOR\DISK&VEN__USB&PROD__SANDISK&REV_1.00\04010D18A394&0`]
	if !ok {
		t.Fatalf("the event-only device is not in the inventory: %v", found)
	}
	if sandisk.InRegistry {
		t.Error("InRegistry should be false for a device with no devnode")
	}
	if sandisk.ConnectEvents != 1 || sandisk.DisconnectEvents != 1 {
		t.Errorf("connect/disconnect = %d/%d, want 1/1",
			sandisk.ConnectEvents, sandisk.DisconnectEvents)
	}
	if sandisk.Serial != "04010d18a394" {
		// Derived from the identity, which is all an event-only device has.
		t.Errorf("serial = %q, want 04010d18a394", sandisk.Serial)
	}

	patriot := found[`USBSTOR\DISK&VEN_PATRIOT&PROD_&REV_\24111912130128&0`]
	if !patriot.InRegistry {
		t.Error("InRegistry should be true for a device with a devnode")
	}
	if patriot.EventCount != 0 {
		t.Errorf("event_count = %d, want 0", patriot.EventCount)
	}
}

// MountedDevices keeps a device's own casing while other sources upper-case it.
// A case-sensitive join returns nothing while looking like an absence of
// evidence, which is the worst way for a join to fail.
func TestIdentityJoinsAcrossCasingAndForm(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USBSTOR", `Disk&Ven_PATRIOT&Prod_&Rev_`, "24111912130128&0", "PATRIOT USB Device"),
		// The portable-devices node stores the same device as a device path
		// wrapped in the _??_ form, with an interface GUID appended.
		devnode("SWD", "WPDBUSENUM",
			`_??_USBSTOR#Disk&Ven_PATRIOT&Prod_&Rev_#24111912130128&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`,
			""),
	}); err != nil {
		t.Fatal(err)
	}

	err := store.LoadEvents(map[string]string{"pnp.evtx": "src-2"}, []eventlog.Record{
		event(1, eventlog.KindConnect,
			`USBSTOR\DISK&VEN_PATRIOT&PROD_&REV_\24111912130128&0`,
			at("2026-07-26T09:13:47Z")),
	})
	if err != nil {
		t.Fatal(err)
	}

	found := devices(t, store)
	if len(found) != 1 {
		t.Fatalf("three namings of one device produced %d devices: %v", len(found), found)
	}

	device := found[`USBSTOR\DISK&VEN_PATRIOT&PROD_&REV_\24111912130128&0`]
	if device.EventCount != 1 {
		t.Errorf("event_count = %d, want 1", device.EventCount)
	}
	// The WPDBUSENUM node stores another device's whole path as its instance
	// id. Reading that as a serial produces a "serial" that is a device path.
	if device.Serial != "24111912130128" {
		t.Errorf("serial = %q, want 24111912130128", device.Serial)
	}
	if device.FriendlyName != "PATRIOT USB Device" {
		t.Errorf("friendly_name = %q", device.FriendlyName)
	}
}

// Windows generates an instance id with '&' as its second character when the
// device reported no serial. Those are not unique, and reporting one as a
// serial invites two different devices being called the same device.
func TestGeneratedInstanceIDIsNotReportedAsASerial(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USB", "VID_8087&PID_0AAA", "5&caff80&0&14", "Intel Bluetooth"),
	}); err != nil {
		t.Fatal(err)
	}

	device := devices(t, store)[`USB\VID_8087&PID_0AAA\5&CAFF80&0&14`]
	if device.Serial != "" {
		t.Errorf("serial = %q, want empty for a generated instance id", device.Serial)
	}
	if !device.IdentityNotUnique {
		t.Error("identity_not_unique should be true for a generated instance id")
	}
}

// Evidence is not obliged to hold text. A value that is not valid UTF-8 must
// still load: replacing it with U+FFFD destroys the value and dropping the row
// destroys the record.
func TestNonUTF8ValueIsKeptNotDropped(t *testing.T) {
	store := open(t)

	err := store.LoadEvents(map[string]string{"pnp.evtx": "src-1"}, []eventlog.Record{{
		Channel: "Microsoft-Windows-DeviceSetupManager/Admin", SourceFile: "pnp.evtx",
		RecordID: 48, EventID: 121, TimeUTC: at("2026-07-26T09:00:00Z"),
		Kind: eventlog.KindOther,
		Fields: []eventlog.Field{
			{Name: "Prop_MilliSeconds", Value: "\x86S"},
			{Name: "DeviceInstanceId", Role: eventlog.RoleDeviceInstanceID,
				Value: `USBSTOR\Disk&Ven_X&Prod_Y&Rev_1\SERIAL&0`},
		},
	}})
	if err != nil {
		t.Fatalf("a record with a non-UTF-8 field was not loaded: %v", err)
	}

	var value string
	if err := store.DB().QueryRow(
		`SELECT value FROM event_field WHERE name = 'Prop_MilliSeconds'`,
	).Scan(&value); err != nil {
		t.Fatal(err)
	}
	// The bytes are recoverable from the stored form, and the marker cannot be
	// mistaken for content the evidence held.
	if value != "<non-utf8:8653>" {
		t.Errorf("value = %q, want the bytes in hex behind a marker", value)
	}
}

func removableTarget(letter, serial, label, path string) FileTarget {
	return FileTarget{
		SourceID: "src-1", SourceFile: path + ".lnk", Origin: "shell_link",
		Path: path, DriveLetter: letter, VolumePresent: true,
		DriveType: "removable", VolumeSerialHex: serial, VolumeLabel: label,
		Removable: true,
	}
}

// Two volumes sharing a drive letter is the ordinary case, not an edge case.
// The reference evidence has E: used by both a PATRIOT and a TEST volume, and
// grouping file activity by letter attributes one device's files to the other.
func TestRemovableVolumesAreGroupedBySerialNotByLetter(t *testing.T) {
	store := open(t)

	err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "00C9-0010", "PATRIOT", `E:\notes.txt`),
		removableTarget("E", "E607-9156", "TEST", `E:\report.docx`),
		removableTarget("E", "E607-9156", "TEST", `E:\budget.xlsx`),
		// A target on a fixed disk is not part of this question.
		{SourceID: "src-1", Path: `C:\Users\a\file.txt`, DriveLetter: "C",
			VolumePresent: true, DriveType: "fixed"},
	})
	if err != nil {
		t.Fatal(err)
	}

	volumes, err := store.RemovableVolumes()
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 2 {
		t.Fatalf("got %d volumes, want 2 for one reused letter: %+v", len(volumes), volumes)
	}

	byLabel := map[string]RemovableVolume{}
	for _, volume := range volumes {
		byLabel[volume.VolumeLabel] = volume
	}
	if byLabel["TEST"].TargetCount != 2 {
		t.Errorf("TEST holds %d target(s), want 2", byLabel["TEST"].TargetCount)
	}
	if byLabel["PATRIOT"].TargetCount != 1 {
		t.Errorf("PATRIOT holds %d target(s), want 1", byLabel["PATRIOT"].TargetCount)
	}
}

// Every output is a copy of a view. If an export could be assembled another
// way, two outputs could disagree about the evidence and both look right.
func TestExportsMatchTheViewsTheyCameFrom(t *testing.T) {
	store := open(t)

	ledger := provenance.NewLedger()
	path := filepath.Join(t.TempDir(), "SYSTEM")
	if err := os.WriteFile(path, []byte("hive"), 0o644); err != nil {
		t.Fatal(err)
	}
	source, err := ledger.AddSource(path, "SYSTEM")
	if err != nil {
		t.Fatal(err)
	}
	ledger.Observe(provenance.Observation{
		SourceID: source.ID, Kind: "devnode.value", Field: "FriendlyName",
		Raw: "PATRIOT USB Device",
	})

	if err := store.LoadLedger(ledger); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadDevnodes(source.ID, []registry.Devnode{
		devnode("USBSTOR", `Disk&Ven_PATRIOT&Prod_&Rev_`, "24111912130128&0", "PATRIOT USB Device"),
	}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)

	dir := t.TempDir()
	written, err := store.ExportAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != len(exports) {
		t.Fatalf("wrote %d of %d exports", len(written), len(exports))
	}

	for _, export := range written {
		if export.SHA256 == "" {
			t.Errorf("%s was written without a hash", export.Name)
		}
		if _, err := os.Stat(export.Path); err != nil {
			t.Errorf("%s: %v", export.Name, err)
		}

		var rows int
		if err := store.DB().QueryRow(
			"SELECT count(*) FROM " + export.View).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != export.Rows {
			t.Errorf("%s reports %d rows, %s holds %d",
				export.Name, export.Rows, export.View, rows)
		}
	}

	// The row an analyst reads in devices.csv is the row the view produced.
	file, err := os.Open(filepath.Join(dir, "data", "devices.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("devices.csv holds %d line(s), want a header and one device", len(records))
	}
	if !strings.Contains(strings.Join(records[1], ","), "24111912130128") {
		t.Errorf("the device row does not carry its serial: %v", records[1])
	}

	// Provenance travels with the observation, so a figure can be checked
	// without the manifest open beside it.
	observations, err := os.ReadFile(filepath.Join(dir, "provenance", "observations.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(observations), source.SHA256) {
		t.Error("observations.jsonl does not carry the source hash")
	}
}

const patriotID = `USBSTOR\Disk&Ven_PATRIOT&Prod_&Rev_\24111912130128&0`

// Several channels report the same arrival within seconds of each other. Each
// is a record of one connection, not a connection of its own, and counting them
// separately would multiply every visit by the number of channels that saw it.
func TestRepeatedArrivalsAreOneConnection(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-Kernel-PnP/Configuration", 410,
			eventlog.KindConnect, patriotID, at("2026-07-26T08:28:25Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2026-07-26T08:28:27Z"), ""),
		stateEvent(3, "Microsoft-Windows-DeviceSetupManager/Admin", 126,
			eventlog.KindConnect, patriotID, at("2026-07-26T08:28:31Z"), ""),
		stateEvent(4, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, patriotID, at("2026-07-26T08:39:06Z"), ""),
	)

	connections, err := store.Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 {
		t.Fatalf("got %d connections, want 1: %+v", len(connections), connections)
	}

	connection := connections[0]
	// The window opens at the earliest record, which is the first moment the
	// evidence places the device on the machine.
	if got := connection.StartedUTC.Format(time.RFC3339); got != "2026-07-26T08:28:25Z" {
		t.Errorf("started = %s", got)
	}
	if got := connection.EndedUTC.Format(time.RFC3339); got != "2026-07-26T08:39:06Z" {
		t.Errorf("ended = %s", got)
	}
	if connection.SupportingRecords != 4 {
		t.Errorf("supporting records = %d, want 4", connection.SupportingRecords)
	}
	if connection.OpenEnded || !connection.StartKnown {
		t.Error("both ends of this window are evidenced")
	}
}

// Closing an open window at the end of the log would manufacture a removal the
// evidence never recorded.
func TestArrivalWithNoRemovalStaysOpen(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2026-07-26T11:02:48Z"), ""),
	)

	connections, err := store.Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 {
		t.Fatalf("got %d connections, want 1", len(connections))
	}
	if !connections[0].OpenEnded || connections[0].EndedUTC != nil {
		t.Error("a window with no removal must stay open")
	}
	if connections[0].SpanSeconds != nil {
		t.Error("an open window has no span")
	}
}

// A second arrival with no removal logged between the two is a second
// connection, not more of the first. This was once read as one unbroken run of
// the same state, so the later record was discarded and the window ran on to
// whatever came next: on USB-LENOVO-Multi-USBs a SanDisk plugged in at 02:21
// was folded into an arrival from eleven months earlier, the run reported a
// single connection spanning 8438 hours, and the device's arrival was dated to
// the wrong year. The two arrivals here are far enough apart to be two
// connections rather than two channels seeing one.
func TestASecondArrivalIsASecondConnection(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2025-08-17T11:38:37Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2026-08-04T02:21:17Z"), ""),
		stateEvent(3, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, patriotID, at("2026-08-04T02:24:10Z"), ""),
	)

	connections, err := store.Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 2 {
		t.Fatalf("got %d connections, want 2: %+v", len(connections), connections)
	}

	byStart := make(map[string]Connection, len(connections))
	for _, connection := range connections {
		byStart[connection.StartedUTC.Format(time.RFC3339)] = connection
	}

	// The second arrival keeps its own window, closed by the removal that
	// followed it. This is the record that used to be thrown away.
	second, ok := byStart["2026-08-04T02:21:17Z"]
	if !ok {
		t.Fatalf("the second arrival opened no window: %+v", connections)
	}
	if got := second.EndedUTC.Format(time.RFC3339); got != "2026-08-04T02:24:10Z" {
		t.Errorf("second window ended = %s", got)
	}
	if *second.SpanSeconds != 173 {
		t.Errorf("second window span = %d seconds, want 173", *second.SpanSeconds)
	}

	// The first is bounded rather than ended. The device must have gone away —
	// it arrived again — but nothing recorded when, so the window has no
	// removal and no span, only the moment it cannot have outlasted.
	first := byStart["2025-08-17T11:38:37Z"]
	if first.EndedUTC != nil || !first.OpenEnded {
		t.Error("a window with no removal recorded must stay open")
	}
	if first.SpanSeconds != nil {
		t.Error("a window with no recorded end has no span")
	}
	if first.EndedBeforeUTC == nil {
		t.Fatal("a window superseded by another arrival is bounded by it")
	}
	if got := first.EndedBeforeUTC.Format(time.RFC3339); got != "2026-08-04T02:21:17Z" {
		t.Errorf("first window bounded at %s", got)
	}
}

// The bound matters because it decides what the window can place. A window the
// device left during cannot say it was attached at a moment inside it, and
// saying so is how a folder view recorded at 02:09 came to be attributed,
// probable and unopposed, to a device that did not arrive until 02:21.
func TestASupersededWindowPlacesNothing(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2025-08-17T11:38:37Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2026-08-04T02:21:17Z"), ""),
		stateEvent(3, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, patriotID, at("2026-08-04T02:24:10Z"), ""),
	)

	var placing, total int
	if err := store.db.QueryRow(
		`SELECT (SELECT count(*) FROM v_connection_placing),
		        (SELECT count(*) FROM v_connection)`).
		Scan(&placing, &total); err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("got %d windows, want 2", total)
	}
	// Only the bounded one is withheld. An open window that nothing supersedes
	// still places the device, which is what a collection taken with the stick
	// still in the port looks like.
	if placing != 1 {
		t.Errorf("got %d placing window(s), want 1: the superseded one places nothing", placing)
	}
}

// A removal with nothing before it means the device was already connected when
// the evidence begins. Its start is unknown, not the time of the first record.
func TestRemovalWithNoArrivalHasAnUnknownStart(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, patriotID, at("2025-08-17T03:03:44Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2025-08-17T11:36:34Z"), ""),
	)

	connections, err := store.Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 2 {
		t.Fatalf("got %d connections, want 2: %+v", len(connections), connections)
	}

	var unknownStart *Connection
	for index := range connections {
		if !connections[index].StartKnown {
			unknownStart = &connections[index]
		}
	}
	if unknownStart == nil {
		t.Fatal("the leading removal produced no window with an unknown start")
	}
	if unknownStart.StartedUTC != nil {
		t.Error("an unknown start must be absent, not guessed at")
	}
	if got := unknownStart.EndedUTC.Format(time.RFC3339); got != "2025-08-17T03:03:44Z" {
		t.Errorf("ended = %s", got)
	}
}

// A Kernel-PnP 420 is a removal only when the problem code is 45,
// CM_PROB_DEVICE_DISCONNECTED. With any other code the device is still present,
// and treating it as a removal ends a connection that never ended.
func TestDeviceProblemThatIsNotADisconnectDoesNotCloseAWindow(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2026-07-26T08:28:25Z"), ""),
		// CM_PROB_FAILED_START, not a removal.
		stateEvent(2, "Microsoft-Windows-Kernel-PnP/Configuration", 420,
			eventlog.KindDisconnect, patriotID, at("2026-07-26T08:30:00Z"), "10"),
	)

	connections, err := store.Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(connections) != 1 {
		t.Fatalf("got %d connections, want 1", len(connections))
	}
	if !connections[0].OpenEnded {
		t.Errorf("a fault closed the window: ended %v", connections[0].EndedUTC)
	}

	// The same event with the disconnect code does close it.
	store2 := open(t)
	loadState(t, store2,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, patriotID, at("2026-07-26T08:28:25Z"), ""),
		stateEvent(2, "Microsoft-Windows-Kernel-PnP/Configuration", 420,
			eventlog.KindDisconnect, patriotID, at("2026-07-26T08:30:00Z"), "45"),
	)
	closed, err := store2.Connections()
	if err != nil {
		t.Fatal(err)
	}
	if len(closed) != 1 || closed[0].OpenEnded {
		t.Errorf("problem code 45 should close the window: %+v", closed)
	}
}

const sandiskID = `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\04010d18a394&0`

// The case this whole chain exists for, taken from the reference evidence:
// drive E: carried two different volumes, MountedDevices maps E: to the Patriot
// device today, and the files labelled TEST were on the SanDisk.
//
// The letter is the obvious join and it gives the wrong device. The label plus
// a connection window gives the right one, and neither is allowed to silence
// the other: both candidates are reported, ranked.
func TestContestedDriveLetterRanksTheEvidenceCorrectly(t *testing.T) {
	store := open(t)

	// MountedDevices maps E: to the Patriot device — as it stands now.
	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: patriotID,
	}}); err != nil {
		t.Fatal(err)
	}

	// Portable Devices records a label against each device.
	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "PATRIOT", DeviceInstanceID: patriotID},
		{FriendlyName: "TEST", DeviceInstanceID: sandiskID},
	}); err != nil {
		t.Fatal(err)
	}

	// The SanDisk was on the machine when the file was opened.
	opened := at("2026-07-26T10:00:30Z")
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-07-26T10:00:06Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-07-26T10:01:44Z"), ""),
	)

	target := removableTarget("E", "E607-9156", "TEST", `E:\10MB-TESTFILE.ORG.pdf`)
	target.LastAccessUTC = &opened
	if err := store.LoadFileTargets([]FileTarget{target}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.DB().Query(`
        SELECT device_instance_id, route, confidence
        FROM v_file_attribution WHERE path = 'E:\10MB-TESTFILE.ORG.pdf'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	found := map[string]string{}
	for rows.Next() {
		var device, route, confidence string
		if err := rows.Scan(&device, &route, &confidence); err != nil {
			t.Fatal(err)
		}
		found[route] = confidence + " " + device
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// The right answer, and why it is the right answer: the label is unique to
	// the SanDisk and a connection window independently places it there.
	label := found["volume_label_unique"]
	if label != "probable "+sandiskID {
		t.Errorf("label route gave %q, want probable %s", label, sandiskID)
	}

	// The wrong answer is still reported, because MountedDevices really does
	// map E: to the Patriot device — but only as possible, because nothing
	// places that device on the machine when the file was opened.
	letter := found["drive_letter_mounted_devices_device_path"]
	if letter != "possible "+patriotID {
		t.Errorf("letter route gave %q, want possible %s", letter, patriotID)
	}

	contested, _, err := store.Attributions()
	if err != nil {
		t.Fatal(err)
	}
	if len(contested) != 1 || contested[0].CandidateDevices != 2 {
		t.Fatalf("the contest was not reported: %+v", contested)
	}
	if contested[0].BestConfidence != "probable" {
		t.Errorf("best confidence = %q, want probable", contested[0].BestConfidence)
	}
}

// The timeline names the device the strongest route reached, not only the
// device every route agrees on.
//
// Requiring agreement was right while the routes could tie. They no longer
// routinely do: the letter route is demoted wherever no connection window
// places the device, so the contest above has a winner. Refusing to name it
// discarded an answer the evidence had settled — on USB-LENOVO-Multi-USBs ten
// file opens sat on the timeline with no device against them while
// file-attribution.csv named the right one for each.
func TestTheTimelineNamesTheDeviceTheStrongestRouteReached(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: patriotID,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "PATRIOT", DeviceInstanceID: patriotID},
		{FriendlyName: "TEST", DeviceInstanceID: sandiskID},
	}); err != nil {
		t.Fatal(err)
	}

	// The SanDisk was on the machine when the file was opened; nothing places
	// the Patriot there, so the letter route cannot reach probable.
	opened := at("2026-07-26T10:00:30Z")
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-07-26T10:00:06Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-07-26T10:01:44Z"), ""),
	)
	target := removableTarget("E", "E607-9156", "TEST", `E:\10MB-TESTFILE.ORG.pdf`)
	target.LastAccessUTC = &opened
	if err := store.LoadFileTargets([]FileTarget{target}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var device, confidence, detail string
	err := store.DB().QueryRow(`
        SELECT device_key, confidence, detail FROM v_timeline
        WHERE event = 'file_opened' AND path = 'E:\10MB-TESTFILE.ORG.pdf'`).
		Scan(&device, &confidence, &detail)
	if err != nil {
		t.Fatal(err)
	}
	if device != strings.ToUpper(sandiskID) {
		t.Errorf("the timeline named %q, want the device the label route reached", device)
	}
	if confidence != "probable" {
		t.Errorf("confidence = %q, want probable", confidence)
	}
	// Naming a winner is a judgement between routes, so the row says one was
	// made and how many candidates it beat. A named device that hid the contest
	// would read as though the evidence had only ever offered one answer.
	if !strings.Contains(detail, "2 candidate devices") ||
		!strings.Contains(detail, "strongest route") {
		t.Errorf("the row does not say it chose between candidates: %q", detail)
	}
}

// A tie at the top is still unnamed. Two devices reached with equal confidence
// is a question the evidence has not settled, and picking one would settle it
// by fiat — which is what the old rule guarded against and what the new one
// must keep guarding against.
//
// The fixture had to change when the contradiction rule went in, and the reason
// is worth recording. It used to be a label naming one device and a drive
// letter naming another, both at possible — and that is no longer a tie, by
// design: a record's own label is dated evidence and the mount table is not, so
// the letter is contradicted and the label wins.
//
// What remains a genuine tie is one route reaching two devices, and the mount
// table is where that happens: MountedDevices is per control set, and a
// collection carrying two of them can map one letter to two devices with
// nothing to choose between. The record here has no label at all, so there is
// nothing to break the tie with and nothing that should try.
func TestTwoDevicesAtEqualConfidenceLeaveTheRowUnnamed(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{
		{ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
			DriveLetter: "E", TargetKind: registry.TargetDevicePath,
			DeviceInstanceID: patriotID},
		{ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
			DriveLetter: "E", TargetKind: registry.TargetDevicePath,
			DeviceInstanceID: sandiskID},
	}); err != nil {
		t.Fatal(err)
	}
	opened := at("2026-07-26T10:00:30Z")
	// No label: the letter alone reaches two devices, and nothing places either
	// on the machine, so both land on possible.
	target := removableTarget("E", "E607-9156", "", `E:\10MB-TESTFILE.ORG.pdf`)
	target.LastAccessUTC = &opened
	if err := store.LoadFileTargets([]FileTarget{target}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var device, confidence, detail string
	err := store.DB().QueryRow(`
        SELECT device_key, confidence, detail FROM v_timeline
        WHERE event = 'file_opened' AND path = 'E:\10MB-TESTFILE.ORG.pdf'`).
		Scan(&device, &confidence, &detail)
	if err != nil {
		t.Fatal(err)
	}
	if device != "" {
		t.Errorf("the timeline named %q where two devices tie", device)
	}
	if confidence != "possible" {
		t.Errorf("confidence = %q, want possible", confidence)
	}
	if !strings.Contains(detail, "equal confidence") {
		t.Errorf("the row does not say why nothing is named: %q", detail)
	}
}

// EMDMgmt holds the volume serial, the label and the device in one key name, so
// nothing is inferred between them. It is the only artefact that does, which is
// why its absence on current Windows forces the weaker routes.
func TestEMDMgmtSerialGivesAConfirmedAttribution(t *testing.T) {
	store := open(t)

	if err := store.LoadEMDVolumes("src-1", []registry.EMDMgmtEntry{{
		KeyName:     `_??_USBSTOR#Disk&Ven__USB#04010d18a394&0#{guid}_TEST_3859325782`,
		VolumeLabel: "TEST",
		// 3859255638 is 0xE6079156, the serial a shell link renders E607-9156.
		VolumeSerialDecimal: "3859255638",
		DeviceInstanceID:    sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}

	if err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "E607-9156", "TEST", `E:\report.docx`),
	}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	var device, confidence string
	if err := store.DB().QueryRow(`
        SELECT device_instance_id, confidence FROM v_file_attribution
        WHERE route = 'volume_serial_emdmgmt'`).Scan(&device, &confidence); err != nil {
		t.Fatalf("the serial route produced no attribution: %v", err)
	}
	if confidence != "confirmed" || device != sandiskID {
		t.Errorf("got %s %s, want confirmed %s", confidence, device, sandiskID)
	}
}

// The artefact column used to read 'file_record' for both a shortcut and a
// jump list entry, with the answer demoted to detail. An analyst filtering
// timeline.csv for jump list activity had to know to read a second column, and
// the CSVs disagreed with the vocabulary used everywhere else in the tool.
//
// These strings are a published contract: they appear in timeline.csv,
// file-attribution.csv, file-attribution-summary.csv and letter-activity.csv,
// and a saved filter or a downstream script depends on them.
func TestAShortcutAndAJumpListNameThemselves(t *testing.T) {
	store := open(t)

	opened := at("2026-07-26T10:00:30Z")

	link := removableTarget("E", "E607-9156", "TEST", `E:\report.docx`)
	link.LastAccessUTC = &opened

	jump := removableTarget("E", "E607-9156", "TEST", `E:\budget.xlsx`)
	jump.Origin = "jump_list"
	jump.AppID = "f01b4d95cf55d32a"
	jump.LastAccessUTC = &opened

	if err := store.LoadFileTargets([]FileTarget{link, jump}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	for _, want := range []struct {
		path     string
		artefact string
		detail   string
	}{
		// A shortcut has no sub-source to name: it is one file, and
		// source_file already says which.
		{`E:\report.docx`, "shell_link", ""},
		// A jump list does, and it is the AppID — left as the hash it is,
		// because a wrong application name is worse than none.
		{`E:\budget.xlsx`, "jump_list", "app f01b4d95cf55d32a"},
	} {
		var artefact, detail string
		err := store.DB().QueryRow(`
            SELECT artefact, detail FROM v_file_activity WHERE path = ?`,
			want.path).Scan(&artefact, &detail)
		if err != nil {
			t.Fatalf("%s: %v", want.path, err)
		}
		if artefact != want.artefact || detail != want.detail {
			t.Errorf("%s: got artefact %q detail %q, want %q and %q",
				want.path, artefact, detail, want.artefact, want.detail)
		}
	}

	// The timeline carries the same names, and still calls both an opening.
	// The event and the artefact are separate questions: renaming the artefact
	// must not disturb what the row says happened.
	rows, err := store.DB().Query(`
        SELECT artefact, event FROM v_timeline
        WHERE artefact IN ('shell_link', 'jump_list', 'file_record')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	seen := map[string]bool{}
	for rows.Next() {
		var artefact, event string
		if err := rows.Scan(&artefact, &event); err != nil {
			t.Fatal(err)
		}
		if artefact == "file_record" {
			t.Errorf("the timeline still emits the collapsed name 'file_record'")
		}
		if event != "file_opened" {
			t.Errorf("%s: got event %q, want file_opened", artefact, event)
		}
		seen[artefact] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !seen["shell_link"] || !seen["jump_list"] {
		t.Errorf("the timeline reached %v, want both shell_link and jump_list", seen)
	}
}

// Without a connection window the label still identifies a device, but nothing
// places that device on the machine when the record was made. That difference
// is the whole distance between possible and probable.
func TestLabelWithoutAConnectionWindowStaysPossible(t *testing.T) {
	store := open(t)

	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "TEST", DeviceInstanceID: sandiskID},
	}); err != nil {
		t.Fatal(err)
	}

	opened := at("2026-07-26T10:00:30Z")
	// A window for the same device, an hour after the file was opened.
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-07-26T11:00:00Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-07-26T11:30:00Z"), ""),
	)

	target := removableTarget("E", "E607-9156", "TEST", `E:\report.docx`)
	target.LastAccessUTC = &opened
	if err := store.LoadFileTargets([]FileTarget{target}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	var confidence string
	if err := store.DB().QueryRow(`
        SELECT confidence FROM v_file_attribution
        WHERE route = 'volume_label_unique'`).Scan(&confidence); err != nil {
		t.Fatal(err)
	}
	if confidence != "possible" {
		t.Errorf("confidence = %q, want possible: the window does not cover the record",
			confidence)
	}
}

// ---- physical device grouping ---------------------------------------------

// The three SanDisk sticks in the reference evidence each appear under a USB
// identity holding a 120 character serial and a USBSTOR identity holding its
// first 63 characters, so serial equality never fires and only the ContainerID
// carries them.
func sanDiskPair(container string) []registry.Devnode {
	const long = "0401B570C5371292F08BD55E8C5C18A36ADDC998D84A78A94890C6C009D97EA" +
		"851060000000000000000000060A0AEDCFF885E188155810787AF6903"
	const short = "0401B570C5371292F08BD55E8C5C18A36ADDC998D84A78A94890C6C009D97EA"

	return []registry.Devnode{
		{
			ControlSet: "ControlSet001", Enumerator: "USBSTOR",
			DeviceID: "Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00", InstanceID: short,
			DeviceInstanceID: `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\` + short,
			FriendlyName:     "USB  SanDisk 3.2Gen1 USB Device", ContainerID: container,
		},
		{
			ControlSet: "ControlSet001", Enumerator: "USB",
			DeviceID: "VID_0781&PID_5581", InstanceID: long,
			DeviceInstanceID: `USB\VID_0781&PID_5581\` + long,
			ContainerID:      container,
		},
	}
}

func groupOf(t *testing.T, store *Store, identity string) string {
	t.Helper()
	consolidate(t, store)
	var group string
	if err := store.DB().QueryRow(
		"SELECT physical_device_id FROM v_device_group WHERE device_key = ?",
		identity).Scan(&group); err != nil {
		t.Fatalf("group of %s: %v", identity, err)
	}
	return group
}

// A USB node and a USBSTOR node are one stick. Reporting them as two devices
// would tell an analyst that two SanDisks were used where one was.
func TestContainerIDGroupsATruncatedSerial(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1",
		sanDiskPair("{2988c0d8-c5c7-58a8-8331-991530145bee}")); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d devices, want 1: the identities share a ContainerID", len(rows))
	}
	if rows[0].IdentityCount != 2 {
		t.Errorf("identity_count = %d, want 2", rows[0].IdentityCount)
	}
	if !strings.Contains(rows[0].GroupingMethods, "container_id") {
		t.Errorf("grouping_methods = %q, should name container_id",
			rows[0].GroupingMethods)
	}

	// The prefix route reached the same answer, which is corroboration and not
	// a second grouping.
	consolidate(t, store)
	links, err := store.CandidateLinks()
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || !links[0].AlreadyGrouped {
		t.Errorf("candidate links = %+v, want one already grouped", links)
	}
}

// The same two identities with no ContainerID. A prefix is not equality: a
// vendor issuing sequential serials produces prefixes between different
// devices, so the link is reported and not acted on.
func TestSerialPrefixAloneDoesNotGroup(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", sanDiskPair("")); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d devices, want 2: a serial prefix must not assert sameness",
			len(rows))
	}

	consolidate(t, store)
	links, err := store.CandidateLinks()
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 {
		t.Fatalf("got %d candidate links, want 1", len(links))
	}
	if links[0].AlreadyGrouped {
		t.Error("the candidate should be reported as unresolved, not as corroboration")
	}
	if links[0].Method != "serial_prefix_candidate" {
		t.Errorf("method = %q", links[0].Method)
	}
}

// Windows writes a placeholder ContainerID for devices it puts in no container,
// and dozens of unrelated devices carry it. Treating it as a match would report
// most of the machine as one device.
func TestPlaceholderContainerIDDoesNotGroup(t *testing.T) {
	store := open(t)

	placeholder := "{00000000-0000-0000-ffff-ffffffffffff}"
	first := devnode("SCSI", "Disk&Ven_NVME&Prod_SAMSUNG", "5&1a89cd96&0&000000", "disk")
	first.ContainerID = placeholder
	second := devnode("SWD", "PRINTENUM", "PrintQueues", "print queues")
	second.ContainerID = placeholder

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{first, second}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d devices, want 2: the placeholder container is not a container",
			len(rows))
	}
}

// A root hub publishes a ParentIdPrefix that every device plugged into it
// carries. Without the hub guard, one "physical device" would be the hub and
// everything ever attached to it.
func TestRootHubDoesNotAbsorbTheDevicesPluggedIntoIt(t *testing.T) {
	store := open(t)

	hub := devnode("USB", "ROOT_HUB30", "4&d2fc86a&0&0", "USB Root Hub")
	hub.ParentIDPrefix = "5&caff80&0"
	hub.Service = "USBHUB3"
	reader := devnode("USB", "VID_058F&PID_9540", "5&caff80&0&11", "Card Reader")
	mouse := devnode("USB", "VID_413C&PID_301A", "5&caff80&0&2", "USB Input Device")

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{hub, reader, mouse}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d devices, want 3: a hub is not the devices attached to it",
			len(rows))
	}
}

// A composite device's function nodes carry their parent's ParentIdPrefix, and
// grouping them is what the route is for.
func TestParentIDPrefixGroupsACompositeDevice(t *testing.T) {
	store := open(t)

	parent := devnode("USB", "VID_8087&PID_0ACA", "05022016", "USB Composite Device")
	parent.ParentIDPrefix = "7&1e2cd3d3&0"
	parent.Service = "usbccgp"
	child := devnode("USB", "VID_8087&PID_0ACA&MI_00", "7&1e2cd3d3&0&0000", "USB Serial Device")

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{parent, child}); err != nil {
		t.Fatal(err)
	}

	if got, want := groupOf(t, store, `USB\VID_8087&PID_0ACA&MI_00\7&1E2CD3D3&0&0000`),
		`USB\VID_8087&PID_0ACA\05022016`; got != want {
		t.Errorf("group = %q, want %q", got, want)
	}
}

// The reference host holds three different Intel products all reporting the
// serial 05022016. A serial is unique within a vendor and product, not across
// them, so an equal serial alone must not merge different products.
func TestTheSameSerialUnderDifferentProductsDoesNotGroup(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USB", "VID_8087&PID_0ACA", "05022016", "composite"),
		devnode("USB", "VID_8087&PID_0AF1", "05022016", "composite"),
		devnode("USB", "VID_8087&PID_0AC9", "05022016", "composite"),
	}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d devices, want 3: 05022016 is three products' serial", len(rows))
	}
}

// A SetupAPI install section names some devices by hardware id, which has no
// instance segment. Reading its last segment as a serial would invent a serial
// out of the product id and then join every device sharing that product.
func TestAHardwareIDIsNotReadAsASerial(t *testing.T) {
	store := open(t)

	if err := store.LoadSetupSections("src-1", []setupapi.Section{{
		SourceFile:       "setupapi.dev.log",
		Kind:             setupapi.KindInstall,
		DeviceInstanceID: `USB\VID_8087&PID_0AAA&REV_0002`,
		LineNumber:       1,
	}}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d devices, want 1", len(rows))
	}
	if rows[0].Serial != "" {
		t.Errorf("serial = %q, want empty: a hardware id names a model, not a device",
			rows[0].Serial)
	}
}

// That hardware id belongs to a devnode which declares it, and matching them is
// the only route from an install section to the device it installed.
func TestAUniqueHardwareIDReachesItsDevnode(t *testing.T) {
	store := open(t)

	node := devnode("USB", "VID_8087&PID_0AAA", "5&caff80&0&14", "Intel Bluetooth")
	node.HardwareID = `USB\VID_8087&PID_0AAA&REV_0002|USB\VID_8087&PID_0AAA`
	if err := store.LoadDevnodes("src-1", []registry.Devnode{node}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadSetupSections("src-1", []setupapi.Section{{
		SourceFile:       "setupapi.dev.log",
		Kind:             setupapi.KindInstall,
		DeviceInstanceID: `USB\VID_8087&PID_0AAA&REV_0002`,
		LineNumber:       1,
	}}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	rows, err := store.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d devices, want 1: the hardware id names exactly one devnode",
			len(rows))
	}
	if rows[0].SetupSections != 1 {
		t.Errorf("setup_sections = %d, want 1", rows[0].SetupSections)
	}
}

// Two identical devices declare the same hardware id, so it identifies neither.
// The link is reported and not acted on.
func TestAnAmbiguousHardwareIDDoesNotGroup(t *testing.T) {
	store := open(t)

	first := devnode("USB", "VID_8087&PID_0AAA", "5&caff80&0&14", "Intel Bluetooth")
	first.HardwareID = `USB\VID_8087&PID_0AAA&REV_0002`
	second := devnode("USB", "VID_8087&PID_0AAA", "5&caff80&0&15", "Intel Bluetooth")
	second.HardwareID = `USB\VID_8087&PID_0AAA&REV_0002`

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{first, second}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadSetupSections("src-1", []setupapi.Section{{
		SourceFile:       "setupapi.dev.log",
		Kind:             setupapi.KindInstall,
		DeviceInstanceID: `USB\VID_8087&PID_0AAA&REV_0002`,
		LineNumber:       1,
	}}); err != nil {
		t.Fatal(err)
	}

	consolidate(t, store)
	links, err := store.CandidateLinks()
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d candidate links, want 2", len(links))
	}
	for _, link := range links {
		if link.Method != "hardware_id_ambiguous" {
			t.Errorf("method = %q, want hardware_id_ambiguous", link.Method)
		}
	}
	if group := groupOf(t, store, `USB\VID_8087&PID_0AAA&REV_0002`); group !=
		`USB\VID_8087&PID_0AAA&REV_0002` {
		t.Errorf("the ambiguous identity was grouped into %q", group)
	}
}

// ---- classification --------------------------------------------------------

// usbNode builds a devnode with the compatible ids Windows writes for a USB
// device of the given base class, which is what the classification reads.
func usbNode(deviceID, instanceID, name, class, service string) registry.Devnode {
	node := devnode("USB", deviceID, instanceID, name)
	node.CompatibleIDs = fmt.Sprintf(
		`USB\Class_%s&SubClass_06&Prot_50|USB\Class_%s`, class, class)
	node.Service = service
	return node
}

func classified(t *testing.T, store *Store, id string) Device {
	t.Helper()
	device, ok := devices(t, store)[id]
	if !ok {
		t.Fatalf("device %s is not in the inventory", id)
	}
	return device
}

func TestAMassStorageDeviceIsTierOneStorage(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR"),
	}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `USB\VID_0781&PID_5581\0401B570C537`)
	if device.Category != "Storage" || device.Tier != 1 {
		t.Errorf("category/tier = %s/%d, want Storage/1", device.Category, device.Tier)
	}
	if !strings.Contains(device.ClassificationReason, "storage_identity") {
		t.Errorf("the reason should name the fact it rests on: %q",
			device.ClassificationReason)
	}
}

// The reference document's own example of a class conflicting with the apparent
// purpose, and the reason classification cannot be a single-field lookup.
func TestAHIDBesideStorageIsFlaggedRatherThanCalledAKeyboard(t *testing.T) {
	store := open(t)

	container := "{aaaaaaaa-0000-0000-0000-000000000001}"
	storage := usbNode("VID_1234&PID_5678", "0001", "USB Device", "08", "USBSTOR")
	storage.ContainerID = container
	human := usbNode("VID_1234&PID_5678&MI_01", "0002", "USB Input Device", "03", "HidUsb")
	human.ContainerID = container

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{storage, human}); err != nil {
		t.Fatal(err)
	}

	found := devices(t, store)
	if len(found) != 1 {
		t.Fatalf("the two interfaces share a ContainerID and should be one device: %v",
			found)
	}
	var device Device
	for _, only := range found {
		device = only
	}

	if device.Category != "PotentialOffensiveDevice" {
		t.Errorf("category = %s, want PotentialOffensiveDevice", device.Category)
	}
	if device.Tier != 1 {
		t.Errorf("tier = %d, want 1", device.Tier)
	}
	if !device.ReviewRequired {
		t.Error("a class that conflicts with the apparent purpose must be flagged")
	}
}

// The same pairing with a hub between the two, which is what a dock is. On the
// reference host this shape was every dock and every hub-and-ethernet adapter,
// and reporting each of them as a potentially offensive device is the kind of
// false positive that teaches an analyst to stop reading the flag.
func TestADockIsADockRatherThanAKeystrokeInjector(t *testing.T) {
	store := open(t)

	container := "{aaaaaaaa-0000-0000-0000-000000000002}"
	hub := usbNode("VID_0424&PID_7240", "0003", "USB Hub", "09", "usbhub3")
	hub.ContainerID = container
	network := usbNode("VID_0BDA&PID_8153", "0004", "Realtek USB GbE", "ff", "rtu53cx22x64")
	network.ClassGUID = "{4d36e972-e325-11ce-bfc1-08002be10318}"
	network.ContainerID = container
	human := usbNode("VID_0424&PID_7260&MI_01", "0005", "USB Input Device", "03", "HidUsb")
	human.ContainerID = container

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{hub, network, human}); err != nil {
		t.Fatal(err)
	}

	found := devices(t, store)
	if len(found) != 1 {
		t.Fatalf("the three interfaces share a ContainerID and should be one device: %v",
			found)
	}
	var device Device
	for _, only := range found {
		device = only
	}

	if device.Category == "PotentialOffensiveDevice" {
		t.Error("a hub with a keyboard and an ethernet port on it is a dock")
	}
	// Network rather than DockHubComposite, because the network rule outranks the
	// dock rule and is the more useful thing to say: a dock puts an ethernet
	// interface on the machine, and that is a route around the monitored network
	// path whatever the plastic around it is called.
	if device.Category != "Network" {
		t.Errorf("category = %s, want Network", device.Category)
	}
	// Still tier 1, and still visible: what passed through a dock was not seen,
	// which is a reason to look at it rather than a reason to hide it.
	if device.Tier != 1 {
		t.Errorf("tier = %d, want 1", device.Tier)
	}
	// The pairing is not thrown away. An analyst who wants the question asked
	// can find it, and a rule set that suppressed the observation entirely would
	// be rubber-stamping the ordinary reading.
	if !strings.Contains(device.ClassificationReason, "mixed_interfaces_behind_hub") {
		t.Errorf("the pairing behind the hub is not recorded: %q",
			device.ClassificationReason)
	}
	if strings.Contains(device.ClassificationReason, "hid_with_storage_or_network") {
		t.Errorf("the unqualified pairing should not be claimed: %q",
			device.ClassificationReason)
	}
}

// A phone that never appeared under USBSTOR must not be missed, which is what
// the negated condition on the mobile rule is for.
func TestAPortableDeviceWithoutStorageIsAMobileDevice(t *testing.T) {
	store := open(t)

	phone := devnode("USB", "VID_18D1&PID_4EE1", "PHONESERIAL01", "Android Phone")
	phone.Service = "WpdUsb"
	if err := store.LoadDevnodes("src-1", []registry.Devnode{phone}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `USB\VID_18D1&PID_4EE1\PHONESERIAL01`)
	if device.Category != "MobileDevice" || device.Tier != 1 {
		t.Errorf("category/tier = %s/%d, want MobileDevice/1",
			device.Category, device.Tier)
	}
}

// Windows attaches the portable-device file system driver to ordinary mass
// storage volumes. Reading it as MTP made every memory stick in the reference
// evidence claim a second interface it does not have.
func TestTheWPDFileSystemDriverIsNotReadAsMTP(t *testing.T) {
	store := open(t)

	stick := usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "WUDFWpdFs")
	if err := store.LoadDevnodes("src-1", []registry.Devnode{stick}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `USB\VID_0781&PID_5581\0401B570C537`)
	if device.Category != "Storage" {
		t.Errorf("category = %s, want Storage", device.Category)
	}
	if strings.Contains(device.ClassificationReason, "mtp_interface") {
		t.Errorf("WUDFWpdFs was read as MTP: %q", device.ClassificationReason)
	}
}

// The machine's own disk is reported, because it explains the file records that
// reach no removable device, and it is not ranked among the removable media.
func TestInternalStorageIsReportedButNotTierOne(t *testing.T) {
	store := open(t)

	internal := devnode("SCSI", "Disk&Ven_NVME&Prod_SAMSUNG", "5&1a89cd96&0&000000", "SAMSUNG")
	internal.ClassGUID = "{4d36e967-e325-11ce-bfc1-08002be10318}"
	if err := store.LoadDevnodes("src-1", []registry.Devnode{internal}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `SCSI\DISK&VEN_NVME&PROD_SAMSUNG\5&1A89CD96&0&000000`)
	if device.Category != "Storage" {
		t.Errorf("category = %s, want Storage", device.Category)
	}
	if device.Tier != 3 {
		t.Errorf("tier = %d, want 3: it never appeared on the USB bus", device.Tier)
	}
	// It has no serial and no vendor id, and flagging that would put the
	// machine's own disk in review on every case.
	if device.ReviewRequired {
		t.Errorf("internal storage should not be flagged for review: %q",
			device.ReviewReason)
	}
}

// A keyboard has no serial and never did. Flagged on every such device, the
// absence buries the cases where it means something: on the reference host
// eight of thirteen review flags were device classes behaving normally, and a
// flag raised on everything is a flag raised on nothing.
func TestAnAbsentSerialIsNotFlaggedOnAClassThatNeverHasOne(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		usbNode("VID_04F3&PID_0000", "5&19151cb4&0&0000", "keyboard", "03", "kbdhid"),
	}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `USB\VID_04F3&PID_0000\5&19151CB4&0&0000`)
	if !strings.Contains(device.ClassificationReason, "hid_interface") {
		t.Fatalf("the fixture is not a HID: %q", device.ClassificationReason)
	}
	if device.ReviewRequired {
		t.Errorf("a keyboard with no serial is flagged for review: %q",
			device.ReviewReason)
	}
}

// The exception is for the absence, not for the class. A serial two devices
// share is a finding whatever they are, and a keyboard is not exempt from it.
func TestADuplicateSerialIsStillFlaggedOnThatSameClass(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		usbNode("VID_04F3&PID_0001", "SHARED123", "keyboard", "03", "kbdhid"),
		usbNode("VID_04F3&PID_0002", "SHARED123", "keypad", "03", "kbdhid"),
	}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `USB\VID_04F3&PID_0001\SHARED123`)
	if !device.ReviewRequired {
		t.Fatal("a shared serial is not flagged")
	}
	if !strings.Contains(device.ReviewReason, "shared with another") {
		t.Errorf("review reason = %q, want the duplicate serial", device.ReviewReason)
	}
}

// A device nothing is known about is Unknown and flagged, rather than being
// quietly filed under the nearest category.
func TestADeviceWithNoRecognisableEvidenceIsUnknownAndFlagged(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("XYZBUS", "SomeThing", "A1B2C3D4", "mystery"),
	}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `XYZBUS\SOMETHING\A1B2C3D4`)
	if device.Category != "Unknown" {
		t.Errorf("category = %s, want Unknown", device.Category)
	}
	if !device.ReviewRequired {
		t.Error("an unknown class must raise review_required")
	}
}

// Reweighting changes placement and score. It must never change what was
// extracted, which facts were derived, or which category a rule assigned.
func TestAProfileChangesTheScoreAndNotTheCategory(t *testing.T) {
	general := open(t)
	if err := general.LoadDevnodes("src-1", []registry.Devnode{
		usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR"),
	}); err != nil {
		t.Fatal(err)
	}
	baseline := classified(t, general, `USB\VID_0781&PID_5581\0401B570C537`)

	weighted := open(t)
	rules, err := classify.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := weighted.LoadRules(rules, "exfiltration"); err != nil {
		t.Fatal(err)
	}
	if err := weighted.LoadDevnodes("src-1", []registry.Devnode{
		usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR"),
	}); err != nil {
		t.Fatal(err)
	}
	reweighted := classified(t, weighted, `USB\VID_0781&PID_5581\0401B570C537`)

	if reweighted.Category != baseline.Category || reweighted.Tier != baseline.Tier {
		t.Errorf("the profile changed the category: %s/%d became %s/%d",
			baseline.Category, baseline.Tier, reweighted.Category, reweighted.Tier)
	}
	if reweighted.Score <= baseline.Score {
		t.Errorf("the exfiltration profile should raise a storage device's score: "+
			"%v then %v", baseline.Score, reweighted.Score)
	}
}

// A short row would load NULLs into real columns, and absent evidence and a
// mis-shaped insert must never look the same.
func TestShortRowIsRejected(t *testing.T) {
	store := open(t)

	err := store.insert("emd_volume",
		"source_id,registry_path,key_name,volume_label,volume_serial_decimal", 1,
		func(add func(...any) error) error {
			return add("src-1", "path", "key")
		})
	if err == nil {
		t.Fatal("a row with too few values was accepted")
	}
	if !strings.Contains(err.Error(), "3 values for 5 columns") {
		t.Errorf("the error should say what was wrong: %v", err)
	}
}

// ---- the timeline ----------------------------------------------------------

// zone is a host with a one-hour daylight shift, so both seasonal readings of a
// wall clock exist and can be told apart.
//
// The transition months are part of what makes it one. A daylight bias on its
// own is not: Windows stores one for every zone that has ever had daylight
// saving, and marks the zones that do not take it by leaving these rules empty.
func zone() registry.TimeZone {
	return registry.TimeZone{
		KeyName: "W. Europe Standard Time", StandardName: "CET",
		BiasMinutes: -60, DaylightBiasMinutes: -60,
		StandardStartMonth: 10, DaylightStartMonth: 3,
		Found: true,
	}
}

// perthZone is the shape that caught this: a real daylight bias, and no
// transition rules to apply it under.
func perthZone() registry.TimeZone {
	return registry.TimeZone{
		KeyName: "W. Australia Standard Time", StandardName: "AWST",
		BiasMinutes: -480, DaylightBiasMinutes: -60, Found: true,
	}
}

func bagAt(path, local string) registry.ShellBag {
	moment, err := time.Parse("2006-01-02 15:04:05", local)
	if err != nil {
		panic(err)
	}
	return registry.ShellBag{
		Hive: "UsrClass", Profile: "Admin", Path: path, Name: path,
		DriveLetter: "E", Depth: 1, RegistryPath: `BagMRU\1`,
		ModifiedLocal: &moment,
	}
}

func timeline(t *testing.T, store *Store) []TimelineEntry {
	t.Helper()
	consolidate(t, store)
	entries, err := store.Timeline(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

// entriesFor returns the timeline entries of one kind, so a test can assert
// about the shape it cares about without depending on everything else present.
func entriesFor(entries []TimelineEntry, event string) []TimelineEntry {
	var matched []TimelineEntry
	for _, entry := range entries {
		if entry.Event == event {
			matched = append(matched, entry)
		}
	}
	return matched
}

// A host that does not change its clock gets one reading of a wall clock, not
// two — however large a daylight bias its zone definition carries.
//
// Western Australia abolished daylight saving in 2009, but Windows still stores
// DaylightBias -60 for W. Australia Standard Time and signals the absence by
// leaving the transition rules empty. Deciding from the bias alone reported
// every Perth host as seasonally ambiguous and offered a UTC+9 reading of every
// wall clock on it: 88 entries on USB-LENOVO-Multi-USBs, none of them supported
// by anything.
func TestAZoneWithNoTransitionRulesGivesOneReading(t *testing.T) {
	store := open(t)

	if err := store.LoadTimeZone("src-1", "ControlSet001", perthZone()); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadShellBags("src-3",
		[]registry.ShellBag{bagAt(`E:\Reports`, "2026-08-04 10:09:12")}); err != nil {
		t.Fatal(err)
	}

	items := entriesFor(timeline(t, store), "shell_item_modified")
	if len(items) != 1 {
		t.Fatalf("got %d shell item entries, want 1", len(items))
	}
	item := items[0]
	if item.TimeAmbiguous {
		t.Error("a host with no transition rules writes in only one season")
	}
	if item.TimeUTCAlt != nil {
		t.Errorf("a second reading was offered where no season exists: %v",
			item.TimeUTCAlt)
	}
	if item.TimeBasis != "standard_time" {
		t.Errorf("basis = %q, want standard_time", item.TimeBasis)
	}
	// UTC = local + bias, and the bias is the standard one alone.
	if got := wintime.Format(*item.TimeUTC); got != "2026-08-04T02:09:12.000000000Z" {
		t.Errorf("converted to %s, want the standard reading", got)
	}
}

// A wall clock sitting on a default the clock never left is not converted.
//
// The value was written by a device whose real-time clock had reset, using its
// own clock, which has no zone at all. Applying the examiner's host bias to it
// produces an instant that appears in no artefact: on a host east of UTC,
// 2000-01-01 00:30 becomes 1999-12-31, which reads as a genuine twentieth
// century date and sorts like one. The row keeps the value as recorded and says
// what it is.
func TestASentinelWallClockIsNotConvertedToAnInstant(t *testing.T) {
	store := open(t)

	if err := store.LoadTimeZone("src-1", "ControlSet001", perthZone()); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadShellBags("src-3", []registry.ShellBag{
		bagAt(`E:\Reset`, "2000-01-01 00:30:00"),
		bagAt(`E:\Real`, "2026-08-04 10:09:12"),
	}); err != nil {
		t.Fatal(err)
	}

	var sentinel, real TimelineEntry
	for _, entry := range entriesFor(timeline(t, store), "shell_item_modified") {
		if strings.Contains(entry.Path, "Reset") {
			sentinel = entry
		} else {
			real = entry
		}
	}

	if sentinel.TimeUTC != nil {
		t.Errorf("the placeholder was converted to %v; nothing should have been",
			sentinel.TimeUTC)
	}
	if sentinel.TimeLocal != "2000-01-01 00:30:00" {
		t.Errorf("the value must survive as recorded, got %q", sentinel.TimeLocal)
	}
	if sentinel.EpochDefault != "an unset device clock at 2000-01-01" {
		t.Errorf("epoch default = %q, want the row to say what it is",
			sentinel.EpochDefault)
	}
	if !strings.Contains(sentinel.TimeBasis, "a default no clock ever left") {
		t.Errorf("basis = %q, want it to say why there is no instant",
			sentinel.TimeBasis)
	}

	// The neighbouring row is converted as usual: suppressing the placeholder
	// must not suppress the wall clocks around it.
	if real.TimeUTC == nil {
		t.Fatal("a genuine wall clock lost its reading")
	}
	if real.EpochDefault != "" {
		t.Errorf("a genuine wall clock was named a default: %q", real.EpochDefault)
	}
}

// A UTC instant and a zoneless wall clock are both timestamped records and
// belong in one timeline. What must never happen is their being merged: a row
// has to say which of the two it rests on.
func TestAWallClockAndAUTCInstantAreKeptApart(t *testing.T) {
	store := open(t)

	if err := store.LoadTimeZone("src-1", "ControlSet001", zone()); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadEvents(map[string]string{"pnp.evtx": "src-2"},
		[]eventlog.Record{event(1, eventlog.KindInstall,
			`USB\VID_0781&PID_5581\0401B570C537`, at("2026-07-26T10:00:00Z"))},
	); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadShellBags("src-3",
		[]registry.ShellBag{bagAt(`E:\Reports`, "2026-07-26 12:00:00")}); err != nil {
		t.Fatal(err)
	}

	entries := timeline(t, store)

	installs := entriesFor(entries, "install")
	if len(installs) != 1 {
		t.Fatalf("got %d install entries, want 1", len(installs))
	}
	if installs[0].TimeBasis != "recorded_utc" {
		t.Errorf("an event log record carries a UTC instant, so its basis should "+
			"be recorded_utc, got %q", installs[0].TimeBasis)
	}
	if installs[0].TimeLocal != "" {
		t.Errorf("a UTC record has no local wall clock: %q", installs[0].TimeLocal)
	}
	if installs[0].TimeAmbiguous {
		t.Error("a recorded UTC instant is never seasonally ambiguous")
	}

	shellItems := entriesFor(entries, "shell_item_modified")
	if len(shellItems) != 1 {
		t.Fatalf("got %d shell item entries, want 1", len(shellItems))
	}
	item := shellItems[0]
	if item.TimeLocal != "2026-07-26 12:00:00" {
		t.Errorf("the wall clock must be carried exactly as recorded, got %q",
			item.TimeLocal)
	}
	if !item.TimeAmbiguous || item.TimeUTC == nil || item.TimeUTCAlt == nil {
		t.Fatalf("a wall clock in a zone that observes daylight saving has two "+
			"readings: ambiguous=%v utc=%v alt=%v",
			item.TimeAmbiguous, item.TimeUTC, item.TimeUTCAlt)
	}

	// Windows counts minutes west of UTC, so a bias of -60 is UTC+1 and the
	// standard reading of 12:00 local is 11:00 UTC. Daylight adds another hour.
	if got := item.TimeUTC.Format("15:04:05"); got != "11:00:00" {
		t.Errorf("standard reading = %s, want 11:00:00", got)
	}
	if got := item.TimeUTCAlt.Format("15:04:05"); got != "10:00:00" {
		t.Errorf("daylight reading = %s, want 10:00:00", got)
	}
}

// With no host time zone there is no offset to convert with, and a fabricated
// instant would be worse than none. The record still appears — it is evidence —
// and its basis says why it has no UTC reading.
func TestAWallClockWithNoHostTimeZoneHasNoUTCReading(t *testing.T) {
	store := open(t)

	if err := store.LoadShellBags("src-1",
		[]registry.ShellBag{bagAt(`E:\Reports`, "2026-07-26 12:00:00")}); err != nil {
		t.Fatal(err)
	}

	shellItems := entriesFor(timeline(t, store), "shell_item_modified")
	if len(shellItems) != 1 {
		t.Fatalf("got %d shell item entries, want 1: a record with no convertible "+
			"time is still a record", len(shellItems))
	}
	if shellItems[0].TimeUTC != nil {
		t.Errorf("time_utc = %v, want none: no host zone means no reading",
			shellItems[0].TimeUTC)
	}
	if !strings.Contains(shellItems[0].TimeBasis, "no host time zone") {
		t.Errorf("the basis must say why there is no reading, got %q",
			shellItems[0].TimeBasis)
	}
	// It is still placed, by reading the wall clock as though it were UTC,
	// because an entry dropped to the end of the timeline is an entry hidden.
	if shellItems[0].SortUTC == nil {
		t.Error("the entry has no position at all")
	}
}

// The timeline converts a SetupAPI wall clock with the same biases the loader
// used. Two conversions of one recorded time that disagree would put the same
// install in two places.
func TestTheTimelineAgreesWithTheStoredSetupAPIReadings(t *testing.T) {
	store := open(t)

	host := zone()
	if err := store.LoadTimeZone("src-1", "ControlSet001", host); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadSetupSections("src-1", []setupapi.Section{{
		SourceFile:       "setupapi.dev.log",
		Kind:             setupapi.KindInstall,
		Operation:        "Device Install (Hardware initiated)",
		DeviceInstanceID: `USB\VID_0781&PID_5581\0401B570C537`,
		LineNumber:       12,
		StartLocal:       "2026/07/26 12:00:00.123",
		StartUTC: wintime.SeasonalCandidates(
			at("2026-07-26T12:00:00.123Z"),
			host.BiasMinutes+host.StandardBiasMinutes, host.DaylightBiasMinutes),
	}}); err != nil {
		t.Fatal(err)
	}

	installs := entriesFor(timeline(t, store), "setupapi.install")
	if len(installs) != 1 {
		t.Fatalf("got %d setupapi entries, want 1", len(installs))
	}

	var stored, storedAlt *time.Time
	if err := store.db.QueryRow(
		"SELECT start_utc, start_utc_alt FROM setup_section").Scan(
		&stored, &storedAlt); err != nil {
		t.Fatal(err)
	}
	if stored == nil || installs[0].TimeUTC == nil ||
		!stored.Equal(*installs[0].TimeUTC) {
		t.Errorf("the timeline reads %v where the loader stored %v",
			installs[0].TimeUTC, stored)
	}
	if storedAlt == nil || installs[0].TimeUTCAlt == nil ||
		!storedAlt.Equal(*installs[0].TimeUTCAlt) {
		t.Errorf("the alternative reading is %v where the loader stored %v",
			installs[0].TimeUTCAlt, storedAlt)
	}
}

// Several channels report one arrival within a few seconds of each other. The
// timeline shows the transition once, with the count of records behind it, or
// one plug-in reads as four.
func TestOneArrivalIsOneTimelineEntry(t *testing.T) {
	store := open(t)

	identity := `USB\VID_0781&PID_5581\0401B570C537`
	if err := store.LoadEvents(map[string]string{"state.evtx": "src-1"},
		[]eventlog.Record{
			stateEvent(1, "Microsoft-Windows-Kernel-PnP/Configuration", 400,
				eventlog.KindConnect, identity, at("2026-07-26T10:00:00Z"), ""),
			stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1001,
				eventlog.KindConnect, identity, at("2026-07-26T10:00:02Z"), ""),
			stateEvent(3, "Microsoft-Windows-Ntfs/Operational", 142,
				eventlog.KindConnect, identity, at("2026-07-26T10:00:03Z"), ""),
			stateEvent(4, "Microsoft-Windows-StorageVolume/Operational", 1002,
				eventlog.KindDisconnect, identity, at("2026-07-26T10:30:00Z"), ""),
		}); err != nil {
		t.Fatal(err)
	}

	entries := timeline(t, store)

	connected := entriesFor(entries, "device_connected")
	if len(connected) != 1 {
		t.Fatalf("got %d device_connected entries, want 1: three channels "+
			"reporting one arrival is one arrival", len(connected))
	}
	// Four: the three arrivals and the departure that closes the window. It is
	// the count of records the window rests on, not the count of arrivals.
	if !strings.Contains(connected[0].Detail, "4 record(s)") {
		t.Errorf("the entry should say how many records support it: %q",
			connected[0].Detail)
	}
	if got := connected[0].TimeUTC.Format("15:04:05"); got != "10:00:00" {
		t.Errorf("the window opens at the earliest record, got %s", got)
	}
	if len(entriesFor(entries, "device_removed")) != 1 {
		t.Error("the removal should appear once")
	}

	// The raw arrival records are still in events.csv. Repeating them here
	// would put one plug-in on the timeline four times.
	for _, entry := range entries {
		if entry.Event == "connect" || entry.Event == "disconnect" {
			t.Errorf("entry %d repeats a state change the window already "+
				"describes", entry.EntryID)
		}
	}
}

// A device that appears only in the registry still has a timeline: the key
// write and the PnP dates are the only times the evidence offers for it, and a
// device with nothing on the timeline reads as a device that was never used.
func TestADeviceKnownOnlyFromTheRegistryStillHasEntries(t *testing.T) {
	store := open(t)

	node := usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR")
	arrival := at("2026-07-26T10:00:00Z")
	written := at("2026-07-26T10:05:00Z")
	node.Activity.LastArrivalDate = &arrival
	node.KeyLastWriteUTC = &written
	if err := store.LoadDevnodes("src-1", []registry.Devnode{node}); err != nil {
		t.Fatal(err)
	}

	entries := timeline(t, store)
	if len(entriesFor(entries, "last_arrival_date")) != 1 {
		t.Fatal("the stored arrival date is missing from the timeline")
	}
	if len(entriesFor(entries, "registry_key_written")) != 1 {
		t.Fatal("the key write is missing from the timeline")
	}

	// It is one stored state and not a history, and the row has to say so or a
	// device connected fifty times reads as a device connected once.
	meaning := entriesFor(entries, "last_arrival_date")[0].Meaning
	if !strings.Contains(meaning, "not a connection history") {
		t.Errorf("the meaning must say what the value is: %q", meaning)
	}
	for _, entry := range entries {
		if entry.DeviceLabel != "SanDisk" {
			t.Errorf("entry %d should name the device: label %q",
				entry.EntryID, entry.DeviceLabel)
		}
	}
}

// hashedSources registers real files as sources, so a view asked for the file
// a row came from has one to give. Loaders take a source id, and until the
// ledger carries that id there is no path behind it.
func hashedSources(t *testing.T, store *Store, artefacts ...string) map[string]string {
	t.Helper()

	directory := t.TempDir()
	ledger := provenance.NewLedger()
	ids := map[string]string{}
	for _, artefact := range artefacts {
		path := filepath.Join(directory, artefact)
		if err := os.WriteFile(path, []byte(artefact), 0o600); err != nil {
			t.Fatal(err)
		}
		source, err := ledger.AddSource(path, artefact)
		if err != nil {
			t.Fatal(err)
		}
		ids[artefact] = source.ID
	}
	if err := store.LoadLedger(ledger); err != nil {
		t.Fatal(err)
	}
	return ids
}

// Every timeline entry has to be followable back to the record it came from,
// which means a source, the file that source is, and something naming the place
// within it.
//
// The file is the part this once got wrong. Four of the five device_state arms
// carried an empty source_path and rendered as a row naming its control set and
// nothing else, beside a fifth arm from the same hive that named the file — so
// the report asserted a date and offered no way to go and check it. Three more
// arms put a registry key in the column, which is a locator and not a file.
func TestEveryTimelineEntryNamesTheFileItWasReadFrom(t *testing.T) {
	store := open(t)
	sources := hashedSources(t, store, "SYSTEM", "pnp.evtx", "UsrClass.dat")

	if err := store.LoadTimeZone(sources["SYSTEM"], "ControlSet001", zone()); err != nil {
		t.Fatal(err)
	}
	// Both the stored PnP dates and the key write, because they reach the
	// timeline down different arms and only one of them used to name a file.
	node := usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR")
	arrival := at("2026-07-26T09:00:00Z")
	written := at("2026-07-26T10:05:00Z")
	node.Activity.LastArrivalDate = &arrival
	node.KeyLastWriteUTC = &written
	if err := store.LoadDevnodes(sources["SYSTEM"],
		[]registry.Devnode{node}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadEvents(map[string]string{"pnp.evtx": sources["pnp.evtx"]},
		[]eventlog.Record{event(1, eventlog.KindInstall,
			`USB\VID_0781&PID_5581\0401B570C537`, at("2026-07-26T10:00:00Z"))},
	); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadShellBags(sources["UsrClass.dat"],
		[]registry.ShellBag{bagAt(`E:\Reports`, "2026-07-26 12:00:00")}); err != nil {
		t.Fatal(err)
	}

	entries := timeline(t, store)
	if len(entries) == 0 {
		t.Fatal("the timeline is empty")
	}
	if len(entriesFor(entries, "last_arrival_date")) != 1 {
		t.Fatal("the stored arrival date is not on the timeline to be checked")
	}
	for _, entry := range entries {
		if entry.SourceID == "" {
			t.Errorf("entry %d (%s) names no source", entry.EntryID, entry.Event)
		}
		if entry.SourcePath == "" {
			t.Errorf("entry %d (%s) names no file it was read from",
				entry.EntryID, entry.Event)
		}
		// A registry key is where in the hive, not which file. The column that
		// answers "what do I open" must not hold the answer to "where did you
		// look inside it" — that belongs in detail, and does.
		if strings.Contains(entry.SourcePath, `BagMRU\`) {
			t.Errorf("entry %d (%s) has a registry key in source_path: %q",
				entry.EntryID, entry.Event, entry.SourcePath)
		}
		if entry.Meaning == "" {
			t.Errorf("entry %d (%s) does not say what its time means",
				entry.EntryID, entry.Event)
		}
		if entry.TimeBasis == "" {
			t.Errorf("entry %d (%s) does not say what its time rests on",
				entry.EntryID, entry.Event)
		}
	}
}

// Every date the rule claims, and the nearby ones it must not.
//
// Table-driven against the macro because the window boundaries are the whole
// risk here: too narrow and a converted sentinel escapes, too wide and a real
// date is labelled. The two 2000 rows are values seen on live evidence.
func TestAClockDefaultIsNamedAndAnOrdinaryDateIsLeftAlone(t *testing.T) {
	store := open(t)

	for _, want := range []struct{ moment, name string }{
		{"1601-01-01 00:00:00", "FILETIME zero, 1601-01-01"},
		{"1970-01-01 00:00:00", "the Unix epoch, 1970-01-01"},
		{"1980-01-01 00:00:00", "the FAT epoch, 1980-01-01"},
		// The FAT epoch as a wall clock converted on a host east of UTC, which
		// is the form that equals no stored sentinel and set a real report's
		// evidence span to 1979.
		{"1979-12-31 14:00:00", "the FAT epoch, 1980-01-01"},
		// 2000-01-01 00:00:30 written by a device at UTC+11 thirty seconds
		// after its clock reset.
		{"1999-12-31 13:00:30", "an unset device clock at 2000-01-01"},
		// Three of eight jump list entries naming PDFs on one volume, minutes
		// apart in a single session three days after a reset. Nothing round
		// sits behind them — a sentinel repeats one value, and this is a clock
		// running — so they are named as the weaker thing they are.
		{"2000-01-04 04:05:02", "an unset device clock running on from 2000-01-01"},
		{"2000-01-04 05:39:58", "an unset device clock running on from 2000-01-01"},
		{"2000-01-04 17:54:20", "an unset device clock running on from 2000-01-01"},
		{"2000-01-31 23:59:59", "an unset device clock running on from 2000-01-01"},

		// And the dates the rule must not touch. February 2000 is where the
		// claim stops: a device left powered for a month is plausible, a flag
		// creeping across years of genuine dates is not.
		{"2000-02-01 00:00:00", ""},
		{"2000-06-15 09:30:00", ""},
		{"1999-12-30 09:00:00", ""},
		// Comfortably outside every window, and the ordinary case.
		{"2026-07-26 10:00:00", ""},
	} {
		var name string
		if err := store.db.QueryRow(
			`SELECT epoch_default_name(CAST(? AS TIMESTAMP))`,
			want.moment).Scan(&name); err != nil {
			t.Fatal(err)
		}
		if name != want.name {
			t.Errorf("epoch_default_name(%s) = %q, want %q",
				want.moment, name, want.name)
		}
	}
}

// A date that came from a clock's default is not a date the case reaches back
// to, whether the clock was a field that was never written or a device whose
// clock was never set.
//
// The exact stored sentinels are refused in wintime, which is why this survived
// so long: the value only becomes unrecognisable after it has passed that check
// and been converted. A shell item's wall clock of 1980-01-01 00:00, read on a
// host east of UTC, arrives as a date in December 1979 that equals no sentinel
// any more — and it set the head of a real report's evidence span.
func TestAnEpochDefaultIsNamedAndSetsNoEdgeOfTheEvidenceSpan(t *testing.T) {
	store := open(t)
	sources := hashedSources(t, store, "SYSTEM", "pnp.evtx", "UsrClass.dat")

	if err := store.LoadTimeZone(sources["SYSTEM"], "ControlSet001", zone()); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadDevnodes(sources["SYSTEM"], []registry.Devnode{
		usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadEvents(map[string]string{"pnp.evtx": sources["pnp.evtx"]},
		[]eventlog.Record{event(1, eventlog.KindInstall,
			`USB\VID_0781&PID_5581\0401B570C537`, at("2026-07-26T10:00:00Z"))},
	); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadShellBags(sources["UsrClass.dat"], []registry.ShellBag{
		bagAt(`E:\Reports`, "1980-01-01 00:00:00"),
		bagAt(`E:\Notes`, "2026-07-26 12:00:00"),
	}); err != nil {
		t.Fatal(err)
	}

	entries := timeline(t, store)
	var sentinels, real int
	var flagged *time.Time
	for _, entry := range entries {
		if entry.EpochDefault == "" {
			real++
			continue
		}
		sentinels++
		flagged = entry.SortUTC
		if !strings.Contains(entry.EpochDefault, "FAT epoch") {
			t.Errorf("entry %d names the wrong epoch: %q",
				entry.EntryID, entry.EpochDefault)
		}
	}
	// Kept, not dropped. The record is real and only its timestamp is not, and
	// deleting the row to fix the date would lose the evidence to tidy a number.
	if sentinels != 1 {
		t.Errorf("got %d entries flagged as an epoch default, want 1", sentinels)
	}
	if real == 0 {
		t.Fatal("no ordinary entry survived, so the fixture proves nothing")
	}

	summary, err := store.Summary()
	if err != nil {
		t.Fatal(err)
	}
	if summary.EpochDefaultEntries != 1 {
		t.Errorf("the summary counts %d epoch defaults, want 1",
			summary.EpochDefaultEntries)
	}
	if summary.EarliestUTC == nil {
		t.Fatal("the summary reports no evidence span at all")
	}
	if summary.EarliestUTC.Year() < 2000 {
		t.Errorf("the span begins at %v: a sentinel is setting its edge",
			summary.EarliestUTC)
	}
	// The flagged row does sort before everything else, so this fixture is one
	// where the exclusion is what produced the answer rather than one where the
	// sentinel was harmlessly in the middle and the test would pass regardless.
	if flagged == nil || !flagged.Before(*summary.EarliestUTC) {
		t.Errorf("the flagged entry sorts at %v, which is not before the span "+
			"start %v: this fixture does not exercise the exclusion",
			flagged, summary.EarliestUTC)
	}

	// And the console line has to agree with the report's head; they read the
	// same timeline and a run that said two different things about when the
	// evidence begins would be worse than one that said neither.
	_, _, _, earliest, _, err := store.TimelineSpan()
	if err != nil {
		t.Fatal(err)
	}
	if earliest == nil || !earliest.Equal(*summary.EarliestUTC) {
		t.Errorf("TimelineSpan starts at %v, the summary at %v",
			earliest, summary.EarliestUTC)
	}
}

// The machine's own root hub is not a dock. Everything on the machine hangs off
// it, so reading it as a composite device puts the motherboard in tier 1 and
// fills the significant timeline with it.
func TestARootHubIsNotADock(t *testing.T) {
	store := open(t)

	hub := devnode("USB", "ROOT_HUB30", "4&2e0b8fe4&0", "USB Root Hub (USB 3.0)")
	hub.Service = "USBHUB3"
	hub.CompatibleIDs = `USB\Class_09`
	if err := store.LoadDevnodes("src-1", []registry.Devnode{hub}); err != nil {
		t.Fatal(err)
	}

	device := classified(t, store, `USB\ROOT_HUB30\4&2E0B8FE4&0`)
	if device.Tier != 3 {
		t.Errorf("tier = %d, want 3: a root hub is part of the machine",
			device.Tier)
	}
	if device.Category == "DockHubComposite" {
		t.Error("the root hub was classified as a dock")
	}
	// Named, not silently dropped into the generic bucket: an analyst should be
	// able to see the rule that decided this.
	if !strings.Contains(device.ClassificationReason, "hub.internal") {
		t.Errorf("the reason should name the rule: %q", device.ClassificationReason)
	}
}

// prefetchRun builds a run that touched one volume, with its executable either
// on that volume or somewhere else entirely.
func prefetchRun(executable, devicePath, serial string, ranFrom bool,
	when time.Time) *prefetch.Run {

	run := &prefetch.Run{
		SourceFile: `C:\Windows\Prefetch\` + executable + "-DEADBEEF.pf",
		Executable: executable,
		Version:    "Win10",
		RunCount:   3,
		RunTimes:   []time.Time{when},
		Volumes: []prefetch.Volume{
			{DevicePath: devicePath, SerialHex: serial},
		},
		// A prefetch file lists the files the loader touched, and the
		// executable is among them wherever it lives. That is what says which
		// volume the programme itself ran from.
		Files: []string{devicePath + `\DOCUMENT.DOCX`},
	}
	if ranFrom {
		run.Files = append(run.Files, devicePath+`\`+executable)
	} else {
		run.ExecutablePath = `\DEVICE\HARDDISKVOLUME3\WINDOWS\` + executable
	}
	return run
}

// Two volumes matching the executable equally well leave the record unresolved.
//
// The header truncates an executable's name at 29 characters, so the prefix
// match exists precisely to recover a truncated name — and it is precisely
// there that two files on two volumes can match the same record. Picking the
// lexicographically first device path, which is what the view did, does not
// produce a doubtful answer: it produces a confident one, with ran_from set,
// a device reached and score weight attached to a volume chosen by sorting.
//
// The abstention has to be visible as well as correct, so the candidate view is
// checked in the same test: an empty result and a withheld answer are the same
// blank otherwise.
func TestTwoVolumesMatchingOneExecutableEquallyWellNameNoVolume(t *testing.T) {
	store := open(t)
	ran := at("2026-03-04T09:15:00Z")

	// One record, two volumes, and the executable's name on both. Nothing in
	// the file says which of them the loader ran it from.
	run := &prefetch.Run{
		SourceFile: `C:\Windows\Prefetch\COLLECTOR.EXE-DEADBEEF.pf`,
		Executable: "COLLECTOR.EXE",
		Version:    "Win10",
		RunCount:   1,
		RunTimes:   []time.Time{ran},
		Volumes: []prefetch.Volume{
			{DevicePath: `\VOLUME{AAAA}`, SerialHex: "00C9-0010"},
			{DevicePath: `\VOLUME{BBBB}`, SerialHex: "00C9-0020"},
		},
		Files: []string{
			`\VOLUME{AAAA}\COLLECTOR.EXE`,
			`\VOLUME{BBBB}\COLLECTOR.EXE`,
		},
	}
	if err := store.LoadPrefetchRuns([]*prefetch.Run{run},
		map[string]string{run.SourceFile: "src-pf"}); err != nil {
		t.Fatalf("loading the run: %v", err)
	}

	var resolved int
	if err := store.DB().QueryRow(
		`SELECT count(*) FROM v_prefetch_run_volume`).Scan(&resolved); err != nil {
		t.Fatalf("querying the resolved volume: %v", err)
	}
	if resolved != 0 {
		t.Errorf("v_prefetch_run_volume named a volume for a record that "+
			"matched two equally well, so the answer came from sorting rather "+
			"than from the evidence (%d rows)", resolved)
	}

	rows, err := store.DB().Query(
		`SELECT device_path, match_precision, is_best_match, best_candidates,
                chosen, outcome
         FROM v_prefetch_run_volume_candidate`)
	if err != nil {
		t.Fatalf("querying the candidates: %v", err)
	}
	defer rows.Close()

	var candidates int
	for rows.Next() {
		var path, precision, outcome string
		var best, chosen bool
		var count int
		if err := rows.Scan(&path, &precision, &best, &count, &chosen,
			&outcome); err != nil {
			t.Fatalf("scanning a candidate: %v", err)
		}
		candidates++
		if !best || count != 2 {
			t.Errorf("%s: is_best_match=%t best_candidates=%d, want both "+
				"volumes reported as equally good", path, best, count)
		}
		if chosen {
			t.Errorf("%s was marked as chosen while the view abstained", path)
		}
		if !strings.Contains(outcome, "more than one volume matched") {
			t.Errorf("%s: outcome = %q, which does not say why no volume was "+
				"named — an abstention nobody can read is a blank", path, outcome)
		}
	}
	if candidates != 2 {
		t.Errorf("got %d candidates, want 2: the volumes that were not chosen "+
			"have to be exported or the abstention cannot be checked", candidates)
	}
}

// A prefetch file names every volume the loader touched, so a programme sitting
// on the system disk that opened one file on a stick looks, in that table,
// exactly like a programme executed off the stick. On the reference host four
// executables reached the PATRIOT volume and one ran from it; reported without
// the distinction the report said four programmes ran from the device. The
// weaker reading is still recorded — it is a real finding — but it is a
// different one.
func TestAProgrammeThatReadAFileIsNotAProgrammeThatRanFromTheDevice(t *testing.T) {
	store := open(t)

	const devicePath = `\VOLUME{0000000000000000-00c90010}`
	ran := at("2026-07-26T09:00:00Z")

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: patriotID,
	}}); err != nil {
		t.Fatal(err)
	}
	// The bridge from a serial to a letter is a shell link recording both. With
	// no file record naming the volume, prefetch reaches no device at all.
	if err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "00C9-0010", "PATRIOT", `E:\notes.txt`),
	}); err != nil {
		t.Fatal(err)
	}

	runs := []*prefetch.Run{
		prefetchRun("COLLECTOR.EXE", devicePath, "00C9-0010", true, ran),
		prefetchRun("CONHOST.EXE", devicePath, "00C9-0010", false, ran),
	}
	sources := map[string]string{}
	for _, run := range runs {
		sources[run.SourceFile] = "src-1"
	}
	if err := store.LoadPrefetchRuns(runs, sources); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	rows, err := store.DB().Query(
		`SELECT executable, ran_from FROM v_prefetch_device_link`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	got := map[string]bool{}
	for rows.Next() {
		var executable string
		var ranFrom bool
		if err := rows.Scan(&executable, &ranFrom); err != nil {
			t.Fatal(err)
		}
		got[executable] = ranFrom
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Both reach the device. Only one ran from it.
	if len(got) != 2 {
		t.Fatalf("got %v, want both executables linked to the device", got)
	}
	if !got["COLLECTOR.EXE"] {
		t.Error("the executable listed on the volume did not read as running from it")
	}
	if got["CONHOST.EXE"] {
		t.Error("a programme that only opened a file on the volume was reported " +
			"as having run from it")
	}

	// And only the one that ran from it becomes the fact the classification
	// weighs, because that is the fact the weight was written for.
	var evidence string
	err = store.DB().QueryRow(`
        SELECT evidence FROM v_device_fact
        WHERE fact = 'executable_run_from_removable'`).Scan(&evidence)
	if err != nil {
		t.Fatalf("no executable_run_from_removable fact: %v", err)
	}
	if !strings.Contains(evidence, "COLLECTOR.EXE") ||
		strings.Contains(evidence, "CONHOST.EXE") {
		t.Errorf("the fact should rest on the programme that ran from the "+
			"device and no other: %q", evidence)
	}
}

// Prefetch is the only artefact Boobook reads that names a volume by serial and
// never by drive letter, so none of the letter-based routes can reach it. The
// serial itself is exact — the same number in the same spelling a shell link
// records — but the device is still a hop beyond the volume, which is what caps
// the route below confirmed.
func TestAPrefetchRunReachesItsDeviceByTheVolumeSerialAlone(t *testing.T) {
	store := open(t)

	const devicePath = `\VOLUME{0000000000000000-00c90010}`
	ran := at("2026-07-26T09:00:00Z")

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: patriotID,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "00C9-0010", "PATRIOT", `E:\notes.txt`),
	}); err != nil {
		t.Fatal(err)
	}

	run := prefetchRun("COLLECTOR.EXE", devicePath, "00C9-0010", true, ran)
	if err := store.LoadPrefetchRuns([]*prefetch.Run{run},
		map[string]string{run.SourceFile: "src-1"}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var device, confidence, detail string
	err := store.DB().QueryRow(`
        SELECT device_instance_id, confidence, detail FROM v_file_attribution
        WHERE route = 'volume_serial_prefetch'`).Scan(&device, &confidence, &detail)
	if err != nil {
		t.Fatalf("the prefetch route reached no device: %v", err)
	}
	if device != patriotID {
		t.Errorf("reached %q, want the Patriot device", device)
	}
	// No connection window places the device on the machine at that moment, so
	// the route earns probable and not strong. A serial that identifies a
	// volume does not date the device's presence.
	if confidence != "probable" {
		t.Errorf("confidence %q, want probable with no connection window", confidence)
	}
	if !strings.Contains(detail, "E") {
		t.Errorf("the detail should name the letter the chain went through: %q", detail)
	}
}

// MountedDevices holds the drive letter as it stands when the hive is read,
// and that can be behind the very evidence being explained. On
// USB-LENOVO-Multi-USBs the Velociraptor collector ran from PATRIOT one minute
// after it was plugged in as E:, and the SYSTEM hive still had E: pointing at a
// SanDisk unplugged three minutes earlier — the mount had not been flushed when
// the collector read the hive. Nothing was misparsed; the artefact was a minute
// stale, and a minute was enough to report the wrong device.
//
// The contradiction is checkable from what the row already carries. The shell
// link recorded the volume's own label beside its serial, and that label
// belongs to a different device than the letter reaches. Where the two
// disagree, the letter is the one asserting something it cannot know.
func TestAStaleDriveLetterIsCaughtByTheVolumesOwnLabel(t *testing.T) {
	store := open(t)

	const devicePath = `\VOLUME{0000000000000000-00c90010}`

	// The letter points at the SanDisk: the last device to hold E: before the
	// mount that has not yet reached the hive.
	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}
	// The volume the programme ran from is labelled PATRIOT, and Portable
	// Devices gives that label to the Patriot and not to the SanDisk.
	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "PATRIOT", DeviceInstanceID: patriotID},
		{FriendlyName: "TEST", DeviceInstanceID: sandiskID},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "00C9-0010", "PATRIOT", `E:\notes.txt`),
	}); err != nil {
		t.Fatal(err)
	}

	run := prefetchRun("COLLECTOR.EXE", devicePath, "00C9-0010", true,
		at("2026-08-04T02:28:19Z"))
	if err := store.LoadPrefetchRuns([]*prefetch.Run{run},
		map[string]string{run.SourceFile: "src-1"}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var contradicted bool
	var confidence, label string
	err := store.DB().QueryRow(`
        SELECT letter_contradicted, volume_confidence, volume_label
        FROM v_prefetch_device_link`).Scan(&contradicted, &confidence, &label)
	if err != nil {
		t.Fatalf("the prefetch chain reached no device: %v", err)
	}
	if !contradicted {
		t.Error("the letter names a device the volume's own label does not")
	}
	// The row is kept and demoted, not dropped and not swapped. The mapping is
	// real evidence, and choosing between two disagreeing routes belongs to the
	// analyst rather than to the query that found the disagreement.
	if confidence != "possible" {
		t.Errorf("volume confidence %q, want possible once contradicted", confidence)
	}
	if label != "PATRIOT" {
		t.Errorf("volume label %q, want the label that raised the contradiction", label)
	}

	var attributed, detail string
	err = store.DB().QueryRow(`
        SELECT confidence, detail FROM v_file_attribution
        WHERE route = 'volume_serial_prefetch'`).Scan(&attributed, &detail)
	if err != nil {
		t.Fatal(err)
	}
	// A connection window covering the execution cannot rescue a mapping that
	// names the wrong device, so this stays at possible where an uncontradicted
	// chain would reach strong or probable.
	if attributed != "possible" {
		t.Errorf("attribution confidence %q, want possible", attributed)
	}
	if !strings.Contains(detail, "contradicted") ||
		!strings.Contains(detail, "PATRIOT") {
		t.Errorf("the detail should say what disagrees and how: %q", detail)
	}

	// And the fact the classification weighs is not recorded against a device
	// the volume's own label says the programme did not run from.
	var facts int
	if err := store.DB().QueryRow(`
        SELECT count(*) FROM v_device_fact
        WHERE fact = 'executable_run_from_removable'`).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if facts != 0 {
		t.Errorf("got %d run-from fact(s); a contested chain scores none", facts)
	}
}

// activity_id is a row_number, and a row_number over a partial ordering is
// free to number tied rows either way round on each evaluation. Nothing maps
// the id back to the row afterwards: the attribution is consolidated into a
// table from one evaluation of v_file_activity and the timeline joins it
// against another, so a reshuffle between the two swaps two records'
// attributions silently.
//
// It stayed invisible while both rows reached the same device. It surfaced on
// USB-LENOVO-SANDISK the moment a route could tell them apart — three jump list
// entries for one PDF on E:, two from when a SanDisk held the letter and one
// from when PATRIOT did — and the timeline printed each against the other's
// device while file-attribution.csv named them correctly.
//
// The reshuffle itself does not reproduce here and this test does not try to
// force it: DuckDB is stable on a table this small, and a test that depended on
// it not being would pass or fail for reasons that have nothing to do with the
// code. What is checked is the property that makes the reshuffle impossible —
// that the id is a function of the row's content, so the time it is derived
// does not matter.
func TestOneFileOpenedTwiceKeepsEachOpeningsOwnIdentity(t *testing.T) {
	store := open(t)

	// Identical in artefact, path and drive letter — the whole of the old sort
	// key — and different in nothing else a reader can see but the time.
	var targets []FileTarget
	for index, moment := range []string{
		"2026-07-26T10:00:36Z", "2026-07-26T10:00:36Z", "2026-07-26T11:30:00Z",
		"2026-07-26T12:15:00Z", "2026-07-26T13:40:00Z",
	} {
		when := at(moment)
		target := removableTarget("E", "E607-9156", "FIELDWORK", `E:\twice.pdf`)
		target.Origin = "jump_list"
		target.SourceFile = fmt.Sprintf("opening%d.automaticDestinations-ms", index)
		target.LastAccessUTC = &when
		targets = append(targets, target)
	}
	if err := store.LoadFileTargets(targets); err != nil {
		t.Fatal(err)
	}

	// A window covering only the first opening, so the two rows differ in what
	// the attribution says about them and a swap has something to show.
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-07-26T10:00:06Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-07-26T10:01:44Z"), ""),
	)
	consolidate(t, store)

	// The consolidated table was numbered by one evaluation of v_file_activity
	// and every reader joins it against another. If the two disagree about
	// which row an id names, this join pairs a record with another record's
	// time — which is what reached the page.
	var mismatched int
	if err := store.DB().QueryRow(`
        SELECT count(*) FROM file_attribution f
        JOIN v_file_activity a USING (activity_id)
        WHERE f.recorded_utc IS DISTINCT FROM a.recorded_utc
           OR f.path <> a.path`).Scan(&mismatched); err != nil {
		t.Fatal(err)
	}
	if mismatched != 0 {
		t.Errorf("%d attribution row(s) landed on a different record than the "+
			"one they were computed from", mismatched)
	}

	var openings int
	if err := store.DB().QueryRow(
		`SELECT count(DISTINCT activity_id) FROM v_file_activity
         WHERE path = 'E:\twice.pdf'`).Scan(&openings); err != nil {
		t.Fatal(err)
	}
	if openings != 5 {
		t.Fatalf("got %d ids for five openings of one file, want 5", openings)
	}

	// And the id follows the content. Every column of the view is in the sort
	// key, so with artefact, path and letter equal across these five the order
	// is decided by the recorded time — which is what the old key left free.
	rows, err := store.DB().Query(
		`SELECT recorded_utc FROM v_file_activity
         WHERE path = 'E:\twice.pdf' ORDER BY activity_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var previous time.Time
	for rows.Next() {
		var when time.Time
		if err := rows.Scan(&when); err != nil {
			t.Fatal(err)
		}
		if when.Before(previous) {
			t.Errorf("activity ids run %s then %s: the id is not determined "+
				"by the row", previous, when)
		}
		previous = when
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

const genericID = `USBSTOR\Disk&Ven_Specific&Prod_STORAGE_DEVICE&Rev_0009\197860&0`
const kingstonID = `USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_0000\4CED&0`

// Three sticks holding E: in turn, which is the shape MountedDevices cannot
// describe. MountMgr frees a letter when the volume goes and hands an arriving
// volume the lowest free one, so E: names a different device at different
// moments of one uptime — no reboot involved — while the hive holds only the
// mapping as it stood at collection.
//
// A shell bag is the worst case for this, and the reason the route exists: it
// carries a letter and neither a serial nor a label, so the stale mapping is
// the only route that reaches it and it reaches the wrong device for two of the
// three. Asking instead who was attached at that moment answers all three.
func TestTheOnlyDeviceConnectedIsTheDeviceTheRecordWasOn(t *testing.T) {
	store := open(t)

	// The mapping as the hive holds it: the last device to have held E:.
	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, genericID, at("2026-08-04T02:07:06Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, genericID, at("2026-08-04T02:12:10Z"), ""),
		stateEvent(3, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, kingstonID, at("2026-08-04T02:13:28Z"), ""),
		stateEvent(4, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, kingstonID, at("2026-08-04T02:20:11Z"), ""),
		stateEvent(5, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T02:21:17Z"), ""),
		stateEvent(6, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-08-04T02:24:10Z"), ""),
	)

	first := at("2026-08-04T02:09:12Z")
	second := at("2026-08-04T02:14:06Z")
	third := at("2026-08-04T02:22:13Z")
	bag := func(path string, when time.Time) registry.ShellBag {
		return registry.ShellBag{
			Hive: "UsrClass", Profile: "User", Path: path, Name: path,
			DriveLetter: "E", Depth: 1, RegistryPath: `BagMRU\1`,
			KeyLastWriteUTC: &when,
		}
	}
	if err := store.LoadShellBags("src-1", []registry.ShellBag{
		bag(`E:\Generic`, first),
		bag(`E:\Kingston`, second),
		bag(`E:\SanDisk`, third),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	rows, err := store.DB().Query(`
        SELECT path, device_instance_id, confidence
        FROM v_file_attribution WHERE route = 'sole_connected_device'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	reached := map[string]string{}
	for rows.Next() {
		var path, device, confidence string
		if err := rows.Scan(&path, &device, &confidence); err != nil {
			t.Fatal(err)
		}
		// Never confirmed, however clean the window: a second device could have
		// been attached with nothing recording it, and there is no independent
		// link to the device here to catch that.
		if confidence != "probable" {
			t.Errorf("%s reached %q, want probable", path, confidence)
		}
		reached[path] = device
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		`E:\Generic`:  genericID,
		`E:\Kingston`: kingstonID,
		`E:\SanDisk`:  sandiskID,
	}
	for path, device := range want {
		if reached[path] != device {
			t.Errorf("%s reached %q, want %q", path, reached[path], device)
		}
	}
}

// Where two devices were attached at once the route abstains rather than
// picking one. This is the case the drive letter is actually needed for, and
// answering it from the windows alone would be a guess dressed as a reading.
func TestTwoDevicesConnectedAtOnceLeaveTheRouteSilent(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, kingstonID, at("2026-08-04T02:13:28Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, kingstonID, at("2026-08-04T02:20:11Z"), ""),
		// The overlap: a second stick arrives while the first is still there.
		stateEvent(3, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T02:16:11Z"), ""),
		stateEvent(4, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-08-04T02:19:15Z"), ""),
	)

	during := at("2026-08-04T02:17:07Z")
	if err := store.LoadShellBags("src-1", []registry.ShellBag{{
		Hive: "UsrClass", Profile: "User", Path: `E:\Either`, Name: `E:\Either`,
		DriveLetter: "E", Depth: 1, RegistryPath: `BagMRU\1`,
		KeyLastWriteUTC: &during,
	}}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var reached int
	if err := store.DB().QueryRow(`
        SELECT count(*) FROM v_file_attribution
        WHERE route = 'sole_connected_device'`).Scan(&reached); err != nil {
		t.Fatal(err)
	}
	if reached != 0 {
		t.Errorf("got %d row(s); two devices were connected and neither is the "+
			"only one", reached)
	}
}

// A connection window is an arrival and the next removal recorded for the same
// device, which is not the same as the device having stayed in the port. Three
// of the five reference collections carry a window of 262 days, and read as
// continuous attachment it made a stick that arrived in November 2025 the sole
// connected device for records in July 2026 — while the same file, a minute
// later, was attributed by its own label to the device that had just arrived.
// No laptop keeps a stick through 262 days and every reboot in them with no
// second arrival logged: the silence in the middle is the logging failing.
//
// The bound is on the distance from the arrival and not on the length of the
// window, because that is where the doubt lies. An hour after a recorded
// arrival is the strongest this route ever gets, however badly the far end of
// the same window is evidenced.
func TestAWindowOpenForMonthsStillOnlyPlacesTheDayItOpened(t *testing.T) {
	store := open(t)

	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2025-11-06T07:41:30Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-07-26T09:13:47Z"), ""),
	)

	soonAfter := at("2025-11-06T08:41:30Z")
	monthsLater := at("2026-07-26T08:27:56Z")
	near := removableTarget("E", "E607-9156", "FIELDWORK", `E:\near.pdf`)
	near.LastAccessUTC = &soonAfter
	far := removableTarget("E", "E607-9156", "FIELDWORK", `E:\far.pdf`)
	far.LastAccessUTC = &monthsLater
	if err := store.LoadFileTargets([]FileTarget{near, far}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	rows, err := store.DB().Query(`
        SELECT path FROM v_file_attribution
        WHERE route = 'sole_connected_device'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var reached []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			t.Fatal(err)
		}
		reached = append(reached, path)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(reached) != 1 || reached[0] != `E:\near.pdf` {
		t.Errorf("reached %v, want only the record within a day of the arrival",
			reached)
	}
}

// Windows keeps the last eight executions of a programme and overwrites the
// rest, so the count it stores and the number of times the timeline can place
// are different numbers. A row that showed only the second invites "it ran
// twice"; one that showed only the first invites four hundred entries that do
// not exist. Every execution row carries both.
func TestEveryExecutionSaysHowManyRunsItCannotAccountFor(t *testing.T) {
	store := open(t)

	run := &prefetch.Run{
		SourceFile:     `C:\Windows\Prefetch\RUNME.EXE-DEADBEEF.pf`,
		Executable:     "RUNME.EXE",
		ExecutablePath: `\DEVICE\HARDDISKVOLUME3\TOOLS\RUNME.EXE`,
		Version:        "Win10",
		RunCount:       400,
		RunTimes: []time.Time{
			at("2026-07-26T09:00:00Z"),
			at("2026-07-25T09:00:00Z"),
		},
	}
	if err := store.LoadPrefetchRuns([]*prefetch.Run{run},
		map[string]string{run.SourceFile: "src-1"}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	rows, err := store.DB().Query(`
        SELECT detail FROM v_timeline WHERE event = 'program_executed'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	entries := 0
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		entries++
		if !strings.Contains(detail, "400 execution(s)") {
			t.Errorf("an execution row did not carry the stored run count: %q", detail)
		}
		if !strings.Contains(detail, "of 2 recorded") {
			t.Errorf("an execution row did not say how many survive: %q", detail)
		}
	}
	// Both slots, not just the most recent: an earlier execution is a separate
	// event and dropping it would shorten the reported span of the case.
	if entries != 2 {
		t.Errorf("got %d execution entries, want 2", entries)
	}
}

// One registry key holds a whole MRU list and carries one write time, so that
// time dates the entry at position 0 and merely bounds every entry below it —
// each of which is older, by an amount nothing records.
//
// Reading it as each entry's own moment is not a small error. On
// USB-LENOVO-Multi-USBs the RecentDocs list was last written at 02:23:10 on
// 2026-08-04, two minutes into a SanDisk's connection, while the entry at
// position 21 was `PATRIOT (E:)` from a session eleven days earlier. Given the
// key's time, that entry fell inside the SanDisk's window and the drive letter
// route was lifted to probable on the strength of it — naming, at the report's
// strongest confidence, a stick the record has nothing to do with.
func TestAnMRUKeysWriteTimeDatesOnlyItsFirstEntry(t *testing.T) {
	store := open(t)

	written := at("2026-08-04T02:23:10Z")

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}
	// A window that covers the key's write time, and nothing else.
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T02:21:17Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-08-04T02:24:10Z"), ""),
	)

	entry := func(name string, position int) registry.MRUEntry {
		return registry.MRUEntry{
			Profile: "User", Source: "RecentDocs", Kind: "recent_doc",
			Name: name, Path: name + ".lnk", DriveLetter: "E",
			LetterFromName: true, Position: position,
			RegistryPath:    `Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`,
			KeyLastWriteUTC: &written,
		}
	}
	if err := store.LoadMRUEntries("src-1", []registry.MRUEntry{
		entry("newest", 0),
		entry("older", 3),
		// -1 is a list that recorded no order at all, which places an entry no
		// better than a position further down does.
		entry("unordered", -1),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	rows, err := store.DB().Query(`
        SELECT path, route, confidence
        FROM v_file_attribution WHERE artefact = 'mru'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	reached := map[string]map[string]string{}
	for rows.Next() {
		var path, route, confidence string
		if err := rows.Scan(&path, &route, &confidence); err != nil {
			t.Fatal(err)
		}
		if reached[path] == nil {
			reached[path] = map[string]string{}
		}
		reached[path][route] = confidence
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// The first entry is the one the write time is about, so the window places
	// it and the letter earns the lift.
	if got := reached["newest.lnk"]["drive_letter_mounted_devices_device_path"]; got != "probable" {
		t.Errorf("the entry the key's time dates reached %q, want probable", got)
	}
	// The rest are only known to be older than it. The letter still reaches a
	// device — the mapping is real — but nothing places that device when the
	// record was made, so the route stays where an unplaced letter belongs.
	for _, path := range []string{"older.lnk", "unordered.lnk"} {
		got := reached[path]["drive_letter_mounted_devices_device_path"]
		if got != "possible" {
			t.Errorf("%s reached %q, want possible: the key's write time bounds "+
				"this entry, it does not date it", path, got)
		}
	}

	// sole_connected_device is the route that must be silent here. It has no
	// independent link to the device at all — the window is the whole of the
	// evidence — so a moment the record does not have is the one thing it
	// cannot be given.
	if got, ok := reached["newest.lnk"]["sole_connected_device"]; !ok || got != "probable" {
		t.Errorf("the dated entry reached %q from the window route, want probable", got)
	}
	for _, path := range []string{"older.lnk", "unordered.lnk"} {
		if got, ok := reached[path]["sole_connected_device"]; ok {
			t.Errorf("%s was placed on a device at %q by a window it only "+
				"predates", path, got)
		}
	}

	// And the timeline has to say the same thing the attribution does.
	//
	// It did not. The bound was understood in v_file_activity, respected by
	// every attribution route, and then thrown away by the timeline arm, which
	// drew all three entries at the key's write time under one event name. So
	// file-attribution.csv correctly refused to place two of them on a device
	// while timeline.csv showed all three as files listed at 02:23:10 — a
	// reader working from the timeline, which is the document that tells the
	// story, saw an exact moment for an entry that could be eleven days older.
	//
	// The row stays on the timeline: it is real evidence and the bound is the
	// best time anyone has for it. The event name is what changes, because the
	// name is what a reader filters and counts on.
	events := map[string]string{}
	timelineRows, err := store.DB().Query(`
        SELECT path, event FROM v_timeline WHERE artefact = 'mru'`)
	if err != nil {
		t.Fatal(err)
	}
	defer timelineRows.Close()
	for timelineRows.Next() {
		var path, event string
		if err := timelineRows.Scan(&path, &event); err != nil {
			t.Fatal(err)
		}
		events[path] = event
	}
	if err := timelineRows.Err(); err != nil {
		t.Fatal(err)
	}

	if got := events["newest.lnk"]; got != "mru_key_written" {
		t.Errorf("the dated entry is on the timeline as %q, want mru_key_written: "+
			"what happened at that moment is the key being written", got)
	}
	for _, path := range []string{"older.lnk", "unordered.lnk"} {
		got, ok := events[path]
		if !ok {
			t.Errorf("%s is not on the timeline at all; a bounded record is "+
				"still evidence and must be kept", path)
			continue
		}
		if got != "file_listed_no_later_than" {
			t.Errorf("%s is on the timeline as %q, want "+
				"file_listed_no_later_than: the key's write time bounds this "+
				"entry and an event name that reads as an instant states a "+
				"moment the evidence does not have", path, got)
		}
	}
}

// A ShellBag key write is a key write, and the timeline has to call it one.
//
// v_file_activity has always said this plainly — the meaning reads "when
// Explorer last updated the view and not necessarily when the folder was
// opened" — and the timeline then relabelled the same row `folder_displayed`
// and drew it as an exact moment. The prose said one thing under an event name
// that said another, and the event name is what a reader filters, counts and
// puts in a statement.
//
// The distinction is not pedantry. Explorer writes a bag for view state — a
// column resized, a sort order changed, a window moved — as well as for a
// folder being displayed, and a BagMRU hierarchy can be updated by an
// operation that never showed the folder to anybody. That the location was
// known to the shell is the finding; that somebody looked at it at 12:00:00 is
// not. This is the same rule the shortcut work established: the event names
// what the timestamp evidences.
func TestAShellBagKeyWriteIsNamedAsAKeyWriteAndNotAsAFolderBeingDisplayed(t *testing.T) {
	store := open(t)
	sources := hashedSources(t, store, "UsrClass.dat")

	// bagAt carries only the shell item's wall clock; this test is about the
	// key's own write time, so it needs one.
	bag := bagAt(`E:\Reports`, "2026-07-26 12:00:00")
	keyWritten := at("2026-07-26T12:04:00Z")
	bag.KeyLastWriteUTC = &keyWritten
	if err := store.LoadShellBags(sources["UsrClass.dat"],
		[]registry.ShellBag{bag}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var event, meaning, basis string
	err := store.DB().QueryRow(`
        SELECT t.event, t.meaning, a.recorded_basis
        FROM v_timeline t
        JOIN v_file_activity a ON a.path = t.path AND a.artefact = t.artefact
        -- A bag also puts its shell item's own FAT wall clock on the timeline,
        -- which is a different time evidencing a different thing and is
        -- already named for what it is. This is about the key write.
        WHERE t.artefact = 'shell_bag' AND t.event <> 'shell_item_modified'`).
		Scan(&event, &meaning, &basis)
	if err != nil {
		t.Fatal(err)
	}

	if event == "folder_displayed" {
		t.Error("a bag key write is on the timeline as the folder being " +
			"displayed, which states a user action the key write does not " +
			"establish — Explorer writes a bag for view state as well")
	}
	if event != "shell_bag_key_written" {
		t.Errorf("event = %q, want shell_bag_key_written", event)
	}
	// The row is still an instant — the key really was written then — and the
	// meaning still has to carry the caveat about what that does and does not
	// prove. Renaming the event does not remove the need to explain it.
	if basis != "instant" {
		t.Errorf("recorded_basis = %q, want instant: the key write is a real "+
			"moment, it is just not a moment of somebody looking at a folder",
			basis)
	}
	if !strings.Contains(meaning, "not necessarily when the folder was opened") {
		t.Errorf("the row does not carry the caveat: %q", meaning)
	}
}

// sessionEvent builds one of the host's own records: a boot, a shutdown, a
// sleep. These name no device, which is the whole reason they need a helper of
// their own — every other record in these tests carries a device identity.
func sessionEvent(recordID uint64, ruleID string, eventID int64,
	when time.Time) eventlog.Record {

	return eventlog.Record{
		Channel:    "System",
		SourceFile: "state.evtx",
		RecordID:   recordID,
		EventID:    eventID,
		TimeUTC:    when,
		RuleID:     ruleID,
		Kind:       eventlog.KindSession,
	}
}

// A window with no removal recorded used to place the device for ever after the
// arrival. That is right while the evidence simply ends with the stick in the
// port — a collection taken mid-session looks exactly like that — and wrong the
// moment the host is recorded going off, because a shutdown with a device
// attached writes no departure record. The open window is not evidence the
// device stayed; it is evidence nothing recorded it leaving, and the shutdown
// says why.
//
// Until this was read the hole was large. On USB-LENOVO an arrival at
// 2025-11-06 07:41:30 with no removal went on covering every record for the
// following nine months, including 332 record-and-window pairings after the
// host had shut down forty seconds later.
func TestAnOpenWindowStopsPlacingOnceTheHostGoesOff(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}

	loadState(t, store,
		// An arrival with no removal after it, ever.
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T10:00:00Z"), ""),
		// The host goes off half an hour later and comes back ten minutes on.
		sessionEvent(2, "System:EventLog:6006", 6006, at("2026-08-04T10:30:00Z")),
		sessionEvent(3, "System:EventLog:6005", 6005, at("2026-08-04T10:40:00Z")),
	)

	before := at("2026-08-04T10:10:00Z")
	after := at("2026-08-04T11:00:00Z")
	bag := func(path string, when time.Time) registry.ShellBag {
		return registry.ShellBag{
			Hive: "UsrClass", Profile: "User", Path: path, Name: path,
			DriveLetter: "E", Depth: 1, RegistryPath: `BagMRU\1`,
			KeyLastWriteUTC: &when,
		}
	}
	if err := store.LoadShellBags("src-1", []registry.ShellBag{
		bag(`E:\while-attached`, before),
		bag(`E:\after-the-reboot`, after),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var stopped sql.NullTime
	if err := store.DB().QueryRow(`
        SELECT host_stopped_utc FROM v_connection
        WHERE ended_utc IS NULL AND started_utc IS NOT NULL`).Scan(&stopped); err != nil {
		t.Fatal(err)
	}
	if !stopped.Valid {
		t.Fatal("the open window was not bounded by the shutdown that explains it")
	}
	if want := at("2026-08-04T10:30:00Z"); !stopped.Time.Equal(want) {
		t.Errorf("host_stopped_utc = %v, want %v", stopped.Time, want)
	}

	confidence := map[string]string{}
	rows, err := store.DB().Query(`
        SELECT path, confidence FROM v_file_attribution
        WHERE route LIKE 'drive_letter_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var path, got string
		if err := rows.Scan(&path, &got); err != nil {
			t.Fatal(err)
		}
		confidence[path] = got
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// Inside the window and before the host went off: the letter reaches the
	// device and the window covers the moment, which is what the lift is for.
	if got := confidence[`E:\while-attached`]; got != "probable" {
		t.Errorf("a record made while the device was attached reached %q, "+
			"want probable", got)
	}
	// After the machine came back up. The letter still maps to the device and
	// the row is still reported — it is the lift that goes, not the row.
	if got := confidence[`E:\after-the-reboot`]; got != "possible" {
		t.Errorf("a record made after the host rebooted reached %q, want "+
			"possible: nothing says the device came back with it", got)
	}
}

// An unclean stop is reported by the boot that discovers it, so its record time
// is on the far side of the outage. Read as the moment the host went off — which
// is what v_host_stopped did until this was separated out — an open window was
// extended across the whole outage and went on placing the device on a machine
// that was switched off. A host down overnight placed a stick on itself all
// night.
//
// What the evidence supports is an interval: the host stopped after the last
// thing it recorded and before the boot that noticed. The window reaches the
// earlier end, because that is the last moment anything says the host was on.
//
// Latent on all five reference collections — none carries a 6008 or a 41, which
// is what a set of cleanly shut down hosts looks like — so only a fixture can
// hold it.
func TestAnUncleanStopBoundsAnOpenWindowRatherThanDatingIt(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}

	loadState(t, store,
		// An arrival with no removal after it, ever.
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T10:00:00Z"), ""),
		// The host says it is up. This is the last thing it records: the power
		// goes at some unrecorded moment after it.
		sessionEvent(2, "System:EventLog:6013", 6013, at("2026-08-04T10:20:00Z")),
		// Six hours later it comes back and reports what it found. Neither of
		// these two records dates the stop.
		sessionEvent(3, "System:EventLog:6005", 6005, at("2026-08-04T16:00:00Z")),
		sessionEvent(4, "System:EventLog:6008", 6008, at("2026-08-04T16:00:05Z")),
	)

	inside := at("2026-08-04T10:10:00Z")
	outage := at("2026-08-04T15:00:00Z")
	bag := func(path string, when time.Time) registry.ShellBag {
		return registry.ShellBag{
			Hive: "UsrClass", Profile: "User", Path: path, Name: path,
			DriveLetter: "E", Depth: 1, RegistryPath: `BagMRU\1`,
			KeyLastWriteUTC: &when,
		}
	}
	if err := store.LoadShellBags("src-1", []registry.ShellBag{
		bag(`E:\while-running`, inside),
		bag(`E:\during-the-outage`, outage),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var clean, after, before sql.NullTime
	if err := store.DB().QueryRow(`
        SELECT host_stopped_utc, host_stopped_after_utc, host_stopped_before_utc
        FROM v_connection
        WHERE ended_utc IS NULL AND started_utc IS NOT NULL`).
		Scan(&clean, &after, &before); err != nil {
		t.Fatal(err)
	}
	if clean.Valid {
		t.Errorf("host_stopped_utc = %v: an unclean stop is not a recorded "+
			"shutdown and must not be reported as one", clean.Time)
	}
	if want := at("2026-08-04T10:20:00Z"); !after.Valid || !after.Time.Equal(want) {
		t.Errorf("host_stopped_after_utc = %v, want %v: the last record before "+
			"the outage is the last moment the host is known to be running",
			after, want)
	}
	if want := at("2026-08-04T16:00:00Z"); !before.Valid || !before.Time.Equal(want) {
		t.Errorf("host_stopped_before_utc = %v, want %v: the boot that reported "+
			"the unclean stop is where the outage certainly ended", before, want)
	}

	var reaches sql.NullTime
	if err := store.DB().QueryRow(`
        SELECT places_until_utc FROM v_connection_placing`).Scan(&reaches); err != nil {
		t.Fatal(err)
	}
	if want := at("2026-08-04T10:20:00Z"); !reaches.Valid || !reaches.Time.Equal(want) {
		t.Errorf("places_until_utc = %v, want %v: the window reaches the last "+
			"evidence the host was on, not the boot that found it off",
			reaches, want)
	}

	confidence := map[string]string{}
	rows, err := store.DB().Query(`
        SELECT path, confidence FROM v_file_attribution
        WHERE route LIKE 'drive_letter_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var path, got string
		if err := rows.Scan(&path, &got); err != nil {
			t.Fatal(err)
		}
		confidence[path] = got
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if got := confidence[`E:\while-running`]; got != "probable" {
		t.Errorf("a record made while the host was recorded running reached "+
			"%q, want probable", got)
	}
	// The row is kept and the letter still reaches the device. What it loses is
	// the lift, because the host was off and nothing places the stick in it.
	if got := confidence[`E:\during-the-outage`]; got != "possible" {
		t.Errorf("a record timed inside the outage reached %q, want possible: "+
			"the host was not running and the window cannot cover it", got)
	}
}

// The interval an unclean stop supplies rests entirely on having identified the
// boot that reported it, and the nearest preceding start is only a candidate
// for that. Where the association cannot be made the bound is withheld — the
// record still says the host stopped uncleanly, and it stops saying when.
//
// Both shapes here were reported by a review as surviving the repair that
// separated the record time from the stop. Neither is exercised by the test
// above, whose 6005 sits five seconds before its 6008 and is unambiguously the
// reporting boot.
func TestAnUncleanStopWithNoEstablishedReportingBootBoundsNothing(t *testing.T) {
	// Each case ends with an arrival that nothing closes, an unclean stop
	// reported afterwards, and an event inside the restarted session — which is
	// the value the old fallback reached for.
	cases := []struct {
		name    string
		claim   string
		session []eventlog.Record
	}{{
		name: "the reporting boot was never logged",
		// A collection whose System channel begins part way through, or one
		// that has rolled. The nearest preceding start is the boot before the
		// outage, and the session it began ended cleanly — so drawing the
		// interval from it would place the stop a day early and on the far side
		// of a shutdown that was recorded perfectly well.
		claim: "the nearest preceding start belongs to a session that ended " +
			"cleanly, so it is not the boot that reported the unclean stop",
		session: []eventlog.Record{
			sessionEvent(2, "System:EventLog:6005", 6005, at("2026-08-03T08:00:00Z")),
			sessionEvent(3, "System:EventLog:6006", 6006, at("2026-08-03T18:00:00Z")),
			sessionEvent(4, "System:EventLog:6013", 6013, at("2026-08-04T10:20:00Z")),
			sessionEvent(5, "System:EventLog:6013", 6013, at("2026-08-04T15:59:00Z")),
			sessionEvent(6, "System:EventLog:6008", 6008, at("2026-08-04T16:00:05Z")),
		},
	}, {
		name: "no start was recorded at all",
		// The dangerous half. With no boot to be found the old view fell back
		// to the report's own time and took the last event before it — which is
		// a record from the session that had already restarted, so the interval
		// reached forwards past the outage it exists to bound and the window
		// went on placing the device on a machine that had been off.
		claim: "the last event before the report is from the restarted " +
			"session and cannot be the last moment of the one that died",
		session: []eventlog.Record{
			sessionEvent(4, "System:EventLog:6013", 6013, at("2026-08-04T10:20:00Z")),
			sessionEvent(5, "System:EventLog:6013", 6013, at("2026-08-04T15:59:00Z")),
			sessionEvent(6, "System:Microsoft-Windows-Kernel-Power:41", 41,
				at("2026-08-04T16:00:05Z")),
		},
	}}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			store := open(t)

			records := []eventlog.Record{
				stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
					eventlog.KindConnect, sandiskID, at("2026-08-04T10:00:00Z"), ""),
			}
			loadState(t, store, append(records, test.session...)...)
			consolidate(t, store)

			var associated bool
			var boot, after sql.NullTime
			if err := store.DB().QueryRow(`
                SELECT boot_associated, boot_utc, stopped_after_utc
                FROM v_host_unclean_stop`).
				Scan(&associated, &boot, &after); err != nil {
				t.Fatal(err)
			}
			if associated {
				t.Errorf("boot_associated is true with boot_utc = %v: %s",
					boot.Time, test.claim)
			}
			if after.Valid {
				t.Errorf("stopped_after_utc = %v: %s. A bound that cannot be "+
					"established is withheld, not guessed", after.Time, test.claim)
			}

			// The record is still evidence and is still reported. What it has
			// lost is the right to say when.
			var reported sql.NullTime
			var before sql.NullTime
			if err := store.DB().QueryRow(`
                SELECT reported_utc, stopped_before_utc
                FROM v_host_unclean_stop`).Scan(&reported, &before); err != nil {
				t.Fatal(err)
			}
			if want := at("2026-08-04T16:00:05Z"); !reported.Valid ||
				!reported.Time.Equal(want) {
				t.Errorf("reported_utc = %v, want %v: the record is kept "+
					"whatever can be made of it", reported, want)
			}
			// The report's own time is a true upper bound whatever else fails:
			// the host cannot have gone off after the record saying it had.
			if !before.Valid || !before.Time.Equal(reported.Time) {
				t.Errorf("stopped_before_utc = %v, want the report's own time "+
					"%v: it is the only upper bound left", before, reported.Time)
			}

			var windowAfter sql.NullTime
			var undated bool
			if err := store.DB().QueryRow(`
                SELECT host_stopped_after_utc, host_stopped_undated
                FROM v_connection
                WHERE ended_utc IS NULL AND started_utc IS NOT NULL`).
				Scan(&windowAfter, &undated); err != nil {
				t.Fatal(err)
			}
			if windowAfter.Valid {
				t.Errorf("the open window reaches %v: %s",
					windowAfter.Time, test.claim)
			}
			// The window is open and the reason is not that the host was never
			// recorded going off. It was; the record just cannot be dated, and
			// a report saying the evidence simply ends with the device attached
			// would be false in the direction that keeps the device attached.
			if !undated {
				t.Error("host_stopped_undated is false: an unclean stop was " +
					"reported after this window began, and the window must " +
					"not read as one the host was never recorded going off in")
			}
		})
	}
}

// The other half of the same claim. Where nothing records the host going off,
// an open window still places the device: the evidence ends while the stick is
// in the port, which is what a collection taken mid-session looks like, and the
// Velociraptor run on PATRIOT is exactly that shape on four of the five
// reference collections.
func TestAnOpenWindowStillPlacesWhereTheHostWasNeverRecordedGoingOff(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T10:00:00Z"), ""),
		// A boot before the arrival, so the collection does have session
		// records — the point is that none of them follows the window.
		sessionEvent(2, "System:EventLog:6005", 6005, at("2026-08-04T09:00:00Z")),
	)

	when := at("2026-08-04T11:00:00Z")
	if err := store.LoadShellBags("src-1", []registry.ShellBag{{
		Hive: "UsrClass", Profile: "User", Path: `E:\still-attached`,
		Name: "still-attached", DriveLetter: "E", Depth: 1,
		RegistryPath: `BagMRU\1`, KeyLastWriteUTC: &when,
	}}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var confidence string
	if err := store.DB().QueryRow(`
        SELECT confidence FROM v_file_attribution
        WHERE route LIKE 'drive_letter_%'`).Scan(&confidence); err != nil {
		t.Fatal(err)
	}
	if confidence != "probable" {
		t.Errorf("confidence = %q, want probable: no shutdown follows this "+
			"window, so nothing bounds it and the device was still attached "+
			"as far as the evidence goes", confidence)
	}
}

// MountedDevices holds the mapping as it stood when the hive was read and is
// dated by nothing. A record that carries a volume label carries what the
// volume called itself at the moment the record was made. Where the two
// disagree the record's own testimony is the better evidence, and the letter is
// reading a table that has moved on.
//
// This is the check prefetch already had as letter_contradicted, generalised to
// any record carrying both — a shell link states a label beside its letter, and
// since the drive-root captions were read, so does a RecentDocs entry. Before
// it, `PATRIOT (E:)` on USB-LENOVO-Multi-USBs reached PATRIOT by its label and
// the SanDisk by the stale letter, both at possible, and the timeline named
// neither: a tie that the evidence had in fact settled.
func TestARecordsOwnLabelOutranksAMountTableThatDisagrees(t *testing.T) {
	store := open(t)

	// The letter points at the SanDisk: the last device to hold E: before a
	// mount that has not reached the hive.
	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "PATRIOT", DeviceInstanceID: patriotID},
		{FriendlyName: "TEST", DeviceInstanceID: sandiskID},
	}); err != nil {
		t.Fatal(err)
	}
	// A time, so the record reaches the timeline at all — which is where the
	// tie was being lost. Nothing places either device at this moment, and that
	// is deliberate: the point is which device is named, not how confidently.
	opened := at("2026-08-04T02:23:10Z")
	target := removableTarget("E", "00C9-0010", "PATRIOT", `E:\notes.txt`)
	target.LastAccessUTC = &opened
	if err := store.LoadFileTargets([]FileTarget{target}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	routes := map[string]struct {
		confidence   string
		contradicted bool
	}{}
	rows, err := store.DB().Query(`
        SELECT route, confidence, contradicted FROM v_file_attribution`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var route, confidence string
		var contradicted bool
		if err := rows.Scan(&route, &confidence, &contradicted); err != nil {
			t.Fatal(err)
		}
		routes[route] = struct {
			confidence   string
			contradicted bool
		}{confidence, contradicted}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	letter, ok := routes["drive_letter_mounted_devices_device_path"]
	if !ok {
		t.Fatal("the letter route vanished; it is capped, not dropped — the " +
			"mapping is real evidence and choosing between two disagreeing " +
			"routes belongs to the analyst")
	}
	if !letter.contradicted {
		t.Error("the letter names a device the record's own label does not")
	}
	if letter.confidence != "possible" {
		t.Errorf("the contradicted letter reached %q, want possible",
			letter.confidence)
	}
	if label, ok := routes["volume_label_unique"]; !ok {
		t.Error("the label route reached nothing")
	} else if label.contradicted {
		t.Error("the label route cannot contradict itself")
	}

	// The point of the whole thing: the timeline names one device, and it is
	// the one the record's own label named.
	var named, confidence string
	if err := store.DB().QueryRow(`
        SELECT device_key, confidence FROM v_timeline
        WHERE category = 'file' AND path = 'E:\notes.txt'
        LIMIT 1`).Scan(&named, &confidence); err != nil {
		t.Fatal(err)
	}
	// device_key is the normalised, upper-cased form of the instance id.
	if !strings.EqualFold(named, patriotID) {
		t.Errorf("the timeline named %q, want the device the label named (%q)",
			named, patriotID)
	}
	// Named, not promoted. Nothing places either device at this moment, so the
	// answer is still only possible — what changed is that there is one.
	if confidence != "possible" {
		t.Errorf("confidence = %q, want possible: breaking the tie is not the "+
			"same as strengthening the evidence", confidence)
	}
}

// The contradiction has to be a disagreement, not merely two routes firing. A
// letter can map to several devices across control sets and routes, and if any
// of them is the device the label names then the two agree and nothing is
// contradicted — capping the letter there would demote a corroboration.
func TestALetterThatReachesTheLabelledDeviceIsNotContradicted(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: patriotID,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "PATRIOT", DeviceInstanceID: patriotID},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "00C9-0010", "PATRIOT", `E:\notes.txt`),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var contradicted int
	if err := store.DB().QueryRow(`
        SELECT count(*) FROM v_file_attribution WHERE contradicted`).
		Scan(&contradicted); err != nil {
		t.Fatal(err)
	}
	if contradicted != 0 {
		t.Errorf("%d routes were marked contradicted where the letter and the "+
			"label reach the same device", contradicted)
	}
}

// "The label says X" is only a statement where the label names one device.
// Where two devices on a host carry the same label there is no X, so there is
// nothing for the letter to disagree with and the contradiction must not fire —
// otherwise a reused label would silently demote every letter on the host.
//
// Two things stop it, and this test passes on the first: v_device_volume_link
// only offers a label link where the label is unique among the host's portable
// devices, so a shared label reaches no device at all and the contradiction
// never gets a candidate. The devices = 1 guard in v_letter_contradicted is the
// second, and is belt and braces — it matters if a label route that does not
// enforce uniqueness is ever added. The test is here for the behaviour rather
// than for either mechanism, so it holds whichever of them is doing the work.
func TestASharedLabelContradictsNothing(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}
	// Two devices formatted with the same name, which is what happens when
	// somebody labels a batch of sticks.
	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{FriendlyName: "BACKUP", DeviceInstanceID: patriotID},
		{FriendlyName: "BACKUP", DeviceInstanceID: genericID},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadFileTargets([]FileTarget{
		removableTarget("E", "00C9-0010", "BACKUP", `E:\notes.txt`),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var contradicted int
	if err := store.DB().QueryRow(`
        SELECT count(*) FROM v_file_attribution WHERE contradicted`).
		Scan(&contradicted); err != nil {
		t.Fatal(err)
	}
	if contradicted != 0 {
		t.Errorf("%d routes were contradicted by a label two devices share, "+
			"which names neither of them", contradicted)
	}
}

// viewsSource is the embedded views.sql with its line endings normalised.
//
// The embedded copy rather than a file read: it is the string the store
// actually executes, so a test cannot pass against a file the binary does not
// use. Normalised because git checks the file out with CRLF on Windows, and a
// test searching for a semicolon followed by a newline passed in a working
// tree written by an editor and would have failed on a fresh clone.
func viewsSource() string {
	return strings.ReplaceAll(viewsSQL, "\r\n", "\n")
}

// viewBodies splits views.sql into one entry per view definition.
func viewBodies(t *testing.T) map[string]string {
	t.Helper()
	sql := viewsSource()

	bodies := map[string]string{}
	for index := 0; ; {
		start := strings.Index(sql[index:], "\nCREATE VIEW ")
		if start < 0 {
			break
		}
		start += index + 1
		rest := sql[start+len("CREATE VIEW "):]
		name, _, ok := strings.Cut(rest, " ")
		if !ok {
			t.Fatalf("unparseable view definition at offset %d", start)
		}
		end := strings.Index(sql[start:], ";\n")
		if end < 0 {
			t.Fatalf("%s: view definition does not end", name)
		}
		bodies[name] = sql[start : start+end]
		index = start + end
	}
	if len(bodies) == 0 {
		t.Fatal("no views were found, so this test asserts nothing")
	}
	return bodies
}

// One record has one time, and one answer to what that time means, wherever an
// analyst reads it.
//
// This is the invariant the LNK correction broke. The rule that a shortcut's
// header timestamps describe its target and not any opening of it was applied
// in v_file_activity — correctly, and with the reasoning written down — and
// two older views went on reaching past it into file_target for
// target_written_utc. So on USB-LENOVO-Multi-USBs one shortcut appeared in
// timeline.csv as an opening at 10:10:31, in letter-activity.csv at 09:38:34
// with nothing to say the two were the same record, and in volumes.csv as the
// moment a stick's activity began — a document written on another machine
// before that stick was ever plugged into this host.
//
// Nothing failed. Every test passed, both views were internally consistent,
// and the defect was found by a reviewer reading four CSVs side by side.
//
// So the rule is now structural: the columns that carry a raw artefact
// timestamp may be named by the view that reads that artefact's own table and
// by v_file_activity, which is where the judgement lives. Everything else asks
// v_file_activity. A view that recomputes the answer is a second
// implementation of it, and the two diverge on the first correction to either
// — which is not a hypothetical, it is the bug this test is named after.
//
// This cannot fail as written. It fails the moment somebody adds a consumer
// that bypasses the contract, which is the only moment it needs to.
func TestOnlyTheCanonicalViewDecidesWhatARecordsTimeMeans(t *testing.T) {
	// The raw timestamps an artefact stores, before anything decides which of
	// them dates the record.
	rawTimes := []string{
		"target_written_utc",
		"target_accessed_utc",
		"target_created_utc",
		"source_modified_utc",
		"last_access_utc",
	}

	// The views entitled to name them. v_file_activity because it is where the
	// choice between them is made; the rest because they export one artefact's
	// own stored fields, which is a different job from saying when a record
	// was used — a reader of file-targets.csv is looking at what the .lnk
	// holds, not at a conclusion drawn from it.
	permitted := map[string]bool{
		"v_file_activity": true,
		"v_file_target":   true,
	}

	for name, body := range viewBodies(t) {
		if permitted[name] {
			continue
		}
		for _, column := range rawTimes {
			if strings.Contains(body, column) {
				t.Errorf("%s names %s directly. Read recorded_utc and "+
					"recorded_basis from v_file_activity instead: a view that "+
					"picks its own timestamp out of the raw record is deciding "+
					"again what that record's time means, and will disagree "+
					"with the timeline the first time either is corrected.",
					name, column)
			}
		}
	}
}

// And the same thing proved rather than asserted structurally: load one record
// and read it back everywhere an analyst would.
//
// The structural test above catches a new view reaching past the contract. This
// catches the contract being applied and then contradicted — a consumer that
// reads recorded_utc correctly and renders it under a name or a meaning that
// says something else.
func TestOneRecordTellsOneStoryInEveryExport(t *testing.T) {
	store := open(t)

	targetWritten := at("2026-08-04T01:38:34Z")
	shortcutWritten := at("2026-08-04T02:10:31Z")

	link := removableTarget("E", "E607-9156", "TEST", `E:\report.docx`)
	link.TargetWrittenUTC = &targetWritten
	link.SourceModifiedUTC = &shortcutWritten
	link.LinkContext = "recent"
	if err := store.LoadFileTargets([]FileTarget{link}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	// Every view an analyst would reach for, and the column each calls the
	// record's time.
	for _, source := range []struct{ view, column, where string }{
		{"v_file_activity", "recorded_utc", "artefact = 'shell_link'"},
		{"v_letter_activity", "recorded_utc", "artefact = 'shell_link'"},
		{"v_timeline", "time_utc",
			"artefact = 'shell_link' AND event <> 'shell_item_modified'"},
		// The report shows an unattributed record here; a record that reached a
		// device goes to v_report_file_activity. Both read the same column of
		// the same view, and this fixture has no device.
		{"v_report_file_unattributed", "recorded_utc", "artefact = 'shell_link'"},
	} {
		var got time.Time
		query := "SELECT " + source.column + " FROM " + source.view +
			" WHERE " + source.where
		if err := store.DB().QueryRow(query).Scan(&got); err != nil {
			t.Errorf("%s: %v", source.view, err)
			continue
		}
		if !got.Equal(shortcutWritten) {
			t.Errorf("%s.%s = %v, want %v — the same record is dated "+
				"differently depending on which output is read, and an "+
				"analyst comparing two of these files has no way to tell "+
				"they are looking at one thing",
				source.view, source.column, got, shortcutWritten)
		}
	}

	// The volume summary is the other half of what went wrong: it reported the
	// target's write time as when activity on the volume began, so a stick's
	// use was dated to a document written on another machine.
	var firstInteraction *time.Time
	var undated int
	err := store.DB().QueryRow(`
        SELECT first_interaction_utc, undated_records
        FROM v_removable_volume`).Scan(&firstInteraction, &undated)
	if err != nil {
		t.Fatal(err)
	}
	if firstInteraction == nil || !firstInteraction.Equal(shortcutWritten) {
		t.Errorf("the volume's first interaction is %v, want %v",
			firstInteraction, shortcutWritten)
	}
	if undated != 0 {
		t.Errorf("undated_records = %d, want 0: this record carries an "+
			"interaction time", undated)
	}
	// The target's own write time is still on the record, in the export that
	// is about the record rather than about the volume.
	var kept time.Time
	if err := store.DB().QueryRow(
		`SELECT target_written_utc FROM v_file_target`).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if !kept.Equal(targetWritten) {
		t.Errorf("the target's write time is %v, want %v — it is real evidence "+
			"about the file and must not be lost in fixing what it was used for",
			kept, targetWritten)
	}
}

// Every exported view has to state an order, and that order has to be total.
//
// SQL guarantees nothing about row order without an ORDER BY, and DuckDB scans
// in parallel, so a view without one is reproducible by luck. A view *with* one
// that leaves ties is no better: a row_number over a tie may number the tied
// rows either way round on each evaluation, which is how entry_id came to name
// a different timeline row on a second run of the same binary over the same
// evidence.
//
// This matters because the manifest records a SHA-256 per output file. An
// examiner who reruns a case and gets different hashes has to explain why, and
// "the rows come out in a different order each time" is a bad answer in a
// report. A citation like "timeline.csv entry 776" that resolves to a different
// record on a rerun is worse.
//
// As written this cannot fail for a view that already has an ORDER BY — it is
// here to fail the moment a new export is added without one.
func TestEveryExportedViewStatesAnOrder(t *testing.T) {
	sql := viewsSource()

	for _, spec := range exports {
		start := strings.Index(sql, "CREATE VIEW "+spec.view+" AS")
		if start < 0 {
			t.Errorf("%s: exported but not defined in views.sql", spec.view)
			continue
		}
		end := strings.Index(sql[start:], ";\n")
		if end < 0 {
			t.Errorf("%s: view definition does not end", spec.view)
			continue
		}
		if !strings.Contains(sql[start:start+end], "ORDER BY") {
			t.Errorf("%s is exported to %s with no ORDER BY, so its row order "+
				"is whatever the scan happened to produce", spec.view, spec.name)
		}
	}
}

// Stating an order is not the same as stating a total one.
//
// TestEveryExportedViewStatesAnOrder holds the exported views and asks only
// that an ORDER BY is present. The views the report reads are not exported, so
// they were outside that test entirely — and an order that ties is invisible to
// it in any case, because the clause is there.
//
// This was live. v_report_file_unattributed ordered by drive letter and path,
// and USB-LENOVO-SANDISK has two MRU lists recording one executable under one
// letter: ComDlg32\OpenSavePidlMRU\* and ComDlg32\OpenSavePidlMRU\exe. Same
// letter, same path, same recorded time — nothing left to sort on. Two runs of
// one binary over one evidence root rendered those two records in either order,
// so report.html differed between them and so did its SHA-256 in the manifest.
// Every CSV was byte-identical, which is why it survived the reproducibility
// work that fixed the same defect in the exports: nothing anybody was diffing
// showed it.
//
// The fixture below is that pair, reduced to what makes it tie. The assertion
// is on the ordering key rather than on the rendered order, because a view can
// be stable within one process and unstable across two — which is exactly what
// makes this class of defect so hard to see.
func TestTwoRecordsAlikeInEveryOrderingColumnStillSortInAFixedOrder(t *testing.T) {
	store := open(t)
	written := at("2026-07-26T08:37:17Z")

	// One file, one letter, one moment, recorded by two different MRU lists.
	// Nothing but the list name distinguishes them, and the list name was not
	// in either view's ORDER BY.
	entry := func(source string) registry.MRUEntry {
		return registry.MRUEntry{
			Profile: "User", Source: source, Kind: "open_save",
			Name: "collector.exe", Path: `This PC\E:\collector.exe`,
			DriveLetter: "E", Position: 0,
			RegistryPath: `Software\Microsoft\Windows\CurrentVersion\Explorer\` +
				source,
			KeyLastWriteUTC: &written,
		}
	}
	if err := store.LoadMRUEntries("src-1", []registry.MRUEntry{
		entry(`ComDlg32\OpenSavePidlMRU\*`),
		entry(`ComDlg32\OpenSavePidlMRU\exe`),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	for _, view := range []string{"v_report_file_unattributed"} {
		body := viewBodies(t)[view]
		if body == "" {
			t.Fatalf("%s is not defined in views.sql", view)
		}
		keys := orderingKeys(body)
		if len(keys) == 0 {
			t.Errorf("%s has no ORDER BY, so its row order is whatever the "+
				"scan produced", view)
			continue
		}

		var rows, distinct int
		if err := store.DB().QueryRow(fmt.Sprintf(
			`SELECT count(*), count(DISTINCT (%s)) FROM %s`,
			strings.Join(keys, ", "), view)).Scan(&rows, &distinct); err != nil {
			t.Fatalf("%s: %v", view, err)
		}
		if rows == 0 {
			// Without this the test passes by asserting nothing, which is the
			// failure mode of every fixture that stopped matching its view.
			t.Fatalf("%s returned no rows, so this test proves nothing about it",
				view)
		}
		if distinct < rows {
			t.Errorf("%s: %d rows share only %d distinct ordering keys (%s). "+
				"Rows that tie come back in whatever order the scan produced, "+
				"so the rendered report — and its hash in the manifest — "+
				"changes between two runs over one evidence root.",
				view, rows, distinct, strings.Join(keys, ", "))
		}
	}

	// v_report_file_activity has the same shape of ordering and the same
	// exposure — it ends on a path, and one file opened twice at one recorded
	// moment ties there too. It is per device, so reaching it needs a whole
	// attributed case rather than two registry values, and the claim made
	// about it here is correspondingly weaker and is said to be: its key must
	// end on the row identity. This is a structural check, not a demonstration.
	body := viewBodies(t)["v_report_file_activity"]
	keys := orderingKeys(body)
	if len(keys) == 0 || keys[len(keys)-1] != "activity_id" {
		t.Errorf("v_report_file_activity orders by %v, whose last key is not "+
			"the row identity, so two records alike in device, confidence, "+
			"time and path sort in whatever order the scan produced", keys)
	}
}

// orderingKeys pulls the expressions out of a view's trailing ORDER BY, with
// the direction and null placement stripped and any qualifier dropped, so they
// can be selected from outside the view.
func orderingKeys(body string) []string {
	at := strings.LastIndex(body, "\nORDER BY ")
	if at < 0 {
		return nil
	}

	var keys []string
	depth := 0
	current := strings.Builder{}
	flush := func() {
		key := strings.TrimSpace(current.String())
		current.Reset()
		for _, suffix := range []string{" DESC", " ASC", " NULLS LAST", " NULLS FIRST"} {
			for strings.HasSuffix(key, suffix) {
				key = strings.TrimSpace(strings.TrimSuffix(key, suffix))
			}
		}
		if key == "" {
			return
		}
		// A qualified name refers to a table inside the view; from outside, the
		// column is exposed under its bare name.
		if !strings.ContainsAny(key, "( ") {
			if _, after, ok := strings.Cut(key, "."); ok {
				key = after
			}
		}
		keys = append(keys, key)
	}
	for _, r := range body[at+len("\nORDER BY "):] {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == ',' && depth == 0:
			flush()
			continue
		}
		current.WriteRune(r)
	}
	flush()
	return keys
}

// The same discipline one level down. A joined list assembled by string_agg
// with no ORDER BY inside it is a value that changes between runs, which puts a
// different string in a CSV and a different hash in the manifest for evidence
// that has not changed at all.
//
// Nine of these were shipping. The worst read "exposes 2 interface classes:
// vendor_specific_interface, biometric_interface" on one run and the two names
// the other way round on the next.
func TestEveryAggregatedListStatesAnOrder(t *testing.T) {
	sql := viewsSource()

	for index := 0; ; {
		start := strings.Index(sql[index:], "string_agg(")
		if start < 0 {
			break
		}
		start += index
		// Walk to the matching bracket: these calls nest, and stopping at the
		// first ')' would miss the ORDER BY of anything with a coalesce in it.
		depth, end := 0, start
		for i := strings.Index(sql[start:], "(") + start; i < len(sql); i++ {
			if sql[i] == '(' {
				depth++
			} else if sql[i] == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		call := sql[start : end+1]
		if !strings.Contains(call, "ORDER BY") {
			line := strings.Count(sql[:start], "\n") + 1
			t.Errorf("views.sql:%d: string_agg with no ORDER BY, so the joined "+
				"value differs between runs: %s", line,
				strings.Join(strings.Fields(call), " "))
		}
		index = end + 1
	}
}

// A shortcut's three header timestamps all describe the target file as it stood
// when the shortcut was written. None of them is when the target was opened.
//
// The time that says that is the shortcut's own last-written time, because the
// shell rewrites the .lnk on every open. Boobook was reading the header write
// time and putting the row on the timeline as file_opened, which on
// USB-LENOVO-Multi-USBs reported three documents as opened from a stick at
// 01:38 UTC — twenty minutes before that stick was plugged in. They were
// authored on another machine and copied across, and 01:38 is when they were
// last written there. The shortcuts' own mtimes are 02:10 and 02:11, inside the
// window the device was attached.
//
// Nothing caught it because every fixture set LastAccessUTC on its shell links,
// which real shell links never carry: that field is a jump list's DestList
// time. The fallback path was the one real evidence always takes and the one
// nothing tested.
func TestAShortcutIsTimedByItsOwnWriteAndNotByItsTargets(t *testing.T) {
	store := open(t)

	targetWritten := at("2026-08-04T01:38:34Z")
	shortcutWritten := at("2026-08-04T02:10:31Z")

	link := removableTarget("E", "E607-9156", "TEST", `E:\report.docx`)
	link.TargetWrittenUTC = &targetWritten
	link.SourceModifiedUTC = &shortcutWritten
	// From the Recent folder, which is what licenses reading the mtime as an
	// opening: the shell maintains those links and rewrites them on each open.
	// See TestAShortcutOutsideAShellMaintainedFolderIsNotAnOpening for the
	// other side of it.
	link.LinkContext = "recent"
	if err := store.LoadFileTargets([]FileTarget{link}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var recorded time.Time
	var meaning, event string
	err := store.DB().QueryRow(`
        SELECT a.recorded_utc, a.recorded_meaning, t.event
        FROM v_file_activity a
        JOIN v_timeline t ON t.path = a.path AND t.artefact = a.artefact
        WHERE a.artefact = 'shell_link' AND t.event <> 'shell_item_modified'`).
		Scan(&recorded, &meaning, &event)
	if err != nil {
		t.Fatal(err)
	}

	if !recorded.Equal(shortcutWritten) {
		t.Errorf("the row is placed at %v, want the shortcut's own write time %v "+
			"— the target's write time describes the file, not the opening",
			recorded, shortcutWritten)
	}
	if event != "file_opened" {
		t.Errorf("event = %q, want file_opened: the shortcut's own write time "+
			"is when the target was opened", event)
	}
	if !strings.Contains(meaning, "the shortcut itself was last written") {
		t.Errorf("the row does not say which time it rests on: %q", meaning)
	}
}

// The same mtime, from a folder the shell does not maintain, is not an opening.
//
// A Recent shortcut is rewritten by the shell every time its target is opened,
// which is what makes its mtime an interaction. A Desktop shortcut, a pinned
// Quick Launch item or a link a user copied is written when the user did that
// — made it, renamed it, retargeted it, pinned it, copied it. Reading that as
// "the target was opened then" asserts an interaction on the strength of a file
// existing, and it is the same class of error as reading the header write time:
// a real timestamp, attached to the wrong claim.
//
// The row is kept and the event is named for what the time evidences, which is
// the rule this whole area now follows.
func TestAShortcutOutsideAShellMaintainedFolderIsNotAnOpening(t *testing.T) {
	store := open(t)

	shortcutWritten := at("2026-08-04T02:10:31Z")
	link := removableTarget("E", "E607-9156", "TEST", `E:\report.docx`)
	link.SourceModifiedUTC = &shortcutWritten
	link.LinkContext = "desktop"
	if err := store.LoadFileTargets([]FileTarget{link}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var basis, event, meaning string
	err := store.DB().QueryRow(`
        SELECT a.recorded_basis, t.event, a.recorded_meaning
        FROM v_file_activity a
        JOIN v_timeline t ON t.path = a.path AND t.artefact = a.artefact
        WHERE a.artefact = 'shell_link' AND t.event <> 'shell_item_modified'`).
		Scan(&basis, &event, &meaning)
	if err != nil {
		t.Fatal(err)
	}

	if basis != "link_written" {
		t.Errorf("recorded_basis = %q, want link_written for a desktop shortcut",
			basis)
	}
	if event == "file_opened" {
		t.Error("a desktop shortcut's own write time is reported as the target " +
			"being opened; the shell does not rewrite it on open, so nothing " +
			"here evidences an opening at that moment")
	}
	if event != "shortcut_written" {
		t.Errorf("event = %q, want shortcut_written", event)
	}
	if !strings.Contains(meaning, "created, edited, pinned or copied") {
		t.Errorf("the row does not say why its time is weaker here: %q", meaning)
	}
}

// Where the shortcut's own time is not available — a collector that did not
// preserve it, or a link recovered from somewhere with no file behind it — the
// header write time is all there is. The row stays, because a shortcut is
// evidence its target was opened whatever time it carries, and it must not be
// called an opening: a row placed at the target's write time and named
// file_opened puts a person at a machine at a moment nothing says they were
// there.
func TestATargetsWriteTimeIsNotAnOpening(t *testing.T) {
	store := open(t)

	targetWritten := at("2026-08-04T01:38:34Z")
	link := removableTarget("E", "E607-9156", "TEST", `E:\report.docx`)
	link.TargetWrittenUTC = &targetWritten
	// No SourceModifiedUTC: this is the collection that lost it.
	if err := store.LoadFileTargets([]FileTarget{link}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var event, meaning string
	var recorded time.Time
	err := store.DB().QueryRow(`
        SELECT t.event, t.meaning, t.time_utc
        FROM v_timeline t
        WHERE t.artefact = 'shell_link' AND t.event <> 'shell_item_modified'`).
		Scan(&event, &meaning, &recorded)
	if err != nil {
		t.Fatal(err)
	}

	// Kept: the record is real and only the interaction time is missing.
	if !recorded.Equal(targetWritten) {
		t.Errorf("the row moved to %v; the header time is all this record has",
			recorded)
	}
	if event == "file_opened" {
		t.Error("a row timed by the target's own write time is named as an " +
			"opening, which places a person at a moment nothing evidences")
	}
	if event != "target_file_written" {
		t.Errorf("event = %q, want target_file_written", event)
	}
	if !strings.Contains(meaning, "not any opening of it") {
		t.Errorf("the row does not say the time is not an opening: %q", meaning)
	}
}

// And it must not be checked against a connection window either.
//
// Naming the event honestly fixed what a reader sees and left the arithmetic
// alone: the same target write time was still handed to every route that asks
// "was a device attached at this moment?". That question cannot be asked of it.
// A target's write time is the file's own metadata and may have been set on a
// different computer entirely, before the file was ever copied to the volume —
// which is precisely the shape of the evidence that started all of this, three
// documents authored elsewhere and copied to a stick.
//
// So a window covering that time corroborates nothing, and lifting the letter
// route to probable on the strength of it manufactures confidence out of a
// coincidence between this host's uptime and somebody else's clock.
//
// The row is kept and the device is still reached — by the letter, which is
// real evidence. What it does not get is the lift.
func TestATargetsWriteTimeInsideAConnectionWindowDoesNotLiftConfidence(t *testing.T) {
	store := open(t)

	if err := store.LoadMountEntries("src-1", []registry.MountEntry{{
		ValueName: `\DosDevices\E:`, Kind: registry.MountDriveLetter,
		DriveLetter: "E", TargetKind: registry.TargetDevicePath,
		DeviceInstanceID: sandiskID,
	}}); err != nil {
		t.Fatal(err)
	}

	// The stick is on the machine from 02:00 to 02:40, and the target's write
	// time is 02:30 — comfortably inside. A route reading that time as the
	// record's own moment finds the window covering it and says probable.
	loadState(t, store,
		stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
			eventlog.KindConnect, sandiskID, at("2026-08-04T02:00:00Z"), ""),
		stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
			eventlog.KindDisconnect, sandiskID, at("2026-08-04T02:40:00Z"), ""),
	)

	targetWritten := at("2026-08-04T02:30:00Z")
	// No label, so the letter is the only route, and no interaction time
	// survives, so the header write time is all this record has.
	link := removableTarget("E", "", "", `E:\report.docx`)
	link.TargetWrittenUTC = &targetWritten
	if err := store.LoadFileTargets([]FileTarget{link}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var places bool
	var confidence, reason string
	err := store.DB().QueryRow(`
        SELECT a.recorded_places, f.confidence, f.detail
        FROM v_file_activity a
        JOIN file_attribution f ON f.activity_id = a.activity_id
        WHERE a.artefact = 'shell_link' AND f.route LIKE 'drive_letter%'`).
		Scan(&places, &confidence, &reason)
	if err != nil {
		t.Fatal(err)
	}

	if places {
		t.Error("a target's write time is treated as placing the record on " +
			"this host, so every connection window will be checked against a " +
			"timestamp that may have been written on another machine")
	}
	if confidence != "possible" {
		t.Errorf("confidence = %q, want possible: the window covers the "+
			"target's write time and that is not evidence about this record",
			confidence)
	}
	if !strings.Contains(reason, "another computer") &&
		!strings.Contains(reason, "predate") {
		t.Errorf("the row does not say why the window was not checked: %q", reason)
	}
}

// A jump list is one file per application holding many entries, so the file's
// own write time dates the newest entry and not this one — the same shape as an
// MRU key, and the same reason it must not be used per entry. What a jump list
// does carry per entry is the DestList access time, which is the application
// recording that it opened the target. That one is a real interaction time and
// stays the preferred reading.
func TestAJumpListEntryPrefersItsOwnRecordedAccess(t *testing.T) {
	store := open(t)

	opened := at("2026-08-04T02:20:00Z")
	targetWritten := at("2026-08-04T01:38:34Z")
	containerWritten := at("2026-08-04T02:29:00Z")

	entry := removableTarget("E", "E607-9156", "TEST", `E:\budget.xlsx`)
	entry.Origin = "jump_list"
	entry.LastAccessUTC = &opened
	entry.TargetWrittenUTC = &targetWritten
	// Set, and must be ignored: it belongs to the file, not to this entry.
	entry.SourceModifiedUTC = &containerWritten
	if err := store.LoadFileTargets([]FileTarget{entry}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var recorded time.Time
	var event string
	err := store.DB().QueryRow(`
        SELECT t.time_utc, t.event FROM v_timeline t
        WHERE t.artefact = 'jump_list' AND t.event <> 'shell_item_modified'`).
		Scan(&recorded, &event)
	if err != nil {
		t.Fatal(err)
	}
	if !recorded.Equal(opened) {
		t.Errorf("the entry is placed at %v, want its own recorded access %v",
			recorded, opened)
	}
	if event != "file_opened" {
		t.Errorf("event = %q, want file_opened", event)
	}
}

// "No USB attachment was observed" and "this is the machine's own disk" are
// different statements, and the second was being made from the first. Every
// storage identity with no usb_attached fact was labelled internal_bus, so a
// collection missing a control set, a hive that failed to replay, or a devnode
// walk that was refused all produced an affirmative finding about a bus nobody
// had read. That is the standing rule — absence is absence — failing in the
// one place a negative was being written down as a fact.
//
// Latent on every reference collection, where all six such identities are
// enumerated on SCSI and are exactly what the old label said they were.
func TestStorageOnNoObservedBusIsNotCalledAnInternalDisk(t *testing.T) {
	store := open(t)

	// A disk known only from a portable-device node, which is the shape an
	// incomplete collection leaves behind: it is storage by its service, and
	// nothing in the evidence says which bus carried it.
	unknown := devnode("WPDBUSENUM", `Disk&Ven_Unknown&Prod_Media`, "8&2a1f9c&0",
		"Unknown media")
	unknown.Service = "disk"

	// And the machine's own disk beside it, which is affirmatively enumerated
	// on a fixed bus and must go on being reported as one.
	internal := devnode("SCSI", `Disk&Ven_NVMe&Prod_SAMSUNG`, "5&1a89cd96&0&000000",
		"SAMSUNG MZVLB512")
	internal.Service = "disk"

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{unknown, internal}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	// Keyed by device and fact, because the two arms must be mutually
	// exclusive: a device carrying both would be scored twice and would be
	// saying two different things about one bus.
	held := map[string]bool{}
	rows, err := store.DB().Query(`
        SELECT physical_device_id, fact FROM v_device_fact
        WHERE fact IN ('internal_bus', 'usb_attachment_not_observed')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var device, fact string
		if err := rows.Scan(&device, &fact); err != nil {
			t.Fatal(err)
		}
		held[fact+" on "+device] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for claim, want := range map[string]bool{
		"internal_bus on " + strings.ToUpper(internal.DeviceInstanceID):                true,
		"usb_attachment_not_observed on " + strings.ToUpper(unknown.DeviceInstanceID):  true,
		"internal_bus on " + strings.ToUpper(unknown.DeviceInstanceID):                 false,
		"usb_attachment_not_observed on " + strings.ToUpper(internal.DeviceInstanceID): false,
	} {
		if held[claim] != want {
			t.Errorf("%q is %v, want %v", claim, held[claim], want)
		}
	}

	// Both stay out of the removable set. The unknown is excluded because
	// nothing affirms a USB attachment, not because anything affirms a disk —
	// under-claiming, which is the direction this has to fail in.
	var removable int
	if err := store.DB().QueryRow(
		`SELECT count(*) FROM v_removable_device`).Scan(&removable); err != nil {
		t.Fatal(err)
	}
	if removable != 0 {
		t.Errorf("%d removable devices, want none: neither of these was seen "+
			"arriving over USB", removable)
	}
}

// A serial is unique within a vendor's range and nowhere else. The
// cross-enumerator route said so in its own comment and then joined on the
// serial alone, so a generic, cloned or firmware-default value merged two
// vendors' devices into one — and grouping is transitive, so the merge became
// the answer everywhere downstream.
//
// The host's own evidence settles it: one physical device has one product key
// per enumerator, so a serial appearing under two of them is being shared
// rather than owned. The link is kept and reported, because two devices with
// one serial is itself worth seeing; it stops asserting they are one device.
func TestOneSerialOnTwoProductsIsACandidateRatherThanAMerge(t *testing.T) {
	store := open(t)

	// Two vendors, one unremarkable serial, no ContainerID to arbitrate.
	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USBSTOR", `Disk&Ven_Alpha&Prod_Stick`, "05022016&0", "Alpha stick"),
		devnode("SCSI", `Disk&Ven_Alpha&Prod_Stick`, "05022016&1", "Alpha disk"),
		devnode("USBSTOR", `Disk&Ven_Beta&Prod_Card`, "05022016&2", "Beta card"),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var method string
	var asserts bool
	err := store.DB().QueryRow(`
        SELECT method, asserts_same_device FROM v_device_link
        WHERE method LIKE 'serial_across%' LIMIT 1`).Scan(&method, &asserts)
	if err != nil {
		t.Fatalf("the serial link is not reported at all: %v", err)
	}
	if asserts {
		t.Errorf("%s asserts one device from a serial two products report",
			method)
	}

	// And the merge did not happen: three identities, three devices.
	var devices int
	if err := store.DB().QueryRow(
		`SELECT count(DISTINCT physical_device_id) FROM v_device_group`).
		Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if devices != 3 {
		t.Errorf("%d physical devices, want 3: a shared serial merged them",
			devices)
	}
}

// The other direction, and the one that matters more: the route still groups
// the ordinary case. A stick's USB node and its USBSTOR node report one serial
// and are one device, and on a host where the ContainerID is a placeholder this
// is the only route that reaches that answer.
func TestOneSerialOnOneProductStillNamesOneDevice(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USB", `VID_0781&PID_5581`, "0401B570C537", "SanDisk Ultra"),
		devnode("USBSTOR", `Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00`,
			"0401B570C537&0", "SanDisk Ultra USB Device"),
	}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var devices int
	if err := store.DB().QueryRow(
		`SELECT count(DISTINCT physical_device_id) FROM v_device_group`).
		Scan(&devices); err != nil {
		t.Fatal(err)
	}
	if devices != 1 {
		t.Errorf("%d physical devices, want 1: the stick's two identities no "+
			"longer reach each other", devices)
	}
}

// A portable-device node's FriendlyName is the volume's label, and where a
// volume has no label Windows writes the drive path into it instead. That is a
// mount point rather than a device: it moves between devices within one uptime,
// and two sticks that each held D: end up with the same name.
//
// Reported from real evidence. The file activity section showed two cards both
// headed "D:\" and a chip row reading "D:\ D:\", with the vendor and product
// sitting unread in the instance id underneath. It does not appear on any
// reference collection because every stick in them carries a volume label.
func TestADrivePathIsNotADeviceName(t *testing.T) {
	store := open(t)

	// A generic vendor's stick: no FriendlyName on the USBSTOR node, and a
	// DeviceDesc that fits every disk on the host.
	disk := devnode("USBSTOR", `Disk&Ven_Vendor&Prod_Product&Rev_2.00`,
		"9207ABCDEF&0", "")
	disk.DeviceDesc = "@disk.inf,%disk_devdesc%;Disk drive"
	disk.ContainerID = "{aabbccdd-1111-2222-3333-444455556666}"

	volume := devnode("SWD", "WPDBUSENUM",
		`_??_USBSTOR#Disk&Ven_Vendor&Prod_Product&Rev_2.00#9207ABCDEF&0#`,
		`D:\`)
	volume.ContainerID = disk.ContainerID

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{disk, volume}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var label string
	if err := store.DB().QueryRow(
		`SELECT device_label FROM v_device_label`).Scan(&label); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(label, `D:`) {
		t.Errorf("device_label = %q: a drive letter is where the device was "+
			"mounted, not what it is", label)
	}
	// And what it falls back to is the vendor and product the key carries,
	// which is in the evidence and identifies the thing, rather than the INF
	// template's "Disk drive".
	if label != "Vendor Product" {
		t.Errorf("device_label = %q, want the vendor and product from the "+
			"device id", label)
	}
}

// A name two devices share is not a name. Two sticks of one model carry one
// description, and the report headed both cards with it and listed the pair as
// one chip repeated -- which reads as a rendering fault rather than as two
// devices. Only a real serial disambiguates: a generated instance id would put
// forty characters of key in place of a name on every root hub on the host.
func TestTwoDevicesOfOneModelAreToldApartByTheirSerials(t *testing.T) {
	store := open(t)

	first := devnode("USBSTOR", `Disk&Ven_Vendor&Prod_Product&Rev_2.00`,
		"9207AAAA&0", "")
	second := devnode("USBSTOR", `Disk&Ven_Vendor&Prod_Product&Rev_2.00`,
		"9207BBBB&0", "")

	if err := store.LoadDevnodes("src-1",
		[]registry.Devnode{first, second}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	labels := map[string]bool{}
	rows, err := store.DB().Query(`SELECT device_label FROM v_device_label`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			t.Fatal(err)
		}
		labels[label] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if len(labels) != 2 {
		t.Errorf("two devices of one model share %d label(s): %v",
			len(labels), labels)
	}
	for label := range labels {
		if !strings.Contains(label, "Vendor Product") {
			t.Errorf("%q no longer names the model", label)
		}
	}
}

// A trailing instance index is stripped from the enumerators that append one,
// and from nothing else.
//
// The macro removed a trailing "&<digits>" from every non-generated tail, on
// the reasoning that it is Windows numbering the instance. That is true on
// USBSTOR — and it is the value every downstream join matches on, so applying
// it to a serial a device genuinely reported ending in "&0" silently alters
// evidence. The recorded tail is kept beside the normalised one so the
// alteration can be checked rather than taken on trust.
func TestATrailingInstanceIndexIsRemovedOnlyWhereWindowsAppendsOne(t *testing.T) {
	store := open(t)

	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USBSTOR", `Disk&Ven_Generic&Prod_Flash&Rev_1.00`,
			"0401B570C537&0", "Generic Flash USB Device"),
		devnode("USB", `VID_1234&PID_5678`, "SERIAL&0", "Odd Serial Device"),
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := store.DB().Query(
		`SELECT enumerator, serial, serial_recorded, serial_rule
		 FROM v_devnode ORDER BY enumerator`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	got := map[string][3]string{}
	for rows.Next() {
		var enumerator, serial, recorded, rule string
		if err := rows.Scan(&enumerator, &serial, &recorded, &rule); err != nil {
			t.Fatal(err)
		}
		got[enumerator] = [3]string{serial, recorded, rule}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// The case the strip exists for: without it the stick's USBSTOR node never
	// matches its USB node and one device is reported as two.
	if want := "0401B570C537"; got["USBSTOR"][0] != want {
		t.Errorf("USBSTOR serial = %q, want %q", got["USBSTOR"][0], want)
	}
	if want := "0401B570C537&0"; got["USBSTOR"][1] != want {
		t.Errorf("USBSTOR serial_recorded = %q, want the tail as stored %q",
			got["USBSTOR"][1], want)
	}
	if got["USBSTOR"][2] == "as recorded" {
		t.Error("USBSTOR serial_rule says the value was not altered, and it was")
	}

	// And the case it must not reach. USB does not number instances this way,
	// so the ampersand is part of what the device reported.
	if want := "SERIAL&0"; got["USB"][0] != want {
		t.Errorf("USB serial = %q, want %q — a device-reported serial was "+
			"altered by a rule written for a different enumerator",
			got["USB"][0], want)
	}
	if got["USB"][2] != "as recorded" {
		t.Errorf("USB serial_rule = %q, want \"as recorded\"", got["USB"][2])
	}
}

// A disk reported with no capacity is a removal candidate and closes no window.
//
// On USB-LENOVO-Multi-USBs every one of the four sticks has a positive-capacity
// Partition/Diagnostic 1006 record at its known arrival and a capacity-zero one
// at its known removal, agreeing to the second with the storage channel the
// windows are built from. It is a real signal and worth surfacing, and it is
// not a departure: a multi-slot card reader reports zero capacity for an empty
// slot while the reader itself never leaves the port, and read as a removal
// that closes a window at every one of them.
//
// So the candidate is exported and the window is left to the channels that
// evidence one. What this holds is the second half — a collection whose only
// capacity-zero record is a card reader's empty slot must not lose the
// connection that is still open.
func TestADiskReportedWithNoCapacityIsACandidateRatherThanARemoval(t *testing.T) {
	store := open(t)

	const reader = `USB\VID_0BDA&PID_0316\20100201396000000`
	arrival := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	loadState(t, store, stateEvent(1,
		"Microsoft-Windows-StorageVolume/Operational", 1001,
		eventlog.KindConnect, reader, arrival, ""))

	// Loaded as the event it is, not through disk_layout: a record with no
	// capacity carries no drive layout to decode either, so it never reaches
	// that table. The first version of this view read disk_layout and returned
	// nothing on every collection because of it.
	if err := store.LoadEvents(
		map[string]string{"partition.evtx": "src-2"}, []eventlog.Record{{
			Channel:    "Microsoft-Windows-Partition/Diagnostic",
			SourceFile: "partition.evtx",
			RecordID:   9,
			EventID:    1006,
			TimeUTC:    arrival.Add(5 * time.Minute),
			RuleID:     "Microsoft-Windows-Partition/Diagnostic:1006",
			Kind:       eventlog.KindInventory,
			Fields: []eventlog.Field{
				{Name: "ParentId", Role: eventlog.RoleDeviceInstanceID,
					Value: reader},
				{Name: "Model", Role: eventlog.RoleProduct,
					Value: "Generic MassStorageClass"},
				{Name: "Capacity", Role: eventlog.RoleCapacity, Value: "0"},
			},
		}}); err != nil {
		t.Fatal(err)
	}

	var candidates, corroborated int
	if err := store.DB().QueryRow(
		`SELECT count(*), count(*) FILTER (WHERE corroborated_by_a_recorded_departure)
		 FROM v_disk_departure_candidate`).
		Scan(&candidates, &corroborated); err != nil {
		t.Fatal(err)
	}
	if candidates != 1 {
		t.Fatalf("%d departure candidates, want 1: the record is real "+
			"evidence and has to be in front of an analyst", candidates)
	}
	if corroborated != 0 {
		t.Error("nothing recorded a departure, and the candidate says one did")
	}

	// The window is what must not move. An empty slot is not a removal.
	var ended int
	if err := store.DB().QueryRow(
		`SELECT count(*) FROM v_connection WHERE ended_utc IS NOT NULL`).
		Scan(&ended); err != nil {
		t.Fatal(err)
	}
	if ended != 0 {
		t.Error("a capacity-zero disk record closed a connection window; " +
			"a card reader's empty slot would end a connection the device " +
			"never left")
	}
}

// Row-local parse warnings are gathered by reason, not one row per record.
//
// They lived only in a semicolon-joined column on the record that carries them,
// where nothing counts them: the ledger holds whole-file failures, so a run
// could report one warning with hundreds of partially read records behind it.
// Grouping on the literal message would not fix that — a warning naming an
// offset is one reason seen many times — so the digits are replaced and the
// first full message is kept beside the count.
func TestPartialParsesAreCountedByReasonRatherThanByRecord(t *testing.T) {
	store := open(t)

	partial := func(path, warning string) FileTarget {
		return FileTarget{
			SourceID: "src-1", SourceFile: path + ".lnk", Origin: "shell_link",
			Path: path, DriveLetter: "E", ParseWarnings: warning,
		}
	}
	if err := store.LoadFileTargets([]FileTarget{
		partial(`E:\one.docx`, "shell item at offset 48 declares 900 bytes"),
		partial(`E:\two.docx`, "shell item at offset 112 declares 4096 bytes"),
		partial(`E:\three.docx`, "the target ID list did not parse"),
	}); err != nil {
		t.Fatal(err)
	}

	warnings, err := store.ParseWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 2 {
		t.Fatalf("%d reasons, want 2: two warnings differing only in an "+
			"offset are one reason seen twice", len(warnings))
	}
	if warnings[0].Records != 2 {
		t.Errorf("the commonest reason covers %d record(s), want 2",
			warnings[0].Records)
	}
	// The numbers are still reachable, or the aggregate replaces evidence
	// rather than summarising it.
	if !strings.Contains(warnings[0].Example, "offset") {
		t.Errorf("example = %q, want a message in full", warnings[0].Example)
	}
}

// A portable device's FriendlyName names a volume only where the key names a
// mass-storage identity.
//
// Windows Portable Devices is not a storage list. It holds phones, cameras and
// media players whose FriendlyName is a user-facing device name rather than a
// filesystem label, and one of those coincidentally matching a label a shell
// link recorded would build a device candidate out of nothing. Every label link
// on the five reference collections is USBSTOR, so this cannot be caught by
// running the tool; it is caught by a host with a phone plugged into it.
func TestAPhonesNameIsNotAVolumeLabel(t *testing.T) {
	store := open(t)

	const stick = `USBSTOR\Disk&Ven_Generic&Prod_Flash&Rev_1.00\19786581&0`
	const phone = `USB\VID_18D1&PID_4EE1\29061FDH2000TR`

	if err := store.LoadPortableDevices("src-1", []registry.PortableDevice{
		{KeyName: stick, DeviceInstanceID: stick, FriendlyName: "FIELDWORK"},
		{KeyName: phone, DeviceInstanceID: phone, FriendlyName: "SITEPHOTOS"},
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := store.DB().Query(
		`SELECT volume_label FROM v_device_volume_link
		 WHERE route = 'portable_device_label' ORDER BY volume_label`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var labels []string
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			t.Fatal(err)
		}
		labels = append(labels, label)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if len(labels) != 1 || labels[0] != "FIELDWORK" {
		t.Errorf("label links = %v, want only FIELDWORK: a phone's own name "+
			"was offered as a volume label", labels)
	}
}

// The corroboration on a departure candidate is asked of the physical device,
// not of the devnode that happens to carry the record.
//
// The partition driver names the USB node while StorageVolume names the
// volume's own, so matched on device_key alone every one of the ten candidates
// on USB-LENOVO-Multi-USBs read as uncorroborated while the storage channel had
// recorded the same removal to the second. That is the standing "physical
// devices, not devnodes" rule being load-bearing rather than tidy — and it
// failed quietly, because an uncorroborated candidate is the weaker finding.
func TestADepartureCandidateIsCorroboratedAcrossTheDevicesOwnDevnodes(t *testing.T) {
	store := open(t)

	const usb = `USB\VID_1F75&PID_0918\19786581`
	const storage = `USBSTOR\Disk&Ven_Generic&Prod_Flash&Rev_1.00\19786581&0`

	// One serial on one product under each enumerator, which is what ties the
	// two nodes into one physical device.
	if err := store.LoadDevnodes("src-1", []registry.Devnode{
		devnode("USB", `VID_1F75&PID_0918`, "19786581", "Generic Flash"),
		devnode("USBSTOR", `Disk&Ven_Generic&Prod_Flash&Rev_1.00`,
			"19786581&0", "Generic Flash USB Device"),
	}); err != nil {
		t.Fatal(err)
	}

	removal := time.Date(2026, 8, 4, 2, 12, 10, 0, time.UTC)
	loadState(t, store, stateEvent(1,
		"Microsoft-Windows-StorageVolume/Operational", 1002,
		eventlog.KindDisconnect, storage, removal, ""))

	if err := store.LoadEvents(
		map[string]string{"partition.evtx": "src-2"}, []eventlog.Record{{
			Channel:    "Microsoft-Windows-Partition/Diagnostic",
			SourceFile: "partition.evtx",
			RecordID:   68,
			EventID:    1006,
			TimeUTC:    removal.Add(400 * time.Millisecond),
			RuleID:     "Microsoft-Windows-Partition/Diagnostic:1006",
			Kind:       eventlog.KindInventory,
			Fields: []eventlog.Field{
				{Name: "ParentId", Role: eventlog.RoleDeviceInstanceID,
					Value: usb},
				{Name: "Capacity", Role: eventlog.RoleCapacity, Value: "0"},
			},
		}}); err != nil {
		t.Fatal(err)
	}
	consolidate(t, store)

	var candidates, corroborated int
	if err := store.DB().QueryRow(
		`SELECT count(*), count(*) FILTER (WHERE corroborated_by_a_recorded_departure)
		 FROM v_disk_departure_candidate`).
		Scan(&candidates, &corroborated); err != nil {
		t.Fatal(err)
	}
	if candidates != 1 {
		t.Fatalf("%d departure candidates, want 1", candidates)
	}
	if corroborated != 1 {
		t.Error("the storage channel recorded this removal four tenths of a " +
			"second earlier, on another devnode of the same device, and the " +
			"candidate says nothing corroborates it")
	}
}

// arrivalWithManyRecords builds the shape a real plug-in leaves: several
// channels reporting one arrival, and registry keys whose four lifecycle dates
// all carry that same instant. It is the shape that put twenty-nine rows on the
// report for one event.
func arrivalWithManyRecords(t *testing.T, store *Store) {
	t.Helper()

	identity := `USB\VID_0781&PID_5581\0401B570C537`
	arrival := at("2026-07-26T10:00:00Z")

	node := usbNode("VID_0781&PID_5581", "0401B570C537", "SanDisk", "08", "USBSTOR")
	node.KeyLastWriteUTC = &arrival
	node.Activity = registry.Activity{
		FirstInstallDate: &arrival,
		InstallDate:      &arrival,
		LastArrivalDate:  &arrival,
	}
	if err := store.LoadDevnodes("src-hive", []registry.Devnode{node}); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadEvents(map[string]string{"state.evtx": "src-1"},
		[]eventlog.Record{
			stateEvent(1, "Microsoft-Windows-Kernel-PnP/Configuration", 400,
				eventlog.KindConnect, identity, arrival, ""),
			stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1001,
				eventlog.KindConnect, identity, arrival.Add(2*time.Second), ""),
			stateEvent(3, "Microsoft-Windows-Kernel-PnP/Configuration", 410,
				eventlog.KindOther, identity, arrival.Add(3*time.Second), ""),
			stateEvent(4, "Microsoft-Windows-StorageVolume/Operational", 1002,
				eventlog.KindDisconnect, identity, at("2026-07-26T10:30:00Z"), ""),
		}); err != nil {
		t.Fatal(err)
	}
}

func momentsFor(t *testing.T, store *Store) ([]TimelineRow, map[int][]TimelineRow) {
	t.Helper()
	consolidate(t, store)
	rows, _, err := store.SignificantTimeline(0)
	if err != nil {
		t.Fatal(err)
	}
	members, err := store.TimelineMomentMembers()
	if err != nil {
		t.Fatal(err)
	}
	return rows, members
}

// One arrival is one thing that happened and a great many records of it: the
// PnP configure and start, the StorageVolume mount, and four registry dates
// that all carry the same instant. Listed one per row they read as a page of
// duplicates, because the page shows time to the second and they land inside
// one — on real evidence, twenty-nine rows over twenty distinct instants sixty
// milliseconds apart.
//
// So the report shows the arrival, and the records it rests on go beneath it.
func TestOneArrivalIsOneRowWithItsRecordsBeneathIt(t *testing.T) {
	store := open(t)
	arrivalWithManyRecords(t, store)

	rows, members := momentsFor(t, store)

	var moments []TimelineRow
	for _, row := range rows {
		if row.RowKind == "moment" && row.Event == "device_connected" {
			moments = append(moments, row)
		}
	}
	if len(moments) != 1 {
		t.Fatalf("got %d arrival moments, want 1: one plug-in is one moment",
			len(moments))
	}

	moment := moments[0]
	// The connection window, three event records and four registry dates.
	if moment.MemberCount < 6 {
		t.Errorf("the moment gathered %d records; the arrival leaves the "+
			"connection window, three event records and four registry dates",
			moment.MemberCount)
	}
	if len(members[moment.MomentID]) != moment.MemberCount {
		t.Errorf("the summary counts %d records and the fold holds %d: a "+
			"reader who opens it has to see exactly what was counted",
			moment.MemberCount, len(members[moment.MomentID]))
	}
	if !moment.FirstInstallRecorded {
		t.Error("the arrival carries the registry's first-install date, which " +
			"makes it the first time this device was seen on this host — the " +
			"sort of finding that must not need a disclosure to reach")
	}
	if moment.Supporting == "" {
		t.Error("a summary that says how many records support it and cannot " +
			"say what they were is a number the reader has to take on trust")
	}
}

// The safety property, and the reason a moment is allowed to exist at all: it
// absorbs what evidences the connection and never what evidences use of the
// device.
//
// A file opened in the second a stick was plugged in is the finding an analyst
// came for. Folding it into "this device was connected" would bury the one row
// on the page that matters, under a summary describing records of two entirely
// different kinds as though they were one event.
func TestAFileOpenedAsADeviceArrivedIsNotFoldedIntoTheArrival(t *testing.T) {
	store := open(t)
	arrivalWithManyRecords(t, store)

	if err := store.LoadTimeZone("src-hive", "ControlSet001", perthZone()); err != nil {
		t.Fatal(err)
	}
	// A shortcut, because it states the drive type itself and so reaches the
	// device without a mount table: an unattributed file record is refused by
	// the membership before the category rule is ever consulted, and a test
	// resting on one would hold nothing.
	//
	// Opened one second into the arrival, which is the case this exists for.
	opened := at("2026-07-26T10:00:01Z")
	target := removableTarget("E", "1A2B3C4D", "FIELDWORK", `E:\stolen.docx`)
	target.SourceModifiedUTC = &opened
	if err := store.LoadFileTargets([]FileTarget{target}); err != nil {
		t.Fatal(err)
	}

	_, members := momentsFor(t, store)

	// Asserted first, because the interesting claim below is a negative and a
	// negative over an empty set is free. The bag has to have produced a file
	// record inside the moment's tolerance before "it was not absorbed" says
	// anything at all.
	entries, err := store.Timeline(false, 0)
	if err != nil {
		t.Fatal(err)
	}
	var candidate *TimelineEntry
	for index, entry := range entries {
		if entry.Category == "file" {
			candidate = &entries[index]
		}
	}
	if candidate == nil {
		t.Fatal("the fixture produced no file record, so this test would " +
			"pass without the rule it exists to hold")
	}

	for _, list := range members {
		for _, member := range list {
			if member.Category == "file" {
				t.Errorf("a file record (%s, entry %d) was folded into a "+
					"connection moment: it records what was done with the "+
					"device, not that the device arrived",
					member.Event, member.EntryID)
			}
			if member.EntryID == candidate.EntryID {
				t.Errorf("entry %d is the file record and was folded into a "+
					"moment", member.EntryID)
			}
		}
	}
}

// Nothing is lost to the grouping. Every record the report would have listed is
// either still listed or inside exactly one fold — never both, and never
// neither.
//
// This is the claim the whole design rests on, and the one whose failure would
// be invisible: a summary that quietly dropped a record leaves a page that is
// simply shorter, with nothing on it to say so.
func TestNoTimelineRecordIsLostToAMoment(t *testing.T) {
	store := open(t)
	arrivalWithManyRecords(t, store)
	if err := store.LoadTimeZone("src-hive", "ControlSet001", perthZone()); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadShellBags("src-hive",
		[]registry.ShellBag{bagAt(`E:\stolen`, "2026-07-26 18:00:01")}); err != nil {
		t.Fatal(err)
	}

	rows, members := momentsFor(t, store)

	seen := map[int]int{}
	for _, row := range rows {
		if row.RowKind == "entry" {
			seen[row.EntryID]++
		}
	}
	for _, list := range members {
		for _, member := range list {
			seen[member.EntryID]++
		}
	}

	entries, err := store.Timeline(true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the fixture produced no significant timeline to check")
	}
	for _, entry := range entries {
		switch seen[entry.EntryID] {
		case 1:
		case 0:
			t.Errorf("entry %d (%s %s) reaches neither the list nor a fold",
				entry.EntryID, entry.Category, entry.Event)
		default:
			t.Errorf("entry %d appears %d times: a record folded into a "+
				"moment and listed beside it is counted twice by any reader",
				entry.EntryID, seen[entry.EntryID])
		}
	}
}

// A moment needs two records before it is worth making. Replacing one record
// with a summary of that record, plus a disclosure to open before the record
// can be read, is strictly worse than leaving it where it was — and it would
// happen on every quiet host, which is most of them.
func TestASingleRecordIsNotReplacedByASummaryOfItself(t *testing.T) {
	store := open(t)

	// One arrival and one removal, each reported by a single channel, with no
	// registry evidence and nothing else near either.
	identity := `USB\VID_0781&PID_5581\0401B570C537`
	if err := store.LoadEvents(map[string]string{"state.evtx": "src-1"},
		[]eventlog.Record{
			stateEvent(1, "Microsoft-Windows-StorageVolume/Operational", 1001,
				eventlog.KindConnect, identity, at("2026-07-26T10:00:00Z"), ""),
			stateEvent(2, "Microsoft-Windows-StorageVolume/Operational", 1002,
				eventlog.KindDisconnect, identity, at("2026-07-26T10:30:00Z"), ""),
		}); err != nil {
		t.Fatal(err)
	}

	rows, members := momentsFor(t, store)

	for _, row := range rows {
		if row.RowKind == "moment" {
			t.Errorf("a moment was made for %d record(s): the connection row "+
				"already said this, and now says it behind a fold",
				row.MemberCount)
		}
	}
	if len(members) != 0 {
		t.Errorf("got %d moments holding members, want none", len(members))
	}
}
