package eventlog

import (
	"fmt"
	"sort"
	"strings"
)

// The selection catalogue.
//
// A regex over a flattened payload is a filter, not a selection: it cannot say
// what a record means, it silently keeps whatever happens to mention a volume
// GUID, and nothing about it is checkable. What follows is the opposite — every
// channel and event ID Boobook reads is named here with what it carries and why
// it matters, every field extracted is named with the role it plays, and every
// channel deliberately not read is recorded with the reason. An analyst can
// audit the selection without reading the parser.

// Kind is what a record says happened. It is deliberately coarse: the timeline
// needs to distinguish an arrival from a departure from a description, and
// finer shades are carried by Meaning and the extracted fields.
type Kind string

const (
	// KindConnect is a device or volume arriving.
	KindConnect Kind = "connect"
	// KindDisconnect is a device or volume going away.
	KindDisconnect Kind = "disconnect"
	// KindInstall is driver or device setup activity, which on a first
	// connection happens at roughly the same moment as the arrival.
	KindInstall Kind = "install"
	// KindInventory is a description of a device rather than an action on it.
	// These carry the richest identity — model, serial, capacity — and are what
	// make a device nameable.
	KindInventory Kind = "inventory"
	// KindFault is an error involving a named device.
	KindFault Kind = "fault"
	// KindOther is a record that names a device without stating an action.
	KindOther Kind = "other"
	// KindSession is the host itself starting, stopping, sleeping or waking.
	//
	// These name no device, which is why they need a gate of their own, and
	// they are here for what they say about the silence around a device rather
	// than about a device. A connection with no removal recorded reads one way
	// if the host was shut down with the stick still in it and another way if
	// it ran on for a week afterwards; a gap in the evidence reads differently
	// either side of a boot. Neither reading is available without these.
	KindSession Kind = "session"
	// KindLogon is a person arriving at or leaving the console.
	//
	// Like a session record it names no device. What it is worth is placing
	// somebody at the machine beside a connection, which is a stronger finding
	// than either alone: a stick arriving while a named account is interactively
	// logged on says more than a stick arriving.
	KindLogon Kind = "logon"
)

// Role is what an extracted field means, independent of what the channel that
// wrote it chose to call it. Channels disagree on names for the same thing —
// DeviceInstanceId, Prop_DevnodeId, DiskInstancePath and, on one channel,
// DriverName all hold a device instance ID — so correlation joins on roles.
type Role string

const (
	RoleDeviceInstanceID Role = "device_instance_id"
	RoleParentInstanceID Role = "parent_instance_id"
	RoleVolumeGUID       Role = "volume_guid"
	RoleVolumeLabel      Role = "volume_label"
	RoleDeviceName       Role = "device_name"
	RoleVendor           Role = "vendor"
	RoleProduct          Role = "product"
	RoleRevision         Role = "revision"
	RoleSerial           Role = "serial"
	RoleBusType          Role = "bus_type"
	RoleDiskNumber       Role = "disk_number"
	RoleVolumeNumber     Role = "volume_number"
	RolePartitionOffset  Role = "partition_offset"
	RoleCapacity         Role = "capacity"
	// Raw structures, carried as hex and decoded by internal/partition. These
	// are what tie a MountedDevices volume to the disk it sits on.
	RoleBootRecord    Role = "boot_record"
	RoleDiskLayout    Role = "disk_layout"
	RoleClassGUID     Role = "class_guid"
	RoleDriverName    Role = "driver_name"
	RoleDriverVersion Role = "driver_version"
	RoleDriverDate    Role = "driver_date"
	RoleServiceName   Role = "service_name"
	RoleProblem       Role = "problem_code"
	RoleStatus        Role = "status"
	RoleProcessName   Role = "process_name"
	RoleReason        Role = "reason"
	RoleAccount       Role = "account"
	RoleLogonType     Role = "logon_type"
	RoleFileSystem    Role = "file_system"
	RoleDetail        Role = "detail"
)

// FieldSpec locates one field within a record and says what it means.
type FieldSpec struct {
	// Path is dotted and relative to the Event element: "EventData.VolumeId".
	// A "*" segment matches any single element, which is how the UserData
	// channels are read without hard-coding the element name each provider
	// chose.
	Path string
	// Name is the canonical output name.
	Name string
	Role Role
}

// Rule selects one event and says how to read it.
type Rule struct {
	Channel string
	// Provider narrows the rule to one publisher, and is needed wherever the
	// channel is a shared one. An event ID is unique to its provider and not to
	// the channel it lands on: on the System channel of
	// USB-LENOVO-Multi-USBs, event 12 is written by Kernel-General (15 times,
	// the operating system starting), UserModePowerService (43), Wininit (15)
	// and a fingerprint reader's driver (1). Keyed on the ID alone, "the host
	// booted" would be reported 74 times on a host that booted 15.
	//
	// Empty matches any provider, which is right for the dedicated channels
	// where one publisher owns the whole log.
	Provider string
	EventID  int64
	Kind     Kind
	// Meaning describes what the record evidences, in the terms an analyst
	// would use in a report.
	Meaning string
	// Note records a caveat: an interpretation that is not certain, or a field
	// mapping that would look wrong without explanation. Notes are printed with
	// the catalogue, not buried here.
	Note   string
	Fields []FieldSpec
	// NameValue reads the EventData\Data {Name, Value} form some providers use
	// instead of named elements.
	NameValue bool
	// Gate decides whether an extracted record concerns USB. Nil uses the
	// default: some field naming a USB or portable-device identity.
	Gate func(fields []Field) bool
	// Classify narrows Kind using the record's own fields, for the events
	// where the ID alone does not settle what happened. Nil keeps Kind.
	//
	// Kernel-PnP 420 is why this exists. The rule's Note had said for a long
	// time that problem 45 is CM_PROB_DEVICE_DISCONNECTED and that a record
	// with another problem code is not a removal — and the rule then carried a
	// fixed KindDisconnect, so every 420 that passed the gate closed a
	// connection window whatever its problem code. The comment documented the
	// defect it did not prevent.
	//
	// Returning a kind is deliberate rather than returning a bool: the honest
	// answer for a non-qualifying record is usually not "discard" but "this is
	// a fault, not a departure", and the row is worth keeping as that.
	Classify func(fields []Field) Kind
}

// KindOf returns the kind a record's fields earn under this rule.
func (r Rule) KindOf(fields []Field) Kind {
	if r.Classify == nil {
		return r.Kind
	}
	return r.Classify(fields)
}

// ID is the stable identifier used in output and in the accounting. The
// provider is part of it where there is one, because two rules can otherwise
// share an id and the per-rule counts would silently merge.
func (r Rule) ID() string {
	if r.Provider != "" {
		return fmt.Sprintf("%s:%s:%d", r.Channel, r.Provider, r.EventID)
	}
	return fmt.Sprintf("%s:%d", r.Channel, r.EventID)
}

// identity is the field set the storage channels repeat almost verbatim.
func identity(prefix string) []FieldSpec {
	return []FieldSpec{
		{prefix + ".VolumeId", "VolumeId", RoleVolumeGUID},
		{prefix + ".VolumeCorrelationId", "VolumeCorrelationId", RoleVolumeGUID},
		{prefix + ".VolumeLabel", "VolumeLabel", RoleVolumeLabel},
		{prefix + ".DeviceName", "DeviceName", RoleDeviceName},
		{prefix + ".BusType", "BusType", RoleBusType},
		{prefix + ".VendorId", "VendorId", RoleVendor},
		{prefix + ".ProductId", "ProductId", RoleProduct},
		{prefix + ".ProductRevision", "ProductRevision", RoleRevision},
		{prefix + ".DeviceSerialNumber", "DeviceSerialNumber", RoleSerial},
	}
}

// rules is the whole of what Boobook selects.
var rules = []Rule{
	// -- Kernel-PnP ---------------------------------------------------------
	//
	// The closest thing Windows has to a device connection log. It records
	// every device the PnP manager configures, whichever bus it sits on, so the
	// USB gate does the narrowing.
	{
		Channel: "Microsoft-Windows-Kernel-PnP/Configuration", EventID: 400,
		Kind:    KindInstall,
		Meaning: "device configured: a driver was selected and installed for the device",
		Fields: []FieldSpec{
			{"EventData.DeviceInstanceId", "DeviceInstanceId", RoleDeviceInstanceID},
			{"EventData.ParentDeviceInstanceId", "ParentDeviceInstanceId", RoleParentInstanceID},
			{"EventData.ClassGuid", "ClassGuid", RoleClassGUID},
			{"EventData.DriverName", "DriverName", RoleDriverName},
			{"EventData.DriverVersion", "DriverVersion", RoleDriverVersion},
			{"EventData.DriverDate", "DriverDate", RoleDriverDate},
			{"EventData.DriverProvider", "DriverProvider", RoleDetail},
			{"EventData.MatchingDeviceId", "MatchingDeviceId", RoleDetail},
			{"EventData.Status", "Status", RoleStatus},
		},
	},
	{
		Channel: "Microsoft-Windows-Kernel-PnP/Configuration", EventID: 410,
		Kind:    KindInstall,
		Meaning: "device started: the driver stack for the device was brought up",
		Fields: []FieldSpec{
			{"EventData.DeviceInstanceId", "DeviceInstanceId", RoleDeviceInstanceID},
			{"EventData.ClassGuid", "ClassGuid", RoleClassGUID},
			{"EventData.ServiceName", "ServiceName", RoleServiceName},
			{"EventData.DriverName", "DriverName", RoleDriverName},
			{"EventData.LowerFilters", "LowerFilters", RoleDetail},
			{"EventData.UpperFilters", "UpperFilters", RoleDetail},
			{"EventData.Problem", "Problem", RoleProblem},
			{"EventData.Status", "Status", RoleStatus},
		},
	},
	{
		Channel: "Microsoft-Windows-Kernel-PnP/Configuration", EventID: 420,
		Kind:    KindDisconnect,
		Meaning: "device node removed or reported a problem",
		Note: "the problem code carries the detail — 45 is CM_PROB_DEVICE_DISCONNECTED, " +
			"which is what a removal looks like. A record with another problem code " +
			"is not a removal: it is reported as a fault against the device and " +
			"does not close a connection window.",
		// The kind is decided from the problem code and not from the event ID.
		// Both 420 records in every reference collection carry problem 45, so
		// the happy path concealed this completely.
		Classify: problemCodeDeparture,
		Fields: []FieldSpec{
			{"EventData.DeviceInstanceId", "DeviceInstanceId", RoleDeviceInstanceID},
			{"EventData.ClassGuid", "ClassGuid", RoleClassGUID},
			{"EventData.Problem", "Problem", RoleProblem},
			{"EventData.Status", "Status", RoleStatus},
		},
	},
	{
		Channel: "Microsoft-Windows-Kernel-PnP/Configuration", EventID: 430,
		Kind:      KindOther,
		Meaning:   "device installation activity, reported in the Data name/value form",
		NameValue: true,
	},
	// The four rules that follow sit on System, which is where everything
	// without a log of its own writes, so each names its publisher. Three of
	// the four are named from the evidence rather than from documentation:
	// across the five reference collections, 219 is written only by
	// Kernel-PnP, 20003 only by UserPnp and 10000 only by
	// DriverFrameworks-UserMode. 20001 appears in none of them and is named
	// for UserPnp, which owns 20003 beside it — the weaker of the four claims,
	// and the safe direction to be wrong in: an unmatched rule reports nothing
	// where a rule matching any publisher would report the wrong thing.
	{
		Channel: "System", Provider: "Microsoft-Windows-Kernel-PnP", EventID: 219,
		Kind:    KindFault,
		Meaning: "a driver failed to load for the device",
		Note: "this provider writes the device instance ID into a field called " +
			"DriverName, and the failing driver into FailureName. Reading DriverName " +
			"as a driver here would lose the device entirely.",
		Fields: []FieldSpec{
			{"EventData.DriverName", "DriverName", RoleDeviceInstanceID},
			{"EventData.FailureName", "FailureName", RoleDriverName},
			{"EventData.Status", "Status", RoleStatus},
		},
	},

	// -- UserPnp and the user-mode driver framework -------------------------
	{
		Channel: "System", Provider: "Microsoft-Windows-UserPnp", EventID: 20001,
		Kind:    KindInstall,
		Meaning: "driver installation completed for the device",
		Fields: []FieldSpec{
			{"UserData.*.DeviceInstanceID", "DeviceInstanceID", RoleDeviceInstanceID},
			{"UserData.*.DriverName", "DriverName", RoleDriverName},
			{"UserData.*.DriverFileName", "DriverFileName", RoleDriverName},
			{"UserData.*.DriverDescription", "DriverDescription", RoleProduct},
			{"UserData.*.DriverVersion", "DriverVersion", RoleDriverVersion},
			{"UserData.*.DriverProvider", "DriverProvider", RoleDetail},
			{"UserData.*.InstallStatus", "InstallStatus", RoleStatus},
		},
		Note: "not present in the reference collections; the field paths are matched " +
			"by wildcard rather than by an assumed UserData element name.",
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-UserPnp", EventID: 20003,
		Kind:    KindInstall,
		Meaning: "a service was associated with the device during installation",
		Fields: []FieldSpec{
			{"UserData.*.DeviceInstanceID", "DeviceInstanceID", RoleDeviceInstanceID},
			{"UserData.*.ServiceName", "ServiceName", RoleServiceName},
			{"UserData.*.DriverFileName", "DriverFileName", RoleDriverName},
			{"UserData.*.AddServiceStatus", "AddServiceStatus", RoleStatus},
		},
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-DriverFrameworks-UserMode", EventID: 10000,
		Kind:    KindInstall,
		Meaning: "user-mode driver framework began installing the device",
		Fields: []FieldSpec{
			{"UserData.*.DeviceId", "DeviceId", RoleDeviceInstanceID},
			{"UserData.*.FrameworkVersion", "FrameworkVersion", RoleDriverVersion},
		},
	},
	// These three said "arriving device", "began removing a device" and
	// "finished removing a device", and the first was KindConnect and the other
	// two KindDisconnect. None of that is what the provider says.
	//
	// From the manifest installed on Windows, read with
	// `wevtutil gp Microsoft-Windows-DriverFrameworks-UserMode /ge:true`:
	//
	//	2003  The UMDF Host Process (%1) has been asked to load drivers for
	//	      device %2.
	//	2100  Received a Pnp or Power operation (%3, %4) for device %2.
	//	2102  Forwarded a finished Pnp or Power operation (%3, %4) to the lower
	//	      driver for device %2 with status %9.
	//
	// %3 and %4 are the operation's major and minor request codes. A start, a
	// query, a stop, a remove, a power transition and a surprise removal are
	// all the same event ID and differ only in those parameters, so the ID
	// alone cannot say which happened. Boobook was reading every one of them as
	// a removal, and because KindDisconnect feeds v_device_state_change and
	// v_connection, a single retained 2100 would have ended a connection window
	// at a power event.
	//
	// So all three are KindOther. The record is kept, exported and put on the
	// timeline exactly as before — what it loses is the right to open or close
	// a window, which is the thing it was never evidence for.
	//
	// What is deliberately not done here is guess the field names for the
	// request codes and status. The manifest gives the message strings and not
	// the template, the channel is disabled by default on current Windows, no
	// reference collection carries a record, and this host has no log to read.
	// Inventing a plausible <Data Name="..."> and writing a fixture around it
	// would test the invention. The wildcard specs below surface whatever a
	// real record does carry as detail, and classifying a removal from these
	// events needs one real record first.
	{
		Channel: "Microsoft-Windows-DriverFrameworks-UserMode/Operational", EventID: 2003,
		Kind: KindOther,
		Meaning: "the user-mode driver host was asked to load drivers for this " +
			"device; the drivers loading is not the same as the device arriving, " +
			"because this also happens at boot and when a driver restarts",
		Note: "not present in the reference collections and the channel is not " +
			"enabled by default on current Windows.",
		Fields: []FieldSpec{
			{"UserData.*.InstanceId", "InstanceId", RoleDeviceInstanceID},
			{"UserData.*.DeviceInstanceId", "DeviceInstanceId", RoleDeviceInstanceID},
			{"UserData.*.LifetimeId", "LifetimeId", RoleDetail},
		},
	},
	{
		Channel: "Microsoft-Windows-DriverFrameworks-UserMode/Operational", EventID: 2100,
		Kind: KindOther,
		Meaning: "the user-mode driver host received a PnP or power operation " +
			"for this device; which operation is carried in the request codes " +
			"and not in the event ID, so this is not by itself a removal",
		Note: "the provider's own wording is \"Received a Pnp or Power operation " +
			"(%3, %4) for device %2\". Boobook read this as a removal until an " +
			"independent review checked it against the installed manifest.",
		Fields: []FieldSpec{
			{"UserData.*.InstanceId", "InstanceId", RoleDeviceInstanceID},
			{"UserData.*.DeviceInstanceId", "DeviceInstanceId", RoleDeviceInstanceID},
			{"UserData.*.LifetimeId", "LifetimeId", RoleDetail},
			{"UserData.*.MajorFunction", "MajorFunction", RoleDetail},
			{"UserData.*.MinorFunction", "MinorFunction", RoleDetail},
			{"UserData.*.Operation", "Operation", RoleDetail},
		},
	},
	{
		Channel: "Microsoft-Windows-DriverFrameworks-UserMode/Operational", EventID: 2102,
		Kind: KindOther,
		Meaning: "the user-mode driver host forwarded a finished PnP or power " +
			"operation to the lower driver for this device; which operation is " +
			"carried in the request codes and not in the event ID, so this is " +
			"not by itself a removal",
		Note: "the provider's own wording is \"Forwarded a finished Pnp or Power " +
			"operation (%3, %4) to the lower driver for device %2 with status " +
			"%9\"; see event 2100.",
		Fields: []FieldSpec{
			{"UserData.*.InstanceId", "InstanceId", RoleDeviceInstanceID},
			{"UserData.*.DeviceInstanceId", "DeviceInstanceId", RoleDeviceInstanceID},
			{"UserData.*.LifetimeId", "LifetimeId", RoleDetail},
			{"UserData.*.MajorFunction", "MajorFunction", RoleDetail},
			{"UserData.*.MinorFunction", "MinorFunction", RoleDetail},
			{"UserData.*.Operation", "Operation", RoleDetail},
			{"UserData.*.NtStatus", "NtStatus", RoleStatus},
			{"UserData.*.Status", "Status", RoleStatus},
		},
	},

	// -- Volume arrival and departure ---------------------------------------
	//
	// These two are the most direct statement Windows makes about a USB disk
	// being plugged in and pulled out, and they name the USBSTOR device outright
	// rather than a volume GUID that has to be resolved.
	{
		Channel: "Microsoft-Windows-StorageVolume/Operational", EventID: 1001,
		Kind:    KindConnect,
		Meaning: "a volume on the disk became available",
		Fields: []FieldSpec{
			{"EventData.DiskInstancePath", "DiskInstancePath", RoleDeviceInstanceID},
			{"EventData.DiskNumber", "DiskNumber", RoleDiskNumber},
			{"EventData.VolumeNumber", "VolumeNumber", RoleVolumeNumber},
			{"EventData.PartitionOffset", "PartitionOffset", RolePartitionOffset},
		},
	},
	{
		Channel: "Microsoft-Windows-StorageVolume/Operational", EventID: 1002,
		Kind:    KindDisconnect,
		Meaning: "a volume on the disk went away",
		Fields: []FieldSpec{
			{"EventData.DiskInstancePath", "DiskInstancePath", RoleDeviceInstanceID},
			{"EventData.DiskNumber", "DiskNumber", RoleDiskNumber},
			{"EventData.VolumeNumber", "VolumeNumber", RoleVolumeNumber},
			{"EventData.PartitionOffset", "PartitionOffset", RolePartitionOffset},
			{"EventData.Deleted", "Deleted", RoleDetail},
		},
	},

	// -- Disk inventory -----------------------------------------------------
	{
		Channel: "Microsoft-Windows-Storsvc/Diagnostic", EventID: 1001,
		Kind:    KindInventory,
		Meaning: "disk described by the storage service: model, serial, bus and parent device",
		Fields: []FieldSpec{
			{"EventData.ParentId", "ParentId", RoleDeviceInstanceID},
			{"EventData.DiskNumber", "DiskNumber", RoleDiskNumber},
			{"EventData.VendorId", "VendorId", RoleVendor},
			{"EventData.ProductId", "ProductId", RoleProduct},
			{"EventData.ProductRevision", "ProductRevision", RoleRevision},
			{"EventData.SerialNumber", "SerialNumber", RoleSerial},
			{"EventData.BusType", "BusType", RoleBusType},
			{"EventData.FileSystem", "FileSystem", RoleFileSystem},
			{"EventData.Size", "Size", RoleCapacity},
			{"EventData.PartitionStyle", "PartitionStyle", RoleDetail},
			{"EventData.VolumeCount", "VolumeCount", RoleDetail},
		},
	},
	{
		Channel: "Microsoft-Windows-Partition/Diagnostic", EventID: 1006,
		Kind:    KindInventory,
		Meaning: "disk described by the partition driver: model, serial, capacity and geometry",
		Note: "the Mbr and PartitionTable fields carry the raw boot record and the " +
			"drive layout structure. Both are decoded by internal/partition: they " +
			"hold the disk signature and the GPT partition identifiers that " +
			"MountedDevices stores, which is what ties a drive letter to the disk " +
			"and so to this record's device. The record carries no VBR, so no " +
			"volume serial number comes from this source.",
		Fields: []FieldSpec{
			{"EventData.ParentId", "ParentId", RoleDeviceInstanceID},
			{"EventData.RegistryId", "RegistryId", RoleDetail},
			{"EventData.DiskNumber", "DiskNumber", RoleDiskNumber},
			{"EventData.Manufacturer", "Manufacturer", RoleVendor},
			{"EventData.Model", "Model", RoleProduct},
			{"EventData.Revision", "Revision", RoleRevision},
			{"EventData.SerialNumber", "SerialNumber", RoleSerial},
			{"EventData.Capacity", "Capacity", RoleCapacity},
			{"EventData.BusType", "BusType", RoleBusType},
			{"EventData.PartitionStyle", "PartitionStyle", RoleDetail},
			{"EventData.PartitionCount", "PartitionCount", RoleDetail},
			{"EventData.DiskId", "DiskId", RoleDetail},
			{"EventData.UserRemovalPolicy", "UserRemovalPolicy", RoleDetail},
			{"EventData.Mbr", "Mbr", RoleBootRecord},
			{"EventData.PartitionTable", "PartitionTable", RoleDiskLayout},
		},
	},
	{
		Channel: "Microsoft-Windows-Storage-Storport/Operational", EventID: 551,
		Kind:    KindInventory,
		Meaning: "storage port driver described an attached device",
		Note: "this record names no bus and no device instance ID, so the miniport " +
			"driver decides relevance: only a USBSTOR miniport is taken as USB.",
		Fields: []FieldSpec{
			{"EventData.MiniportName", "MiniportName", RoleDriverName},
			{"EventData.VendorId", "VendorId", RoleVendor},
			{"EventData.ProductId", "ProductId", RoleProduct},
			{"EventData.SerialNumber", "SerialNumber", RoleSerial},
			{"EventData.AdapterSerialNumber", "AdapterSerialNumber", RoleDetail},
			{"EventData.ClassDeviceGuid", "ClassDeviceGuid", RoleDetail},
			{"EventData.Removable", "Removable", RoleDetail},
		},
		Gate: usbMiniport,
	},

	// -- File system mount and dismount -------------------------------------
	//
	// These are what tie a volume GUID to a device serial at a known moment,
	// which is the hinge the whole drive-letter chain turns on.
	{
		Channel: "Microsoft-Windows-Ntfs/Operational", EventID: 4,
		Kind:    KindConnect,
		Meaning: "an NTFS volume was mounted",
		Fields: append(identity("EventData"), []FieldSpec{
			{"EventData.IsBootVolume", "IsBootVolume", RoleDetail},
			{"EventData.AdapterSerialNumber", "AdapterSerialNumber", RoleDetail},
		}...),
	},
	{
		Channel: "Microsoft-Windows-Ntfs/Operational", EventID: 9,
		Kind:    KindOther,
		Meaning: "NTFS reported on a volume, naming the device behind it",
		Note: "kept for the identity it carries — it maps a volume GUID to a device " +
			"serial — not for the state it reports.",
		Fields: append(identity("EventData"), []FieldSpec{
			{"EventData.Reason", "Reason", RoleReason},
			{"EventData.Flags", "Flags", RoleDetail},
		}...),
	},
	{
		Channel: "Microsoft-Windows-Ntfs/Operational", EventID: 300,
		Kind:    KindDisconnect,
		Meaning: "an NTFS volume was dismounted",
		Fields: append(identity("EventData"), []FieldSpec{
			{"EventData.DismountReason", "DismountReason", RoleReason},
			{"EventData.ProcessName", "ProcessName", RoleProcessName},
			{"EventData.ProcessId", "ProcessId", RoleDetail},
		}...),
	},
	{
		Channel: "Microsoft-Windows-Ntfs/Operational", EventID: 303,
		Kind:    KindDisconnect,
		Meaning: "an NTFS volume dismount completed",
		Fields: append(identity("EventData"), []FieldSpec{
			{"EventData.DismountReason", "DismountReason", RoleReason},
			{"EventData.ProcessName", "ProcessName", RoleProcessName},
			{"EventData.ProcessId", "ProcessId", RoleDetail},
		}...),
	},

	// -- Device setup manager -----------------------------------------------
	{
		Channel: "Microsoft-Windows-DeviceSetupManager/Admin", EventID: 121,
		Kind:    KindFault,
		Meaning: "device setup failed for the device",
		Fields: []FieldSpec{
			{"EventData.Prop_DevnodeId", "Prop_DevnodeId", RoleDeviceInstanceID},
			{"EventData.HRESULT", "HRESULT", RoleStatus},
		},
	},
	{
		Channel: "Microsoft-Windows-DeviceSetupManager/Admin", EventID: 123,
		Kind:    KindOther,
		Meaning: "device setup reported elapsed time for the device",
		Fields: []FieldSpec{
			{"EventData.Prop_DeviceId", "Prop_DeviceId", RoleDeviceInstanceID},
			{"EventData.Prop_Seconds", "Prop_Seconds", RoleDetail},
		},
	},
	{
		Channel: "Microsoft-Windows-DeviceSetupManager/Admin", EventID: 126,
		Kind:    KindInstall,
		Meaning: "a driver package was applied to the device",
		Fields: []FieldSpec{
			{"EventData.Prop_DeviceInstanceId", "Prop_DeviceInstanceId", RoleDeviceInstanceID},
			{"EventData.Prop_PackageId", "Prop_PackageId", RoleDetail},
		},
	},
	{
		Channel:   "Microsoft-Windows-DeviceSetupManager/Admin",
		EventID:   127,
		Kind:      KindOther,
		Meaning:   "device setup activity, reported in the Data name/value form",
		NameValue: true,
	},
	{
		Channel: "Microsoft-Windows-DeviceSetupManager/Admin", EventID: 234,
		Kind:    KindOther,
		Meaning: "device setup reported elapsed time for the device",
		Fields: []FieldSpec{
			{"EventData.Prop_DevnodeId", "Prop_DevnodeId", RoleDeviceInstanceID},
			{"EventData.Prop_MilliSeconds", "Prop_MilliSeconds", RoleDetail},
		},
	},

	// -- The host's own sessions --------------------------------------------
	//
	// These name no device and are not about devices. They are here because
	// they say what the silence around a device means, which nothing else in
	// the evidence does.
	//
	// A connection window with no removal recorded is ambiguous: the stick may
	// have been pulled out with nothing logging it, or the host may have been
	// shut down with it still in the port. Those are different findings and
	// only a shutdown time tells them apart. Equally, an hour of no records
	// reads as a quiet hour if the host was up and as nothing at all if it was
	// off. On USB-LENOVO-Multi-USBs the 10:25 shutdown and 10:26 boot were
	// visible only as Kernel-PnP driver loads, which is a poor way to learn
	// that a machine restarted.
	//
	// All of these are on the System channel, which is read already, so they
	// cost nothing to add. Every one names its provider: the System channel is
	// shared, and an id there belongs to a publisher rather than to the log.
	{
		Channel: "System", Provider: "EventLog", EventID: 6005,
		Kind:    KindSession,
		Meaning: "the event log service started, which dates the host starting up",
		Gate:    anyRecord,
	},
	{
		Channel: "System", Provider: "EventLog", EventID: 6006,
		Kind:    KindSession,
		Meaning: "the event log service stopped, which dates a clean shutdown",
		Gate:    anyRecord,
	},
	{
		Channel: "System", Provider: "EventLog", EventID: 6008,
		Kind: KindSession,
		Meaning: "a later start reported that the previous shutdown was " +
			"unexpected: the host lost power or stopped without closing its " +
			"logs, at a moment this record does not date",
		Note: "absent from all five reference collections, which is what a host " +
			"that was always shut down cleanly looks like. It is selected " +
			"because its presence would explain a connection window that " +
			"never closed. Its own time is when the next boot noticed, not " +
			"when the host went off: the message renders the earlier time as " +
			"locale-formatted text, which is not read. v_host_unclean_stop " +
			"bounds the stop between the last record of the dead session and " +
			"this boot rather than dating it here.",
		Gate: anyRecord,
	},
	{
		Channel: "System", Provider: "EventLog", EventID: 6013,
		Kind: KindSession,
		Meaning: "the running system reported its uptime, which it does once a " +
			"day and which places the host as switched on at this moment",
		Gate: anyRecord,
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-Kernel-General", EventID: 12,
		Kind:    KindSession,
		Meaning: "the operating system started",
		Note: "event 12 on this channel is also written by " +
			"UserModePowerService, Wininit and at least one device driver. " +
			"Only Kernel-General's is the operating system starting.",
		Gate: anyRecord,
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-Kernel-General", EventID: 13,
		Kind:    KindSession,
		Meaning: "the operating system is shutting down",
		Gate:    anyRecord,
	},
	{
		Channel: "System", Provider: "User32", EventID: 1074,
		Kind: KindSession,
		Meaning: "a shutdown or restart was requested, naming the process that " +
			"asked for it and the user in whose name it was asked",
		// The only session record that names a person, which is why the fields
		// are worth pulling out where the others carry none.
		Fields: []FieldSpec{
			{"EventData.param1", "Process", RoleProcessName},
			{"EventData.param3", "Reason", RoleReason},
			{"EventData.param5", "ShutdownType", RoleDetail},
			{"EventData.param7", "User", RoleDetail},
		},
		Gate: anyRecord,
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-Kernel-Power", EventID: 42,
		Kind:    KindSession,
		Meaning: "the host entered sleep",
		Gate:    anyRecord,
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-Kernel-Power", EventID: 107,
		Kind:    KindSession,
		Meaning: "the host resumed from sleep",
		Gate:    anyRecord,
	},
	{
		Channel: "System", Provider: "Microsoft-Windows-Kernel-Power", EventID: 41,
		Kind: KindSession,
		Meaning: "the host restarted, having found that it did not shut down " +
			"cleanly beforehand",
		Note: "absent from all five reference collections; see event 6008, which " +
			"is the other half of the same statement. Windows writes this " +
			"during startup, after checking how the last session ended, so " +
			"the record dates the discovery and the restart — never the loss " +
			"of power, which nothing here records.",
		Gate: anyRecord,
	},
	// -- Who was at the console ----------------------------------------------
	//
	// Only read when a run asks for it: see optInChannels. These are the reason
	// the flag exists, and the whole of what is taken from that channel.
	//
	// 4624 and 4634 are audited by default, which is what makes them worth
	// having — 852 and 10 of them on USB-LENOVO-Multi-USBs. 4800 and 4801 are
	// not: they need "Audit Other Logon/Logoff Events" turned on, and are absent
	// from all five reference collections. Their absence must never be reported
	// as the workstation not having been locked.
	{
		Channel: "Security", EventID: 4624,
		Kind: KindLogon,
		Meaning: "an account logged on, with the type saying whether that was at " +
			"the console, over the network or as a service",
		Note: "logon type 2 is interactive and 10 is remote interactive; the " +
			"rest are services, batch jobs and network sessions and place " +
			"nobody at the machine. The type is carried rather than filtered on.",
		Fields: []FieldSpec{
			{"EventData.TargetUserName", "TargetUserName", RoleAccount},
			{"EventData.TargetDomainName", "TargetDomainName", RoleDetail},
			{"EventData.LogonType", "LogonType", RoleLogonType},
			{"EventData.WorkstationName", "WorkstationName", RoleDetail},
			{"EventData.IpAddress", "IpAddress", RoleDetail},
			{"EventData.ProcessName", "ProcessName", RoleProcessName},
		},
		Gate: anyRecord,
	},
	{
		Channel: "Security", EventID: 4634,
		Kind:    KindLogon,
		Meaning: "an account logged off",
		Fields: []FieldSpec{
			{"EventData.TargetUserName", "TargetUserName", RoleAccount},
			{"EventData.TargetDomainName", "TargetDomainName", RoleDetail},
			{"EventData.LogonType", "LogonType", RoleLogonType},
		},
		Gate: anyRecord,
	},
	{
		Channel: "Security", EventID: 4647,
		Kind: KindLogon,
		Meaning: "a user initiated a log off, which is the person acting rather " +
			"than the session ending",
		Fields: []FieldSpec{
			{"EventData.TargetUserName", "TargetUserName", RoleAccount},
			{"EventData.TargetDomainName", "TargetDomainName", RoleDetail},
		},
		Gate: anyRecord,
	},
	{
		Channel: "Security", EventID: 4800,
		Kind:    KindLogon,
		Meaning: "the workstation was locked",
		Note: "needs \"Audit Other Logon/Logoff Events\" enabled, which is not " +
			"the default and is not set on any reference collection. Its " +
			"absence is not evidence the workstation was never locked.",
		Fields: []FieldSpec{
			{"EventData.TargetUserName", "TargetUserName", RoleAccount},
			{"EventData.TargetDomainName", "TargetDomainName", RoleDetail},
		},
		Gate: anyRecord,
	},
	{
		Channel: "Security", EventID: 4801,
		Kind:    KindLogon,
		Meaning: "the workstation was unlocked",
		Note:    "see event 4800.",
		Fields: []FieldSpec{
			{"EventData.TargetUserName", "TargetUserName", RoleAccount},
			{"EventData.TargetDomainName", "TargetDomainName", RoleDetail},
		},
		Gate: anyRecord,
	},
}

// anyRecord admits a record that names no device.
//
// The default gate asks whether a record concerns USB, which is right for every
// rule that describes a device and wrong for the ones that describe the host.
// A boot names nothing and is kept for what it says about the records around
// it.
func anyRecord([]Field) bool { return true }

// dataNameRoles maps the field names used inside the Data {Name, Value} form to
// roles. A name absent here is still kept, as a detail.
var dataNameRoles = map[string]Role{
	"deviceinstanceid":      RoleDeviceInstanceID,
	"deviceid":              RoleDeviceInstanceID,
	"prop_devnodeid":        RoleDeviceInstanceID,
	"prop_deviceid":         RoleDeviceInstanceID,
	"prop_deviceinstanceid": RoleDeviceInstanceID,
	"drivername":            RoleDriverName,
	"classguid":             RoleClassGUID,
	"servicename":           RoleServiceName,
	"status":                RoleStatus,
	"problem":               RoleProblem,
}

// Exclusion is an event that was considered and deliberately not selected. It
// exists so that "Boobook did not report this" is a decision on the record
// rather than an oversight, and so the reasoning can be argued with.
type Exclusion struct {
	Channel   string
	EventID   int64
	Rationale string
}

// exclusions covers events within selected channels. A channel with no rules at
// all is not read, and is accounted for separately.
var exclusions = []Exclusion{
	{"Microsoft-Windows-Ntfs/Operational", 10,
		"cached run statistics: repeats identity already captured by the mount event and adds no time or action of its own"},
	{"Microsoft-Windows-Ntfs/Operational", 142,
		"free space sampling: a volume performance metric, with no device identity"},
	{"Microsoft-Windows-Ntfs/Operational", 145,
		"latency histogram: a performance metric"},
	{"Microsoft-Windows-Ntfs/Operational", 158,
		"volume I/O statistics: a performance metric"},
	{"System", 98,
		"NTFS corruption state: names a volume GUID and a device path but no device identity and no bus, so nothing in it establishes the volume as removable"},
	{"System", 15,
		"kernel hive resize: mentions a volume GUID only because the hive path contains one"},
	{"Security", 4907,
		"audit policy change on an object: matched a naive filter through an embedded path, and evidences nothing about a device"},
	{"Security", 4663,
		"removable storage object access: names \\Device\\HarddiskVolumeN rather than a device, so reaching a device needs the volume resolved first. Deferred to the correlation phase, where the NTFS mount events supply that mapping — selecting it now would flood the output with unattributable file access"},
	{"Security", 4656,
		"handle request on an object: see event 4663"},
}

// unreadChannels records channels present in evidence that Boobook does not
// read at all, with the reason. Every one of these was matched by the throwaway
// regex the catalogue replaces, which is the argument for the catalogue.
var unreadChannels = map[string]string{
	"Microsoft-Windows-AppXDeploymentServer/Operational": "application package deployment: matched only because a package path contains the system volume GUID",
	"Microsoft-Windows-AppXDeploymentServer/Restricted":  "application package deployment: see the Operational channel",
	"Microsoft-Windows-Store/Operational":                "store install activity: no device content",
	"Microsoft-Windows-Kernel-ShimEngine/Operational":    "driver shim engine: names drivers, not devices",
	"Microsoft-Windows-Biometrics/Operational":           "biometric sensor activity: a fingerprint reader is a USB device but out of Tier A scope, and the channel carries no device identity worth joining",
	"Microsoft-Windows-MF-FrameServer/Camera_DeviceMFT":  "camera pipeline: a USB camera is out of Tier A scope",
	"Microsoft-Windows-PowerShell/Operational":           "script block logging: matched on script text mentioning a drive, which evidences the script and not a device",
	"Microsoft-Windows-VHDMP-Operational":                "virtual disk attach and detach: relevant to how evidence was handled, but a virtual disk is not a USB device and reporting it as one would mislead",
	"Microsoft-Windows-Kernel-PnP/Driver Watchdog":       "driver watchdog timeouts: names a driver, not a device",
	"Application": "no rules select this channel",
}

// index gives per-channel lookup of the rules and exclusions.
//
// One (channel, id) holds a list rather than a single rule, because a shared
// channel gives the same id to several providers and each may want reading
// differently — or, more often, only one of them wants reading at all.
type index struct {
	byChannel  map[string]map[int64][]*Rule
	excludedBy map[string]map[int64]string
}

var catalogue = buildIndex()

func buildIndex() *index {
	built := &index{
		byChannel:  map[string]map[int64][]*Rule{},
		excludedBy: map[string]map[int64]string{},
	}
	for i := range rules {
		rule := &rules[i]
		channel := strings.ToLower(rule.Channel)
		if built.byChannel[channel] == nil {
			built.byChannel[channel] = map[int64][]*Rule{}
		}
		built.byChannel[channel][rule.EventID] =
			append(built.byChannel[channel][rule.EventID], rule)
	}
	for _, exclusion := range exclusions {
		channel := strings.ToLower(exclusion.Channel)
		if built.excludedBy[channel] == nil {
			built.excludedBy[channel] = map[int64]string{}
		}
		built.excludedBy[channel][exclusion.EventID] = exclusion.Rationale
	}
	return built
}

// ChannelSelected reports whether any rule reads this channel.
//
// It says nothing about whether a given run will read it: an opt-in channel is
// selected in the catalogue and skipped unless the run asks for it. Keeping the
// two apart is what lets -sources and -rules state what Boobook is capable of
// reading rather than what one invocation happened to want.
func ChannelSelected(channel string) bool {
	return catalogue.byChannel[strings.ToLower(channel)] != nil
}

// optInChannels are read only when the caller asks, with the reason.
//
// Security.evtx holds a little that is worth having and a great deal that is
// not, and it costs whatever the host's log cap is: 37 ms per megabyte, which
// is nothing at the 20 MB default and about 76 seconds on the 2 GB files a
// raised cap produces. Neither "always" nor "never" answers that, so the
// examiner decides per case.
//
// Measured on USB-LENOVO-Multi-USBs: 21,594 records, of which 17,618 are event
// 4907 — 82% of the file is audit-policy churn already on the exclusion list.
// The worthwhile part is 852 logons and 10 logoffs.
var optInChannels = map[string]string{
	"security": "holds logon and logoff records that place a person at the " +
		"console beside a device connection, and little else of use. It is " +
		"skipped unless -security is given, because it is capped at 20 MB by " +
		"default and organisations raise it — a 2 GB Security.evtx has been " +
		"seen in the field, and reading it costs about 76 seconds",
}

// ChannelOptIn reports whether a channel is read only on request, and why.
func ChannelOptIn(channel string) (string, bool) {
	reason, ok := optInChannels[strings.ToLower(channel)]
	return reason, ok
}

// OptInChannels names every channel a run has to ask for, sorted.
func OptInChannels() []string {
	names := make([]string, 0, len(optInChannels))
	for channel := range optInChannels {
		names = append(names, channel)
	}
	sort.Strings(names)
	return names
}

// ChannelRationale explains why a channel is not read, where the reason is
// recorded. The second return value is false where the channel was simply never
// considered, which is itself worth reporting.
func ChannelRationale(channel string) (string, bool) {
	for known, rationale := range unreadChannels {
		if strings.EqualFold(known, channel) {
			return rationale, true
		}
	}
	return "", false
}

// lookup finds the rule reading this record, if any.
//
// A rule naming the provider wins over one that does not, so a catch-all can
// sit beside a specific reading of the same id without shadowing it. A rule
// naming a *different* provider does not match at all: that is the whole point
// of the field, and falling back to it would report a UserModePowerService
// record as the operating system starting.
func lookup(channel, provider string, eventID int64) (*Rule, string, bool) {
	lowered := strings.ToLower(channel)
	var fallback *Rule
	for _, rule := range catalogue.byChannel[lowered][eventID] {
		if rule.Provider == "" {
			fallback = rule
			continue
		}
		if strings.EqualFold(rule.Provider, provider) {
			return rule, "", true
		}
	}
	if fallback != nil {
		return fallback, "", true
	}
	if rationale, ok := catalogue.excludedBy[lowered][eventID]; ok {
		return nil, rationale, false
	}
	return nil, "", false
}

// Channels lists every channel the catalogue reads, sorted.
func Channels() []string {
	seen := map[string]bool{}
	var names []string
	for _, rule := range rules {
		if !seen[rule.Channel] {
			seen[rule.Channel] = true
			names = append(names, rule.Channel)
		}
	}
	sort.Strings(names)
	return names
}

// Rules returns the catalogue, so it can be printed alongside a report.
// StateChangeChannels names the channels whose records say a device arrived or
// went away. A collection without them yields no connection windows, and that
// is a fact about the collection rather than about the devices.
func StateChangeChannels() []string {
	seen := map[string]bool{}
	var channels []string

	for _, rule := range rules {
		if rule.Kind != KindConnect && rule.Kind != KindDisconnect {
			continue
		}
		if !seen[rule.Channel] {
			seen[rule.Channel] = true
			channels = append(channels, rule.Channel)
		}
	}

	sort.Strings(channels)
	return channels
}

// SessionRules names the events that describe the host rather than a device,
// as "Provider event N" strings. Derived rather than written down: the
// capability catalogue quotes it, and a capability document that has drifted is
// worse than none because it is believed.
func SessionRules() []string {
	var named []string
	for _, rule := range rules {
		if rule.Kind != KindSession {
			continue
		}
		named = append(named, fmt.Sprintf("%s event %d", rule.Provider, rule.EventID))
	}
	sort.Strings(named)
	return named
}

func Rules() []Rule {
	copied := make([]Rule, len(rules))
	copy(copied, rules)
	return copied
}

// Exclusions returns the deliberate event-level exclusions.
func Exclusions() []Exclusion {
	copied := make([]Exclusion, len(exclusions))
	copy(copied, exclusions)
	return copied
}

// busTypeUSB is STORAGE_BUS_TYPE BusTypeUsb.
const busTypeUSB = "7"

// usbMiniport gates the storport channel, which reports no bus of its own.
func usbMiniport(fields []Field) bool {
	for _, field := range fields {
		if field.Name == "MiniportName" &&
			strings.EqualFold(strings.TrimSpace(field.Value), "USBSTOR") {
			return true
		}
	}
	return false
}

// problemCodes names the CM_PROB_ values that appear on a removable device, so
// a code can be reported as what it means rather than as a bare number.
var problemCodes = map[string]string{
	"21": "CM_PROB_WILL_BE_REMOVED",
	"22": "CM_PROB_DISABLED",
	"24": "CM_PROB_DEVICE_NOT_THERE",
	"28": "CM_PROB_FAILED_INSTALL",
	"43": "CM_PROB_FAILED_POST_START",
	"45": "CM_PROB_DEVICE_DISCONNECTED",
	"47": "CM_PROB_HELD_FOR_EJECT",
}

// ProblemName names a PnP problem code, returning the code itself where it is
// not one of the known values rather than inventing a description.
func ProblemName(code string) string {
	if name, ok := problemCodes[strings.TrimSpace(code)]; ok {
		return name
	}
	return code
}

// departureProblems are the problem codes that say the device is gone.
//
// Only two, and the line is drawn at "the device is no longer attached" rather
// than at "something is wrong with the device":
//
//	45  CM_PROB_DEVICE_DISCONNECTED  the device was disconnected. This is what
//	                                 a stick being pulled out looks like and is
//	                                 the code on every 420 in every reference
//	                                 collection.
//	24  CM_PROB_DEVICE_NOT_THERE     the device is not present. Windows writes
//	                                 it for a devnode whose hardware has gone.
//
// Everything else in problemCodes is a fault or a state and is not a
// departure. 22 (disabled) and 28 (failed install) describe a device that is
// still in the port; 43 (failed post-start) is a driver failing on a device
// that is present, and reading it as an unplug would end a connection window
// at the moment a driver crashed. 21 (will be removed) and 47 (held for eject)
// are the most tempting and are still refused: both say a removal has been
// *asked for*, not that it happened, and the removal itself writes its own
// record. Treating an intention as the act is how a window closes before the
// device actually left.
var departureProblems = map[string]bool{
	"45": true,
	"24": true,
}

// problemCodeDeparture decides what a Kernel-PnP 420 record evidences.
//
// A qualifying problem code makes it a departure. Anything else is a fault
// against the device: the record is kept, exported and put on the timeline,
// and it does not close a connection window. A record carrying no problem code
// at all is a fault too — the absence is not permission to assume the strongest
// reading.
func problemCodeDeparture(fields []Field) Kind {
	for _, field := range fields {
		if field.Role != RoleProblem {
			continue
		}
		if departureProblems[strings.TrimSpace(field.Value)] {
			return KindDisconnect
		}
	}
	return KindFault
}

// busTypes names the STORAGE_BUS_TYPE values seen on removable media.
var busTypes = map[string]string{
	"1": "SCSI", "2": "ATAPI", "3": "ATA", "4": "1394", "7": "USB",
	"8": "RAID", "9": "iSCSI", "10": "SAS", "11": "SATA", "12": "SD",
	"13": "MMC", "14": "virtual", "15": "file-backed virtual", "17": "NVMe",
}

// BusTypeName names a storage bus type, returning the value itself where it is
// not known.
func BusTypeName(value string) string {
	if name, ok := busTypes[strings.TrimSpace(value)]; ok {
		return name
	}
	return value
}
