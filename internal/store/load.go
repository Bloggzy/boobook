package store

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Bloggzy/boobook/internal/devid"
	"github.com/Bloggzy/boobook/internal/eventlog"
	"github.com/Bloggzy/boobook/internal/jumplist"
	"github.com/Bloggzy/boobook/internal/lnk"
	"github.com/Bloggzy/boobook/internal/partition"
	"github.com/Bloggzy/boobook/internal/prefetch"
	"github.com/Bloggzy/boobook/internal/provenance"
	"github.com/Bloggzy/boobook/internal/registry"
	"github.com/Bloggzy/boobook/internal/setupapi"
	"github.com/Bloggzy/boobook/internal/wintime"
)

// LoadLedger writes the provenance ledger: the sources, every observation, and
// every warning. This is the spine — the typed tables that follow are shaped for
// joining, but any fact in them can be traced through here to a file and a hash.
func (s *Store) LoadLedger(ledger *provenance.Ledger) error {
	sources := ledger.Sources()
	err := s.insert("source",
		"id,sequence,path,staged_path,artefact,size_bytes,sha256,read_at,replayed,"+
			"replay_logs,replay_note,modified_at,verified,verify_note",
		len(sources), func(add func(...any) error) error {
			for _, source := range sources {
				if err := add(source.ID, source.Sequence, source.Path, source.StagedPath,
					source.Artefact, source.SizeBytes, source.SHA256,
					source.ReadAt, source.Replayed,
					strings.Join(source.ReplayLogs, "; "), source.ReplayNote,
					source.ModifiedAt, source.Verified, source.VerifyNote,
				); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	observations := ledger.Observations()
	err = s.insert("observation",
		"id,source_id,kind,field,raw,value,summary,raw_timestamp,time_utc,"+
			"registry_key,registry_value,control_set,event_record_id,"+
			"channel,line_number,byte_offset",
		len(observations), func(add func(...any) error) error {
			for _, observation := range observations {
				locator := observation.Locator
				if err := add(observation.ID, observation.SourceID,
					observation.Kind, observation.Field,
					observation.Raw, observation.Value, observation.Summary,
					observation.RawTimestamp, observation.TimeUTC,
					locator.RegistryKey, locator.RegistryValue, locator.ControlSet,
					locator.EventRecordID, locator.Channel,
					locator.LineNumber, locator.ByteOffset,
				); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	warnings := ledger.Warnings()
	return s.insert("warning",
		"source_id,artefact,path,severity,message,recorded_at",
		len(warnings), func(add func(...any) error) error {
			for _, warning := range warnings {
				if err := add(warning.SourceID, warning.Artefact, warning.Path,
					warning.Severity, warning.Message, warning.At); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadDevnodes inserts device nodes read from a SYSTEM hive.
func (s *Store) LoadDevnodes(sourceID string, devnodes []registry.Devnode) error {
	return s.insert("devnode",
		"source_id,control_set,enumerator,device_id,instance_id,"+
			"device_instance_id,normalised_instance_id,device_key,registry_key,"+
			"raw_key_last_write,key_last_write_utc,"+
			"device_desc,friendly_name,mfg,class,class_guid,service,"+
			"container_id,parent_id_prefix,hardware_id,compatible_ids,"+
			"location_information,bus_reported_desc,"+
			"raw_install_date,install_date_utc,"+
			"raw_first_install_date,first_install_date_utc,"+
			"raw_last_arrival_date,last_arrival_date_utc,"+
			"raw_last_removal_date,last_removal_date_utc",
		len(devnodes), func(add func(...any) error) error {
			for _, devnode := range devnodes {
				activity := devnode.Activity
				registryKey := devnode.ControlSet + `\Enum\` + devnode.Enumerator +
					`\` + devnode.DeviceID + `\` + devnode.InstanceID

				if err := add(sourceID, devnode.ControlSet, devnode.Enumerator,
					devnode.DeviceID, devnode.InstanceID, devnode.DeviceInstanceID,
					devid.Normalise(devnode.DeviceInstanceID),
					devid.Key(devnode.DeviceInstanceID), registryKey,
					devnode.RawKeyLastWrite, devnode.KeyLastWriteUTC,
					devnode.DeviceDesc, devnode.FriendlyName, devnode.Mfg,
					devnode.Class, devnode.ClassGUID, devnode.Service,
					devnode.ContainerID, devnode.ParentIDPrefix, devnode.HardwareID,
					devnode.CompatibleIDs, devnode.LocationInformation,
					devnode.BusReportedDesc,
					activity.RawInstallDate, activity.InstallDate,
					activity.RawFirstInstallDate, activity.FirstInstallDate,
					activity.RawLastArrivalDate, activity.LastArrivalDate,
					activity.RawLastRemovalDate, activity.LastRemovalDate,
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadTimeZone records the host time zone the run read.
//
// The biases are stored and no converted timestamp is, so a local wall clock in
// a shell item can be offered as both seasonal readings at query time rather
// than being resolved to one here.
func (s *Store) LoadTimeZone(sourceID, controlSet string, zone registry.TimeZone) error {
	if !zone.Found {
		return nil
	}
	return s.insert("host_time_zone",
		"source_id,registry_key,control_set,key_name,standard_name,daylight_name,"+
			"bias_minutes,standard_bias_minutes,daylight_bias_minutes,"+
			"active_bias_minutes,standard_start_month,daylight_start_month,"+
			"dynamic_daylight_disabled",
		1, func(add func(...any) error) error {
			return add(sourceID,
				controlSet+`\Control\TimeZoneInformation`, controlSet,
				zone.KeyName, zone.StandardName, zone.DaylightName,
				zone.BiasMinutes, zone.StandardBiasMinutes,
				zone.DaylightBiasMinutes, zone.ActiveBiasMinutes,
				zone.StandardStartMonth, zone.DaylightStartMonth,
				zone.DynamicDaylightDisabled)
		})
}

// LoadMountEntries inserts MountedDevices values.
func (s *Store) LoadMountEntries(sourceID string, entries []registry.MountEntry) error {
	return s.insert("mount_entry",
		"source_id,value_name,kind,drive_letter,volume_guid,target_kind,"+
			"device_path,device_instance_id,device_key,partition_guid,"+
			"target_volume_guid,target_offset_hex,disk_signature,"+
			"partition_offset,raw",
		len(entries), func(add func(...any) error) error {
			for _, entry := range entries {
				if err := add(sourceID, entry.ValueName, string(entry.Kind),
					entry.DriveLetter, entry.VolumeGUID, string(entry.TargetKind),
					entry.DevicePath, entry.DeviceInstanceID,
					devid.Key(entry.DeviceInstanceID), entry.PartitionGUID,
					entry.TargetVolumeGUID, entry.TargetOffsetHex,
					uint64(entry.DiskSignature), entry.PartitionOffset, entry.Raw,
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadPortableDevices inserts the Windows Portable Devices list.
func (s *Store) LoadPortableDevices(sourceID string, devices []registry.PortableDevice) error {
	return s.insert("portable_device",
		"source_id,registry_path,key_name,friendly_name,"+
			"device_instance_id,device_key,volume_guid,volume_offset_hex",
		len(devices), func(add func(...any) error) error {
			for _, device := range devices {
				if err := add(sourceID, device.RegistryPath, device.KeyName,
					device.FriendlyName, device.DeviceInstanceID,
					devid.Key(device.DeviceInstanceID),
					device.VolumeGUID, device.VolumeOffsetHex,
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadEMDVolumes inserts the ReadyBoost volume records.
func (s *Store) LoadEMDVolumes(sourceID string, entries []registry.EMDMgmtEntry) error {
	return s.insert("emd_volume",
		"source_id,registry_path,key_name,volume_label,volume_serial_decimal,"+
			"device_instance_id,device_key",
		len(entries), func(add func(...any) error) error {
			for _, entry := range entries {
				if err := add(sourceID, entry.RegistryPath, entry.KeyName,
					entry.VolumeLabel, entry.VolumeSerialDecimal,
					entry.DeviceInstanceID,
					devid.Key(entry.DeviceInstanceID)); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadMountPoints inserts per-profile volume awareness.
func (s *Store) LoadMountPoints(sourceID string, mountPoints []registry.MountPoint) error {
	return s.insert("mount_point",
		"source_id,profile,registry_path,key_name,kind,drive_letter,"+
			"volume_guid,remote_path,raw_key_last_write,key_last_write_utc",
		len(mountPoints), func(add func(...any) error) error {
			for _, mountPoint := range mountPoints {
				if err := add(sourceID, mountPoint.Profile, mountPoint.RegistryPath,
					mountPoint.KeyName, string(mountPoint.Kind),
					mountPoint.DriveLetter, mountPoint.VolumeGUID,
					mountPoint.RemotePath, mountPoint.RawKeyLastWrite,
					mountPoint.KeyLastWriteUTC,
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// Disk is a disk as one Partition/Diagnostic record described it.
type Disk struct {
	SourceID         string
	SourceFile       string
	RecordID         uint64
	TimeUTC          time.Time
	DeviceInstanceID string
	DiskNumber       string
	Model            string
	Manufacturer     string
	SerialNumber     string
	BusType          string
	Capacity         string

	Layout *partition.Layout
	// BootRecordSignature is read from the boot record sector, separately from
	// the layout structure. Two readings of the same fact that can be compared
	// are worth more than one that has to be trusted.
	BootRecordSignature uint64
	Warnings            []string
}

// DisksFromEvents decodes the disk layout structures carried by the selected
// Partition/Diagnostic records.
//
// A record whose bytes do not decode contributes a warning and no disk. The
// alternative — reading at a guessed offset — produces partition identifiers
// that look real and match nothing, which is worse than an absence.
func DisksFromEvents(sourceByPath map[string]string,
	records []eventlog.Record) []Disk {

	var disks []Disk

	for _, record := range records {
		layoutHex := record.Value(eventlog.RoleDiskLayout)
		bootHex := record.Value(eventlog.RoleBootRecord)
		if layoutHex == "" && bootHex == "" {
			continue
		}

		disk := Disk{
			SourceID:         sourceByPath[record.SourceFile],
			SourceFile:       record.SourceFile,
			RecordID:         record.RecordID,
			TimeUTC:          record.TimeUTC,
			DeviceInstanceID: record.DeviceInstanceID(),
			DiskNumber:       record.Value(eventlog.RoleDiskNumber),
			Model:            record.Value(eventlog.RoleProduct),
			Manufacturer:     record.Value(eventlog.RoleVendor),
			SerialNumber:     record.Value(eventlog.RoleSerial),
			BusType:          record.Value(eventlog.RoleBusType),
			Capacity:         record.Value(eventlog.RoleCapacity),
		}

		if sector, err := hex.DecodeString(bootHex); err == nil {
			if signature, ok := partition.MBRSignature(sector); ok {
				disk.BootRecordSignature = uint64(signature)
			}
		}

		if raw, err := hex.DecodeString(layoutHex); err == nil && len(raw) > 0 {
			layout, err := partition.DecodeLayout(raw)
			if err != nil {
				disk.Warnings = append(disk.Warnings,
					"drive layout did not decode: "+err.Error())
			} else {
				disk.Layout = layout
				disk.Warnings = append(disk.Warnings, layout.Warnings...)
			}
		}

		disks = append(disks, disk)
	}

	return disks
}

// LoadDisks inserts decoded disk layouts and their partitions.
func (s *Store) LoadDisks(disks []Disk) error {
	err := s.insert("disk_layout",
		"source_id,source_file,record_id,time_utc,device_instance_id,device_key,"+
			"disk_number,model,manufacturer,serial_number,bus_type,capacity,"+
			"style,disk_guid,disk_signature,boot_record_signature,"+
			"partition_count,warnings",
		len(disks), func(add func(...any) error) error {
			for _, disk := range disks {
				style, diskGUID := "", ""
				var signature uint64
				count := 0
				if disk.Layout != nil {
					style = string(disk.Layout.Style)
					diskGUID = disk.Layout.DiskGUID
					signature = uint64(disk.Layout.DiskSignature)
					count = disk.Layout.PartitionCount
				}

				if err := add(disk.SourceID, disk.SourceFile, disk.RecordID,
					disk.TimeUTC, disk.DeviceInstanceID,
					devid.Key(disk.DeviceInstanceID),
					disk.DiskNumber, disk.Model, disk.Manufacturer,
					disk.SerialNumber, disk.BusType, disk.Capacity,
					style, diskGUID, signature, disk.BootRecordSignature,
					count, strings.Join(disk.Warnings, "; "),
				); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	partitions := 0
	for _, disk := range disks {
		if disk.Layout != nil {
			partitions += len(disk.Layout.Partitions)
		}
	}

	return s.insert("disk_partition",
		"source_id,record_id,device_key,disk_number,partition_number,"+
			"starting_offset,length_bytes,partition_guid,type_guid,"+
			"partition_name,mbr_type",
		partitions, func(add func(...any) error) error {
			for _, disk := range disks {
				if disk.Layout == nil {
					continue
				}
				for _, entry := range disk.Layout.Partitions {
					if err := add(disk.SourceID, disk.RecordID,
						devid.Key(disk.DeviceInstanceID), disk.DiskNumber,
						entry.Number, entry.StartingOffset, entry.Length,
						entry.PartitionGUID, entry.TypeGUID, entry.Name,
						uint64(entry.MBRType),
					); err != nil {
						return err
					}
				}
			}
			return nil
		})
}

// LoadShellBags inserts the folders a user's Explorer recorded displaying.
func (s *Store) LoadShellBags(sourceID string, bags []registry.ShellBag) error {
	return s.insert("shell_bag",
		"source_id,hive,profile,path,path_has_gap,name,kind,drive_letter,"+
			"depth,node_slot,mru_position,raw_modified,raw_created,raw_accessed,"+
			"modified_local,created_local,accessed_local,mft_entry,mft_sequence,"+
			"registry_path,raw_key_last_write,key_last_write_utc,raw,warnings",
		len(bags), func(add func(...any) error) error {
			for _, bag := range bags {
				if err := add(sourceID, bag.Hive, bag.Profile,
					bag.Path, bag.PathHasGap, bag.Name, bag.Kind, bag.DriveLetter,
					bag.Depth, uint64(bag.NodeSlot), bag.MRUPosition,
					uint64(bag.RawModified), uint64(bag.RawCreated),
					uint64(bag.RawAccessed),
					localTime(bag.ModifiedLocal), localTime(bag.CreatedLocal),
					localTime(bag.AccessedLocal),
					bag.MFTEntry, uint64(bag.MFTSequence),
					bag.RegistryPath, bag.RawKeyLastWrite, bag.KeyLastWriteUTC,
					bag.Raw, strings.Join(bag.Warnings, "; "),
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadMRUEntries inserts RecentDocs and file dialog MRU entries.
func (s *Store) LoadMRUEntries(sourceID string, entries []registry.MRUEntry) error {
	return s.insert("mru_entry",
		"source_id,profile,source_list,kind,name,path,path_has_gap,"+
			"drive_letter,letter_from_name,volume_label,"+
			"position,value_name,raw_modified,modified_local,"+
			"registry_path,raw_key_last_write,key_last_write_utc,raw,warnings",
		len(entries), func(add func(...any) error) error {
			for _, entry := range entries {
				if err := add(sourceID, entry.Profile, entry.Source, entry.Kind,
					entry.Name, entry.Path, entry.PathHasGap, entry.DriveLetter,
					entry.LetterFromName, entry.VolumeLabel,
					entry.Position, entry.ValueName,
					uint64(entry.RawModified), localTime(entry.ModifiedLocal),
					entry.RegistryPath, entry.RawKeyLastWrite,
					entry.KeyLastWriteUTC, entry.Raw,
					strings.Join(entry.Warnings, "; "),
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadEvents inserts selected event log records and their named fields.
//
// sourceByPath maps an event log path to the source record for it. A record
// from a file with no source is not loaded: nothing read from an unhashed file
// can be attested to.
func (s *Store) LoadEvents(sourceByPath map[string]string, records []eventlog.Record) error {
	err := s.insert("event",
		"source_id,channel,source_file,record_id,event_id,provider,"+
			"raw_file_time,time_utc,rule_id,kind,meaning,"+
			"device_instance_id,device_key",
		len(records), func(add func(...any) error) error {
			for _, record := range records {
				sourceID, ok := sourceByPath[record.SourceFile]
				if !ok {
					continue
				}
				instanceID := record.DeviceInstanceID()
				if err := add(sourceID, record.Channel, record.SourceFile,
					record.RecordID, record.EventID, record.Provider,
					record.RawFileTime, record.TimeUTC,
					record.RuleID, string(record.Kind), record.Meaning,
					instanceID, devid.Key(instanceID),
				); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	fields := 0
	for _, record := range records {
		fields += len(record.Fields)
	}

	return s.insert("event_field",
		"source_id,source_file,record_id,name,role,value,path",
		fields, func(add func(...any) error) error {
			for _, record := range records {
				sourceID, ok := sourceByPath[record.SourceFile]
				if !ok {
					continue
				}
				for _, field := range record.Fields {
					if err := add(sourceID, record.SourceFile, record.RecordID,
						field.Name, string(field.Role), field.Value, field.Path,
					); err != nil {
						// Naming the record and field turns a bind failure into
						// something an examiner can look at in the evidence.
						return fmt.Errorf("%w (%s record %d, field %s=%q)",
							err, record.Channel, record.RecordID, field.Name, field.Value)
					}
				}
			}
			return nil
		})
}

// LoadSetupSections inserts device install sections.
//
// Both seasonal readings of the local timestamp are stored, with the ambiguity
// flagged. Picking one would present a guess as a measurement.
func (s *Store) LoadSetupSections(sourceID string, sections []setupapi.Section) error {
	return s.insert("setup_section",
		"source_id,source_file,line_number,operation,kind,target,"+
			"device_instance_id,device_key,start_local,end_local,"+
			"start_utc,start_utc_alt,start_basis,time_ambiguous,"+
			"exit_status,parent_device,driver_inf,class_guid,problem",
		len(sections), func(add func(...any) error) error {
			for _, section := range sections {
				start, alternate, basis := seasonalReadings(section.StartUTC)

				if err := add(sourceID, section.SourceFile, section.LineNumber,
					section.Operation, string(section.Kind), section.Target,
					section.DeviceInstanceID, devid.Key(section.DeviceInstanceID),
					section.StartLocal, section.EndLocal,
					start, alternate, basis, len(section.StartUTC) > 1,
					section.ExitStatus, section.ParentDevice, section.DriverINF,
					section.ClassGUID, section.Problem,
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// seasonalReadings splits the candidate conversions into the first reading, the
// alternative, and the basis of the first. With no host time zone there is no
// reading at all, and a NULL says that where a fabricated UTC value would not.
func seasonalReadings(candidates []wintime.SeasonalCandidate) (
	start, alternate *time.Time, basis string) {

	if len(candidates) > 0 {
		value := candidates[0].UTC
		start = &value
		basis = candidates[0].Basis
	}
	if len(candidates) > 1 {
		value := candidates[1].UTC
		alternate = &value
		basis = candidates[0].Basis + " / " + candidates[1].Basis
	}
	return start, alternate, basis
}

// FileTarget is one file access recorded by a shell link or a jump list.
//
// Whether the target sat on removable media is the recording application's own
// statement, carried through as that. Which device held the drive letter is a
// separate question this row does not answer.
type FileTarget struct {
	SourceID    string
	SourceFile  string
	Origin      string
	AppID       string
	Profile     string
	StreamName  string
	Path        string
	DriveLetter string

	VolumePresent   bool
	DriveType       string
	VolumeSerialHex string
	VolumeLabel     string
	Removable       bool

	RawTargetWritten  uint64
	TargetWrittenUTC  *time.Time
	RawTargetAccessed uint64
	TargetAccessedUTC *time.Time
	TargetCreatedUTC  *time.Time
	TargetSizeBytes   int64
	MachineID         string

	DestListPresent bool
	EntryNumber     int64
	MRUPosition     int
	// AccessCount is nil where the DestList entry records none, which is not
	// the same claim as a count of zero.
	AccessCount  *int64
	RankingValue *float64
	// Pinned is nil where the entry's pin status could not be read, which is
	// not the same claim as an entry that is not pinned.
	Pinned        *bool
	RawLastAccess uint64
	LastAccessUTC *time.Time
	// SourceModifiedUTC is the artefact file's own last-written time. For a
	// shortcut in a shell-maintained directory it is when the target was most
	// recently opened; for a jump list it dates the newest entry in the file
	// and not this one, so it is carried for shortcuts alone.
	SourceModifiedUTC *time.Time
	// LinkContext is the shortcut directory this file came from, which is what
	// decides whether SourceModifiedUTC timed an opening at all. Carried as
	// the fact; v_file_activity draws the conclusion.
	LinkContext string

	// What the link's shell items named, kept apart from what LinkInfo did.
	TargetItemPath string
	// The shell link's StringData, stored as recorded. RelativePath is the one
	// that matters: a link can carry it and no LinkInfo at all, and discarding
	// it left the row with a drive letter and no target.
	RelativePath            string
	WorkingDir              string
	Arguments               string
	IconLocation            string
	TargetItemModifiedLocal string
	MFTEntry                uint64
	MFTSequence             uint64

	ParseWarnings string
}

// localTime renders a FAT timestamp as the wall clock it recorded. It is a
// string and not a TIMESTAMP because it is not an instant: nothing beside it
// says which offset was in force, and a column an analyst can sort against UTC
// event times would invite exactly that mistake.
func localTime(moment *time.Time) string {
	if moment == nil {
		return ""
	}
	return moment.Format("2006-01-02 15:04:05")
}

// FromLink builds a target row from a shell link.
func FromLink(sourceID, sourceFile, profile string, link *lnk.Link) FileTarget {
	return FileTarget{
		SourceID:   sourceID,
		SourceFile: sourceFile,
		Origin:     "shell_link",
		Profile:    profile,
		// The base and the suffix together: MS-SHLLINK splits one path across
		// two fields and the base alone names the folder, not the file.
		Path:              link.FullPath(),
		DriveLetter:       link.DriveLetter,
		VolumePresent:     link.VolumeIDPresent,
		DriveType:         driveTypeOf(link),
		VolumeSerialHex:   volumeSerialOf(link),
		VolumeLabel:       link.VolumeLabel,
		Removable:         link.Removable(),
		RawTargetWritten:  link.RawTargetWritten,
		TargetWrittenUTC:  link.TargetWritten,
		RawTargetAccessed: link.RawTargetAccessed,
		TargetAccessedUTC: link.TargetAccessed,
		TargetCreatedUTC:  link.TargetCreated,
		TargetSizeBytes:   int64(link.TargetSizeBytes),
		MachineID:         link.MachineID,

		TargetItemPath:          link.TargetPath,
		RelativePath:            link.RelativePath,
		WorkingDir:              link.WorkingDir,
		Arguments:               link.Arguments,
		IconLocation:            link.IconLocation,
		TargetItemModifiedLocal: localTime(link.TargetItemModifiedLocal),
		MFTEntry:                link.MFTEntry,
		MFTSequence:             uint64(link.MFTSequence),

		ParseWarnings: strings.Join(link.Warnings, "; "),
	}
}

// FromJumpEntry builds a target row from a jump list entry.
func FromJumpEntry(sourceID, sourceFile, profile string, entry jumplist.Entry) FileTarget {
	target := FileTarget{
		SourceID:        sourceID,
		SourceFile:      sourceFile,
		Origin:          "jump_list",
		AppID:           entry.AppID,
		Profile:         profile,
		StreamName:      entry.StreamName,
		Path:            entry.RecordedPath,
		MachineID:       entry.MachineID,
		DestListPresent: entry.Present,
		RawLastAccess:   entry.RawLastAccess,
		LastAccessUTC:   entry.LastAccessUTC,
	}

	if entry.Present {
		target.EntryNumber = int64(entry.EntryNumber)
		target.MRUPosition = entry.Position
		if entry.AccessCountRecorded {
			count := int64(entry.AccessCount)
			target.AccessCount = &count
		}
		ranking := float64(entry.RankingValue)
		target.RankingValue = &ranking
		if entry.PinnedRecorded {
			pinned := entry.Pinned
			target.Pinned = &pinned
		}
	}

	if entry.Link != nil {
		link := entry.Link
		if path := link.FullPath(); path != "" {
			target.Path = path
		}
		target.DriveLetter = link.DriveLetter
		target.VolumePresent = link.VolumeIDPresent
		target.DriveType = driveTypeOf(link)
		target.VolumeSerialHex = volumeSerialOf(link)
		target.VolumeLabel = link.VolumeLabel
		target.Removable = link.Removable()
		target.RawTargetWritten = link.RawTargetWritten
		target.TargetWrittenUTC = link.TargetWritten
		target.RawTargetAccessed = link.RawTargetAccessed
		target.TargetAccessedUTC = link.TargetAccessed
		target.TargetCreatedUTC = link.TargetCreated
		target.TargetSizeBytes = int64(link.TargetSizeBytes)
		target.TargetItemPath = link.TargetPath
		target.RelativePath = link.RelativePath
		target.WorkingDir = link.WorkingDir
		target.Arguments = link.Arguments
		target.IconLocation = link.IconLocation
		target.TargetItemModifiedLocal = localTime(link.TargetItemModifiedLocal)
		target.MFTEntry = link.MFTEntry
		target.MFTSequence = uint64(link.MFTSequence)
		target.ParseWarnings = strings.Join(link.Warnings, "; ")
	}

	return target
}

// A link that carried no volume information said nothing about the media, and
// an empty column says that where "fixed" would be an invention.
func driveTypeOf(link *lnk.Link) string {
	if !link.VolumeIDPresent {
		return ""
	}
	return lnk.DriveTypeName(link.DriveType)
}

func volumeSerialOf(link *lnk.Link) string {
	if !link.VolumeIDPresent {
		return ""
	}
	return lnk.SerialHex(link.DriveSerialNumber)
}

// LoadPrefetchSetting records whether the host was prefetching.
//
// It is written even when the value was absent, because "the value was not
// there" is itself the answer the coverage section needs: the default applies,
// and the default records launches.
func (s *Store) LoadPrefetchSetting(sourceID string,
	setting registry.PrefetchSetting) error {

	return s.insert("host_prefetch_setting",
		"source_id,registry_key,control_set,value_found,raw_value,description",
		1, func(add func(...any) error) error {
			return add(sourceID, setting.RegistryKey, setting.ControlSet,
				setting.Found, uint64(setting.Value), setting.Describe())
		})
}

// LoadPrefetchRuns inserts prefetch files and everything they carried.
//
// Four tables from one slice, because a run is one row but its executions,
// volumes and loaded files are each many. They join on source_file, which is
// the path of the .pf and so resolves through the ledger to a hash.
func (s *Store) LoadPrefetchRuns(runs []*prefetch.Run, sourceIDs map[string]string) error {
	err := s.insert("prefetch_run",
		"source_id,source_file,executable,executable_path,path_hash,"+
			"format_version,run_count,times_recorded,volume_count,file_count,"+
			"parse_warnings",
		len(runs), func(add func(...any) error) error {
			for _, run := range runs {
				if err := add(sourceIDs[run.SourceFile], run.SourceFile,
					run.Executable, run.ExecutablePath, run.PathHash,
					run.Version, uint64(run.RunCount), len(run.RunTimes),
					len(run.Volumes), len(run.Files),
					strings.Join(run.Warnings, "; "),
				); err != nil {
					return err
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	executions := 0
	volumes := 0
	files := 0
	for _, run := range runs {
		executions += len(run.RunTimes)
		volumes += len(run.Volumes)
		files += len(run.Files)
	}

	err = s.insert("prefetch_execution",
		"source_id,source_file,executable,slot,time_utc",
		executions, func(add func(...any) error) error {
			for _, run := range runs {
				for i, when := range run.RunTimes {
					// Slot 1 is the most recent, which is the order the file
					// stores them in and the order the parser preserved.
					if err := add(sourceIDs[run.SourceFile], run.SourceFile,
						run.Executable, i+1, when); err != nil {
						return err
					}
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	err = s.insert("prefetch_volume",
		"source_id,source_file,executable,device_path,volume_serial_hex,"+
			"raw_serial,created_utc",
		volumes, func(add func(...any) error) error {
			for _, run := range runs {
				for _, volume := range run.Volumes {
					if err := add(sourceIDs[run.SourceFile], run.SourceFile,
						run.Executable, volume.DevicePath, volume.SerialHex,
						uint64(volume.RawSerial), volume.CreatedUTC); err != nil {
						return err
					}
				}
			}
			return nil
		})
	if err != nil {
		return err
	}

	return s.insert("prefetch_file",
		"source_id,source_file,executable,path",
		files, func(add func(...any) error) error {
			for _, run := range runs {
				for _, path := range run.Files {
					if err := add(sourceIDs[run.SourceFile], run.SourceFile,
						run.Executable, path); err != nil {
						return err
					}
				}
			}
			return nil
		})
}

// LoadFileTargets inserts shell link and jump list file records.
func (s *Store) LoadFileTargets(targets []FileTarget) error {
	return s.insert("file_target",
		"source_id,source_file,origin,app_id,profile,stream_name,path,"+
			"drive_letter,volume_present,drive_type,volume_serial_hex,"+
			"volume_label,removable,raw_target_written,target_written_utc,"+
			"raw_target_accessed,target_accessed_utc,target_created_utc,"+
			"target_size_bytes,machine_id,target_item_path,"+
			"relative_path,working_dir,arguments,icon_location,"+
			"target_item_modified_local,mft_entry,mft_sequence,"+
			"destlist_present,entry_number,"+
			"mru_position,access_count,destlist_ranking_value,pinned,"+
			"source_modified_utc,link_context,"+
			"raw_last_access,last_access_utc,"+
			"parse_warnings",
		len(targets), func(add func(...any) error) error {
			for _, target := range targets {
				if err := add(target.SourceID, target.SourceFile, target.Origin,
					target.AppID, target.Profile, target.StreamName, target.Path,
					target.DriveLetter, target.VolumePresent, target.DriveType,
					target.VolumeSerialHex, target.VolumeLabel, target.Removable,
					target.RawTargetWritten, target.TargetWrittenUTC,
					target.RawTargetAccessed, target.TargetAccessedUTC,
					target.TargetCreatedUTC, target.TargetSizeBytes,
					target.MachineID, target.TargetItemPath,
					target.RelativePath, target.WorkingDir,
					target.Arguments, target.IconLocation,
					target.TargetItemModifiedLocal,
					target.MFTEntry, target.MFTSequence,
					target.DestListPresent, target.EntryNumber,
					target.MRUPosition, target.AccessCount,
					target.RankingValue, target.Pinned,
					target.SourceModifiedUTC, target.LinkContext,
					target.RawLastAccess, target.LastAccessUTC,
					target.ParseWarnings,
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// LoadUserAssist inserts the shell's record of what a user launched.
func (s *Store) LoadUserAssist(sourceID string, entries []registry.UserAssist) error {
	return s.insert("user_assist",
		"source_id,profile,category,category_name,name,drive_letter,"+
			"run_count,focus_count,focus_seconds,raw_last_executed,"+
			"last_executed_utc,bookkeeping,value_name,registry_path,raw,warnings",
		len(entries), func(add func(...any) error) error {
			for _, entry := range entries {
				if err := add(sourceID, entry.Profile, entry.Category,
					entry.CategoryName, entry.Name, entry.DriveLetter,
					uint64(entry.RunCount), uint64(entry.FocusCount),
					entry.FocusTime.Seconds(), entry.RawLastExecuted,
					entry.LastExecutedUTC, entry.Bookkeeping, entry.ValueName,
					entry.RegistryPath, entry.Raw,
					strings.Join(entry.Warnings, "; "),
				); err != nil {
					return err
				}
			}
			return nil
		})
}
