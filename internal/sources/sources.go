// Package sources describes what Boobook is capable of reading and what each
// location yields.
//
// This is a capability document, not a record of a run: it answers "what can
// this tool do" without evidence in hand, which is the question asked when
// someone is deciding what to put in a triage profile, or reviewing the tool's
// scope before it goes near a case. What a particular run actually read, with
// hashes, is a different question and the manifest answers it.
//
// The lists that can be derived are derived — the event log channels from the
// selection catalogue, the enumerators from the registry package, the shell
// link directories from evidence discovery. A capability document that has
// drifted from the code is worse than none, so the parts that can be made
// incapable of drifting are.
package sources

import (
	"path/filepath"
	"strings"

	"github.com/Bloggzy/boobook/internal/eventlog"
	"github.com/Bloggzy/boobook/internal/evidence"
	"github.com/Bloggzy/boobook/internal/registry"
)

// Yield is one thing an analyst gets out of a source, and the place inside it
// that thing comes from.
type Yield struct {
	What  string
	Where string
}

// Source is one location Boobook reads.
type Source struct {
	// Class groups sources as an analyst would name them.
	Class string
	// Path is relative to a volume root. Where Pattern is set it is a shape
	// rather than a name, because discovery walks to find the real files and
	// how many there are depends on the host.
	Path    string
	Pattern bool
	Note    string
	Yields  []Yield
}

// Layout is a collection shape the evidence root may take.
type Layout struct {
	Name  string
	Shape string
}

// Layouts are the collection shapes discovery recognises. Detection is by
// probing for a Windows directory, not by trusting a name, so a collection
// that nests one of these inside another still resolves.
func Layouts() []Layout {
	return []Layout{
		{"Mounted volume or image", `<evidence>\Windows\...`},
		{"Velociraptor collection", `<evidence>\uploads\{auto,ntfs,lazy_ntfs,file}\<C%3A>\Windows\...`},
		{"KAPE collection", `<evidence>\<C>\Windows\...`},
	}
}

// All returns the catalogue.
func All() []Source {
	return []Source{
		{
			Class: "Registry — machine",
			Path:  `Windows\System32\config\SYSTEM`,
			Note: "transaction logs (.LOG1, .LOG2) are replayed where present, " +
				"so a hive captured on a running host is read as it would have " +
				"been after the next clean shutdown",
			Yields: []Yield{
				{"every USB and portable device the machine enumerated: instance and hardware ids, friendly name, manufacturer, container id and driver dates",
					`<ControlSet>\Enum\` + strings.Join(registry.Enumerators, ", ")},
				{"first install, most recent arrival and most recent removal, per device",
					"the device properties beneath each instance key"},
				{"drive letters and volume GUIDs mapped to an MBR disk signature and offset, or a GPT partition GUID",
					`MountedDevices`},
				{"the host time zone bias, which is what places every wall-clock timestamp in the case",
					`<ControlSet>\Control\TimeZoneInformation`},
				{"which control set the host last booted from, so the rest is read from the right one",
					`Select`},
			},
		},
		{
			Class: "Registry — machine",
			Path:  `Windows\System32\config\SOFTWARE`,
			Yields: []Yield{
				{"friendly names and volume labels recorded against a device",
					`Microsoft\Windows Portable Devices\Devices`},
				{"a volume serial number tied to a device in one key name — the only artefact that records both together, and so the only confirmed route from a file record to a device",
					`Microsoft\Windows NT\CurrentVersion\EMDMgmt`},
			},
			Note: "EMDMgmt is a ReadyBoost remnant and is absent on any current " +
				"Windows. Its absence is why the weaker attribution routes exist",
		},
		{
			Class:   "Registry — per user",
			Path:    `Users\<profile>\NTUSER.DAT`,
			Pattern: true,
			Yields: []Yield{
				{"the volumes this user mounted, by volume GUID and drive letter",
					`Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`},
				{"recently opened documents, overall and per file extension",
					`Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`},
				{"the open and save dialog's own lists: what was opened and where the user navigated, per file type and per application",
					`Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\{OpenSavePidlMRU, LastVisitedPidlMRU}`},
				{"shell bags for the network and virtual folder tree",
					`Software\Microsoft\Windows\{Shell, ShellNoRoam}\BagMRU`},
				{"what this user launched from the shell, with how many times it was run, how many times it came to the foreground and how long it was there — the per-user half of the execution picture, where prefetch is the per-machine half",
					`Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`},
			},
			Note: "UserAssist names are stored ROT13'd and are decoded. The " +
				"16-byte Windows XP record is not: its run count carries an " +
				"offset of five, and there is no XP evidence here to check a " +
				"reading against, so those values are kept whole and the row " +
				"says its counts were not decoded",
		},
		{
			Class:   "Registry — per user",
			Path:    `Users\<profile>\AppData\Local\Microsoft\Windows\UsrClass.dat`,
			Pattern: true,
			Yields: []Yield{
				{"shell bags for the local tree — folders browsed on a drive letter, with the shell item's own FAT timestamps",
					`Local Settings\Software\Microsoft\Windows\{Shell, ShellNoRoam}\BagMRU`},
			},
			Note: "the local tree is where a removable volume's folders are " +
				"recorded on any current Windows, which makes this hive the one " +
				"that matters for browsing activity",
		},
		{
			Class:   "Event logs",
			Path:    `Windows\System32\winevt\Logs\*.evtx`,
			Pattern: true,
			Yields: []Yield{
				{"device arrival and removal, driver installation and configuration, and volume mount and dismount — as recorded UTC instants, which is what a connection window is built from",
					strings.Join(eventlog.Channels(), ", ")},
				{"the disk layout a Partition/Diagnostic 1006 record carries: the MBR signature or the GPT partition GUIDs, decoded to tie a volume back to a physical disk",
					"Microsoft-Windows-Partition/Diagnostic"},
				{"who was logged on, and when they logged off — read only when asked for, and what -security is for: a stick arriving while a named account is interactively logged on says more than a stick arriving",
					"Security 4624, 4634, 4647, and 4800/4801 where the audit policy records them"},
				{"the host's own starts, shutdowns, sleeps and wakes — which name no device, and are what say whether a stretch with no records is a quiet host or no host, and whether a connection that never closed was a device pulled out unrecorded or a machine switched off with it still attached",
					strings.Join(eventlog.SessionRules(), ", ")},
			},
			Note: "-rules prints every selected event, the fields read from each, " +
				"and the events considered and rejected with the reasoning. " +
				"These channels are read only when asked for: " +
				strings.Join(eventlog.OptInChannels(), ", ") +
				" — pass -security. A run that skipped one says so in the " +
				"report's limitations, because the absence of a logon beside a " +
				"connection otherwise reads as evidence there was none",
		},
		{
			Class: "Driver install log",
			Path:  `Windows\INF\setupapi.dev.log`,
			Note: "rotated copies (setupapi.dev.<timestamp>.log) are read too. " +
				"These times are a local wall clock with no zone recorded, so " +
				"they are converted with the host bias and marked as converted",
			Yields: []Yield{
				{"the first time each device was installed, and the driver chosen for it",
					"device install sections"},
			},
		},
		{
			Class:   "Shell links",
			Path:    `Users\<profile>\<recent folders>\**\*.lnk`,
			Pattern: true,
			Note:    "the folders walked, beneath each profile, are: " + recentDirList(),
			Yields: []Yield{
				{"files opened from a drive letter, with the target's size and timestamps, the volume serial and label, and the recording machine's name",
					"the shortcut header, its LinkInfo block and its shell items"},
			},
		},
		{
			Class:   "Jump lists",
			Path:    `Users\<profile>\...\Recent\{AutomaticDestinations, CustomDestinations}\*.*-ms`,
			Pattern: true,
			Yields: []Yield{
				{"files opened per application, with access counts, pinned state and the order the application last put them in",
					"the DestList stream and the shortcuts embedded beside it"},
			},
			Note: "the application is identified by its AppID, which is left as " +
				"the hash it is: the published translation tables are incomplete " +
				"and a wrong application name is worse than none",
		},
		{
			Class:   "Prefetch",
			Path:    `Windows\Prefetch\*.pf`,
			Pattern: true,
			Yields: []Yield{
				{"which programmes ran, how many times, and when — the last eight executions of each, as recorded UTC instants",
					"the file information block"},
				{"the serial of every volume an execution touched, which is the same value a shell link records and joins to it without conversion, and the files the loader read from each",
					"the volume information block"},
			},
			Note: "prefetch is off by default on Windows Server and can be " +
				"disabled anywhere, so EnablePrefetcher is read from SYSTEM " +
				"alongside it: an empty Prefetch directory on a host that was " +
				"not prefetching says nothing about what ran. A prefetch record " +
				"says a programme ran, not that a person ran it, and the " +
				"eight-slot limit means a high run count beside two recorded " +
				"times is the ordinary case",
		},
	}
}

// NotRead names artefacts an analyst might reasonably expect and will not find,
// so that silence in the report is not read as absence in the evidence.
func NotRead() []string {
	return []string{
		"$MFT, $UsnJrnl and $LogFile — file system journals, which would date file activity independently of the shell artefacts",
		"SRUM — per-application network and resource use",
		"Volume Shadow Copies — earlier states of any of the above",
	}
}

// recentDirList renders the shell link directories as one brace expansion,
// taken from the list discovery actually walks.
func recentDirList() string {
	seen := map[string]bool{}
	var names []string
	for _, dir := range evidence.RecentDirs {
		name := filepath.Join(dir.Path...)
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
