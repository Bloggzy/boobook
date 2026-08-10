# Boobook: the project plan

**Status:** historical. This is the design record that produced the tool, kept
because the reasoning in it (why Boodie's architecture was inverted, why
correlation is labelled rather than gated, why every output is a copy of a view)
is still the reasoning the tool runs on, and is set out here at more length
than anywhere else.

It is **not** a description of the tool as it stands, and it is not the place to
check what the code does. Phases 0 to 3 are complete and phase 4 is open; a
great many decisions have been taken since, several of them reversing something
below after it met real evidence. Where this document and
the code disagree, the code is right and this is what was
thought at the time.

**Date:** 2026-08-01
**Predecessor:** Boodie (Python), `C:\Tools\Boodie`

---

## 1. What Boobook is

A fast, offline, read-only tool that reads a Windows evidence set, either a
triage collection (Velociraptor/KAPE) or a mounted volume, and answers, in one
report an analyst can read in five minutes:

> Which USB devices did this machine see, which of them matter, when were they
> connected, and what file activity can be tied to them?

Everything it says is traceable to a named source artefact. Everything it
extracts is also written as data files an analyst can pivot on.

---

## 2. Why Boodie did not deliver, and what changes

Boodie is not a failed tool. It is a rigorous one whose **information
architecture is inverted**, and whose **correlation is gated too tightly**. The
knowledge in it is the most valuable input Boobook has. Five specific problems
drive the redesign.

### 2.1 The report leads with epistemology instead of answers

Boodie's output is a top level plus `Details/` holding ~20 files named after
*join mechanics*: `Device-Disk-Signature-Links`, `Device-Volume-GUID-Links`,
`Volume-Serial-Links`, `UMDF-Driver-Host-Lifetimes`. Fields are named
`episode_bounds`, `file_context_scope`, `open_end_evidence_state`. An analyst
must learn Boodie's ontology before they can read a finding.

**Change:** the report is organised by the analyst's questions, not by the
tool's internal joins. Detail files are named for what they contain
(`devices.csv`, `connections.csv`, `file-activity.csv`), and the mechanism
lives in a column, not in the filename. Qualification moves from the headline
into a confidence column and a footnote.

### 2.2 Purity gating produces empty answers

The highest-value output, drive letter → file activity, is only emitted when
a complete USBSTOR instance ID is embedded in `MountedDevices`, or an MBR disk
signature matches. The GPT path is documented as blocked. The `RegistryId` path
is documented as blocked. Both are blocked on *substantiation*, which is
intellectually correct and investigatively useless: the analyst gets nothing
where a weaker-but-real inference existed.

**Change:** Boobook never suppresses a correlation for being weak. It emits it
with an explicit `link_method` and `confidence`
(`confirmed` / `strong` / `probable` / `possible`). The report shows
`confirmed`/`strong` inline, and collapses `probable`/`possible` behind a
"weaker associations" disclosure with the reasoning shown. The evidential
discipline is preserved by *labelling*, not by *withholding*.

### 2.3 No investigative tiering

Boodie splits the world into "USBSTOR storage inventory" and "everything else".
`windows_usb_device_investigative_priority.md` describes 18 investigative
categories across 3 tiers, and none of it is implemented.

**Change:** a real classification engine (§5) is a first-class component, and
tier drives report placement directly.

### 2.4 Devnode-centric, not device-centric

Physical grouping exists internally but the outputs still speak in devnodes and
episodes. An analyst thinks "the SanDisk stick", not "the USBSTOR devnode and
its SCSI sibling and their shared container".

**Change:** the unit of the report is the **physical device**. Devnodes are a
drill-down.

### 2.5 Speed and packaging

Python plus `python-evtx` makes `Security.evtx` an hour-scale job. Delivery is a
PyInstaller one-dir bundle that needs its `_internal` folder, gets
mark-of-the-web blocked, and draws EDR attention.

**Change:** compiled language, single static binary (§3).

---

## 3. Stack

### Recommendation: Go + embedded DuckDB, single static binary

**Language: Go.**

- Velociraptor's forensic parsers are Go, Apache-2.0, and proven at scale
  against exactly these artefacts: `regparser` (registry hives), `evtx`,
  `go-ntfs` (`$MFT`, `$UsnJrnl:$J`), `go-prefetch`. These are the same parsers
  that run inside Velociraptor collections in production DFIR work.
- A single static `Boobook.exe` with no runtime, no `_internal` folder, no
  Visual C++ redistributable. This deletes an entire class of deployment pain
  that Boodie's own README spends three paragraphs on.
- Trivial parallelism: one goroutine per artefact, bounded worker pool. The
  233 event logs in the sample collection parse concurrently.
- It matches the existing stack (Firetail-Go is Go 1.26 + DuckDB + Wails), so
  conventions, build scripts and reviewer familiarity carry across.

**Correlation engine: embedded DuckDB.**

Parsers emit rows; correlation is SQL. This follows the established pattern of
pushing logic into SQL rather than Go loops. Concretely it buys:

- Joins across registry / EVTX / LNK / MountedDevices expressed declaratively
  rather than as hand-rolled map-of-slices code, which is where Boodie's
  2,839-line `analysis.py` came from.
- The report and the CSV exports are generated **from the same SQL views**, so
  they cannot disagree. Boodie needed a dedicated regression test for exactly
  this class of contradiction.
- A `case.duckdb` handed to the analyst as a queryable artefact alongside the
  CSVs, at zero extra cost.
- Free Parquet/CSV/JSON export.

**The honest alternative is Rust.** `notatin` (registry, *with* transaction-log
replay) and `omerbenamram/evtx` are the strongest DFIR parsers in any language,
and Rust would be faster still. It is not recommended because Go is already an
order of magnitude past the performance requirement, and Rust costs
significantly more development time in an ecosystem the rest of the toolchain
does not share.

### Registry transaction-log replay: resolved by Phase 0

**Superseded.** This was flagged as the largest technical unknown on the
assumption that `regparser` had no replay. It does:

```go
func RecoverHive(hive *os.File, logFiles ...*os.File) (*os.File, error)
```

It copies the hive, applies dirty pages from the logs in sequence order, skips a
log whose sequence number does not follow the base, and corrects the header
checksum. Verified against all four sample collections. The source file is only
ever read and the recovered copy is ours to delete, which is the staging
contract this plan requires.

One Phase 1 refinement: `RecoverHive` writes its copy to `os.TempDir()`. Boobook
must place it under the caller's working root instead, so a run's staged evidence
sits in one controlled location. Either set the process temp directory or vendor
the function, which is small and known.

We still do not silently parse a dirty hive as if it were clean: the run reports
whether replay succeeded either way.

### Performance target (a gate, not an aspiration)

Phase 0 must demonstrate, on `C:\Source\USB-LENOVO-SANDISK-LATER`
(SOFTWARE 95 MB, SYSTEM 20 MB, Security.evtx 21 MB, 233 EVTX files):

> **Full parse of every USB-relevant artefact in under 60 seconds, wall clock,
> on a normal analyst laptop.**

If that gate is not met, the stack decision is revisited before any report work
starts.

---

## 4. Architecture

```
                 ┌─────────────┐
  evidence root  │  discovery  │  layout detection, no writes below source,
  (triage pack   │             │  junction/symlink refusal, per-file SHA-256
   or mounted    └──────┬──────┘
   volume)              │
                 ┌──────▼──────┐
                 │   staging   │  copy selected files to working root,
                 │             │  replay registry transaction logs there only
                 └──────┬──────┘
                 ┌──────▼──────┐
                 │   parsers   │  parallel; each emits typed rows +
                 │  (goroutine │  a provenance id (source file, hash, offset/
                 │   per file) │  key path, raw value)
                 └──────┬──────┘
                 ┌──────▼──────┐
                 │   DuckDB    │  raw observation tables
                 │  case.duckdb│
                 └──────┬──────┘
                 ┌──────▼──────┐
                 │ correlation │  SQL views: physical devices, connections,
                 │   (SQL)     │  volume/letter chain, file activity, timeline
                 └──────┬──────┘
                 ┌──────▼──────┐
                 │  classify   │  investigative category + tier + score
                 └──────┬──────┘
          ┌─────────────┴──────────────┐
   ┌──────▼──────┐            ┌────────▼────────┐
   │ report.html │            │ CSV / JSON /    │
   │ (self-      │            │ Parquet exports │
   │  contained) │            │ + case.duckdb   │
   └─────────────┘            └─────────────────┘
```

**Layer discipline:** parsers know nothing about USB semantics; they turn bytes
into rows. All USB meaning lives in the SQL correlation layer and the
classifier. This is what keeps the parser layer testable against public fixtures
and the semantics layer reviewable as plain SQL.

### Evidence safety (non-negotiable, carried over from Boodie intact)

- Source evidence is opened read-only. Nothing is ever written below the
  evidence root.
- Every read source file is SHA-256 hashed and recorded in a run manifest.
- Transaction-log replay happens only against staged copies in the working root.
- Discovery refuses any path resolving outside the evidence root (real junction
  test, not a simulated one).
- Every output row carries an observation id resolving to source file, hash and
  in-file location.
- A run manifest records tool version and build hash, examiner and case
  reference (a gap Boodie flagged and never closed), inputs, hashes, timings,
  and every warning.

---

## 5. Device model and classification

### 5.1 Physical device grouping

Devnodes are clustered into physical devices in this precedence order, and the
method used is recorded on the device:

1. Exact `ContainerID` match, excluding both of Windows' placeholder GUIDs.
2. Device-reported serial match across the storage stack enumerators
   (`USB` ↔ `USBSTOR` ↔ `SCSI` ↔ `WPDBUSENUM`), five characters or more.
3. `VID`/`PID` + serial, which is what makes a short serial safe to join on.
4. Parent / `ParentIdPrefix` relationship, excluding hubs and the machine node.
5. Hardware id to the one devnode declaring it, which is how a SetupAPI install
   section reaches the device it installed.

Grouping is transitive: the links are taken as a graph and the closure walked,
so a `USB` node linked to a `USBSTOR` node by `ContainerID` and to an interface
node by parentage puts all three on one device.

A Windows-generated instance id (`&` as second character) is flagged
`not_unique` and is **never** used to assert two records are the same device.

Links that are suggestive but not conclusive, such as a serial that is a prefix
of another or a hardware id declared by two identical devices, are recorded as
candidates with their reason, reported, and never grouped on.

### 5.2 Investigative category

The 18 categories from the priority document, assigned from a weighted rule set
over: enumerator, setup class, class GUID, service, compatible IDs (declared USB
base class), hardware IDs, `BusReportedDeviceDesc`, sibling interfaces in the
same container, and whether a mounted volume was ever associated.

Deliberately **not** a single-field lookup. A dock is inferred from its child
functions; a phone from MTP/PTP/composite interfaces without a `USBSTOR` record;
a suspicious HID from a HID interface sitting alongside storage or networking in
one container.

### 5.3 Tier and score

Tier 1/2/3 per the priority document, plus a numeric score from the weighted
indicator lists (high-value / suspicion / lower-value) in §"Suggested
Device-Scoring Factors". Every device carries a `classification_reason` naming
the evidence that produced its category and score: a classification an analyst
cannot interrogate is one they will not trust.

**`review_required`** is a separate flag, not a tier: unknown class, unknown
VID/PID, missing or generic or duplicated serial, class/purpose mismatch,
multiple interfaces, unclear parentage.

### 5.4 Case profile

Default weighting is the general corporate profile. A `--profile` flag
(`exfiltration`, `printing`, `network-bypass`, `identity`, `ot`) reweights so
that, for example, printers become Tier 1 in an unauthorised-printing matter.
Reweighting changes *placement and score only*, never what is extracted.

---

## 6. Sources parsed

**Tier A: core, Phase 1**

| Source | Yields |
|---|---|
| `SYSTEM\ControlSet*\Enum\{USB,USBSTOR,SCSI,STORAGE,HID,USBPRINT,WPDBUSENUM,SWD,BTHENUM,BTHLEDEVICE}` | devnodes, identifiers, class, service, container, parent |
| `...\Enum\...\Properties\{GUID}\ID` | install / first-install / last-arrival / last-removal FILETIMEs |
| `SYSTEM\MountedDevices` | drive letter ↔ volume GUID ↔ device path / disk signature |
| `SYSTEM\...\Control\Class\{GUID}\NNNN` | driver detail, network adapter identity |
| `SYSTEM\...\Control\Print\Printers` | printer queues |
| `SYSTEM\...\Control\TimeZoneInformation` | bias, for SetupAPI local-time conversion |
| `SOFTWARE\...\Windows Portable Devices` | friendly names, volume labels |
| `SOFTWARE\...\EMDMgmt` | volume serial ↔ device (absent on Win11, handled) |
| `NTUSER.DAT` / `UsrClass.dat` | `MountPoints2`, RecentDocs, OpenSave/LastVisited MRU, ShellBags |
| `Windows\INF\setupapi.dev.log` | device installation, local time + both seasonal UTC candidates |
| Dedicated EVTX channels | Partition/Diagnostic, Kernel-PnP Config + Device Config, StorSvc, DeviceSetupManager, DriverFrameworks-UserMode, StorageVolume, WPD-MTPClassDriver, Ntfs/Operational |
| `System.evtx` (20001/20003), `Security.evtx` (6416) | driver install, new external device recognised |
| User LNK files, Automatic + Custom Jump Lists | target path, drive letter, **volume serial**, timestamps |

**Tier B: Phase 3**

Prefetch, `$MFT` / `$UsnJrnl:$J` on the host volume, Recycle Bin, PCA
(`Windows\appcompat\pca`), Windows Search index (`Windows.db`, present in the
sample collections and an underused source of paths on removable volumes).

**Notable:** unlike Boodie, `System.evtx` and `Security.evtx` are **not**
deferred to a separate "full" mode. At Go speed there is no reason for a triage
mode that omits them: the whole triage/full split disappears, along with the
"a triage workspace cannot be promoted to full" trap.

### Event log selection is a catalogue, not a filter

Implemented in Phase 1 (`internal/eventlog/catalogue.go`), printable with
`boobook -rules`. Every channel and event ID read is named there with what it
carries, every extracted field is named with the **role** it plays, and every
event considered and rejected is recorded **with the reason**. Correlation joins
on roles, not on field names, because the channels disagree: `DeviceInstanceId`,
`Prop_DevnodeId`, `DiskInstancePath` and, on `System` 219, `DriverName` all
hold a device instance ID.

Two consequences worth stating plainly:

- **Files on unread channels are not parsed at all.** Each is listed in the
  manifest by name, size and reason. This is what keeps the run near a second:
  on the sample collections, 7.8 MB is read and 130 MB is skipped by rule.
- **`Security.evtx` 4663/4656 are catalogued but not yet selected.** Removable
  storage auditing names `\Device\HarddiskVolumeN`, not a device, so reaching a
  device needs the volume resolved first. The NTFS mount events supply exactly
  that mapping, so this becomes available once correlation lands. Selecting it
  now would flood the output with file access that cannot be attributed. This
  is a deviation from "Security.evtx is not deferred": the file is read when a
  rule selects it, and for v1 no rule does.

---

## 7. The drive-letter and file-activity chain

This is the output the analyst actually wants and the one Boodie most often left
empty. Boobook walks every available route and labels each:

| Route | Confidence |
|---|---|
| Complete USBSTOR instance ID embedded in a `MountedDevices` value | `confirmed` |
| Volume serial in a LNK/JumpList matched to an `EMDMgmt` subkey for the device | `confirmed` |
| MBR disk signature in `Device Parameters\Partmgr` matched to `MountedDevices` | `strong` |
| MBR disk signature from a Partition/Diagnostic 1006 record, partition offsets agreeing | `strong` |
| Volume GUID ↔ device via `MountedDevices`, letter via `MountPoints2` | `strong` |
| Unique device-reported serial component appearing in a persisted path | `probable` |
| GPT `DMIO:ID:` partition GUID vs Partition/Diagnostic `PartitionTable` bytes | `possible`: layout undocumented, **emitted and labelled as unverified** rather than blocked |
| `RegistryId` from Partition/Diagnostic resolved into the SYSTEM hive | `possible`: matching key unverified, labelled |
| Volume label ↔ Portable Devices FriendlyName, unique match only | `possible` |

File activity is then joined on **volume serial first** (which belongs to the
volume, so it survives letter reuse and can place two devices at one letter) and
on drive letter within a connection window second.

Timing is stated but never overstated: a path inside an open-ended window is
context, not proof the device was connected, and the row says so.

### What the reference evidence actually supports: Phase 2 scoping

Two findings from checking the routes above against the four sample collections,
rather than against the documentation.

**`EMDMgmt` is unavailable on every sample host.** It is absent on the three
Lenovo collections and present but empty on the CTF one. That removes a route
rated `confirmed`, and it is the only route that ties a **volume serial** to a
device.
Nothing else supplies one: `Partition/Diagnostic` 1006 carries `Mbr`, `Ebr0`–`3`
and `PartitionTable` but **no VBR**, so no volume serial number comes from the
event logs either. On any current Windows, the volume serial a shell link
records cannot be tied to a device by a documented route at all.

The consequence is that the **volume label ↔ Portable Devices FriendlyName**
route, rated `possible`, does the work the `confirmed` route was meant to do.
Its confidence does not rise because it is needed. It rises only when a
connection window corroborates it, and the uniqueness qualifier has to be
enforced rather than assumed: on the Lenovo host the label `UEFI_NTFS` appears
twice, so that label resolves to nothing and must say so.

**That route does resolve the letter-reuse case.** Portable Devices on the
Lenovo host maps:

| Label | Device |
|---|---|
| `PATRIOT` | `USBSTOR\Disk&Ven_PATRIOT&Prod_&Rev_\24111912130128&0` |
| `TEST` | `USBSTOR\Disk&Ven__USB&Prod__SanDisk_3.2Gen1&Rev_1.00\04010D18A394…` |

So the twelve `E:` files labelled `TEST` belong to the **SanDisk**, not to the
Patriot device that `MountedDevices` maps `E:` to today. That is the correct
answer to the case in the table below, and producing it is the acceptance test
for Phase 2's file-activity attribution.

**Two byte fields Phase 1 deferred are now decoded** (`internal/partition`).
`PartitionTable` is a `DRIVE_LAYOUT_INFORMATION_EX` and `Mbr` is the boot record
sector; between them they carry the GPT partition identifiers and the MBR disk
signature that `MountedDevices` stores. Decoding them turns "some volume" into
"a volume on this device".

Three checks stand behind that decode, because a decoder reading at the wrong
offset produces plausible-looking GUIDs rather than an error:

- The type GUIDs come out as the documented well-known values (EFI System,
  Microsoft Reserved, Basic Data, Windows Recovery), which nothing but correct
  offsets would produce.
- On the Lenovo host, `C:` in `MountedDevices` is
  `{d3c26787-16ab-4663-8b6d-20737e298b82}`, which is exactly partition 3 of
  disk 1 as decoded from the event log. Two artefacts, decoded independently,
  agreeing.
- On the four MBR disks the signature from the layout structure and the
  signature read from the boot sector at `0x1B8` are equal in every case. The
  record carries the same fact twice and the readings match.

The GPT route then produced a link the evidence did not previously yield: on the
CTF host `\??\Volume{e47e1776-1531-11f0-bddd-000c296521ab}`, which
`MountedDevices` identifies by a partition GUID and nothing else, resolves to a
Kingston device at `strong`.

An MBR disk always reports its four table slots whether or not they hold
anything, so empty slots are counted and not reported as partitions. Otherwise
every MBR disk in a case acquires three phantom volumes.

### The reference evidence contains the letter-reuse case

Phase 1 landed the shell link, jump list and SetupAPI parsers, and the sample
collections turned out to hold exactly the case that makes "join on the letter"
wrong: **drive `E:` was used by two different volumes**.

| Letter | Volume serial | Label | Targets |
|---|---|---|---|
| `E:` | `00C9-0010` | PATRIOT | 2 |
| `E:` | `E607-9156` | TEST | 12 |

`MountedDevices` maps `E:` to the PATRIOT device today, so a letter join would
have attributed all fourteen files to it. The volume serial separates them, and
until the correlation phase resolves which device held the letter when, Boobook
reports the volumes and says the letter does not settle it.

Also confirmed in the reference evidence: the CTF host has `EMDMgmt` **present
but holding no volume records**, which is a third state distinct from present
and from absent. All three are reported as themselves.

---

## 8. Output

```
Boobook/
├── HOST-Boobook-Report.html         the report, self-contained, no network
├── HOST-Boobook-Summary.json        the headline, machine-readable
├── case.duckdb                      the whole case, queryable
├── data/
│   ├── devices.csv                  one row per device identity      [P1]
│   ├── devnodes.csv                 one row per registry device node [P1]
│   ├── events.csv                   selected event records           [P1]
│   ├── file-activity.csv            LNK and JumpList targets         [P1]
│   ├── shellbags.csv                folders Explorer displayed       [P1]
│   ├── mru.csv                      RecentDocs and file dialog lists [P1]
│   ├── letter-activity.csv          every record naming a letter     [P1]
│   ├── volumes.csv                  volumes, serials, labels, letters [P1]
│   ├── connections.csv              observed connection windows
│   ├── timeline.csv                 every timestamped record, all sources
│   ├── timeline-significant.csv     the same, tier 1 and tier 2 devices only
│   ├── device-volume-links.csv      the chain in §7, with method + confidence
│   └── printers.csv, network.csv    class-specific detail where it exists
└── provenance/
    ├── observations.jsonl           every raw observation with source + hash [P1]
    ├── sources.csv                  every file read, with size and hash      [P1]
    ├── warnings.json                parse failures, absences, truncations
    ├── coverage.json                what each artefact covers in time
    └── manifest.json                run, tool build, examiner, case, hashes  [P1]
```

`[P1]` marks what Phase 1 produces. One row per **device identity**, not per
physical device: grouping the several identities a single physical device
presents is Phase 2's job (§5.1), and asserting it earlier would merge devices
on a guess.

### Shell items: what a letter carried, when the volume is gone

Implemented in Phase 1 (`internal/shellitem`, `internal/registry/shellbags.go`).

Shell bags, RecentDocs and the file dialog MRUs all record places through shell
item lists, so one parser serves all three, and the shell link parser now reads
its target ID list through the same code rather than stepping over it.

These artefacts name a **drive letter and nothing else**. No volume serial, no
device. That is precisely the join §7 says is unsafe on its own, so they are
reported as what they are: a place, a letter and a time. `letter-activity.csv`
collects every record naming a letter from all four artefacts, because an
analyst asking "what was on E:" should not have to know which of four registry
keys and two file formats to look in.

Two constraints the format imposes:

- **The timestamps are FAT date and time values: local wall clock with no zone.**
  They are stored in `_local` columns as text, deliberately not as `TIMESTAMP`,
  so they cannot be sorted against UTC event times without an analyst noticing
  they are a different kind of thing. This is the same treatment SetupAPI local
  times get, for the same reason.
- **A path is built one item per level, and an item can name nothing.** Where a
  level does not decode, the row carries `path_has_gap` and the path stops
  rather than closing over the hole. A path with a missing middle segment is a
  reading, not a place the user visited.

The CTF host shows why this matters. Its bags record seven drive letters,
`C:` through `J:`, including `F:\KAPE`, a forensics toolkit run from removable
media. `MountedDevices` maps only `G:` to a device. For the other five letters
the bag is the sole surviving record that the volume was ever browsed, with the
bag key's last-write time saying when.

### Every output is a copy of a view

Implemented in Phase 1 (`internal/store/schema.sql`, `internal/store/views.sql`).

Nothing assembles an output row in Go. Each file in `data/` and `provenance/`
is `COPY (SELECT * FROM <view>) TO <file>`, and the manifest records which view
produced which file, how many rows it held and the SHA-256 of what was written.
The console summary reads the same views. A second implementation in Go, even
a faithful one, would be a second answer that has to be kept in agreement, and
the failure mode is two numbers that are each defensible and not equal.

The same reasoning applies inside the SQL. The serial rule is a macro
(`device_serial`), not a repeated expression: a device known only from event
records has no registry key to read a serial from, and the rule must give the
same answer there as it does for a devnode or the two will not join.

Three things this shook out of the reference evidence:

- **The inventory has to be a union, not a registry walk.** Between twelve and
  fourteen device identities per host are named by event, SetupAPI or portable
  device evidence with no registry key in the collection. A registry-first
  inventory drops them, and a device missing from a report looks exactly like a
  device that never existed. `devices.csv` carries `in_registry` for this.
- **A WPDBUSENUM node stores another device's whole path as its instance id.**
  Reading the last segment as a serial yields a "serial" that is a device path,
  or a volume GUID. Serials are read from the normalised identity, which is what
  `internal/devid` exists to produce.
- **Evidence is not obliged to hold text.** A `DeviceSetupManager` field in the
  Lenovo collection holds bytes that are not valid UTF-8 and that DuckDB will
  not store as `VARCHAR`. Replacing them with U+FFFD destroys the value and
  dropping the row destroys the record, so they are kept in hex behind a
  `<non-utf8:…>` marker that cannot be mistaken for content the evidence held.

`cmd/spike` was retired here. It carried its own loader and its own correlation
query (a serial matched as a substring of a whole record, which the event
catalogue replaced), and keeping it would have meant maintaining a second,
weaker answer. Its Phase 0 go/no-go is recorded above and in commit `11b5405`.

### Report structure: answer first

1. **At a glance**: devices seen, how many significant, evidence date range,
   headline findings in plain sentences.
2. **Significant devices**, one card per Tier 1/2 physical device: make, model,
   serial, category, first seen, last seen, connection count, drive letters,
   count of file paths linked, and the source of each fact.
3. **Timeline**: significant events only, chronological, one line each,
   filterable by device.
4. **File activity on USB volumes**: grouped by device, `confirmed`/`strong`
   inline, weaker links behind a disclosure.
5. **All other devices** *(collapsed)*: Tier 3, grouped by category, count
   badge on the header.
6. **Evidence coverage and limitations**: what was read, how far it reaches,
   what was missing, what the tool does not claim.

Times to the second, UTC named in the column header, truncated not rounded; full
precision in the data files. No network fetch of any kind. Evidence text escaped
so a device name cannot become markup. (These three are carried directly from
Boodie, and they were right.)

### Progress reporting

Phase, current artefact, records processed, elapsed and ETA, all to stderr,
rewritten in place at a terminal, one line per phase when redirected. ETA
projected from measured throughput, held separately per artefact class.
`--quiet` silences. Carried over from Boodie, which got this right.

---

## 9. Phases

**Phase 0, the spike (gates everything else).** No report, no polish. Prove:
registry hive parse incl. transaction-log replay; EVTX parse; the 60-second
performance gate against the Lenovo sample; DuckDB load and one non-trivial
correlation query. Output is a throughput measurement and a go/no-go on the Go
stack. *This phase decides whether the plan below is the right plan.*

**Phase 1, the evidence spine.** Discovery (triage-pack and mounted-volume
layouts, Velociraptor/KAPE encoded roots, percent-encoded EVTX names), hashing,
staging, manifest, all Tier A parsers, DuckDB schema, provenance chain.
Deliverable:
`devices.csv` + `devnodes.csv` + `observations.jsonl`, correct and traceable.

**Phase 2, correlation and classification.** Six units, in this order:

1. **Volume model and device↔volume links**: volumes as first-class rows, one
   link row per route with its confidence, plus the MBR and GPT decoding above.
2. **Connection windows**: arrival and removal evidence paired into intervals,
   with unpaired arrivals left open-ended and said to be. *(Done.)*

   Three things the reference evidence forced. Several channels report the same
   arrival within seconds, so repeated changes of one state are a single
   transition; otherwise every visit is multiplied by the number of channels
   that saw it. A Kernel-PnP 420 is a removal only at problem code 45; with any
   other code the device is still present and closing the window would
   manufacture a removal. And the interval between an arrival and the next
   removal is reported as a **span**, not a duration: the Lenovo evidence holds
   an arrival in November and the next removal the following July, and nothing
   records whether the device stayed connected for eight months or the log
   simply rolled. `duration` would have stated a continuity nothing evidenced.

   The Ntfs volume mount records are excluded from windows because they name
   `\Device\HarddiskVolumeN` rather than a device. The CTF host produces no
   windows at all, having collected none of the channels that carry arrivals,
   and the run says so, because an empty section reads as "nothing was
   connected".
3. **File activity attribution**: every file and folder record joined to a
   device by serial, then unique label, then letter within a window. *(Done;
   the acceptance test passes.)*

   On the reference evidence, `E:\10MB-TESTFILE.ORG.pdf` now yields:

   | Route | Device | Confidence |
   |---|---|---|
   | `volume_label_unique` | SanDisk | `probable` |
   | `drive_letter_mounted_devices_device_path` | Patriot | `possible` |

   The label is unique to the SanDisk *and* a connection window independently
   places that device on the machine when the file was opened. The letter route
   still reports the Patriot device, because `MountedDevices` really does map
   `E:` to it, but only as `possible`, with the reason stated: the mapping is
   current and nothing places that device there at the time.

   **Both candidates are kept.** Collapsing to one answer per file is a
   judgement, and it belongs to the analyst reading the evidence rather than to
   the query that assembled it. `file-attribution-summary.csv` names every
   record the evidence has not settled to one device.

   The letter route is capped at `probable` however strong the letter-to-device
   link is, because `MountedDevices` is not time-bound. A connection window
   covering the record is what lifts it from a current mapping to a placement in
   time; without one it stays `possible`.

   Records that reach no device are reported grouped by drive letter, because
   that is the explanation: almost all are on the internal disk. A bare total
   invites "60 records could not be attributed" to be read as a parse failure.

   `EMDMgmt`'s key name is now decoded for the device it embeds, so the
   `confirmed` serial route works on hosts that have the key. None of the four
   reference hosts do.
4. ~~**Physical device grouping**: §5.1 precedence, method recorded.~~ **Done.**

   `devices.csv` is now one row per physical device. On the reference hosts 103
   to 105 identities group into 82 or 83 devices; twelve or thirteen devices per
   host were named more than one way. Every identity remains reachable in
   `device-identities.csv`, and every link that made a group is in
   `device-links.csv` with the reason for it.

   Two routes beyond §5.1's four were needed by the evidence, and one §5.1 route
   needed a guard:

   - **A hardware id is not a serial.** SetupAPI install sections name some
     devices by hardware id (`USB\VID_8087&PID_0AAA&REV_0002` has no instance
     segment), and reading its last segment as a serial invents a serial out of
     the product id, which then joins every device sharing that product. An
     identity with fewer than three segments now has no serial at all.
   - **Hardware id to devnode** is the fifth route, and the only way an install
     section reaches the device it installed. It groups when exactly one devnode
     declares that hardware id, and is reported as `hardware_id_ambiguous`
     without grouping when two identical devices declare it.
   - **`ParentIdPrefix` excludes hubs and the machine node.** A root hub
     publishes a prefix that every device plugged into it carries, so without
     the guard one "physical device" would be the hub and everything ever
     attached to it.
   - **The serial route is restricted** to the storage stack enumerators and to
     serials of five characters or more. A serial is unique within a vendor and
     product, not across them: one reference host holds three different Intel
     products all reporting the serial `05022016`.
   - **Both placeholder ContainerIDs are excluded.** Around sixty unrelated
     devices per host carry `{00000000-0000-0000-ffff-ffffffffffff}`, and
     treating it as a container would report most of the machine as one device.

   **The truncated SanDisk serial resolved as predicted.** The `USB` enumerator
   holds a 120 character serial that `USBSTOR` stores as its first 63, so serial
   equality never fires and `ContainerID` carries it. The prefix is emitted as
   `serial_prefix_candidate` and never grouped on: a vendor issuing sequential
   serials produces prefixes between devices that are not the same.

   That distinction earned itself on `USB-LENOVO-SANDISK`, where one SanDisk has
   no registry key at all: both its identities come from events and SetupAPI, so
   there is no `ContainerID` to read and the prefix is the only link there is.
   Boobook reports the two identities as separate devices and names the
   unresolved candidate rather than merging on a prefix. Where a candidate
   agrees with a grouping made another way it is reported as corroboration, so
   the analyst is told which of the two it is instead of noticing a link was
   dropped.

   The physical device id is the identity that speaks for the group, chosen by a
   total ordering: a real serial first, then an instance id over a hardware id,
   then the enumerator that names a vendor and product. It is the same on every
   run over the same evidence, because an identifier that moved between runs
   could not be cited in a report.
5. ~~**Classification**: category, tier, score, `classification_reason`,
   `review_required`, weights in a data file, `--profile` reweighting.~~ **Done.**

   **Rules match on facts, and the rules are data.** A fact is something derived
   from the evidence that can be pointed at: a USB base class in a compatible
   id, a mounted volume, a HID interface sitting beside storage. The derivations
   live in `views.sql`, each carrying the value that produced it; the rules,
   weights and profiles live in `internal/classify/rules.json` and are loaded
   into the case database as tables. The classification is then a view over
   them, so it is traceable the same way everything else is, and a run carries
   the rule set that produced its answers rather than whatever the tool ships
   later. `classification/rules.csv` and `classification/weights.csv` are
   exported beside the results, weights with the profile already folded in.

   **The USB base class is the backbone, not the setup class.** `USB\Class_08`
   is what the device said it can do; the setup class is what Windows filed the
   driver under. `USB\COMPAT_VID_0781&Class_08` deliberately does not match:
   that is the vendor's own compatible id and matching it counts one interface
   twice.

   Four things the reference evidence corrected, each of which would have been a
   confident wrong answer:

   - **`WUDFWpdFs` is not MTP.** Windows attaches the portable-device file
     system driver to ordinary mass storage, so reading it as MTP made every
     memory stick claim a second interface and raised a review flag on all of
     them.
   - **The placeholder-container problem again, in a new form:** the WAN
     miniports carry the `Net` setup class and landed in tier 1 above the memory
     sticks. They are software-enumerated nodes; nobody plugged one in. The
     `software_device` fact excludes any group holding a `WPDBUSENUM` identity,
     because a phone can be known only from its `WPDBUSENUM` node and
     suppressing that would drop a portable device out of tier 1 entirely.
   - **The machine's own disk is not a USB finding.** Internal storage is
     reported, because it explains the file records that reach no removable
     device, and the `internal_bus` fact keeps it at tier 3.
   - **The virtual machine's SATA CD-ROM was reported as a potentially
     offensive device**, because storage plus an emulated optical volume is how
     payloads are delivered. That rule now requires `usb_attached`.

   **`review_required` had to be scoped or it was worthless.** Flagging every
   missing serial and missing vendor id put 81 of 82 devices in review, which is
   the same as flagging none. Review now excludes software nodes and internal
   storage, things that have no serial because they are not devices, and lands
   on 6 to 15 devices per host.

   The result on the reference evidence: tier 1 is 3 to 5 devices per host, and
   on `USB-CTF` it is exactly the three Kingston sticks. `-profile
   network-bypass` lifts the Fibocom mobile broadband adapter above them, which
   is the point of a profile: placement and score change, and what was
   extracted, which facts were derived, and which category a rule assigned do
   not.

   Two categories are defined and deliberately never assigned. `PowerOnly`
   cannot be, because a power-only device does not enumerate. `DeveloperEmbedded`
   needs a vendor reference list, and guessing at VID/PID ranges would turn a
   gap in the reference data into an assertion.

   **A performance note that is really a design note.** The grouping is a
   recursive closure and the facts are a wide union over it, so evaluating them
   per reader took a run from four seconds to not finishing. Both are now
   consolidated once into `device_group` and `device_fact` by a step that runs
   after the last load and before the first read. The reasoning stays in
   `v_device_grouping` and `v_device_fact_computed`, so there is still one place
   where each thing is decided.
6. ~~**Timeline**: every timestamped record in one shape, with UTC instants and
   zoneless local wall clock kept distinguishable rather than merged.~~ **Done.**

   `v_timeline` is one row per timestamped record from thirteen branches: event
   log records, connection windows, SetupAPI install sections, the four PnP
   lifecycle dates, devnode key writes, file and folder records with the device
   the attribution reached, shell item FAT timestamps, mount point key writes
   and disk layout reads. `data/timeline.csv` is the whole of it and
   `data/timeline-significant.csv` the same view filtered to tier 1 and tier 2
   devices: a filter, not a second query, so narrowing the question never
   loses the answer to the wider one.

   **The records do not all carry the same kind of time, and merging them is
   how a timeline acquires events that never happened.** An event log record
   carries a UTC instant. A SetupAPI section and a shell item's FAT timestamp
   carry local wall clock with no zone. So `time_utc` is only ever a UTC
   instant, `time_local` only ever the wall clock exactly as recorded, and
   `time_basis` says which of the two the row rests on.

   **Converting a wall clock needs the host biases, so they are now in the
   database.** `host_time_zone` stores `Bias`, `StandardBias` and
   `DaylightBias` and no converted value, because which one applies depends on
   whether daylight saving was in force when the record was written and nothing
   in the record says. Both readings are offered, `time_utc` and
   `time_utc_alt`, with `time_ambiguous` set, which is what
   `LoadSetupSections` already did for its own timestamps; the timeline now
   does it for every wall clock, using the same biases, and a test asserts the
   two conversions agree. On `USB-CTF` the host is Pacific and 20 entries carry
   two readings an hour apart; on the Lenovo hosts the zone is UTC, the two
   readings coincide, and `time_basis` says `standard_time` rather than
   claiming an ambiguity that does not exist. With no zone recoverable at all
   there is no reading: `time_utc` stays NULL rather than being computed from
   an assumed offset.

   An entry that cannot be given a UTC instant is still **placed**, by reading
   its wall clock as though it were UTC, because an entry sorted to the end of
   the timeline is an entry hidden. `time_basis` on the row says that is what
   happened.

   **A connection is one entry, not four.** Several channels report the same
   arrival within seconds of each other, so the timeline takes its arrivals and
   departures from `v_connection`, which already folds them into the single
   transition they describe, and carries the count of records behind it. The
   raw records stay in `events.csv`, reachable by the record id on the row. A
   test asserts no `connect` or `disconnect` record appears in its own right.

   Two things the reference evidence corrected:

   - **The machine's own root hub was being read as a dock.** Everything on the
     machine hangs off the root hub, so `dock.hub_with_functions` put the
     motherboard in tier 1 and filled the significant timeline with it. Both
     hub rules now negate `internal_hub`, and a new `hub.internal` rule names
     what it is rather than letting it fall into the generic bucket. Tier 2
     went from 7 to 5 devices on the Lenovo hosts and from 5 to 2 on `USB-CTF`.
   - **An event record whose catalogue rule carried no wording produced a row
     that did not say what its timestamp was.** Every row has to answer that,
     so it falls back to the record's own write time and names the channel.

   The `1980-01-01` entries at the head of the Lenovo timelines are not a
   parsing fault: those links record `119600064000000000` as the target's
   written, accessed and created time alike, which is what Windows writes for a
   shortcut to a volume root. It is reported as recorded and is traceable to
   the raw FILETIME beside it.

   373 to 752 entries per collection, 20 to 48 of them resting on a wall clock.
   Runs are 5.6 to 8.9 seconds.

Deliverable: the full `data/` set. **Phase 2 is complete.**

Units 1 and 2 are independent and both gate unit 3. Unit 4 gates unit 5. Unit 6
is last because it consumes the windows and the attribution.

**Phase 3, the report.** Self-contained HTML, answer-first structure, tiering
and disclosure behaviour, progress reporting, case profiles.

1. ~~**Skeleton, at a glance and coverage**: the package, the embedded
   template, and the two sections that frame everything else.~~ **Done.**

   **The report is a document, so Go renders it; the findings are not, so they
   are views.** `internal/report` holds an embedded template and stylesheet and
   assembles nothing: `v_report_summary`, `v_report_finding`,
   `v_report_coverage` and `v_report_limitation` produce every figure and every
   headline sentence, read the same way the console summary reads a view and
   the CSVs are copied from one. A number in the prose and a number in a data
   file have one query behind them and cannot drift apart.

   **A headline finding carries its own basis.** Each names the file a reader
   can open to argue with it: `devices.csv, category Storage`,
   `file-attribution-summary.csv, candidate_devices = 0`. Findings with nothing
   behind them do not appear: a report should not spend the top of its page
   saying what it did not find, so there is no "0 storage devices were found"
   where the answers go. The exception is a finding that *is* an absence, "no
   connection window could be derived", because silence there reads as
   "nothing was ever connected".

   Gaps rank alongside answers rather than below them. On `USB-CTF` the second
   finding is that 50 file records reached no device at all; on
   `USB-LENOVO-SANDISK` it is 58. Leaving those out would make the attributed
   set look complete.

   **One correction the reference evidence forced.** `Source.Replayed` was a
   plain `bool`, so every event log, shortcut and jump list in a collection
   stored `false`, and the coverage table duly reported "7 hives parsed
   without transaction-log replay" against `EVTX`, `LNK` and `JUMPLIST`. Replay
   applies to a registry hive and to nothing else, so it is now `*bool` and nil
   says the question does not arise. The same distinction the tool makes
   everywhere else between absent and false.

   Self-containment is a test, not an intention: the rendered document is
   checked for `http`, `//cdn`, `<script`, `src=` and `@import`, because an
   examiner opens a report on a machine with no network, often years later.
   Evidence text is escaped by `html/template`, so a device named
   `<script>alert(1)</script>` renders as its name, and a test asserts it.
   Times are truncated rather than rounded, since rounding up can place a
   record after an event it preceded.

   `-no-report` writes the data files alone. The report is recorded in the
   manifest with its SHA-256 like every other output.
2. ~~**Significant device cards**: one per tier 1/2 physical device, with the
   source of each fact.~~ **Done.**

   The unit of the card is the physical device, and each card names the
   identities it grouped and the route that grouped them, so the grouping is
   shown rather than asserted. `v_report_device` adds only the counts that
   cross into the volume and file layers; everything else on the card is the
   same `Device` the inventory and `devices.csv` carry, so a card and a file
   cannot describe a device differently.

   **`v_report_device_field` is the view the first stated requirement rests
   on.** A card says "serial 24111912130128"; this says which registry key, in
   which file, with that file's SHA-256 as this run read it. Where the
   identities in a group disagreed about a field, the card says so and gives
   the count: a value was chosen, and the reader should know a choice existed.

   **The first version of it cited the wrong record, which is worse than citing
   none** because it looks checked. The card header read "PATRIOT USB Device"
   while the field table cited a `WPDBUSENUM` node holding "PATRIOT". The
   ranking has to reproduce, exactly, how `v_physical_device` picked the value:
   the lowest-preference identity that carries the field, and within one
   identity the greatest value, because `v_device` aggregates across control
   sets with `max()`. A test now asserts that every field on a card matches the
   value the card shows, and that each is cited to a real locator and a real
   file.

   The Windows-generated-serial caveat moved out of the value and into a note
   for the same reason: the ranking compares values, and decorating one changes
   which record the citation points at.

   **Two wordings the evidence forced.** "Connected X to Y" states a continuity
   nothing evidenced: the log records an arrival and, later, the next removal,
   and one SanDisk's single window spans eight months. It reads "earliest
   arrival …; latest removal …". And a count of zero is shown rather than
   hidden: "0 file paths linked" on a storage device is a finding, where an
   absent row would read as not having been looked at.

   **Adding the cards took a run from 8 to 19 seconds; it now finishes in 6 to
   9.6**, faster than before the report existed. Three things, in order of
   effect. `v_file_attribution` is consolidated into a table like the grouping
   and the facts, because each of its routes asks per record whether a
   connection window covers it and five readers now want the answer. The
   headline counts came from five subqueries over `v_device_classified`, which
   is five full evaluations of the grouping, the facts and the rules for five
   numbers one scan produces. It is one pass with `FILTER` now, and the findings
   read a `MATERIALIZED` CTE. And the card drill-downs are read once for all
   devices and distributed, rather than three queries per card.

   The report phase is 0.9 to 1.7 seconds of that.
3. ~~**Timeline**: significant events only, filterable by device.~~ **Done.**

   Every timestamped record belonging to a tier 1 or tier 2 device, oldest
   first, read from `v_timeline_significant`. Each row carries what its
   timestamp *means* ("one stored state and not a connection history" beside a
   `last_arrival_date`, "not the time it was opened" beside a file's written
   time), the artefact it came from, the file, and its `entry_id` in
   `timeline-significant.csv`, so any row on the page can be found in the data.

   **A time this run worked out and a time an artefact recorded are different
   claims, and the column exists to keep them apart.** Every row is labelled
   `UTC` or `local→UTC`, and a converted row carries the wall clock exactly as
   written plus the sentence that qualifies it. Where the host observes daylight
   saving and the record does not say which season it was written in, both
   readings are shown, "either 11:00:00 or 10:00:00 UTC", rather than one
   being chosen. Where no host zone was recovered at all the row says it has no
   UTC reading and is placed by reading its wall clock as UTC.

   **The filter is CSS, not script.** A radio per device and one generated rule
   each; nothing on the page depends on script running, and with no rule
   matching every entry stays visible, which is the direction a filter has to
   fail in. Printing ignores the filter and says so on the page: a printed
   report that silently dropped the entries a reader had filtered out would lie
   by omission with nothing on the paper to show it.

   Three things the reference evidence corrected:

   - **Three sticks of one model produce one friendly name.** The chips read
     "USB SanDisk 3.2Gen1 USB Device" three times, which is a filter that cannot
     answer the question it exists for. Where a name repeats, the serial tail is
     added, to the chip and to every row, so the two agree.
   - **A confidence on every row said nothing.** Each non-file branch of the
     timeline is `confirmed` by construction, because the record names the
     device. A page of confirmed chips both drowns the handful that are weaker
     and invites the wrong reading, that the *event* is confirmed rather than
     the link to the device. It is shown only where it is less than certain, and
     worded "probable link to this device".
   - **The count query was a second full evaluation.** Short of the cap the rows
     *are* the total, so only a run that fills the page asks.

   Capped at 750 entries with the omission stated; 123 to 317 per collection, so
   nothing is currently capped. The report phase is 1.5 to 2.2 seconds.
4. ~~**File activity**: grouped by device, weaker links behind a
   disclosure.~~ **Done.**

   `v_report_file_activity` is one row per device and record, carrying the
   strongest route that reached that pairing and the reasoning behind it, and
   `v_report_file_unattributed` is every record that reached no device with what
   stopped it. Each row shows the file, the artefact, the recorded time *and
   what that time means*, the route, the reason, the source file and its hash.

   **The disclosure splits per device, not against a fixed bar, and the
   reference evidence forced that.** The plan said confirmed and strong inline
   with probable and possible disclosed. Across all four collections there is
   not one confirmed or strong link: the `EMDMgmt` key that tied a volume serial
   to a device is gone from current Windows, so the routes that remain are the
   unique volume label and the drive letter, both capped at probable. A fixed
   bar would have hidden every file record in every collection, and `USB-CTF`,
   which is entirely `possible`, would have shown an empty section with
   everything behind a disclosure. What each device shows inline is the firmest
   link it actually has, with the rest disclosed beneath, and the page says that
   is what it is doing and why.

   **The reason travels on the row, because the word is a ranking and the reason
   is the evidence.** "The letter maps to this device and a connection window
   covers the time of this record" and "the letter maps to this device now;
   nothing places the device on the machine when this record was made" are both
   `possible`-to-`probable` territory, and they are not the same claim. A record
   several devices claim says so on every one of its rows.

   **A gap says what stopped it.** 50 to 60 records per collection reach no
   device; the reason is either that the record carries no letter, serial or
   label at all, or that its letter is linked to no USB device, which for `C:`
   is the expected answer and for a removable letter is a finding. A gap with no
   reason beside it reads as a failure of this tool rather than of the evidence.

   The four-column table this started as put a sentence of reasoning into a
   two-inch column and stood it on end; the rows reuse the timeline's shape.
   Capped at 500 records and 200 gaps with the omission stated, neither reached.
   The report phase is 1.5 to 2.3 seconds.

   One thing this surfaced and did not fix: `USB-CTF` holds RecentDocs entries
   named `A2-64 (G).lnk`, a volume label and a drive letter in the display
   string, with no letter in the record itself. Reading a device out of that is
   inference from how Explorer renders a name rather than from a stored field,
   so it is a candidate route for Phase 4 and not a silent one here.
5. ~~**Tier 3, collapsed**: visible without swamping the analyst.~~ **Done.**

   26 to 73 devices per collection sit at tier 3: hubs, keyboards, cameras, the
   machine's own disks. They are all present, grouped by category behind five
   collapsed lines, each naming its device count and the event records behind
   it. A tier is a ranking and not a filter: a report that dropped them could
   not be checked, and one that listed them flat would bury the two that matter.
   They carry no drill-downs, because seventy devices with eleven cited fields
   each is a megabyte of page nobody opens and `devices.csv` holds the same
   detail.

   **Review is lifted out of the collapsed groups, and building that exposed a
   rule that was flagging noise.** The first render put eight devices under
   "flagged for review" at the head of the section, every one of them reading
   "No serial number is present, or Windows generated it": four keyboards, two
   root hubs, a Bluetooth radio and a smartcard reader. None of those classes
   carries a serial and none ever did. Thirteen flags on the reference host,
   eight of them device classes behaving normally: a flag raised on everything
   is a flag raised on nothing, and this section would have led with it.

   So a review fact can now carry `unless`, facts that make it normal rather
   than notable, in the rule set beside the fact itself, with the reason
   written down where it can be argued with. `no_serial` is excepted for
   `hid_interface`, `hub_interface`, `wireless_interface` and
   `smartcard_interface`; `no_vid_pid` for `internal_hub`, because a root hub
   having no vendor id is what a root hub is. The exception is for the absence
   only: a serial two devices *share* is still flagged at any class, and a test
   asserts both halves of that. Review counts fell from 13 to 5 on the Lenovo
   hosts and from 6 to 0 on `USB-CTF`, where every flag had been a hub or a HID
   with no serial, and every survivor is a duplicated serial, a multi-interface
   token or a device of unknown class.

   Verified across all four collections: 252 KB to 569 KB of self-contained
   HTML, report phase 1.7 to 2.5 seconds, whole runs 8 to 13 seconds.
6. **Progress reporting**: phase, artefact, elapsed and ETA. *(Done.)*

   One line, rewritten in place at a terminal: the phase, the artefact in hand,
   how many of the phase's files are done, the records read, elapsed and an
   estimate. Redirected it writes one line per phase and never a carriage
   return, because a log file full of them is worse than no progress at all.

   The estimate divides the bytes still to read by throughput this run has
   measured, held per artefact class. Nothing is assumed: until a class has been
   measured no estimate is shown, which is why the first line of a phase carries
   none. The artefact in hand counts as unread until it is finished, so the
   figure errs long rather than short. Elapsed is kept moving by a tick, because
   the phases that say nothing for seconds, the consolidation and the export,
   are exactly the ones that look like a hung run.

   Two things the reference collections forced. The event log phase declares its
   own work from inside the parser: 96 of 103 logs on `USB-CTF` are on channels
   no rule reads, and a count of the files handed over would have shown a run
   stalled at seven per cent for the whole phase and then finishing. And an
   artefact that failed to parse is still counted as handled, or one bad hive
   leaves the counter short of its total and the run reads as stalled at the end.

   `-quiet` silences the narration; errors and the manifest path on stdout are
   not narration and survive it. The hive reader's own notes about skipped
   transaction logs go through the reporter as well: written straight to stderr
   they landed in the middle of the progress line and stayed there, and they
   ignored `-quiet` entirely.

**Phase 4, depth.** Tier B sources, GPT partition chain, `$UsnJrnl`, subject-USB
filesystem bundle, adversarial/malformed fixtures, packaged smoke tests in CI.

### Validation approach

Boodie's strongest engineering decision was testing adapters against a real,
hash-verified public registry hive in CI and failing the build if a real-fixture
test skipped. That is carried over and extended to EVTX, LNK and Jump List,
which Boodie never got to. The four sample collections give us a known-answer
regression suite: `USB-LENOVO` (no stick), `USB-LENOVO-SANDISK` (stick present),
`USB-LENOVO-SANDISK-LATER` (later state) is a natural before/after triple, and
`USB-CTF` a full `$MFT`-bearing volume.

---

## 10. Decisions taken

Settled 2026-08-01.

1. **Stack: Go + embedded DuckDB.** Single static binary, Velociraptor-derived
   parsers, correlation in SQL. Registry transaction-log replay is the one open
   technical question and is resolved in Phase 0.
2. **Delivery: CLI first, GUI later.** Phases 0–4 target a CLI producing the
   HTML report and data files. A Wails GUI over the same `case.duckdb` remains
   possible later, as in Firetail, but is out of scope until the CLI is proven.
3. **v1 artefact scope: Tier A only.** Registry, SetupAPI, USB-relevant EVTX,
   and user shell artefacts. Host `$MFT`/`$UsnJrnl`/prefetch and the Windows
   Search index stay in Phase 4.
4. **Case profiles: default weighting only for v1.** The general corporate
   profile ships first; `--profile` is added once the scoring is validated
   against real collections. The classifier is still built so that weights are
   data, not code, so adding profiles later is not a rewrite.

### Consequences for the phase plan

- Phase 3's report is the last deliverable of v1; Phase 4 is post-v1.
- The classifier's weight table lives in a separate data file from Phase 2, even
  though only one profile is populated.
- No GUI concerns constrain the output design: the HTML report is the interface,
  and the DuckDB file is the power-user escape hatch.
