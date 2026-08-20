<p align="center">
  <img src="logo/boobook-384.png" alt="Boobook" width="192" height="192">
</p>

<h1 align="center">Boobook</h1>

<p align="center">Digital forensics USB artefact parser</p>

Boobook reads a Windows evidence set, either a triage collection
(Velociraptor, KAPE) or a mounted volume, and answers, in one report an analyst
can read in five minutes:

> Which USB devices did this machine see, which of them matter, when were they
> connected, and what file activity can be tied to them?

It is offline, read-only, and a single static binary. Everything it says is
traceable to a named source artefact with that artefact's SHA-256 as the run
read it. Everything it extracts is also written as CSV an analyst can pivot on.

Licensed under the **Apache License 2.0**; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Third-party components are listed with their licences in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md); a distributed binary
statically links them and must carry that file.

**Boobook is an investigative aid.** It reports what artefacts on a Windows
system record. It does not establish what a person did, and no output of it
should be presented as a conclusion without an examiner's own analysis of the
cited sources.

---

## What it is for

Four things, in priority order. They are the reason the tool exists and the
tie-breaker whenever a design decision is close:

1. **A forensic tool that does not change the source, and lets any finding be
   traced back to its source easily.** Sources are opened read-only, hashed,
   and never written to. Nothing is ever written below the evidence root.
2. **Fast**, with progress and an ETA while it works. The reference collections
   (120 to 180 MB, 300 to 540 source files) run in 29 to 43 seconds, which
   includes hashing every source twice: once as it is read and once at the end,
   to confirm the digest attests the bytes that were parsed.
3. **An analyst report** summarising the devices and timelining the significant
   events, especially storage and printers.
4. **File activity correlated** to a USB drive that was mounted as a letter.

Alongside the report it writes CSV and JSONL cataloguing every device and every
event, so the report can be checked and pivoted on rather than believed.

## Quick start

Download `boobook.exe` from the
[latest release](https://github.com/Bloggzy/boobook/releases/latest). There is
nothing to install: it is a single static binary with no runtime dependency.

Windows marks a file that came from the internet, and SmartScreen will warn
about it or block it on that mark alone. Clear it first, in PowerShell:

```bash
Unblock-File .\boobook.exe
```

Then point it at some evidence and say where the results should go. Those two
paths are all it needs:

```bash
.\boobook.exe -evidence "E:\Triage\HOST01" -output "C:\Cases\2026-014"
```

`-evidence` wants the top of the source machine's system drive, not a folder
inside it. The test is simple: at the path you give, you should be able to see
that machine's `Windows\` and `Users\` folders sitting side by side. Point it at
`Windows\System32\config` because that is where the registry hives live and it
will find nothing at all, because that pair of folders is what it looks for.

In practice that means:

| What you have | What to pass |
|---|---|
| a mounted image, or a drive on a write blocker | the volume root, `E:\` |
| a Velociraptor or KAPE triage collection | the folder the collector produced, the one holding `uploads\` or `C\` |

A collection keeps the host's `Windows\` and `Users\` a level or two further
down, under names like `uploads\auto\C%3A\`. You do not have to dig for them:
Boobook recognises the collector's shape, finds the volumes inside it, and
records which layout it decided on in the manifest, so a run can be checked
against what it thought it was reading. It handles a collection holding more
than one volume.

### What you get

A run directory beneath `-output`, stamped with the UTC date and time the run
started, so a second run never overwrites a report already cited somewhere.
A tool calling Boobook can name that directory itself with `-run-id`, or ask for
no run directory at all with `-in-place` and have the results written into
`-output` itself. Either way the run knows where it is putting things before it
starts, and either way a directory that already holds results is refused:

```
C:\Cases\2026-014\20260810T094132Z\
  report.html        the analyst report: open this first
  manifest.json      what was read, what was written, and every hash
  case.duckdb        the case database, queryable directly
  data\              every device, event and correlation, as CSV
  classification\    the rule set exactly as it was applied
  provenance\        every source file with its hash, and every stored value
```

Every file is listed under [What a run produces](#what-a-run-produces) below.

Progress goes to stderr and the manifest path goes to stdout, so a scripted run
can be piped without filtering the narration out of it.

### Recording the case

Three more flags record who ran it and what for. They are written into the
manifest and printed on the report, and change nothing about what is read:

```bash
.\boobook.exe -evidence "E:\Triage\HOST01" -output "C:\Cases\2026-014" -case "2026-014" -examiner "A. Analyst" -host "HOST01"
```

The rest are under [Flags](#flags) below. The one worth knowing about early is
`-profile`, which reweights the relevance score for the kind of case you are
working.

### Building from source

Released binaries cover Windows x64. To build it yourself:

```bash
go install github.com/Bloggzy/boobook/cmd/boobook@latest
```

or from a clone:

```bash
go build -o boobook.exe ./cmd/boobook
```

Building needs a C toolchain: DuckDB is a C library and the whole store layer is
behind cgo. The released binary needs none of that.

### Flags

| Flag | What it does |
|---|---|
| `-evidence` | evidence root: a mounted Windows volume or a triage collection |
| `-output` | output root; results are written to a run directory beneath it |
| `-run-id` | name the run directory instead of taking a UTC timestamp |
| `-in-place` | write into the output root itself, with no run directory |
| `-working` | scratch root, if it should not sit inside the output |
| `-keep-working` | keep the scratch directory instead of removing it |
| `-security` | read `Security.evtx` for logon and logoff records, off by default |
| `-case` | case reference, recorded in the manifest |
| `-examiner` | examiner name, recorded in the manifest |
| `-host` | label for the host under examination, recorded in the manifest |
| `-profile` | reweight the relevance score for the kind of case |
| `-rule-set` | a classification rule set file instead of the built-in one |
| `-no-report` | write only the data files |
| `-quiet` | silence progress and narration; errors are still reported |
| `-rules` | print the event log selection catalogue and exit |
| `-sources` | print the evidence sources that can be read, and what each yields, and exit |

The profiles are `general`, `exfiltration`, `printing`, `network-bypass`,
`identity` and `ot`. Each multiplies the weight of the facts it names and leaves
the rest at 1.0, so `-profile printing` lifts a printer into tier 1 in an
unauthorised-printing matter. **Reweighting changes placement and score only.**
It never changes what was extracted, which facts were derived, or which category
a rule assigned.

`-security` is off by default because `Security.evtx` holds little else worth
having and costs the size of the file, which a raised log cap can make
gigabytes. A run that skipped it says so in the report's limitations, so the
absence of a logon beside a connection is never mistaken for evidence there
was none.

## What a run produces

```
<output>/<runID>/
  report.html                       the analyst report, self-contained
  manifest.json                     what was read, what was written, hashes
  case.duckdb                       the case database, queryable directly
  data/
    devices.csv                     one row per physical device
    device-identities.csv           the identities each device groups
    device-links.csv                every link that made a group, with why
    device-facts.csv                the facts the classification rested on
    device-rule-matches.csv         every rule that matched, not only the winner
    devnodes.csv  events.csv  volumes.csv  disks.csv  connections.csv
    device-lifecycle.csv  device-volume-links.csv
    disk-departure-candidates.csv   a disk reported with no capacity, which
                                    is what a removal looks like from the
                                    partition driver and is not treated as one
    shellbags.csv  mru.csv  file-activity.csv  letter-activity.csv
    user-assist.csv                 what Explorer launched, per user
    prefetch-runs.csv               one row per prefetch file
    prefetch-executions.csv         every recorded execution
    prefetch-volumes.csv            the volumes executions touched
    prefetch-run-volume-candidates.csv
                                    which volume each executable ran from,
                                    including where more than one matched
                                    equally well and none was named
    prefetch-files-removable.csv    files loaded from removable media
    file-attribution.csv            file records linked to devices
    file-attribution-summary.csv    including those that reached none, and why
    timeline.csv                    every timestamped record
    timeline-significant.csv        the same, filtered to tier 1 and tier 2
    timeline-moments.csv            one arrival or removal, with the records
                                    gathered under it and what they were
    timeline-moment-support.csv     that breakdown, one row per kind of record
    timeline-moment-members.csv     which record was gathered under which
                                    moment, and how far it sat from it
  classification/
    rules.csv  weights.csv          the rule set exactly as it was applied
  provenance/
    sources.csv                     every file read, with its hash, in
                                    read_order, the order the run read them,
                                    which the source id is not a sort key for
    parse-warnings.csv              what parsed only in part, by reason
    observations.jsonl              every stored value, with its locator
    host-time-zone.csv
```

Scratch, a hive recovered by replaying transaction logs, goes in a `working/`
directory inside the run, and is removed at the end. It holds nothing a finding
depends on: a recovered hive is derived, no source record points at it, and the
hive and each of its transaction logs are hashed in
`provenance/sources.csv`, so what was read stays reproducible. Use
`-keep-working` to retain it, or `-working` to put it on a different disk when
the output is on a network share.

## The report

One HTML file, self-contained: **no network fetch of any kind, and no script at
all.** What an examiner opens in five years is what was written today. Evidence
text is escaped, so a device name cannot become markup.

Every major section is collapsed when the report opens, so an analyst meets the
document's shape and chooses where to dig. Each fold's label carries a count or
the names of what it holds, so a section can be dismissed without being opened.

**One arrival is one row.** Windows records a device being plugged in many times
over: the PnP configure and start, the volume mount, the setupapi section, and
four registry dates against each of the keys the device enumerates under. Listed
one per row, that is thirty lines saying the same thing. The timeline
gathers the records that evidence a connection under the connection they
evidence, states the conclusion with the breakdown beside it, and folds the
records beneath. It never gathers a record of *use*: a file opened in the second
a stick arrived is the finding an analyst came for and stays a row of its own.
Nothing is dropped: every record keeps its own id in `timeline.csv`, the
grouping is exported so the summary can be taken apart, and printing opens the
folds.

Disclosures are hidden checkboxes plus generated CSS rules rather than
`<details>`, because a closed `<details>` cannot be forced open by any
stylesheet, and the print
stylesheet must be able to open everything. **Printing carries the whole report**
and says on the page that it did.

Sections: **Summary: At a glance** (counts, evidence span, headline findings) ·
**Significant devices** (a cited card per tier 1 and tier 2 device) ·
**Timeline** · **File activity** · **Programmes and the devices they touched** ·
**Other devices** (tier 3, in full) · **Evidence coverage** · **Limitations**.

The programmes section keeps "ran from a device" and "read a file from one"
under separate headings, because a programme on the system disk that opened a
single file on a stick reaches that device through the same chain as one
executed off it, and a table holding both invites counting four programmes as
having run from a device when one did.

## What it reads

Registry `SYSTEM` (device enumeration, `MountedDevices`, mount points, time
zone), `SOFTWARE` (portable devices, `EMDMgmt` where present), user `NTUSER.DAT`
and `UsrClass.dat` (ShellBags, RecentDocs, OpenSave MRU, UserAssist), Windows
event logs (a curated channel and event catalogue; see `-rules`),
`setupapi.dev.log`, shortcut (LNK) files and jump lists, prefetch (`.pf`), and
the disk layout carried in `Microsoft-Windows-Partition/Diagnostic` 1006
records.

**UserAssist** is the per-user half of the execution picture and evidences a
person rather than a process: prefetch is per machine and covers anything the
loader touched, so a service starting looks like a double-click, where
UserAssist is what Explorer launched and counts foreground focus as well as
runs. Every launch carrying a drive letter is a headline finding whether or not
a device was reached: on one reference host it is the only artefact that
reports a forensic tool having been run from `F:\` at all.

**Prefetch** is the one artefact that names a volume by serial and never by a
drive letter, and that serial is the same value a shell link records, so it
joins to the rest without conversion. It answers a question nothing else here
can: which programmes ran off a USB volume, and which read files from one.
`EnablePrefetcher` is read from `SYSTEM` beside it, because prefetch is off by
default on Windows Server and can be disabled anywhere: on a host that was not
prefetching, an empty directory says nothing about what ran, and the report says
so rather than leaving the silence to be misread.

`-sources` prints the whole list with what each location yields, without needing
evidence to hand: it answers "what can this tool do" when you are deciding what
to collect.

## Design decisions worth knowing

**Every output is a copy of a view.** Files are written with
`COPY (SELECT * FROM <view>) TO <file>`. Go may *distribute* rows, grouping
them into cards, tiers and chips, but it never *decides*. Two outputs cannot
disagree about the evidence, and the manifest records the view behind each file.

**Weak correlations are labelled, not withheld.** Every link carries a
`link_method` and a confidence: `confirmed`, `strong`, `probable`, `possible`.
The predecessor tool gated the highest-value output, drive letter to file
activity, on complete substantiation, which is intellectually correct and
investigatively useless. Evidential discipline is kept by labelling.

**A physical device, not a devnode.** One stick appears under several
enumerators; counting identities reports one stick three times. Identities are
grouped, and every grouping records the method that made it, because a grouping
an analyst cannot interrogate is one they cannot rebut.

**Tiering, so the report does not swamp the reader.** Tier 1 is what an
investigation usually turns on; tier 3 is hubs, keyboards and the machine's own
disks, present in full but collapsed. Review is a flag, not a tier: a tier 3
keyboard with a duplicated serial is still the thing to look at.

**Two kinds of time, kept apart.** Event logs and registry FILETIMEs record UTC
instants. SetupAPI sections and FAT timestamps record a local wall clock with no
zone; those are converted with the host bias and marked `local→UTC`. Where the
host keeps two offsets the season is not recorded, so the row carries both
readings (`time_utc` and `time_utc_alt`) rather than one being guessed. An entry
is never counted or listed twice.

**Sentinels are absences, not dates.** A zeroed DOS date widened into a FILETIME
is 1980-01-01, and Explorer writes it into a shortcut whose target has no
timestamps of its own. Read as a write time it drags the reported span of a
whole case back forty years. Both forms are refused *exactly*, and the raw value
is kept. A wall clock is converted after that check, though, and on a host east
of UTC the same placeholder resurfaces as a date in December 1979 equal to no
sentinel at all, so a second check names any timestamp landing on FILETIME
zero, the Unix epoch or the FAT epoch. The same check covers 2000-01-01, which
is where a camera or a stick restarts its clock after losing power, and the
weeks after it, where such a device carries on recording its own uptime as
dates. Those rows stay on the timeline, marked `epoch default` and named for
which default they came from, and set no edge of the reported evidence span.

**The report cites files, the manifest carries hashes.** Source paths on the
page are relative to the evidence root, which is named once in the masthead: the
drive an image happened to be mounted on identifies nothing and, repeated on
every row, buries what does. The absolute path and the SHA-256 of every file
read are in `provenance/sources.csv` and the manifest, once per file, where a
hash can be compared rather than scrolled past.

**Absence, failure and a partial read are three different findings.** A missing
artefact makes the report silent rather than negative: "no file record reached
this storage device" is a finding, where an absent row reads as "not looked at".
A directory that could not be read is not an absence at all and is recorded as a
failure, so its silence can never be offered as evidence there was nothing
there. And a record that parsed with something inside it that did not is a third
case again: it is in the outputs and a reader will rely on it, so it is kept,
counted by reason in `provenance/parse-warnings.csv`, and listed in the
limitations as `partial`.

**False positives cost more than they look.** The rule that flags a HID beside a
network interface, the shape of a device that types and then exfiltrates, also
requires the absence of a hub, because a dock is a hub with a keyboard and an
ethernet port hanging off it. The pairing behind a hub is still recorded, at a
low weight and without a review flag, so the observation survives without the
tool drawing the conclusion.

## Development

```bash
go build ./...
go vet ./...
gofmt -l ./cmd ./internal ./tools
go test ./...
```

305 tests. The `store` and `report` packages each take several minutes, because
they build a real DuckDB case per test rather than mocking the thing under test,
and `cmd/boobook` runs the whole tool twice over a synthetic evidence tree: one
where everything parses and one where nothing does.

The suite is not the whole check. **Run the tool against a real collection and
read the rendered report before committing**: several defects here were visible
only in the output, and two in the most recent change were found by diffing a
run against one from the previous commit rather than by any test: a view that
returns nothing passes every test written about what it must not claim.

**Versions** run `0.2.1`, `0.2.2` … `0.2.9`, `0.3.0`: three segments, each
counting 0 to 9 before carrying left. The current version lives in
`internal/workspace/manifest.go`, is written into every manifest and printed on
every report, and should be bumped in the same commit as the change it
describes.

**Everything derived from the logo is generated, and the generator is
committed.** `logo/logo.png` is the 1024-square source; from it come
`cmd/boobook/rsrc_windows_amd64.syso` (the resource object the linker folds
into the binary, so Explorer shows the owl), `logo/boobook.ico`, and
`logo/boobook-384.png`, the image at the top of this file. Regenerate all three
when the logo changes:

```bash
go run ./tools/icongen
```

A committed binary nobody can reproduce is one nobody can audit, which is why
the `.syso` has a generator rather than a provenance note.

What is known to be incomplete, and why, is in
[docs/OPEN-WORK.md](docs/OPEN-WORK.md); read it before assuming a silence in
the output is a finding.

### Standing constraints

Six rules the whole design rests on. A change that breaks one is wrong even if
it passes the tests.

1. **The source is never modified, and any finding traces back to its source
   easily.** Evidence is opened read-only, hashed, and boundary-enforced against
   directory junctions. Nothing is ever written below the evidence root.
2. **Every output is a copy of a view.** Files are written with
   `COPY (SELECT * FROM <view>) TO <file>`. Go may *distribute* rows; it never
   *decides*. A Go-side calculation a view could have done is a regression.
3. **The report fetches nothing and runs no script.** No `http://`, no `src=`,
   no `@import`, no `<script>`. Evidence text is escaped. There is a test for
   each of these, and they must not be weakened.
4. **Printing carries everything.** Folds are hidden checkboxes plus generated
   CSS, not `<details>`, because a closed `<details>` cannot be forced open by a
   stylesheet. A report that silently omitted a section on paper would lie by
   omission.
5. **Weak correlations are labelled, never suppressed.** Discipline is kept by
   labelling, not by withholding.
6. **Absence is reported as absence.** A missing artefact makes the report
   silent, not negative. A sentinel timestamp is "no time recorded", not a date.
   A place that could not be read is a failure, never a silence.

`internal/store/views.sql` is the largest file in the project and the centre of
gravity: extraction, derivation, classification and the timeline all live there
as views. Read it before changing behaviour anywhere else.

Comments say *why*, not what: the convention is that a comment records the
reasoning or the counterexample that produced the code. Test names are sentences
stating the claim the body proves. Prose and comments are in British English.
