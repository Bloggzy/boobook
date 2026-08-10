# Phase 0: spike results

**Date:** 2026-08-01
**Verdict:** **GO.** Go + `regparser` + `evtx` + embedded DuckDB is the stack.
**Code:** `cmd/spike`, `internal/{evidence,registry,eventlog,store}`, as they
stood on the day. `cmd/spike` was removed once phase 1 replaced it; the four
`internal` packages are still there and have grown a great deal.

This is a dated record of a decision, kept because the measurements behind the
stack choice are the only place they are written down. It is not a description
of the tool.

Phase 0 asked four questions. All four are answered.

---

## 1. Registry parse including transaction-log replay: YES

`regparser` exposes `RecoverHive(hive, logFiles...)`. It copies the hive, applies
dirty pages in sequence order, skips a log whose sequence does not follow the
base, and corrects the header checksum. It replayed successfully on all four
collections, and correctly reported a sequence mismatch on
`SYSTEM.LOG2` in one of them rather than applying it blindly:

```
[info] skipping log file SYSTEM.LOG2, sequence number mismatch
       (log starts at sequence number 953, base is already at 958)
```

**The risk flagged in the plan was wrong.** This was called the largest
technical unknown, and it turned out to be a solved problem in the library.

*Phase 1 follow-up:* `RecoverHive` writes its copy to `os.TempDir()`. It must go
under the caller's working root instead.

## 2. EVTX at speed: YES

**~50 MB/s per run**, parsing every EVTX file in the collection with one
goroutine per file. Zero file-level parse failures across 785 event log files.

## 3. DuckDB holding the result and expressing correlation in SQL: YES

Schema loads in ~280 ms for ~1,000 rows. The Phase 0 correlation query joins
`USBSTOR` devnodes to their USB descriptor identity via shared `ContainerID`,
and to event activity via serial, entirely in SQL. It runs in ~11 ms.

The join is the real one, not a toy: a `USBSTOR` key carries SCSI inquiry text
and never a VID/PID, so the container is the only sound route to the USB
identity. It resolved correctly on every sample.

## 4. The 60-second gate: PASS, by a factor of 20

| Collection | Evidence | EVTX files | Records read | USB-relevant | Total |
|---|---:|---:|---:|---:|---:|
| USB-CTF | 152.8 MB | 103 | 24,742 | 370 | **1.0 s** |
| USB-LENOVO | 234.1 MB | 216 | 76,064 | 767 | **2.9 s** |
| USB-LENOVO-SANDISK | 270.2 MB | 233 | 87,451 | 852 | **2.9 s** |
| USB-LENOVO-SANDISK-LATER | 276.2 MB | 233 | 89,139 | 877 | **3.0 s** |

Boodie's equivalent work was hour-scale on the event logs alone. There is no
longer any argument for a triage mode that omits `Security.evtx` and
`System.evtx`, and §6 of the plan can be taken as settled.

---

## Findings that change Phase 1

### A device can exist in the event logs and not in the registry

In `USB-LENOVO-SANDISK`, a SanDisk 3.2Gen1 (`VID_0781&PID_5591`, serial
`04010d18a394...`) has **15+ event records across five channels** at
2026-07-26 10:00:06 (Kernel-PnP Configuration, StorageVolume, Partition
Diagnostic, Storsvc Diagnostic, Kernel-ShimEngine) and **zero rows anywhere in
the SYSTEM hive**, including after transaction-log replay. The same device is
present in the registry in `USB-LENOVO-SANDISK-LATER`.

The hive snapshot predates the PnP writes; the event logs do not. This is the
ordinary result of a collector reading artefacts in sequence while the machine
keeps running, and it appears in **one of our three real collections**, so it is
not an edge case.

**Consequence:** a registry-first device inventory silently loses devices. The
device inventory must be built from the **union** of registry and event-log
evidence, with each device stating which sources attest to it. Boodie called
these "event-backed USBSTOR candidates"; in Boobook they are first-class device
records carrying a source attestation, not a lesser class of finding.

This is also a direct vindication of the confidence-labelling design in plan §7:
the honest output here is "device seen, event evidence only, no registry record",
which is far more useful than either silence or an unqualified claim.

### Two silent-failure bugs, both now covered by tests

1. **`REG_SZ` values retain their NUL terminator.** A `ContainerID` read from the
   hive would not equal the same GUID as a clean string. Every container-based
   join would have quietly returned nothing, and the symptom would have read as
   "no correlation found" rather than as a bug. Fixed in `trimStored`; a trailing
   run of NULs is stripped, an interior NUL is preserved as data.

2. **`EventID` is nested as `{"Value": n}` and arrives at varying integer
   widths.** A type switch over `int64`/`uint64`/`int`/`float64` missed the width
   actually used and returned 0 for all 852 retained records, indistinguishable
   from a genuine event 0. `toInt` now reads any integer width reflectively.

Both are exactly the class of defect that produces a confident, wrong, empty
report. Both have regression tests.

### Prefer the record's own metadata over the filename

Event records carry their own `Channel` and a `TimeCreated.SystemTime` with
sub-second precision. The filename is only an encoding of the channel and can be
mangled by a collector; the record header time is whole-second. Phase 1 should
read from the record and keep the filename as provenance only.

### Raw FILETIME is lost by the library

`regparser` converts key last-write times to `time.Time` at parse. The plan
requires the raw FILETIME preserved beside every derived value, so Phase 1 needs
to read that field directly rather than take the library's conversion.

---

## What the spike is not

No provenance chain, no hashing, no staging, no discovery of triage-collection
layouts, no classification, no report. The USB relevance filter is a regex over
a flattened payload, serviceable for measuring throughput but not the real
selection logic. All Phase 1.
