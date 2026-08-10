# Open work

What is known to be incomplete, and why each item is not done. **These are open,
not done.** A summary that treats them otherwise is wrong however small the
remainder looks.

Several of these came out of independent forensic correctness reviews. The most
valuable thing those reviews produced was not any single defect but the shape
they shared: **an artefact decoded correctly and a conclusion built from it that
is stronger than the artefact supports.** A well-formed output misleads more
readily than a parse failure, because nothing about it looks wrong.

---

## Correctness

**A refused LinkInfo offset still reads as a field the link did not carry.**
`readUTF16Z` returns an empty string for an out-of-range offset and reports no
missing terminator; `parseNetworkShare` does the same for an invalid offset or
size; the Unicode local base, common suffix and volume label all go through the
same unchecked reader. So a damaged structure and an absent one produce the same
output, which is the confusion `Set.Failures` was written to remove one level
up. What it needs is every offset-bearing reader returning a status, each
refusal carrying its own partial-parse warning, and each offset required to lie
inside the substructure that declared it.

**The digest and the parse are still two opens.** `Ledger.Reverify` detects a
source that moved between the hash and the read, and reports it; it does not
prevent the window. Closing it means either one handle carried through every
parser, or staging each input under the working root and hashing the staged
copy. `Workspace.Stage` and `Source.StagedPath` exist for the second and are
unused. Detection is weaker than prevention and is honest about being so.

A narrower case inside it is worth fixing first: EVTX is parsed *before* its
initial source hash is taken, so for that one artefact class the two opens are
not merely separate but in the wrong order, and a change between them is
attested without `Reverify` having anything to compare.

**Typed sub-locators for the file formats.** A jump list's stream and entry
number, a shell link's structure offset, a prefetch section and a shell item's
byte range live in database columns or nowhere, so an observation from one of
those artefacts locates itself only to the file. `Locator` covers a registry key,
an event record and a log line and stops there. Real work rather than a rename.

## Artefacts not yet read

**The XP UserAssist record is not decoded.** Its run count carries an offset of
five, so a naive read reports five extra executions of everything and a genuine
single run as "not run", and there is no XP evidence here to check a fix against.
`bookkeeping` no longer stands in the way; it had been suppressing
`UEME_RUNPATH` and its siblings. Decoding the 16-byte record is now the only
thing between this tool and those hosts' execution evidence.

**Classifying a removal from a UMDF record needs one real record.** Events 2003,
2100 and 2102 are `KindOther`, and the request-code field names are deliberately
not guessed: the manifest gives the message strings and not the template, the
channel is disabled by default on current Windows, and no reference collection
carries a record. Inventing a plausible `<Data Name="…">` and writing a fixture
around it would test the invention.

**Event 6008's rendered previous-shutdown time is not decoded.** It is a
locale-formatted string in the message rather than a field, and no reference
collection carries a record to check a decoder against. One real record would
make it a better upper bound on an unclean stop than the boot that reported it.

**Phase 4, depth.** Tier B sources, the GPT partition chain, `$UsnJrnl`.

## Calibrations that would benefit from more evidence

**Resolve the daylight-saving season.** `StandardStart` / `DaylightStart` are
read, but only `wMonth`, which is enough to say whether a host changes its clock
at all and not enough to say which side of a transition a record falls on.
Decoding the rest of each rule (week, day of week, hour) would resolve most
wall-clock timestamps to a single reading.

Three caveats to design around: the stored rules are current as of collection, so
applying them to older records is wrong wherever the rules have since changed;
the repeated hour at the autumn fall-back is genuinely two instants and is
irreducible; and a local time inside the skipped spring hour never existed, which
is itself a finding.

**Promoting the capacity-zero disk record to a departure.**
`v_disk_departure_candidate` collects it and closes no window. What is needed
before it can close one is a collection containing a multi-slot card reader with
an empty slot, the shape that would make it manufacture removals, since such a
reader reports zero capacity continuously while never leaving the port; and the
same pairing checked on more Windows versions than the one host that shows it
working. Until then the corroboration column is the whole of what it claims.

**The fifteen-second arrival tolerance is the thinnest calibration in
`v_connection`.** It is bounded below by one test fixture (a six-second
cross-channel spread) and above by one real gap (80.5 seconds). It is the first
thing to look at if a collection ever splits one arrival into two windows or
folds two connections into one.

**The twenty-four-hour bound on `sole_connected_device` is the second thinnest.**
The gap it sits in is large: every genuine window on the reference collections
closes within eleven minutes, and the case it excludes is 262 days. Nothing
turns on the exact figure today. What would strain it is a device genuinely left
attached across a working day with the logs recording nothing in between, where
the route would go quiet part way through. That reads as under-claiming rather
than as a wrong answer, which is the right direction to fail in, but it is the
number to revisit if a collection ever shows a long, well-evidenced attachment
losing its records half way.

## Test corpus

**A wider fixture corpus.** A fixture must never import the parser it is a
fixture for, and there is a test for that. The builders cover LNK, DestList,
shell items, all four prefetch formats, a compound file, a non-Unicode CP1251
`StringData` field and a DestList whose declared version and entry shape
disagree. What is still missing is multiple items and competing candidates within
one fixture.
