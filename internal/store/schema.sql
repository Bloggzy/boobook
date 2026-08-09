-- The case database.
--
-- Every table that holds a fact carries source_id. That column is not
-- decoration: it is what makes a row in devices.csv resolvable back to a file,
-- its SHA-256 and the offset the value sat at. A table without it could hold a
-- number nobody can check.
--
-- Raw stored forms are kept beside derived ones throughout. A converted
-- timestamp with no FILETIME beside it is a conclusion wearing the clothes of
-- an observation.

-- ---- provenance -----------------------------------------------------------

CREATE TABLE source (
    id          VARCHAR PRIMARY KEY,
    path        VARCHAR,
    staged_path VARCHAR,
    artefact    VARCHAR,
    size_bytes  BIGINT,
    sha256      VARCHAR,
    read_at     TIMESTAMP,
    -- A hive parsed without transaction-log replay may be missing its most
    -- recent writes. That difference must never be invisible in a query.
    --
    -- NULL means replay does not apply: an event log or a shortcut has no
    -- transaction logs, and storing false for one makes it read as a hive whose
    -- logs were skipped.
    --
    -- True means a transaction log supplied a page that reached the values
    -- read from this hive, not that the recovery call returned without an
    -- error. Recovery succeeds having merely copied the file, so the two are
    -- very different claims and this used to be the weaker one.
    replayed    BOOLEAN,
    -- The logs that supplied those pages, not every log found beside the hive:
    -- a superseded, empty or unsupported log is present and contributed
    -- nothing, and naming it here asserted otherwise.
    replay_logs VARCHAR,
    -- What happened, in one sentence, including the case a boolean cannot
    -- express: recovery ran and changed nothing.
    replay_note VARCHAR,
    -- The file's own last-written time as it stood when the run hashed it.
    modified_at TIMESTAMP,
    -- Whether the file was still the file that was hashed when the run
    -- finished with it. Hashing and parsing are separate opens, so on evidence
    -- that can move — a live host, a share, a collection still being written —
    -- observations could otherwise carry the digest of bytes nobody read.
    verified    BOOLEAN,
    verify_note VARCHAR
);

CREATE TABLE observation (
    id              VARCHAR,
    source_id       VARCHAR,
    kind            VARCHAR,
    -- field names which fact within the kind, raw is the stored form of that
    -- fact, value is what was made of it, and summary is the narration. The
    -- first three were being used for the fourth: eight recorders put a joined
    -- description in raw, so a consumer could not tell whether a row held
    -- bytes, decoded text or a sentence — which is the one thing raw is for.
    field           VARCHAR,
    raw             VARCHAR,
    value           VARCHAR,
    summary         VARCHAR,
    raw_timestamp   UBIGINT,
    time_utc        TIMESTAMP,
    registry_key    VARCHAR,
    registry_value  VARCHAR,
    control_set     VARCHAR,
    event_record_id UBIGINT,
    channel         VARCHAR,
    line_number     INTEGER,
    byte_offset     BIGINT
);

-- Warnings are evidence about the collection, not run noise: an absent
-- artefact is a finding, so it is queryable alongside what was found.
CREATE TABLE warning (
    source_id VARCHAR,
    artefact  VARCHAR,
    path      VARCHAR,
    severity  VARCHAR,
    message   VARCHAR,
    -- "at" is reserved.
    recorded_at TIMESTAMP
);

-- ---- registry -------------------------------------------------------------

CREATE TABLE devnode (
    source_id            VARCHAR,
    control_set          VARCHAR,
    enumerator           VARCHAR,
    device_id            VARCHAR,
    instance_id          VARCHAR,
    device_instance_id   VARCHAR,
    -- The Enum form. A WPDBUSENUM node stores another device's path as its
    -- instance id ("_??_USBSTOR#..."), so the stored form is not the device's
    -- identity and its last segment is not a serial.
    normalised_instance_id VARCHAR,
    -- device_key is the case-folded join key. MountedDevices keeps a device's
    -- own casing while Portable Devices upper-cases it, so a case-sensitive
    -- join returns nothing while looking like an absence of evidence.
    device_key           VARCHAR,
    registry_key         VARCHAR,
    raw_key_last_write   UBIGINT,
    key_last_write_utc   TIMESTAMP,
    device_desc          VARCHAR,
    friendly_name        VARCHAR,
    mfg                  VARCHAR,
    class                VARCHAR,
    class_guid           VARCHAR,
    service              VARCHAR,
    container_id         VARCHAR,
    parent_id_prefix     VARCHAR,
    hardware_id          VARCHAR,
    compatible_ids       VARCHAR,
    location_information VARCHAR,
    bus_reported_desc    VARCHAR,
    -- The PnP lifecycle properties. Each records only the most recent event of
    -- its kind, so these are states and not a connection history.
    raw_install_date       UBIGINT,
    install_date_utc       TIMESTAMP,
    raw_first_install_date UBIGINT,
    first_install_date_utc TIMESTAMP,
    raw_last_arrival_date  UBIGINT,
    last_arrival_date_utc  TIMESTAMP,
    raw_last_removal_date  UBIGINT,
    last_removal_date_utc  TIMESTAMP
);

-- The host's configured time zone, as the registry records it.
--
-- It is in the database rather than only in the manifest because the timeline
-- needs it: a shell item's FAT timestamp is local wall clock with no zone, and
-- without the host biases there is no way to offer a UTC reading of it at all.
-- Both seasonal readings are derived from these biases at query time, which is
-- why the biases are stored and no converted value is.
CREATE TABLE host_time_zone (
    source_id            VARCHAR,
    registry_key         VARCHAR,
    control_set          VARCHAR,
    key_name             VARCHAR,
    standard_name        VARCHAR,
    daylight_name        VARCHAR,
    -- Minutes west of UTC, as Windows stores them: UTC = local + bias.
    bias_minutes          INTEGER,
    standard_bias_minutes INTEGER,
    daylight_bias_minutes INTEGER,
    -- The bias in force when the hive was written. It dates the collection, not
    -- the records, so it is never applied to a timestamp.
    active_bias_minutes   INTEGER,
    -- wMonth from the two SYSTEMTIME transition rules, and the user switch that
    -- overrides them. Zero months mean the zone never changes its clock, which
    -- the daylight bias alone does not say: Windows stores DaylightBias -60 for
    -- W. Australia Standard Time with both rules empty.
    standard_start_month  INTEGER,
    daylight_start_month  INTEGER,
    dynamic_daylight_disabled BOOLEAN
);

CREATE TABLE mount_entry (
    source_id          VARCHAR,
    value_name         VARCHAR,
    kind               VARCHAR,
    drive_letter       VARCHAR,
    volume_guid        VARCHAR,
    target_kind        VARCHAR,
    device_path        VARCHAR,
    device_instance_id VARCHAR,
    device_key         VARCHAR,
    partition_guid     VARCHAR,
    target_volume_guid VARCHAR,
    target_offset_hex  VARCHAR,
    disk_signature     UBIGINT,
    partition_offset   UBIGINT,
    raw                VARCHAR
);

CREATE TABLE portable_device (
    source_id          VARCHAR,
    registry_path      VARCHAR,
    key_name           VARCHAR,
    friendly_name      VARCHAR,
    device_instance_id VARCHAR,
    device_key         VARCHAR,
    volume_guid        VARCHAR,
    volume_offset_hex  VARCHAR
);

CREATE TABLE emd_volume (
    source_id             VARCHAR,
    registry_path         VARCHAR,
    key_name              VARCHAR,
    volume_label          VARCHAR,
    volume_serial_decimal VARCHAR,
    -- The one key name carries the volume serial, the label and the device
    -- together, which is what makes this the strongest route from a file
    -- record to a device: no inference sits between them.
    device_instance_id    VARCHAR,
    device_key            VARCHAR
);

CREATE TABLE mount_point (
    source_id          VARCHAR,
    profile            VARCHAR,
    registry_path      VARCHAR,
    key_name           VARCHAR,
    kind               VARCHAR,
    drive_letter       VARCHAR,
    volume_guid        VARCHAR,
    remote_path        VARCHAR,
    raw_key_last_write UBIGINT,
    key_last_write_utc TIMESTAMP
);

-- ---- shell bags and MRU lists ---------------------------------------------

-- A bag names a folder Explorer displayed. It survives the folder and the
-- volume, so a bag on a drive letter can be the only surviving record that a
-- folder existed on a removable device.
--
-- The FAT timestamps are local wall clock with no zone recorded, which is why
-- they are named _local and are not TIMESTAMP columns an analyst would sort
-- against UTC event times without noticing.
CREATE TABLE shell_bag (
    source_id      VARCHAR,
    hive           VARCHAR,
    profile        VARCHAR,
    path           VARCHAR,
    path_has_gap   BOOLEAN,
    name           VARCHAR,
    kind           VARCHAR,
    drive_letter   VARCHAR,
    depth          INTEGER,
    node_slot      UBIGINT,
    mru_position   INTEGER,
    raw_modified   UBIGINT,
    raw_created    UBIGINT,
    raw_accessed   UBIGINT,
    modified_local VARCHAR,
    created_local  VARCHAR,
    accessed_local VARCHAR,
    mft_entry      UBIGINT,
    mft_sequence   UBIGINT,
    registry_path  VARCHAR,
    raw_key_last_write UBIGINT,
    key_last_write_utc TIMESTAMP,
    raw            VARCHAR,
    warnings       VARCHAR
);

CREATE TABLE mru_entry (
    source_id      VARCHAR,
    profile        VARCHAR,
    source_list    VARCHAR,
    kind           VARCHAR,
    name           VARCHAR,
    path           VARCHAR,
    path_has_gap   BOOLEAN,
    drive_letter   VARCHAR,
    -- Set where the letter was read out of the displayed name rather than out
    -- of a shell item. Both are the shell's own doing and neither is a guess,
    -- but a reader checking the row looks in a different place for each.
    letter_from_name BOOLEAN,
    -- The label Explorer showed beside the letter for a drive root, which is
    -- the volume's own name when the entry was written.
    volume_label   VARCHAR,
    position       INTEGER,
    value_name     VARCHAR,
    raw_modified   UBIGINT,
    modified_local VARCHAR,
    registry_path  VARCHAR,
    raw_key_last_write UBIGINT,
    key_last_write_utc TIMESTAMP,
    raw            VARCHAR,
    warnings       VARCHAR
);

-- The shell's own record of what a user launched, as against prefetch's record
-- of what the loader touched. Per user, and it counts focus as well as runs.
CREATE TABLE user_assist (
    source_id      VARCHAR,
    profile        VARCHAR,
    category       VARCHAR,
    category_name  VARCHAR,
    name           VARCHAR,
    drive_letter   VARCHAR,
    run_count      UBIGINT,
    focus_count    UBIGINT,
    focus_seconds  DOUBLE,
    raw_last_executed UBIGINT,
    last_executed_utc TIMESTAMP,
    -- The shell's own counters rather than a launch. Kept, and excluded from
    -- anything that reads as "a programme was run".
    bookkeeping    BOOLEAN,
    value_name     VARCHAR,
    registry_path  VARCHAR,
    raw            VARCHAR,
    warnings       VARCHAR
);

-- ---- event logs -----------------------------------------------------------

CREATE TABLE event (
    source_id          VARCHAR,
    channel            VARCHAR,
    source_file        VARCHAR,
    record_id          UBIGINT,
    event_id           BIGINT,
    provider           VARCHAR,
    raw_file_time      UBIGINT,
    time_utc           TIMESTAMP,
    rule_id            VARCHAR,
    kind               VARCHAR,
    meaning            VARCHAR,
    device_instance_id VARCHAR,
    device_key         VARCHAR
);

-- One row per extracted field. Keeping fields as rows rather than as a
-- flattened blob is what lets a join name the field it matched on, so a
-- correlation can say where it came from instead of asserting a match.
CREATE TABLE event_field (
    source_id   VARCHAR,
    source_file VARCHAR,
    record_id   UBIGINT,
    name        VARCHAR,
    role        VARCHAR,
    value       VARCHAR,
    path        VARCHAR
);

-- ---- disks ----------------------------------------------------------------

-- A disk as a Partition/Diagnostic 1006 record described it, with its layout
-- decoded from the raw structures the record carries.
--
-- This is what connects a volume to a device. MountedDevices identifies a
-- volume by a GPT partition identifier or an MBR disk signature and offset, and
-- says nothing about which physical disk that is. This record names both: the
-- disk's device instance, and the identifiers its partitions carry.
CREATE TABLE disk_layout (
    source_id          VARCHAR,
    source_file        VARCHAR,
    record_id          UBIGINT,
    time_utc           TIMESTAMP,
    device_instance_id VARCHAR,
    device_key         VARCHAR,
    disk_number        VARCHAR,
    model              VARCHAR,
    manufacturer       VARCHAR,
    serial_number      VARCHAR,
    bus_type           VARCHAR,
    capacity           VARCHAR,
    style              VARCHAR,
    disk_guid          VARCHAR,
    -- Set for an MBR disk from the layout structure, and separately read from
    -- the boot record sector. Where both are present they must agree; where
    -- only one is, the other simply was not carried.
    disk_signature     UBIGINT,
    boot_record_signature UBIGINT,
    partition_count    INTEGER,
    warnings           VARCHAR
);

CREATE TABLE disk_partition (
    source_id       VARCHAR,
    record_id       UBIGINT,
    device_key      VARCHAR,
    disk_number     VARCHAR,
    partition_number INTEGER,
    starting_offset UBIGINT,
    length_bytes    UBIGINT,
    -- partition_guid is unique to this partition and is what MountedDevices
    -- stores in its DMIO:ID: form. type_guid says what kind of partition it is,
    -- is shared by every partition of that kind, and identifies nothing.
    partition_guid  VARCHAR,
    type_guid       VARCHAR,
    partition_name  VARCHAR,
    mbr_type        UBIGINT
);

-- ---- setupapi -------------------------------------------------------------

-- The log writes local time with no zone. start_utc and start_utc_alt hold both
-- seasonal readings where daylight saving could apply, and time_ambiguous says
-- which case this is. Collapsing them to one column would present a guess as a
-- measurement, and an hour either way changes what a timeline says.
CREATE TABLE setup_section (
    source_id          VARCHAR,
    source_file        VARCHAR,
    line_number        INTEGER,
    operation          VARCHAR,
    kind               VARCHAR,
    target             VARCHAR,
    device_instance_id VARCHAR,
    device_key         VARCHAR,
    start_local        VARCHAR,
    end_local          VARCHAR,
    start_utc          TIMESTAMP,
    start_utc_alt      TIMESTAMP,
    start_basis        VARCHAR,
    time_ambiguous     BOOLEAN,
    exit_status        VARCHAR,
    parent_device      VARCHAR,
    driver_inf         VARCHAR,
    class_guid         VARCHAR,
    problem            VARCHAR
);

-- ---- file activity --------------------------------------------------------

-- Whether a target sat on removable media is the recording application's own
-- statement, taken from the link's volume information. It is stored as that
-- statement. Which device held the letter is a separate question and is not
-- answered in this table.
CREATE TABLE file_target (
    source_id           VARCHAR,
    source_file         VARCHAR,
    origin              VARCHAR,
    app_id              VARCHAR,
    profile             VARCHAR,
    stream_name         VARCHAR,
    path                VARCHAR,
    drive_letter        VARCHAR,
    volume_present      BOOLEAN,
    drive_type          VARCHAR,
    volume_serial_hex   VARCHAR,
    volume_label        VARCHAR,
    removable           BOOLEAN,
    raw_target_written  UBIGINT,
    target_written_utc  TIMESTAMP,
    raw_target_accessed UBIGINT,
    target_accessed_utc TIMESTAMP,
    target_created_utc  TIMESTAMP,
    target_size_bytes   BIGINT,
    -- The NetBIOS name in the link tracker block: the machine the shortcut was
    -- made or last updated on, which distributed link tracking uses to resolve
    -- a moved target. It is not the machine that opened the file.
    machine_id          VARCHAR,
    -- The target as the link's shell items named it, kept apart from the path
    -- LinkInfo recorded: a link can carry one and not the other, and where it
    -- carries both and they differ that is a finding.
    target_item_path    VARCHAR,
    -- The shell link's StringData fields, which were parsed and then discarded.
    --
    -- relative_path is the one that cost evidence. MS-SHLLINK 2.4 defines it as
    -- the path to use when resolving the target, and a link can carry it with
    -- no LinkInfo at all — at which point Boobook exported an empty path, kept
    -- the drive letter, and put a `file_opened` row on the timeline for a
    -- target it could not name while the shortcut held the name the whole time.
    --
    -- It is stored as recorded and never joined onto anything to make it
    -- absolute. A relative path is relative to something the link does not
    -- record, so completing it would be a guess wearing the shape of a path;
    -- path_basis says which of the three the row's path came from instead.
    relative_path       VARCHAR,
    -- The rest of StringData, kept because a shortcut is evidence about what
    -- somebody ran as well as about what they opened: arguments and a working
    -- directory are the difference between a document being opened and a
    -- programme being launched against it.
    working_dir         VARCHAR,
    arguments           VARCHAR,
    icon_location       VARCHAR,
    target_item_modified_local VARCHAR,
    mft_entry           UBIGINT,
    mft_sequence        UBIGINT,
    -- Jump list detail. destlist_present false means the link is real but its
    -- place in the order is not known; a position of zero would invent a rank.
    destlist_present    BOOLEAN,
    entry_number        BIGINT,
    mru_position        INTEGER,
    -- How many times the application recorded opening the entry, from the
    -- integer field the modern DestList carries. NULL where the entry records
    -- none: a Windows 7 DestList has no such field, and a zero there would
    -- read as "opened, never".
    access_count        BIGINT,
    -- The undocumented float stored beside the entry number. It was once read
    -- as the access count and is not one — values of 3.7 and 25.98 appear on
    -- the reference collections — so it is exported under its own name for
    -- whoever eventually works out what it means.
    destlist_ranking_value DOUBLE,
    -- Whether the application pinned the entry. NULL where the pin status could
    -- not be read — which is a different claim from an entry that is not
    -- pinned, and is what a DestList whose declared version contradicts its
    -- entry shape leaves behind: the status is one sign bit at an offset that
    -- shape decides.
    pinned              BOOLEAN,
    -- The shortcut file's own last-written time. The times inside the link
    -- describe the target, not the opening, so this is the only interaction
    -- time a .lnk can carry — but whether it is one depends on link_context.
    source_modified_utc TIMESTAMP,
    -- Which directory the shortcut was found in: recent, office_recent,
    -- quick_launch or desktop. The shell rewrites a Recent link on every open,
    -- so there the mtime is an opening. A Desktop or pinned link is written
    -- when a user creates, edits, pins or copies it, and reading that as an
    -- opening puts somebody at a machine at a moment nothing evidences.
    -- v_file_activity decides; this column is the fact it decides on.
    link_context        VARCHAR,
    raw_last_access     UBIGINT,
    last_access_utc     TIMESTAMP,
    parse_warnings      VARCHAR
);

-- ---- prefetch --------------------------------------------------------------

-- Whether Windows was recording programme launches at all.
--
-- One row, or none where no SYSTEM hive was read. Without it an empty Prefetch
-- directory has three readings — prefetching off, nothing ran, or the collector
-- did not take it — and the report would have to guess between them.
CREATE TABLE host_prefetch_setting (
    source_id    VARCHAR,
    registry_key VARCHAR,
    control_set  VARCHAR,
    -- Absent is not zero. Where the value was never written Windows prefetches
    -- anyway, so a missing value and a stored 0 mean opposite things.
    value_found  BOOLEAN,
    raw_value    UBIGINT,
    description  VARCHAR
);

-- One prefetch file: one executable, on one path.
--
-- source_file is the key the volume, execution and file tables join on. It is
-- the path of the .pf itself, so every row below is one dereference from the
-- file it was read out of and the hash the ledger holds for it.
CREATE TABLE prefetch_run (
    source_id       VARCHAR,
    source_file     VARCHAR,
    executable      VARCHAR,
    -- The kernel path the Windows 10 and 11 formats record. Empty on older
    -- formats, which do not carry it — absent, not "ran from nowhere".
    executable_path VARCHAR,
    -- The hash Windows computed over the full path, and which forms part of the
    -- file name. Two prefetch files for one executable name mean it ran from
    -- two different paths, which is a finding in itself.
    path_hash       VARCHAR,
    format_version  VARCHAR,
    -- run_count is what the file stores. It is not the number of rows in
    -- prefetch_execution: Windows 8 and later keep the last eight executions
    -- and overwrite the rest, so a count of 400 beside two times is ordinary
    -- and not a defect.
    run_count       UBIGINT,
    times_recorded  INTEGER,
    volume_count    INTEGER,
    file_count      INTEGER,
    parse_warnings  VARCHAR
);

-- One recorded execution. Slot 1 is the most recent.
CREATE TABLE prefetch_execution (
    source_id   VARCHAR,
    source_file VARCHAR,
    executable  VARCHAR,
    slot        INTEGER,
    -- A UTC instant, not a wall clock: this is a FILETIME, converted through
    -- wintime like every other one, so a zeroed slot produces no row at all.
    time_utc    TIMESTAMP
);

-- One volume the execution touched.
--
-- volume_serial_hex is the reason this table exists. It is the same value a
-- shell link records in its volume id, rendered the same way, so prefetch and
-- the file records join on it without conversion or inference.
CREATE TABLE prefetch_volume (
    source_id         VARCHAR,
    source_file       VARCHAR,
    executable        VARCHAR,
    -- \DEVICE\HARDDISKVOLUME2 or \VOLUME{GUID}: the prefix the file paths
    -- carry, which is what ties a loaded file to a volume.
    device_path       VARCHAR,
    volume_serial_hex VARCHAR,
    raw_serial        UBIGINT,
    -- When the volume was formatted. Removable volumes on the reference
    -- evidence store a zeroed value, which stays NULL rather than becoming a
    -- date in 1601.
    created_utc       TIMESTAMP
);

-- One file the loader touched, as the kernel path it was stored as.
--
-- Which volume each belongs to is a prefix match against prefetch_volume and is
-- done in a view, not here: the file stores the path and nothing else, and
-- resolving it at load time would put a derivation in a table of observations.
CREATE TABLE prefetch_file (
    source_id   VARCHAR,
    source_file VARCHAR,
    executable  VARCHAR,
    path        VARCHAR
);

-- ---- the classification rule set -------------------------------------------
--
-- The rules are loaded rather than compiled in, so the case database holds the
-- exact rule set and the exact weights the run used. A run reported six months
-- later can be checked against the rules it actually applied, not against
-- whatever the tool ships today.

CREATE TABLE rule_setup_class (
    class_guid VARCHAR,
    class_name VARCHAR
);

CREATE TABLE rule_category (
    category     VARCHAR,
    default_tier INTEGER,
    relevance    VARCHAR,
    note         VARCHAR
);

CREATE TABLE rule (
    rule_id  VARCHAR,
    category VARCHAR,
    tier     INTEGER,
    priority INTEGER,
    note     VARCHAR
);

CREATE TABLE rule_condition (
    rule_id VARCHAR,
    fact    VARCHAR,
    -- A negated condition is how "a portable device that never appeared under
    -- USBSTOR" is expressed, which is the case the reference document warns
    -- against missing.
    negate  BOOLEAN
);

-- The weights as applied, profile multipliers already folded in, so the file
-- records the numbers that produced the score rather than the numbers before
-- the profile touched them.
CREATE TABLE rule_indicator (
    fact           VARCHAR,
    weight         DOUBLE,
    base_weight    DOUBLE,
    indicator_group VARCHAR,
    profile        VARCHAR,
    note           VARCHAR
);

CREATE TABLE rule_review_fact (
    fact VARCHAR,
    note VARCHAR
);

-- Facts that make a review fact normal rather than notable, one row each.
-- A keyboard carries no serial and never did, so no_serial says nothing about
-- it; flagged on every such device it buries the cases where the absence is
-- the finding.
CREATE TABLE rule_review_exception (
    fact        VARCHAR,
    unless_fact VARCHAR,
    note        VARCHAR
);

-- ---- consolidated derivations ----------------------------------------------
--
-- These two hold results computed by views, written once by the consolidation
-- step at the end of a run. They are here because the grouping is a recursive
-- closure and the facts are a wide union over it: every downstream view reads
-- them, and recomputing per reader costs a minute a run for no different answer.
--
-- The reasoning still lives in views.sql — v_device_grouping and
-- v_device_fact_computed — so there is still one place where each thing is
-- decided.

CREATE TABLE device_group (
    device_key         VARCHAR,
    physical_device_id VARCHAR,
    identity_count     BIGINT,
    preference         BIGINT
);

CREATE TABLE device_fact (
    physical_device_id VARCHAR,
    fact               VARCHAR,
    evidence           VARCHAR,
    evidence_count     BIGINT
);

-- The attribution is here for the same reason. Each of its routes asks, per
-- file record, whether a connection window covers it, and five readers now want
-- the answer: two exports, the summary, the headline findings and the device
-- cards. Computed once, they all agree and the run stays under ten seconds.
CREATE TABLE file_attribution (
    activity_id        BIGINT,
    artefact           VARCHAR,
    path               VARCHAR,
    drive_letter       VARCHAR,
    volume_serial_hex  VARCHAR,
    volume_label       VARCHAR,
    profile            VARCHAR,
    recorded_utc       TIMESTAMP,
    device_key         VARCHAR,
    device_instance_id VARCHAR,
    route              VARCHAR,
    confidence         VARCHAR,
    detail             VARCHAR,
    -- Set where the record's own volume label names a device this route's
    -- drive letter does not reach. The row is kept and capped, never dropped
    -- and never swapped; what it loses is the right to win the contest that
    -- names one device on the timeline.
    contradicted       BOOLEAN,
    source_id          VARCHAR
);

-- Which timeline entries were gathered under which connection moment. Here for
-- the same reason as the two above: the membership is a join of the whole
-- timeline against every connection endpoint, and four readers want the answer
-- — the merged report timeline, the members inside each fold, the moment
-- summary and the export. Computed per reader it costs several passes over the
-- most expensive view in the schema.
--
-- The reasoning lives in v_timeline_moment_member_computed, so there is still
-- one place where membership is decided.
CREATE TABLE timeline_moment_member (
    entry_id    BIGINT,
    moment_id   BIGINT,
    -- How far the record sits from the connection endpoint it was gathered
    -- under. Kept because it is the evidence for the grouping: a reader who
    -- wants to know why a record was folded into an arrival can see how close
    -- to it the record actually was.
    distance_ms BIGINT
);
