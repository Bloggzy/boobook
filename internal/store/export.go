package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Bloggzy/boobook/internal/provenance"
)

// Export is one output file, with what produced it and what it holds.
//
// The view name is recorded beside the file because "where did this number come
// from" has to be answerable from the output alone. The hash is recorded so a
// file quoted in a report can be shown to be the file the run wrote.
type Export struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	View   string `json:"view"`
	Format string `json:"format"`
	Rows   int    `json:"rows"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type exportSpec struct {
	name, view, format string
}

// The Phase 1 outputs. Each is a copy of a view: there is no second query, and
// no Go code assembling rows, so two outputs cannot disagree about the evidence.
var exports = []exportSpec{
	// devices.csv is one row per physical device; the identities each groups are
	// listed on the row and carried in full in device-identities.csv, and every
	// link that made a group is in device-links.csv with the reason for it.
	{"data/devices.csv", "v_device_classified", "csv"},
	{"data/device-identities.csv", "v_device_identity", "csv"},
	{"data/device-links.csv", "v_device_link", "csv"},
	// What the classification rested on, and the rules and weights it applied.
	{"data/device-facts.csv", "v_device_fact", "csv"},
	{"data/device-rule-matches.csv", "v_device_rule_match", "csv"},
	{"classification/rules.csv", "v_rule", "csv"},
	{"classification/weights.csv", "v_rule_indicator", "csv"},
	{"data/devnodes.csv", "v_devnode", "csv"},
	{"data/events.csv", "v_event", "csv"},
	{"data/file-activity.csv", "v_file_target", "csv"},
	{"data/volumes.csv", "v_removable_volume", "csv"},
	{"data/connections.csv", "v_connection", "csv"},
	{"data/device-lifecycle.csv", "v_device_lifecycle", "csv"},
	{"data/device-volume-links.csv", "v_device_volume_link", "csv"},
	{"data/disks.csv", "v_disk", "csv"},
	// A capacity-zero disk record is a removal signal that closes no window.
	// Exported so a collection without the storage channels has somewhere to
	// look: it is the only thing there that says a device went away at all.
	{"data/disk-departure-candidates.csv", "v_disk_departure_candidate", "csv"},
	{"data/shellbags.csv", "v_shell_bag", "csv"},
	{"data/mru.csv", "v_mru_entry", "csv"},
	{"data/user-assist.csv", "v_user_assist", "csv"},
	{"data/letter-activity.csv", "v_letter_activity", "csv"},
	// Prefetch. The runs and their volumes are exported in full; the loaded
	// file list is exported filtered to removable media, because a host's
	// prefetch files name tens of thousands of paths and all but a handful are
	// the system volume's own libraries. The full list is in case.duckdb, and
	// the view name says the CSV is narrowed.
	{"data/prefetch-runs.csv", "v_prefetch_run", "csv"},
	{"data/prefetch-executions.csv", "v_prefetch_execution", "csv"},
	{"data/prefetch-volumes.csv", "v_prefetch_volume", "csv"},
	// Which volume each record's own executable ran from, including the cases
	// where more than one matched equally well and Boobook therefore named
	// none. Without this the abstention is invisible and reads as a record
	// that simply named no volume.
	{"data/prefetch-run-volume-candidates.csv", "v_prefetch_run_volume_candidate", "csv"},
	{"data/prefetch-files-removable.csv", "v_prefetch_file_on_removable", "csv"},
	{"data/file-attribution.csv", "v_file_attribution", "csv"},
	{"data/file-attribution-summary.csv", "v_file_attribution_summary", "csv"},
	// timeline.csv is every timestamped record in one shape; the significant
	// one is the same view filtered to tier 1 and tier 2 devices, and is
	// exported beside it rather than instead of it.
	{"data/timeline.csv", "v_timeline", "csv"},
	{"data/timeline-significant.csv", "v_timeline_significant", "csv"},
	// What the parsers could not read inside records that otherwise parsed,
	// by artefact and reason. Held only on the rows themselves, a run could
	// report one warning with hundreds of partial parses behind it.
	{"provenance/parse-warnings.csv", "v_parse_warning", "csv"},
	{"provenance/host-time-zone.csv", "v_host_time_zone", "csv"},
	{"provenance/sources.csv", "v_source", "csv"},
	{"provenance/observations.jsonl", "v_observation", "jsonl"},
}

// ExportAll writes every Phase 1 output beneath dir and reports what it wrote.
func (s *Store) ExportAll(dir string) ([]Export, error) {
	written := make([]Export, 0, len(exports))

	for _, spec := range exports {
		path := filepath.Join(dir, filepath.FromSlash(spec.name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return written, fmt.Errorf("create output directory: %w", err)
		}

		export, err := s.exportView(spec, path)
		if err != nil {
			return written, err
		}
		written = append(written, export)
	}

	return written, nil
}

func (s *Store) exportView(spec exportSpec, path string) (Export, error) {
	export := Export{
		Name:   spec.name,
		Path:   path,
		View:   spec.view,
		Format: spec.format,
	}

	// DuckDB's JSON writer emits one object per line by default, which is the
	// form observations.jsonl has always been streamed in.
	options := "HEADER, DELIMITER ','"
	if spec.format == "jsonl" {
		options = "FORMAT JSON"
	}

	statement := fmt.Sprintf("COPY (SELECT * FROM %s) TO '%s' (%s)",
		spec.view, quotePath(path), options)
	if _, err := s.db.Exec(statement); err != nil {
		return export, fmt.Errorf("export %s from %s: %w", spec.name, spec.view, err)
	}

	if err := s.db.QueryRow(
		"SELECT count(*) FROM " + spec.view).Scan(&export.Rows); err != nil {
		return export, fmt.Errorf("count %s: %w", spec.view, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return export, fmt.Errorf("stat %s: %w", path, err)
	}
	export.Bytes = info.Size()

	digest, err := provenance.HashFile(path)
	if err != nil {
		return export, fmt.Errorf("hash %s: %w", path, err)
	}
	export.SHA256 = digest

	return export, nil
}

// quotePath escapes a path for a SQL string literal. The paths come from the
// examiner's own -working argument, not from evidence, but a run must not fail
// or misbehave because a case directory has an apostrophe in it.
func quotePath(path string) string {
	return strings.ReplaceAll(filepath.ToSlash(path), "'", "''")
}
