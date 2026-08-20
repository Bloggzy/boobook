// Package store is the case database: every parsed fact, loaded into DuckDB,
// with the source it came from beside it.
//
// Correlation belongs in SQL, not in Go loops, and so does export. The schema
// and the views live in schema.sql and views.sql next to this file, and every
// output is a copy of a view — so a figure in the report, a row in devices.csv
// and an analyst's own query are the same answer by construction rather than by
// two implementations agreeing.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"unicode/utf8"

	_ "github.com/duckdb/duckdb-go/v2"
)

//go:embed schema.sql
var schemaSQL string

//go:embed views.sql
var viewsSQL string

// Store is a case database.
type Store struct {
	db *sql.DB
}

// Open creates a case database at path. An empty path gives an in-memory store.
func Open(path string) (*Store, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}

	store := &Store{db: db}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	if _, err := db.Exec(viewsSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create views: %w", err)
	}

	return store, nil
}

// OpenExisting opens a case database whose schema and views are already in
// place, without creating either.
//
// Open is the way a run makes its database and always creates the views, which
// is right there and costs about three and a half seconds: DuckDB checks all 84
// of them, and views.sql is the largest file in the project. That is a price
// worth paying once per run and not once per caller — a tool reading a finished
// case.duckdb to query it wants the answers, not the definitions, and so does a
// test that copies a prepared database rather than building one.
//
// Nothing here checks that the file holds what it says it does. A path that is
// not a case database fails at the first query rather than at the open, which
// is the same behaviour DuckDB itself has.
func OpenExisting(path string) (*Store, error) {
	db, err := sql.Open("duckdb", path)
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the handle. It is safe to call twice, because the run closes
// the database deliberately once everything has been read — so that the file on
// disk is settled and can be hashed into the manifest — and the deferred close
// that guards an early return then has nothing left to do.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	db := s.db
	s.db = nil
	return db.Close()
}

// Checkpoint writes the write-ahead log into the database file.
//
// DuckDB checkpoints on close anyway. It is done explicitly here because the
// manifest hashes case.duckdb, and a digest is only worth recording if it is of
// the settled file: hashing before the WAL is folded in attests bytes that the
// next process to open the database will change.
func (s *Store) Checkpoint() error {
	if s.db == nil {
		return nil
	}
	if _, err := s.db.Exec("CHECKPOINT"); err != nil {
		return fmt.Errorf("checkpoint the case database: %w", err)
	}
	return nil
}

// DB exposes the handle for ad-hoc queries.
func (s *Store) DB() *sql.DB { return s.db }

// insert runs one prepared insert inside a transaction, calling emit once per
// row. Every loader is the same shape, and writing that shape once keeps a
// column list and its placeholders from drifting apart.
func (s *Store) insert(table, columns string, rows int,
	emit func(add func(values ...any) error) error) error {

	if rows == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	names := strings.Split(columns, ",")
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")

	statement, err := tx.Prepare(fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s)", table, columns, placeholders))
	if err != nil {
		return fmt.Errorf("prepare insert into %s: %w", table, err)
	}
	defer statement.Close()

	add := func(values ...any) error {
		if len(values) != len(names) {
			// A silently short row would load NULLs into real columns and look
			// like absent evidence.
			return fmt.Errorf("insert into %s: %d values for %d columns",
				table, len(values), len(names))
		}
		for i, value := range values {
			if text, ok := value.(string); ok {
				values[i] = safeText(text)
			}
		}
		if _, err := statement.Exec(values...); err != nil {
			return fmt.Errorf("insert into %s: %w", table, err)
		}
		return nil
	}

	if err := emit(add); err != nil {
		return err
	}
	return tx.Commit()
}

// safeText makes a stored value loadable without losing it.
//
// Evidence is not obliged to hold text. Event data, registry values and volume
// labels can carry bytes that are not valid UTF-8, and a VARCHAR will not take
// them. Replacing them with U+FFFD would quietly destroy the value, and
// dropping the row would quietly destroy the record, so the bytes are kept in
// hex behind a marker that cannot be mistaken for content the evidence held.
func safeText(text string) string {
	if utf8.ValidString(text) {
		return text
	}
	return fmt.Sprintf("<non-utf8:%x>", text)
}
