package fixture

import (
	"go/build"
	"strings"
	"testing"
)

// A fixture must not import the parser it is a fixture for.
//
// This is the whole value of the package and it is the kind of property that
// erodes silently: reaching for a parser's exported offset constant is the
// obvious thing to do when writing a builder, it compiles, the test passes, and
// the fixture now asserts nothing.
//
// It is not hypothetical. The prefetch builder used to live in
// internal/prefetch's own test file and use that package's volume-entry
// constants, so it wrote 40-byte entries for a version 23 file — the size
// format 17 uses, not the 104 bytes formats 23 and 26 use. The parser and the
// fixture agreed, every test was green, and a genuine multi-volume Windows 7
// prefetch record was misread the whole time. An independent review found it by
// reading the format documentation.
//
// So the builders here take their layout from the published specification and
// this test holds the line. Like the ordering and catalogue invariants it
// cannot fail as written; it fails the moment somebody adds the import that
// makes the fixtures circular again.
func TestAFixtureNeverImportsTheParserItIsAFixtureFor(t *testing.T) {
	// The packages whose formats this one builds. Importing any of them would
	// mean a builder is describing the format as the parser reads it rather
	// than as the specification defines it.
	forbidden := map[string]string{
		"github.com/Bloggzy/boobook/internal/prefetch":  "SCCA volume offsets and entry sizes",
		"github.com/Bloggzy/boobook/internal/lnk":       "shell link structure offsets",
		"github.com/Bloggzy/boobook/internal/jumplist":  "DestList entry offsets",
		"github.com/Bloggzy/boobook/internal/shellitem": "shell item framing",
		"github.com/Bloggzy/boobook/internal/registry":  "hive and value layout",
		"github.com/Bloggzy/boobook/internal/eventlog":  "event field paths and rule matching",
		"github.com/Bloggzy/boobook/internal/setupapi":  "log section framing",
	}

	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("reading this package: %v", err)
	}
	if len(pkg.GoFiles) == 0 {
		t.Fatal("no source files were found, so this test asserts nothing")
	}

	for _, imported := range pkg.Imports {
		if what, bad := forbidden[imported]; bad {
			t.Errorf("internal/fixture imports %s. Its %s would then come from "+
				"the code under test rather than from the format definition, "+
				"and a fixture built that way can only prove the parser agrees "+
				"with itself.", imported, what)
		}
		// Nothing in the project at all, in fact, beyond the standard library.
		// A builder that needed a Boobook type would be describing Boobook's
		// model of the artefact rather than the artefact.
		if strings.HasPrefix(imported, "github.com/Bloggzy/boobook/") {
			if _, known := forbidden[imported]; !known {
				t.Errorf("internal/fixture imports %s; the builders are meant "+
					"to depend on nothing but the standard library", imported)
			}
		}
	}
}
