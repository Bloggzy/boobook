package sources

import (
	"strings"
	"testing"

	"github.com/Bloggzy/boobook/internal/eventlog"
	"github.com/Bloggzy/boobook/internal/evidence"
	"github.com/Bloggzy/boobook/internal/registry"
)

// text is the whole catalogue flattened, which is what a reader sees.
func text(t *testing.T) string {
	t.Helper()

	var b strings.Builder
	for _, source := range All() {
		b.WriteString(source.Path + "\n" + source.Note + "\n")
		for _, yield := range source.Yields {
			b.WriteString(yield.What + "\n" + yield.Where + "\n")
		}
	}
	return b.String()
}

// The channel list is derived from eventlog.Channels(), so as written this
// cannot fail — and that is the point. It holds the derivation in place: the
// obvious future edit is to paste the channel names in as a literal to reword
// them, and the next channel added would then be read without the tool
// admitting to reading it. That is the wrong direction for a forensic tool to
// be wrong in, so the test fails the moment the list stops being derived.
func TestTheCatalogueNamesEveryChannelItReads(t *testing.T) {
	catalogue := text(t)

	channels := eventlog.Channels()
	if len(channels) == 0 {
		t.Fatal("the event log catalogue selects no channels at all")
	}
	for _, channel := range channels {
		if !strings.Contains(catalogue, channel) {
			t.Errorf("channel %s is read but the source catalogue does not name it", channel)
		}
	}
}

// Derived for the same reason, and held for the same reason. The enumerators
// answer "would this tool have seen a printer, a phone, a Bluetooth device",
// and that answer has to come from the list actually walked rather than from
// a copy of it that was accurate once.
func TestTheCatalogueNamesEveryEnumeratorItWalks(t *testing.T) {
	catalogue := text(t)

	if len(registry.Enumerators) == 0 {
		t.Fatal("no enumerators are walked at all")
	}
	for _, enumerator := range registry.Enumerators {
		if !strings.Contains(catalogue, enumerator) {
			t.Errorf("enumerator %s is walked but the source catalogue does not name it", enumerator)
		}
	}
}

// Also derived, also held. A directory added to the shortcut walk is a new
// place evidence comes from, and an analyst deciding what to collect needs it
// named — which only stays true while the note is built from the walk.
func TestTheCatalogueNamesEveryDirectoryItWalksForShortcuts(t *testing.T) {
	catalogue := text(t)

	if len(evidence.RecentDirs) == 0 {
		t.Fatal("no shortcut directories are walked at all")
	}
	for _, dir := range evidence.RecentDirs {
		// The last element is the distinguishing one — Recent, Quick Launch,
		// Desktop — and is what a reader would look for.
		leaf := dir.Path[len(dir.Path)-1]
		if !strings.Contains(catalogue, leaf) {
			t.Errorf("%s is walked for shortcuts but the source catalogue does not name it", leaf)
		}
		// A directory with no context would reach the database with an empty
		// link_context, and v_file_activity reads that column to decide
		// whether a shortcut's own mtime timed an opening. An unnamed context
		// falls to the conservative arm, so this cannot produce a false
		// opening — but it would silently discard a real one.
		if dir.Context == "" {
			t.Errorf("%s is walked for shortcuts and names no context", leaf)
		}
	}
}

// A source with no yields is a path with no reason given, which is the failure
// this catalogue exists to avoid: it would say Boobook reads a file without
// saying what an analyst gets for it.
func TestEverySourceSaysWhatItYields(t *testing.T) {
	for _, source := range All() {
		if source.Path == "" || source.Class == "" {
			t.Errorf("a source is missing its path or class: %+v", source)
		}
		if len(source.Yields) == 0 {
			t.Errorf("%s lists no yields", source.Path)
		}
		for _, yield := range source.Yields {
			if yield.What == "" || yield.Where == "" {
				t.Errorf("%s has a yield missing its what or where: %+v", source.Path, yield)
			}
		}
	}
}

// Derived and held for the same reason as the channel list above. The session
// events are the ones that say what a silence in a report is allowed to mean,
// and they land on the System channel, which the catalogue already names for
// its device rules — so a reader checking whether Boobook would have noticed
// the host being switched off cannot get the answer from the channel list. The
// events have to be named, and named from the rules that are actually read.
func TestTheCatalogueNamesTheHostSessionEventsItReads(t *testing.T) {
	catalogue := text(t)

	named := eventlog.SessionRules()
	if len(named) == 0 {
		t.Fatal("no session rules: a report could not say whether a stretch " +
			"with no records was a quiet host or a host that was switched off")
	}
	for _, rule := range named {
		if !strings.Contains(catalogue, rule) {
			t.Errorf("%s is read but the source catalogue does not name it", rule)
		}
	}
}
