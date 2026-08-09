package registry

import (
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/Bloggzy/boobook/internal/wintime"
)

// UserAssist is one entry from the shell's own record of what a user launched.
//
// It is the other half of the execution picture and a different half from
// prefetch. Prefetch is per machine and covers anything the loader touched, so
// a service starting looks the same as a person double-clicking. UserAssist is
// per user and records what Explorer launched — which is to say what somebody
// chose to run — and it counts focus as well as launches. On USB-CTF it holds
// two executions from `F:\KAPE\`, one of them with 83 seconds of foreground
// focus, and nothing else Boobook reads reports them at all.
type UserAssist struct {
	Profile string
	// Category is the GUID subkey the entry sat under, which says what kind of
	// thing was launched.
	Category string
	// CategoryName is the plain reading of Category where it is one of the two
	// that are unambiguous, and empty otherwise. The published GUID lists are
	// incomplete and disagree with each other, and a wrong category is worse
	// than none — the same reasoning that leaves a jump list AppID as its hash.
	CategoryName string

	// Name is the launched item, with the stored ROT13 undone.
	Name string
	// DriveLetter is set where Name is an ordinary path. Entries name a
	// packaged application or a folder GUID at least as often.
	DriveLetter string

	// RunCount is how many times Explorer recorded launching it, FocusCount how
	// many times it came to the foreground, and FocusTime how long it was there
	// in total.
	RunCount   uint32
	FocusCount uint32
	FocusTime  time.Duration

	RawLastExecuted uint64
	LastExecutedUTC *time.Time

	// Bookkeeping marks the shell's own counters rather than a launch:
	// UEME_CTLSESSION and UEME_CTLCUACount:ctor. They are kept because a
	// silently filtered artefact is one nobody can audit, and excluded from
	// anything that reads as "a programme was run".
	Bookkeeping bool

	ValueName    string
	RegistryPath string
	Raw          string
	Warnings     []string
}

const userAssistPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

// The two category GUIDs that are settled. Others exist on Windows 10 and 11 —
// several of them undocumented — and are carried as the GUID they are.
var userAssistCategories = map[string]string{
	"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "an executable file",
	"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "a shortcut file",
}

// ReadUserAssist parses the UserAssist Count keys of one NTUSER hive.
func ReadUserAssist(registry *regparser.Registry, profile string) []UserAssist {
	root := registry.OpenKey(userAssistPath)
	if root == nil {
		return nil
	}

	var entries []UserAssist
	for _, guid := range root.Subkeys() {
		path := userAssistPath + `\` + guid.Name() + `\Count`
		count := registry.OpenKey(path)
		if count == nil {
			continue
		}
		for _, value := range count.Values() {
			data := value.ValueData()
			if data == nil || len(data.Data) == 0 {
				continue
			}
			entries = append(entries,
				readUserAssistValue(guid.Name(), path, profile,
					value.ValueName(), data.Data))
		}
	}

	return entries
}

func readUserAssistValue(category, path, profile, valueName string,
	raw []byte) UserAssist {

	name := rot13(valueName)
	entry := UserAssist{
		Profile:      profile,
		Category:     category,
		CategoryName: userAssistCategories[strings.ToUpper(category)],
		Name:         name,
		ValueName:    valueName,
		RegistryPath: path,
		Raw:          hex.EncodeToString(raw),
		Bookkeeping:  bookkeeping(name),
	}
	// A UEME_ name that is neither a control counter nor a run entry is a form
	// this does not know, and it will be counted as a programme having been
	// launched. Say so rather than let it pass as one.
	if strings.HasPrefix(name, "UEME_") && !entry.Bookkeeping &&
		!strings.HasPrefix(name, "UEME_RUN") {
		entry.Warnings = append(entry.Warnings,
			"the name is a UEME_ form this does not recognise as either a "+
				"shell counter or a run entry, and is counted as a launch")
	}
	entry.DriveLetter = pathDriveLetter(name)

	// The Windows 7 and later record. Everything in the five reference
	// collections is this shape.
	//
	// The 16-byte Windows XP record is deliberately not decoded. Its run count
	// is stored with an offset of five, so a naive read reports five extra
	// executions of everything and a genuine single run as "not run" — and
	// there is no XP evidence here to check a fix against. The value is kept in
	// Raw and the row says why it was not read, which is a better answer than a
	// number nobody can defend.
	if len(raw) < 72 {
		entry.Warnings = append(entry.Warnings,
			"the value is "+strconv.Itoa(len(raw))+" bytes, not the 72 of a Windows 7 "+
				"or later record, so its counts and time were not decoded")
		return entry
	}

	entry.RunCount = binary.LittleEndian.Uint32(raw[4:8])
	entry.FocusCount = binary.LittleEndian.Uint32(raw[8:12])
	entry.FocusTime = time.Duration(
		binary.LittleEndian.Uint32(raw[12:16])) * time.Millisecond
	entry.RawLastExecuted = binary.LittleEndian.Uint64(raw[60:68])

	// Through wintime like every other Windows time in the project, so a zero
	// slot and the FAT epoch are refused in one place rather than in each
	// parser. An entry with focus and no last-executed time is real — the shell
	// tracked it in the foreground without ever recording a launch — and it
	// must read as "no time recorded" rather than as 1601.
	if converted, ok := wintime.FromFileTime(entry.RawLastExecuted); ok {
		entry.LastExecutedUTC = &converted
	}

	return entry
}

// bookkeeping reports whether a decoded name is one of the shell's own
// counters rather than something a person ran.
//
// This was `strings.HasPrefix(name, "UEME_")`, which is the wrong test: the
// older UserAssist categories record executions under UEME_RUNPATH,
// UEME_RUNPIDL and UEME_RUNCPL, so the prefix suppresses launches alongside
// tallies. Nothing was lost on current evidence — Windows 7 and later write a
// path or an application identity and the only UEME_ names in the five
// reference collections are UEME_CTLSESSION and UEME_CTLCUACount:ctor — but
// the predicate would silently swallow every execution on an XP or Vista hive
// the moment the 16-byte record is decoded.
//
// UEME_CTL is what the shell's control and session counters carry, and it is
// the whole of the rule. A name it does not cover is not suppressed.
func bookkeeping(name string) bool {
	return strings.HasPrefix(name, "UEME_CTL")
}

// rot13 undoes the obfuscation UserAssist stores its names under. It is not a
// secret and never was; it is there to keep the names out of a plain string
// search of the hive.
func rot13(s string) string {
	out := []rune(s)
	for i, r := range out {
		switch {
		case r >= 'a' && r <= 'z':
			out[i] = 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			out[i] = 'A' + (r-'A'+13)%26
		}
	}
	return string(out)
}

// pathDriveLetter reads the letter from an ordinary path, and nothing else.
//
// A UserAssist name is as likely to be a packaged application identity
// (Microsoft.WindowsCalculator_8wekyb3d8bbwe!App) or a path rooted at a folder
// GUID ({1AC14E77-...}\WindowsPowerShell\v1.0\powershell.exe) as it is to be a
// path. Neither has a drive letter, and inventing one would place a record on a
// volume no artefact mentions.
func pathDriveLetter(name string) string {
	if len(name) < 3 || name[1] != ':' || name[2] != '\\' {
		return ""
	}
	letter := name[0]
	if (letter >= 'A' && letter <= 'Z') || (letter >= 'a' && letter <= 'z') {
		return strings.ToUpper(name[:1])
	}
	return ""
}
