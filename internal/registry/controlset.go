package registry

import (
	"fmt"
	"regexp"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// controlSetName matches ControlSet001, ControlSet002 and so on.
var controlSetName = regexp.MustCompile(`(?i)^ControlSet\d{3}$`)

// ControlSets is what a SYSTEM hive holds by way of control sets.
type ControlSets struct {
	// Names is every stored control set, in hive order.
	Names []string
	// Current is the one Select\Current names as active at acquisition.
	Current string
	// Selected records the other Select values, which say what the system had
	// been booting from and what it fell back to.
	Selected map[string]uint64
}

// ReadControlSets enumerates the stored control sets and reads Select.
//
// On an offline hive CurrentControlSet is not a stored key. Reading only the
// current set also loses history: an alternate control set can hold a device
// record the current one no longer does.
func ReadControlSets(registry *regparser.Registry) ControlSets {
	sets := ControlSets{Selected: map[string]uint64{}}

	root := registry.OpenKey("\\")
	if root != nil {
		for _, subkey := range root.Subkeys() {
			if controlSetName.MatchString(subkey.Name()) {
				sets.Names = append(sets.Names, subkey.Name())
			}
		}
	}

	if selectKey := registry.OpenKey("Select"); selectKey != nil {
		for _, value := range selectKey.Values() {
			data := value.ValueData()
			if data == nil {
				continue
			}
			name := value.ValueName()
			sets.Selected[name] = data.Uint64

			if strings.EqualFold(name, "Current") && data.Uint64 > 0 {
				sets.Current = fmt.Sprintf("ControlSet%03d", data.Uint64)
			}
		}
	}

	// A hive with no readable Select still has stored control sets, and naming
	// none of them current is more honest than guessing wrong.
	if sets.Current == "" && len(sets.Names) == 1 {
		sets.Current = sets.Names[0]
	}

	return sets
}

// RawLastWrite reads a key's last-write time as the FILETIME the hive stores.
//
// The registry library converts this to a time.Time and discards the original.
// Boobook keeps the raw value beside every derived one, so the conversion can
// be checked rather than trusted.
func RawLastWrite(key *regparser.CM_KEY_NODE) uint64 {
	if key == nil {
		return 0
	}
	return regparser.ParseUint64(key.Reader,
		key.Profile.Off_CM_KEY_NODE_LastWriteTime+key.Offset)
}
