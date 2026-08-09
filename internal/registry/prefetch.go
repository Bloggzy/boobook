package registry

import (
	"strings"

	"www.velocidex.com/golang/regparser"
)

// PrefetchSetting is the host's prefetcher configuration.
//
// It exists to separate three cases a bare count of .pf files cannot: prefetch
// was on and nothing ran, prefetch was off so nothing was recorded, and the
// collection did not take the directory. Only the registry distinguishes the
// first two, and treating "no prefetch files" as "no programmes ran" would be a
// negative finding the evidence never supported.
type PrefetchSetting struct {
	// Found is whether the value was present. Absent is not the same as zero:
	// on a host where the value was never written, Windows prefetches anyway.
	Found bool
	// Value as stored: 0 disabled, 1 application launch, 2 boot, 3 both.
	Value uint32
	// RegistryKey is where it was read from, for the provenance record.
	RegistryKey string
	ControlSet  string
}

const prefetchParameters = `\Control\Session Manager\Memory Management\PrefetchParameters`

// ReadPrefetchSetting reads EnablePrefetcher from a control set.
func ReadPrefetchSetting(registry *regparser.Registry, controlSet string) PrefetchSetting {
	path := controlSet + prefetchParameters

	key := registry.OpenKey(path)
	if key == nil {
		return PrefetchSetting{ControlSet: controlSet, RegistryKey: path}
	}

	setting := PrefetchSetting{ControlSet: controlSet, RegistryKey: path}
	for _, value := range key.Values() {
		if !strings.EqualFold(value.ValueName(), "EnablePrefetcher") {
			continue
		}
		data := value.ValueData()
		if data == nil {
			continue
		}
		setting.Found = true
		setting.Value = uint32(data.Uint64)
	}

	return setting
}

// Describe renders the setting as the sentence a coverage section can print.
//
// The wording never says programmes did not run: the value governs what Windows
// recorded, not what happened on the host.
func (p PrefetchSetting) Describe() string {
	if !p.Found {
		// This used to end "so the default applies and application launch
		// prefetching was most likely on", which turns an absence into a
		// probabilistic positive. The default differs between client and
		// server installations, and nothing Boobook reads establishes which
		// this host is — so the honest sentence names the gap instead of
		// filling it.
		return "EnablePrefetcher is not set in the registry, so the platform " +
			"default applied; Boobook did not establish what that default is " +
			"for this installation, because nothing it reads names the Windows " +
			"edition"
	}
	switch p.Value {
	case 0:
		return "EnablePrefetcher is 0: prefetching was disabled, so the absence " +
			"of prefetch files says nothing about what ran on this host"
	case 1:
		return "EnablePrefetcher is 1: application launch prefetching was enabled"
	case 2:
		return "EnablePrefetcher is 2: boot prefetching only, so application " +
			"launches were not recorded"
	case 3:
		return "EnablePrefetcher is 3: application launch and boot prefetching " +
			"were both enabled"
	default:
		return "EnablePrefetcher holds an unrecognised value, so what was " +
			"recorded cannot be stated"
	}
}
