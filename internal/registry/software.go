package registry

import (
	"regexp"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// PortableDevice is one entry from the Windows Portable Devices list.
//
// The subkey name is a device path; the FriendlyName is, for a mass storage
// device, the volume label. That makes this the route from a volume label back
// to a device on hosts where EMDMgmt is not written — which is the Windows 11
// case, confirmed absent in the sample collections.
type PortableDevice struct {
	// KeyName is the stored subkey name, unaltered.
	KeyName string
	// FriendlyName is usually the volume label for storage devices.
	FriendlyName string
	// DeviceInstanceID is set where the key name embeds a device path.
	DeviceInstanceID string
	// VolumeGUID and VolumeOffsetHex are set for the {GUID}#offset form, which
	// names a volume rather than a device.
	VolumeGUID      string
	VolumeOffsetHex string
	// RegistryPath is where it was read from.
	RegistryPath string
}

var portableVolumeForm = regexp.MustCompile(`(?i)^SWD#WPDBUSENUM#(\{[0-9a-f-]+\})#([0-9A-F]+)$`)

const portableDevicesPath = `Microsoft\Windows Portable Devices\Devices`

// ReadPortableDevices parses the Windows Portable Devices list from SOFTWARE.
func ReadPortableDevices(registry *regparser.Registry) []PortableDevice {
	key := registry.OpenKey(portableDevicesPath)
	if key == nil {
		return nil
	}

	var devices []PortableDevice
	for _, subkey := range key.Subkeys() {
		device := PortableDevice{
			KeyName:      subkey.Name(),
			RegistryPath: portableDevicesPath + `\` + subkey.Name(),
		}

		for _, value := range subkey.Values() {
			if !strings.EqualFold(value.ValueName(), "FriendlyName") {
				continue
			}
			if data := value.ValueData(); data != nil {
				device.FriendlyName = trimStored(data.String)
			}
		}

		if matches := portableVolumeForm.FindStringSubmatch(subkey.Name()); matches != nil {
			device.VolumeGUID = strings.ToLower(matches[1])
			device.VolumeOffsetHex = matches[2]
		} else {
			// SWD#WPDBUSENUM#_??_USBSTOR#...#{interface guid}
			if index := strings.Index(strings.ToUpper(subkey.Name()), "_??_"); index >= 0 {
				device.DeviceInstanceID = DevicePathToInstanceID(subkey.Name()[index:])
			}
		}

		devices = append(devices, device)
	}

	return devices
}

// EMDMgmtEntry is a ReadyBoost volume record.
//
// Its subkey name embeds a volume serial and label, which is the one route
// that can place two different devices at one drive letter. The key is not
// written on every host — notably not on Windows 11 — so its absence is
// reported rather than treated as "no such volume".
type EMDMgmtEntry struct {
	KeyName      string
	RegistryPath string
	// VolumeSerialDecimal is the serial as stored, in decimal.
	VolumeSerialDecimal string
	// VolumeLabel is the label portion of the key name.
	VolumeLabel string
	// DeviceInstanceID is the device the key name embeds. This is what makes
	// EMDMgmt the strongest route from a file record to a device: the one key
	// name carries the volume serial, the label and the device together, so no
	// inference sits between them.
	DeviceInstanceID string
}

const emdMgmtPath = `Microsoft\Windows NT\CurrentVersion\EMDMgmt`

// emdMgmtName matches the trailing "_LABEL_SERIAL" of an EMDMgmt subkey.
var emdMgmtName = regexp.MustCompile(`^(.*)_([0-9]+)$`)

// ReadEMDMgmt parses the ReadyBoost volume records from SOFTWARE.
//
// The second return value reports whether the key exists at all, so an absent
// key can be distinguished from a present but empty one.
func ReadEMDMgmt(registry *regparser.Registry) ([]EMDMgmtEntry, bool) {
	key := registry.OpenKey(emdMgmtPath)
	if key == nil {
		return nil, false
	}

	var entries []EMDMgmtEntry
	for _, subkey := range key.Subkeys() {
		entry := EMDMgmtEntry{
			KeyName:      subkey.Name(),
			RegistryPath: emdMgmtPath + `\` + subkey.Name(),
		}

		if matches := emdMgmtName.FindStringSubmatch(subkey.Name()); matches != nil {
			entry.VolumeSerialDecimal = matches[2]
			if index := strings.LastIndex(matches[1], "#"); index >= 0 {
				entry.VolumeLabel = matches[1][index+1:]
			} else {
				entry.VolumeLabel = matches[1]
			}
		}

		// The device path the key name wraps, in the same _??_ form the
		// portable-devices list uses.
		if index := strings.Index(strings.ToUpper(subkey.Name()), "_??_"); index >= 0 {
			entry.DeviceInstanceID = DevicePathToInstanceID(subkey.Name()[index:])
		}

		entries = append(entries, entry)
	}

	return entries, true
}
