package registry

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"www.velocidex.com/golang/regparser"

	"github.com/Bloggzy/boobook/internal/wintime"
)

// A device instance stores its properties beneath:
//
//	Enum\<Enumerator>\<DeviceID>\<InstanceID>\Properties\{PropertySetGUID}\<PropertyID>
//
// The property ID is a hex string. Values carry a DEVPROP type rather than a
// REG type, so the registry parser reports them as REG_UNKNOWN and hands back
// raw bytes. Meaning therefore comes from the property identity, not from the
// stored type, and anything not positively identified stays raw.

// Property set GUIDs, lower case as stored.
const (
	// devpkeyDeviceActivity holds the PnP activity dates. Each records only the
	// most recent event of its kind for the device instance.
	devpkeyDeviceActivity = "{83da6326-97a6-4088-9453-a1923f573b29}"
	// devpkeyDriverPackage holds driver package attributes. Its date is the
	// driver's, not the device's, and must never be read as device activity.
	devpkeyDriverPackage = "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}"
	// devpkeyBusReported holds the description the bus reported.
	devpkeyBusReported = "{540b947e-8b40-45bc-a8a2-6a0b894cbda2}"
)

// PropertyKind says how a raw value was read.
type PropertyKind string

const (
	KindFileTime PropertyKind = "filetime"
	KindString   PropertyKind = "string"
	KindUint32   PropertyKind = "uint32"
	KindBinary   PropertyKind = "binary"
)

// knownProperty names a property and says how to read it.
type knownProperty struct {
	Name string
	Kind PropertyKind
	// DeviceActivity marks the four dates that describe the device's own PnP
	// lifecycle, as distinct from driver or package metadata.
	DeviceActivity bool
}

// knownProperties covers only what is positively identified from devpkey.h.
// Everything else is preserved raw with its GUID and ID named, rather than
// being given a meaning this project cannot cite.
var knownProperties = map[string]map[uint32]knownProperty{
	devpkeyDeviceActivity: {
		100: {Name: "DEVPKEY_Device_InstallDate", Kind: KindFileTime, DeviceActivity: true},
		101: {Name: "DEVPKEY_Device_FirstInstallDate", Kind: KindFileTime, DeviceActivity: true},
		102: {Name: "DEVPKEY_Device_LastArrivalDate", Kind: KindFileTime, DeviceActivity: true},
		103: {Name: "DEVPKEY_Device_LastRemovalDate", Kind: KindFileTime, DeviceActivity: true},
	},
	devpkeyDriverPackage: {
		2: {Name: "DEVPKEY_Device_DriverDate", Kind: KindFileTime},
		3: {Name: "DEVPKEY_Device_DriverVersion", Kind: KindString},
		4: {Name: "DEVPKEY_Device_DriverDesc", Kind: KindString},
		5: {Name: "DEVPKEY_Device_DriverInfPath", Kind: KindString},
		6: {Name: "DEVPKEY_Device_DriverInfSection", Kind: KindString},
		9: {Name: "DEVPKEY_Device_DriverProvider", Kind: KindString},
	},
	devpkeyBusReported: {
		4: {Name: "DEVPKEY_Device_BusReportedDeviceDesc", Kind: KindString},
	},
}

// Property is one stored device property.
//
// Raw is always populated. A decoded reading is offered beside it only where
// the property is identified, so a conversion can always be checked against
// the bytes it came from.
type Property struct {
	SetGUID string
	// ID is the property identifier within the set.
	ID uint32
	// IDHex is the subkey name as stored, e.g. "0064".
	IDHex string
	// Name is the devpkey name where the property is identified.
	Name string
	Kind PropertyKind
	// DeviceActivity marks a date describing this device's PnP lifecycle.
	DeviceActivity bool

	// Raw is the stored bytes, hex encoded.
	Raw string
	// RawFileTime is the stored FILETIME, for a date property.
	RawFileTime uint64
	// TimeUTC is the conversion of RawFileTime, where it was readable.
	TimeUTC *time.Time
	// Text is the decoded string, for a string property.
	Text string
	// Number is the decoded integer, for a uint32 property.
	Number uint32
}

// RegistryPath returns where this property sat, for provenance.
func (p Property) RegistryPath(deviceKeyPath string) string {
	return fmt.Sprintf(`%s\Properties\%s\%s`, deviceKeyPath, p.SetGUID, p.IDHex)
}

// DisplayName names the property, falling back to its raw identity where it is
// not one this project can name.
func (p Property) DisplayName() string {
	if p.Name != "" {
		return p.Name
	}
	return fmt.Sprintf("%s\\%s", p.SetGUID, p.IDHex)
}

// ReadProperties walks a device instance's Properties tree.
func ReadProperties(instanceKey *regparser.CM_KEY_NODE) []Property {
	var properties []Property

	for _, subkey := range instanceKey.Subkeys() {
		if !strings.EqualFold(subkey.Name(), "Properties") {
			continue
		}

		for _, setKey := range subkey.Subkeys() {
			setGUID := strings.ToLower(setKey.Name())

			for _, idKey := range setKey.Subkeys() {
				idHex := idKey.Name()
				id, err := strconv.ParseUint(idHex, 16, 32)
				if err != nil {
					continue
				}

				for _, value := range idKey.Values() {
					data := value.ValueData()
					if data == nil || len(data.Data) == 0 {
						continue
					}
					properties = append(properties,
						decodeProperty(setGUID, uint32(id), idHex, data.Data))
				}
			}
		}
	}

	return properties
}

// decodeProperty reads a stored property. The raw bytes are always kept.
func decodeProperty(setGUID string, id uint32, idHex string, raw []byte) Property {
	property := Property{
		SetGUID: setGUID,
		ID:      id,
		IDHex:   idHex,
		Raw:     hex.EncodeToString(raw),
		Kind:    KindBinary,
	}

	known, ok := knownProperties[setGUID][id]
	if !ok {
		// Not a property this project can name. The bytes are preserved and no
		// meaning is invented for them.
		return property
	}

	property.Name = known.Name
	property.Kind = known.Kind
	property.DeviceActivity = known.DeviceActivity

	switch known.Kind {
	case KindFileTime:
		if len(raw) < 8 {
			property.Kind = KindBinary
			return property
		}
		property.RawFileTime = binary.LittleEndian.Uint64(raw[:8])
		if converted, ok := wintime.FromFileTime(property.RawFileTime); ok {
			property.TimeUTC = &converted
		}

	case KindString:
		property.Text = decodeUTF16(raw)

	case KindUint32:
		if len(raw) < 4 {
			property.Kind = KindBinary
			return property
		}
		property.Number = binary.LittleEndian.Uint32(raw[:4])
	}

	return property
}

// decodeUTF16 reads a UTF-16LE string as Windows stores it, dropping the NUL
// terminator. An odd-length buffer is not a string and yields nothing.
func decodeUTF16(raw []byte) string {
	if len(raw)%2 != 0 {
		return ""
	}

	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(raw[i:i+2]))
	}

	return strings.TrimRight(string(utf16.Decode(units)), "\x00")
}

// Activity is the PnP lifecycle a device instance recorded.
//
// Each date records only the most recent event of its kind, so these are named
// states rather than a connection history: a device connected fifty times has
// one LastArrivalDate.
type Activity struct {
	InstallDate      *time.Time
	FirstInstallDate *time.Time
	LastArrivalDate  *time.Time
	LastRemovalDate  *time.Time

	// Raw FILETIMEs beside each derived value, so a conversion is checkable.
	RawInstallDate      uint64
	RawFirstInstallDate uint64
	RawLastArrivalDate  uint64
	RawLastRemovalDate  uint64
}

// ActivityFrom pulls the device lifecycle dates out of a property set.
func ActivityFrom(properties []Property) Activity {
	var activity Activity

	for _, property := range properties {
		if !property.DeviceActivity {
			continue
		}
		switch property.ID {
		case 100:
			activity.InstallDate = property.TimeUTC
			activity.RawInstallDate = property.RawFileTime
		case 101:
			activity.FirstInstallDate = property.TimeUTC
			activity.RawFirstInstallDate = property.RawFileTime
		case 102:
			activity.LastArrivalDate = property.TimeUTC
			activity.RawLastArrivalDate = property.RawFileTime
		case 103:
			activity.LastRemovalDate = property.TimeUTC
			activity.RawLastRemovalDate = property.RawFileTime
		}
	}

	return activity
}
