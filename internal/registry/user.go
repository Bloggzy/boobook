package registry

import (
	"encoding/binary"
	"regexp"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/Bloggzy/boobook/internal/wintime"
)

// MountPoint is one entry from a user's MountPoints2 key.
//
// It establishes that a profile had awareness of a mounted volume. It is not
// evidence that the profile's user connected the device, and it carries no
// time of its own beyond the key's last-write.
type MountPoint struct {
	// Profile is the user profile directory the hive came from.
	Profile string
	// KeyName is the stored subkey name, unaltered.
	KeyName string
	Kind    MountPointKind
	// VolumeGUID is set for the {GUID} form.
	VolumeGUID string
	// DriveLetter is set for the bare-letter form.
	DriveLetter string
	// RemotePath is set for the UNC form.
	RemotePath string

	RegistryPath    string
	RawKeyLastWrite uint64
	KeyLastWriteUTC *time.Time
}

// MountPointKind names what a MountPoints2 subkey identified.
type MountPointKind string

const (
	MountPointVolumeGUID  MountPointKind = "volume_guid"
	MountPointDriveLetter MountPointKind = "drive_letter"
	MountPointRemote      MountPointKind = "remote"
	MountPointOther       MountPointKind = "other"
)

const mountPoints2Path = `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`

var (
	mountPointGUID   = regexp.MustCompile(`(?i)^(\{[0-9a-f-]+\})$`)
	mountPointLetter = regexp.MustCompile(`(?i)^([A-Z])$`)
)

// ReadMountPoints2 parses a user hive's MountPoints2 key.
func ReadMountPoints2(registry *regparser.Registry, profile string) []MountPoint {
	key := registry.OpenKey(mountPoints2Path)
	if key == nil {
		return nil
	}

	var mountPoints []MountPoint
	for _, subkey := range key.Subkeys() {
		name := subkey.Name()

		mountPoint := MountPoint{
			Profile:         profile,
			KeyName:         name,
			Kind:            MountPointOther,
			RegistryPath:    mountPoints2Path + `\` + name,
			RawKeyLastWrite: RawLastWrite(subkey),
		}
		if converted, ok := wintime.FromFileTime(mountPoint.RawKeyLastWrite); ok {
			mountPoint.KeyLastWriteUTC = &converted
		}

		switch {
		case mountPointGUID.MatchString(name):
			mountPoint.Kind = MountPointVolumeGUID
			mountPoint.VolumeGUID = strings.ToLower(name)
		case mountPointLetter.MatchString(name):
			mountPoint.Kind = MountPointDriveLetter
			mountPoint.DriveLetter = strings.ToUpper(name)
		case strings.HasPrefix(name, "##"):
			mountPoint.Kind = MountPointRemote
			mountPoint.RemotePath = name
		}

		mountPoints = append(mountPoints, mountPoint)
	}

	return mountPoints
}

// TimeZone is the host's configured time zone.
//
// Windows stores the biases as DWORDs holding signed minute offsets west of
// UTC. Read as unsigned, a daylight bias of -60 becomes 4294967236, so each is
// converted through int32 before use.
type TimeZone struct {
	// KeyName is the zone identifier, e.g. "AUS Eastern Standard Time".
	KeyName string
	// StandardName and DaylightName are often indirect resource strings such
	// as "@tzres.dll,-932" and are preserved as stored.
	StandardName string
	DaylightName string

	BiasMinutes         int
	StandardBiasMinutes int
	DaylightBiasMinutes int
	ActiveBiasMinutes   int

	// StandardStartMonth and DaylightStartMonth are the wMonth field of the
	// SYSTEMTIME transition rules, and zero is how Windows says a zone has no
	// daylight saving. It is the only reliable signal: DaylightBias is part of
	// the zone's definition and is stored whether or not the transitions are
	// ever taken. W. Australia Standard Time carries DaylightBias -60 with both
	// rules empty, because Western Australia abolished daylight saving in 2009
	// — read from the bias alone, every Perth host looks seasonally ambiguous
	// and gains a UTC+9 reading nothing supports.
	StandardStartMonth int
	DaylightStartMonth int
	// DynamicDaylightDisabled is the user switch that turns daylight saving off
	// for a zone that otherwise takes it. It is a second, independent way for
	// the answer to be no.
	DynamicDaylightDisabled bool

	Found bool
}

// ObservesDaylightSaving reports whether the host actually changes its clock.
//
// All three conditions have to hold: a non-zero daylight bias to apply, both
// transition rules present, and the user switch not set.
func (z TimeZone) ObservesDaylightSaving() bool {
	return z.DaylightBiasMinutes != 0 &&
		z.StandardStartMonth != 0 && z.DaylightStartMonth != 0 &&
		!z.DynamicDaylightDisabled
}

// ReadTimeZone reads the host time zone from a control set.
func ReadTimeZone(registry *regparser.Registry, controlSet string) TimeZone {
	key := registry.OpenKey(controlSet + `\Control\TimeZoneInformation`)
	if key == nil {
		return TimeZone{}
	}

	zone := TimeZone{Found: true}
	for _, value := range key.Values() {
		data := value.ValueData()
		if data == nil {
			continue
		}

		switch strings.ToLower(value.ValueName()) {
		case "timezonekeyname":
			zone.KeyName = trimStored(data.String)
		case "standardname":
			zone.StandardName = trimStored(data.String)
		case "daylightname":
			zone.DaylightName = trimStored(data.String)
		case "bias":
			zone.BiasMinutes = signedMinutes(data.Uint64)
		case "standardbias":
			zone.StandardBiasMinutes = signedMinutes(data.Uint64)
		case "daylightbias":
			zone.DaylightBiasMinutes = signedMinutes(data.Uint64)
		case "activetimebias":
			zone.ActiveBiasMinutes = signedMinutes(data.Uint64)
		case "standardstart":
			zone.StandardStartMonth = transitionMonth(data.Data)
		case "daylightstart":
			zone.DaylightStartMonth = transitionMonth(data.Data)
		case "dynamicdaylighttimedisabled":
			zone.DynamicDaylightDisabled = data.Uint64 != 0
		}
	}

	return zone
}

// signedMinutes reads a DWORD holding a signed minute offset.
func signedMinutes(stored uint64) int {
	return int(int32(uint32(stored)))
}

// transitionMonth reads wMonth out of a stored SYSTEMTIME.
//
// The structure is sixteen bytes of little-endian uint16 — wYear, wMonth,
// wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds — and only the month
// is read here. A zone with no daylight saving stores it as sixteen zero bytes,
// so wMonth is the field that answers the question. The rest of the rule is
// what resolving the season needs and is deliberately not read yet: the stored
// rules are current as of collection and applying them to older records is
// wrong wherever they have since changed.
//
// A short or absent value reads as zero, which is the safe answer: it means the
// timeline offers one reading rather than inventing a second.
func transitionMonth(stored []byte) int {
	if len(stored) < 4 {
		return 0
	}
	return int(binary.LittleEndian.Uint16(stored[2:4]))
}
