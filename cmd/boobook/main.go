// Command boobook reads a Windows evidence set and reports the USB devices it
// saw, the events associated with them, and where every fact came from.
package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Bloggzy/boobook/internal/classify"
	"github.com/Bloggzy/boobook/internal/eventlog"
	"github.com/Bloggzy/boobook/internal/evidence"
	"github.com/Bloggzy/boobook/internal/jumplist"
	"github.com/Bloggzy/boobook/internal/lnk"
	"github.com/Bloggzy/boobook/internal/prefetch"
	"github.com/Bloggzy/boobook/internal/progress"
	"github.com/Bloggzy/boobook/internal/provenance"
	"github.com/Bloggzy/boobook/internal/registry"
	"github.com/Bloggzy/boobook/internal/report"
	"github.com/Bloggzy/boobook/internal/setupapi"
	"github.com/Bloggzy/boobook/internal/sources"
	"github.com/Bloggzy/boobook/internal/store"
	"github.com/Bloggzy/boobook/internal/wintime"
	"github.com/Bloggzy/boobook/internal/workspace"
)

func main() {
	options := parseFlags()

	if options.showRules {
		printCatalogue()
		return
	}

	if options.showSources {
		printSources()
		return
	}

	if err := run(options); err != nil {
		// Not through the reporter: an error is why the run exists to be told
		// about, and -quiet silences the narration, not the failure.
		fmt.Fprintf(os.Stderr, "\nboobook: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	evidenceRoot string
	// outputRoot is where the results go, and is what an examiner is actually
	// choosing when they run the tool.
	outputRoot string
	// runID names the run directory instead of letting the run take a UTC
	// timestamp. A calling tool has to know where the results will be before
	// it starts the run, and it cannot work that out from a stamp taken
	// inside the process.
	runID string
	// inPlace writes the results into the output root itself. For a caller that
	// has already made a directory for this run and does not want a second one
	// inside it.
	inPlace bool
	// workingRoot puts scratch somewhere other than inside the output. Worth
	// setting when the output is on a network share and copying a hive across
	// it would dominate the run.
	workingRoot string
	// keepWorking leaves the scratch directory in place. It holds recovered
	// hives, which are derived rather than evidence, so it is a debugging
	// convenience and not a custody requirement.
	keepWorking bool
	// readSecurity opts into Security.evtx, which is skipped by default. It
	// holds logon records worth having and is capped at 20 MB only until an
	// organisation raises the cap, so the examiner decides per case.
	readSecurity bool
	caseRef      string
	examiner     string
	hostLabel    string
	showRules    bool
	// showSources prints what the tool can read and what each location yields.
	// It answers that without evidence in hand, which is the point: it is asked
	// when deciding what to collect, not after a run.
	showSources bool
	// profile reweights the relevance score for the kind of case in hand. It
	// changes placement and score only: never what is extracted, which facts
	// are derived, or which category a rule assigns.
	profile   string
	rulesFile string
	// noReport suppresses the HTML report. The data files are written either
	// way: the report is a reading of the case, and the case is the data.
	noReport bool
	// quiet silences the narration on stderr. Errors are still reported, and
	// stdout still carries the manifest path, so a scripted run says nothing
	// unless something is wrong.
	quiet bool
}

func parseFlags() options {
	var opts options

	flag.StringVar(&opts.evidenceRoot, "evidence", "",
		"evidence root: a mounted Windows volume or a triage collection")
	flag.StringVar(&opts.outputRoot, "output", "",
		"output root: the report, the case database and the data files are "+
			"written to a run directory beneath it")
	flag.StringVar(&opts.runID, "run-id", "",
		"name the run directory beneath the output root instead of taking a "+
			"UTC timestamp; for a calling tool that has to know the path "+
			"before the run starts. An existing directory is refused")
	flag.BoolVar(&opts.inPlace, "in-place", false,
		"write the results into the output root itself, with no run directory "+
			"beneath it. Refused if that directory already holds anything")
	flag.StringVar(&opts.workingRoot, "working", "",
		"scratch root for recovered hives and staged copies; defaults to "+
			"inside the run's output directory")
	flag.BoolVar(&opts.keepWorking, "keep-working", false,
		"keep the scratch directory instead of removing it at the end of the run")
	flag.BoolVar(&opts.readSecurity, "security", false,
		"read Security.evtx for logon and logoff records. Off by default: it "+
			"holds little else of use and costs the size of the file, which a "+
			"raised log cap can make gigabytes")
	flag.StringVar(&opts.caseRef, "case", "", "case reference, recorded in the manifest")
	flag.StringVar(&opts.examiner, "examiner", "", "examiner name, recorded in the manifest")
	flag.StringVar(&opts.hostLabel, "host", "", "label for the host under examination")
	flag.BoolVar(&opts.showRules, "rules", false,
		"print the event log selection catalogue and exit")
	flag.BoolVar(&opts.showSources, "sources", false,
		"print the evidence sources that can be read, and what each yields, and exit")
	flag.StringVar(&opts.profile, "profile", classify.DefaultProfile,
		"case profile weighting the relevance score: "+
			"general, exfiltration, printing, network-bypass, identity, ot")
	flag.StringVar(&opts.rulesFile, "rule-set", "",
		"classification rule set to use instead of the built-in one")
	flag.BoolVar(&opts.noReport, "no-report", false,
		"skip the HTML report and write only the data files")
	flag.BoolVar(&opts.quiet, "quiet", false,
		"silence progress and narration on stderr; errors are still reported")

	// Replaces the standard usage, which names the binary and lists the flags
	// but says nothing about which build is refusing the command. The flag
	// package calls this on -h and on any unrecognised flag, so every way of
	// getting the invocation wrong arrives at the same greeting a good run
	// starts with.
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, bannerText())
		fmt.Fprintf(os.Stderr, "\n%s\n\nOptions:\n", usageLine)
		flag.PrintDefaults()
	}
	flag.Parse()

	if opts.showRules || opts.showSources {
		return opts
	}

	if opts.evidenceRoot == "" || opts.outputRoot == "" {
		flag.Usage()
		// Named rather than left to be inferred. A synopsis tells someone what
		// a correct command looks like; it does not tell them which part of
		// theirs was wrong, and diffing the two is work the tool can do.
		switch {
		case opts.evidenceRoot == "" && opts.outputRoot == "":
			fmt.Fprintln(os.Stderr, "\nboobook: -evidence and -output are both required.")
		case opts.evidenceRoot == "":
			fmt.Fprintln(os.Stderr, "\nboobook: -evidence is required.")
		// -working used to mean what -output means now, and up to v0.2.5 it was
		// the required flag. Silently accepting it would put the results
		// somewhere other than where the same command used to put them, so it
		// is named and refused instead. A tool that quietly relocates output
		// between versions is one nobody can script against.
		case opts.workingRoot != "":
			fmt.Fprintln(os.Stderr,
				"\nboobook: -output is required. -working no longer sets where "+
					"results go — it now names a scratch directory, which is "+
					"optional. Use -output for the results.")
		default:
			fmt.Fprintln(os.Stderr, "\nboobook: -output is required.")
		}
		os.Exit(2)
	}
	return opts
}

const usageLine = "usage: boobook -evidence <root> -output <root> " +
	"[-working <root>] [-case REF] [-examiner NAME] [-host LABEL]"

// loadRules returns the rule set the run will classify with: the built-in one,
// or a file the examiner supplied for a case the built-in weights do not suit.
func loadRules(opts options) (classify.Rules, error) {
	if opts.rulesFile != "" {
		return classify.LoadFile(opts.rulesFile)
	}
	return classify.Load()
}

func ruleSetSource(opts options) string {
	if opts.rulesFile != "" {
		return opts.rulesFile
	}
	return "built-in"
}

// phases is how many phases a run reports, and so the denominator on every
// progress line.
const phases = 10

// banner is printed before anything else happens.
//
// Not decoration alone: opening the case database and loading the rule set take
// a few seconds before the first phase can start, and a terminal that stays
// blank through them looks like a tool that failed to launch. The banner says
// which tool is running, and the line after it says what it is doing.
//
//go:embed banner.txt
var banner string

// bannerText is the banner with the version centred beneath it.
//
// Every path that greets a person goes through here: the start of a run, -h,
// and any usage error. The version belongs on all three and not just the
// successful one — a run that fails on its arguments never writes the
// manifest that would otherwise have recorded which build was asked, and an
// examiner with two builds on disk has no other way to tell them apart.
func bannerText() string {
	art := strings.TrimRight(banner, "\r\n")

	version := "version " + workspace.Version
	if workspace.BuildHash != "" {
		version += " (" + workspace.BuildHash + ")"
	}

	// Centred on the art rather than on a constant, so the banner can be
	// redrawn at a different width without leaving the version off to one side.
	width := 0
	for _, line := range strings.Split(art, "\n") {
		if n := len([]rune(line)); n > width {
			width = n
		}
	}
	if pad := (width - len([]rune(version))) / 2; pad > 0 {
		version = strings.Repeat(" ", pad) + version
	}

	return art + "\n" + version + "\n"
}

func run(opts options) error {
	startedAt := time.Now()
	ledger := provenance.NewLedger()

	pr := progress.New(os.Stderr, phases, opts.quiet)
	pr.Printf("%s", bannerText())

	// Before the run announces it is starting, and before anything is created.
	//
	// workspace.New calls MkdirAll, and a run that has already made a directory
	// inside the evidence has broken the first standing rule whatever it does
	// next. Nothing stopped an examiner passing one path to both -evidence and
	// -output: the run wrote the case database, every export, the report and
	// the manifest into the collection and exited zero.
	//
	// The boundary is built here rather than taken from discovery, because
	// discovery is phase 1 and this has to happen before phase 0 writes
	// anything. Locate builds its own from the same root; resolving a directory
	// twice is cheaper than threading one through for this.
	writeBoundary, err := evidence.NewBoundary(opts.evidenceRoot)
	if err != nil {
		return err
	}
	if err := writeBoundary.RefuseWrite("-output", opts.outputRoot); err != nil {
		return err
	}
	if opts.workingRoot != "" {
		if err := writeBoundary.RefuseWrite("-working", opts.workingRoot); err != nil {
			return err
		}
	}

	pr.Printf("Starting. Opening the case database and loading the rule set…\n")
	// The hive reader notes a skipped transaction log through the standard
	// logger. Left pointed at stderr those notes land in the middle of the
	// progress line and stay there, and they survive -quiet.
	log.SetOutput(pr.Writer())
	log.SetFlags(0)
	// A failed run leaves the progress line half drawn, and the error would be
	// printed on top of it.
	defer pr.Close()

	// ---- workspace ----------------------------------------------------
	work, err := workspace.New(opts.outputRoot, opts.workingRoot, opts.runID, opts.inPlace)
	if err != nil {
		return err
	}

	// RecoverHive writes its recovered copy to os.TempDir(). Redirecting the
	// process temp dir keeps every recovered byte inside the run's own scratch
	// directory rather than scattered through the system temp folder.
	restoreTempDir, err := work.RedirectProcessTempDir()
	if err != nil {
		return err
	}
	defer restoreTempDir()

	manifest := work.NewManifest(startedAt)
	manifest.Case = workspace.CaseInfo{
		Reference: opts.caseRef,
		Examiner:  opts.examiner,
		HostLabel: opts.hostLabel,
	}

	outputDir, err := work.OutputDir()
	if err != nil {
		return err
	}

	// The case database is opened before anything is parsed, so each phase
	// loads what it read as it reads it rather than holding the whole
	// collection in memory to write at the end.
	db, err := store.Open(filepath.Join(outputDir, "case.duckdb"))
	if err != nil {
		return err
	}
	defer db.Close()

	// The rule set is loaded before anything is parsed, so a mistyped profile
	// fails in the first second rather than after five minutes of hashing.
	rules, err := loadRules(opts)
	if err != nil {
		return err
	}
	if err := db.LoadRules(rules, opts.profile); err != nil {
		return err
	}
	manifest.Classification = workspace.ClassificationInfo{
		RuleSetVersion: rules.Version,
		RuleSetSource:  ruleSetSource(opts),
		Profile:        opts.profile,
	}

	pr.Printf("Run %s  output %s\n", work.RunID, work.Dir)

	// ---- discovery ----------------------------------------------------
	step := time.Now()
	phase := pr.Phase(1, "Discovery")
	set, err := evidence.Locate(opts.evidenceRoot)
	if err != nil {
		return err
	}
	manifest.AddTiming("discovery", time.Since(step), "")

	layout := ""
	volumeRoots := make([]string, 0, len(set.Volumes))
	for _, volume := range set.Volumes {
		volumeRoots = append(volumeRoots, volume.Path)
		layout = string(volume.Layout)
	}
	manifest.Evidence = workspace.EvidenceInfo{
		Root:          set.Root,
		Layout:        layout,
		VolumeRoots:   volumeRoots,
		TotalBytes:    set.TotalBytes(),
		ArtefactCount: len(set.Artefacts),
		NotCollected:  set.Missing,
		NameCollision: set.Collisions,
	}

	for _, missing := range set.Missing {
		ledger.Absent(missingKind(missing), missingPath(missing),
			"not present in the collection")
	}

	// A place that could not be read is not a place that held nothing, and the
	// two used to produce the same silence. Severity is "failed" rather than
	// "absent" because the report must not offer this as evidence there was
	// nothing there: an unreadable Recent folder reads as nobody having opened
	// a file from a device, when it means nobody looked.
	for _, failure := range set.Failures {
		message := discoveryFailureMessage(failure)
		manifest.Evidence.NotLooked = append(manifest.Evidence.NotLooked,
			fmt.Sprintf("%s (%s): %s", failure.Kind, failure.Path, failure.Why))
		ledger.Warn(provenance.Warning{
			Artefact: failure.Kind, Path: failure.Path,
			Severity: "failed", Message: message,
		})
	}

	phase.Finish("%d volume(s) (%s), %d artefact(s), %s",
		len(set.Volumes), layout, len(set.Artefacts), megabytes(set.TotalBytes()))
	if len(set.Missing) > 0 {
		pr.Printf("      not collected: %s\n",
			strings.Join(set.Missing, "; "))
	}

	// ---- registry -----------------------------------------------------
	step = time.Now()
	devnodeCount := 0
	mountCount := 0
	var controlSets registry.ControlSets
	var mountEntries []registry.MountEntry
	var timeZone registry.TimeZone
	var prefetchSetting registry.PrefetchSetting
	var prefetchSourceID string

	systemHives := set.ByKind("SYSTEM")
	phase = pr.Phase(2, "Registry")
	phase.Expect(len(systemHives), evidence.Bytes(systemHives))

	for _, hive := range systemHives {
		phase.Item("SYSTEM", hive.Path, hive.Size())
		source, err := ledger.AddSource(hive.Path, "SYSTEM")
		if err != nil {
			ledger.Warn(provenance.Warning{
				Artefact: "SYSTEM", Path: hive.Path,
				Severity: "failed", Message: err.Error(),
			})
			// Finished, badly. A hive that could not be read is still a hive the
			// phase has no more to do with, and a counter that never reached its
			// total would leave the run looking stalled at the end.
			phase.Read("SYSTEM", hive.Path, hive.Size(), 0)
			continue
		}

		hashTransactionLogs(ledger, hive)

		reg, cleanup, replay, err := registry.LoadHive(hive)
		if err != nil {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "SYSTEM", Path: hive.Path,
				Severity: "failed", Message: err.Error(),
			})
			phase.Read("SYSTEM", hive.Path, hive.Size(), 0)
			continue
		}

		recordReplay(ledger, source, "SYSTEM", hive, replay)

		result := registry.ReadSystem(reg)
		if zone := registry.ReadTimeZone(reg, result.ControlSets.Current); zone.Found {
			timeZone = zone
			ledger.Observe(provenance.Observation{
				SourceID: source.ID,
				Locator: provenance.Locator{
					RegistryKey: result.ControlSets.Current + `\Control\TimeZoneInformation`,
					ControlSet:  result.ControlSets.Current,
				},
				Kind:  "host.time_zone",
				Field: zone.KeyName,
				Summary: fmt.Sprintf("bias=%d standard=%d daylight=%d active=%d",
					zone.BiasMinutes, zone.StandardBiasMinutes,
					zone.DaylightBiasMinutes, zone.ActiveBiasMinutes),
				Value: zone.StandardName,
			})
			if err := db.LoadTimeZone(source.ID,
				result.ControlSets.Current, zone); err != nil {
				return err
			}
		}

		// Whether Windows was recording programme launches at all. Read here
		// rather than beside the prefetch files themselves because it is a
		// SYSTEM value and this is the only phase that opens SYSTEM — and
		// because without it an empty Prefetch directory has three possible
		// readings and the report could not say which.
		setting := registry.ReadPrefetchSetting(reg, result.ControlSets.Current)
		prefetchSetting, prefetchSourceID = setting, source.ID
		if setting.Found {
			ledger.Observe(provenance.Observation{
				SourceID: source.ID,
				Locator: provenance.Locator{
					RegistryKey:   setting.RegistryKey,
					RegistryValue: "EnablePrefetcher",
					ControlSet:    setting.ControlSet,
				},
				Kind:  "host.prefetch_setting",
				Field: "EnablePrefetcher",
				Raw:   fmt.Sprintf("%d", setting.Value),
				Value: setting.Describe(),
			})
		}

		devnodeCount += len(result.Devnodes)
		mountCount += len(result.MountEntries)
		controlSets = result.ControlSets
		mountEntries = append(mountEntries, result.MountEntries...)

		recordDevnodes(ledger, source.ID, result.Devnodes)
		recordMountEntries(ledger, source.ID, result.MountEntries)

		if err := db.LoadDevnodes(source.ID, result.Devnodes); err != nil {
			return err
		}
		if err := db.LoadMountEntries(source.ID, result.MountEntries); err != nil {
			return err
		}
		cleanup()
		phase.Read("SYSTEM", hive.Path, hive.Size(),
			len(result.Devnodes)+len(result.MountEntries))
	}

	// Written once, and written whether or not the value was there: an absent
	// EnablePrefetcher is the answer "the default applied", not the absence of
	// an answer, and the coverage section has to be able to say so.
	if prefetchSourceID != "" {
		if err := db.LoadPrefetchSetting(prefetchSourceID, prefetchSetting); err != nil {
			return err
		}
	}

	manifest.AddTiming("registry", time.Since(step), "SYSTEM")
	manifest.Counts.Devnodes = devnodeCount

	phase.Finish(
		"%d devnode(s) across %d control set(s) (current %s), %d mount entr(ies)",
		devnodeCount, len(controlSets.Names), controlSets.Current, mountCount)
	reportDeviceLinks(pr, mountEntries)

	// ---- SOFTWARE -----------------------------------------------------
	step = time.Now()
	portableCount := 0
	emdFound := false

	softwareHives := set.ByKind("SOFTWARE")
	phase = pr.Phase(3, "SOFTWARE")
	phase.Expect(len(softwareHives), evidence.Bytes(softwareHives))

	for _, hive := range softwareHives {
		phase.Item("SOFTWARE", hive.Path, hive.Size())
		source, err := ledger.AddSource(hive.Path, "SOFTWARE")
		if err != nil {
			ledger.Warn(provenance.Warning{
				Artefact: "SOFTWARE", Path: hive.Path,
				Severity: "failed", Message: err.Error(),
			})
			phase.Read("SOFTWARE", hive.Path, hive.Size(), 0)
			continue
		}

		hashTransactionLogs(ledger, hive)

		reg, cleanup, replay, err := registry.LoadHive(hive)
		if err != nil {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "SOFTWARE", Path: hive.Path,
				Severity: "failed", Message: err.Error(),
			})
			phase.Read("SOFTWARE", hive.Path, hive.Size(), 0)
			continue
		}
		recordReplay(ledger, source, "SOFTWARE", hive, replay)

		portable := registry.ReadPortableDevices(reg)
		portableCount += len(portable)
		recordPortableDevices(ledger, source.ID, portable)

		entries, found := registry.ReadEMDMgmt(reg)
		emdFound = emdFound || found
		if !found {
			// Not written on every host, notably not on Windows 11. Its absence
			// removes the volume-serial route to a device, so it is reported
			// rather than passed over as "no volumes".
			ledger.Absent("EMDMgmt", hive.Path,
				"EMDMgmt is not present; the volume-serial route from a file "+
					"record to a device is unavailable for this host")
		} else if len(entries) == 0 {
			// The key exists and holds nothing. An analyst expecting the
			// volume-serial route to work here needs to know it was looked for
			// and found empty, not merely that no entries were reported.
			ledger.Absent("EMDMgmt", hive.Path,
				"EMDMgmt is present but holds no volume records, so it cannot "+
					"resolve a volume serial to a device on this host")
		}
		recordEMDMgmt(ledger, source.ID, entries)

		if err := db.LoadPortableDevices(source.ID, portable); err != nil {
			return err
		}
		if err := db.LoadEMDVolumes(source.ID, entries); err != nil {
			return err
		}

		cleanup()
		phase.Read("SOFTWARE", hive.Path, hive.Size(), len(portable)+len(entries))
	}
	manifest.AddTiming("software", time.Since(step), "")
	phase.Finish("%d portable device record(s), EMDMgmt %s",
		portableCount, presence(emdFound))

	// ---- user hives ---------------------------------------------------
	//
	// UsrClass is read alongside NTUSER because that is where any current
	// Windows keeps the shell bags for local and removable volumes. Reading
	// only NTUSER would find the network tree and report no bags for the
	// device, which is indistinguishable from the user never opening it.
	step = time.Now()
	mountPointCount := 0
	bagCount := 0
	mruCount := 0
	userAssistCount := 0

	userHives := append(set.ByKind("NTUSER"), set.ByKind("USRCLASS")...)
	phase = pr.Phase(4, "User hives")
	phase.Expect(len(userHives), evidence.Bytes(userHives))

	for _, kind := range []string{"NTUSER", "USRCLASS"} {
		for _, hive := range set.ByKind(kind) {
			phase.Item(kind, hive.Path, hive.Size())
			records := 0

			source, err := ledger.AddSource(hive.Path, kind)
			if err != nil {
				phase.Read(kind, hive.Path, hive.Size(), 0)
				continue
			}

			hashTransactionLogs(ledger, hive)

			reg, cleanup, replay, err := registry.LoadHive(hive)
			if err != nil {
				ledger.Warn(provenance.Warning{
					SourceID: source.ID, Artefact: kind, Path: hive.Path,
					Severity: "failed", Message: err.Error(),
				})
				phase.Read(kind, hive.Path, hive.Size(), 0)
				continue
			}
			recordReplay(ledger, source, kind, hive, replay)

			if kind == "NTUSER" {
				mountPoints := registry.ReadMountPoints2(reg, hive.Profile)
				mountPointCount += len(mountPoints)
				records += len(mountPoints)
				recordMountPoints(ledger, source.ID, mountPoints)
				if err := db.LoadMountPoints(source.ID, mountPoints); err != nil {
					return err
				}

				entries := append(registry.ReadRecentDocs(reg, hive.Profile),
					registry.ReadFileDialogMRU(reg, hive.Profile)...)
				mruCount += len(entries)
				records += len(entries)
				recordMRUEntries(ledger, source.ID, entries)
				if err := db.LoadMRUEntries(source.ID, entries); err != nil {
					return err
				}

				launched := registry.ReadUserAssist(reg, hive.Profile)
				userAssistCount += len(launched)
				records += len(launched)
				recordUserAssist(ledger, source.ID, launched)
				if err := db.LoadUserAssist(source.ID, launched); err != nil {
					return err
				}
			}

			bags := registry.ReadShellBags(reg, kind, hive.Profile)
			bagCount += len(bags)
			records += len(bags)
			recordShellBags(ledger, source.ID, bags)
			if err := db.LoadShellBags(source.ID, bags); err != nil {
				return err
			}

			cleanup()
			phase.Read(kind, hive.Path, hive.Size(), records)
		}
	}
	manifest.AddTiming("user_hives", time.Since(step), "")
	manifest.Counts.ShellBags = bagCount
	manifest.Counts.MRUEntries = mruCount
	manifest.Counts.UserAssistEntries = userAssistCount

	phase.Finish(
		"%d profile(s), %d mount point(s), %d shell bag(s), %d MRU entr(ies), "+
			"%d launch record(s)",
		len(set.ByKind("NTUSER")), mountPointCount, bagCount, mruCount,
		userAssistCount)

	// ---- event logs ---------------------------------------------------
	step = time.Now()
	evtxArtefacts := set.ByKind("EVTX")

	paths := make([]string, 0, len(evtxArtefacts))
	for _, artefact := range evtxArtefacts {
		paths = append(paths, artefact.Path)
	}

	// The phase declares its own work: which channels are read is decided in the
	// parser, and a count of the files handed over would show a run stalling at
	// four of three hundred when the other 296 were never going to be read.
	phase = pr.Phase(5, "Event logs")
	options := eventlog.Options{OptIn: map[string]bool{}}
	if opts.readSecurity {
		for _, channel := range eventlog.OptInChannels() {
			options.OptIn[channel] = true
		}
	}
	records, eventStats := eventlog.ParseTreeWith(paths, phase, options)

	// Only the files actually read are hashed. Hashing every event log in a
	// collection would cost more than the parse and would attest to bytes no
	// finding rests on; a skipped file is accounted for by name and size in the
	// manifest instead.
	sourceByPath := map[string]string{}
	for _, fileStats := range eventStats.Files {
		if fileStats.Skipped {
			continue
		}
		source, err := ledger.AddSource(fileStats.Path, "EVTX")
		if err != nil {
			ledger.Warn(provenance.Warning{
				Artefact: "EVTX", Path: fileStats.Path,
				Severity: "failed", Message: err.Error(),
			})
			continue
		}
		sourceByPath[fileStats.Path] = source.ID

		if fileStats.Err != nil {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "EVTX", Path: fileStats.Path,
				Severity: "failed", Message: fileStats.Err.Error(),
			})
		}
		if fileStats.ChunksFailed > 0 {
			// Records in an unreadable chunk are unread, not absent. Reporting
			// the file as parsed without saying so would overstate coverage.
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "EVTX", Path: fileStats.Path,
				Severity: "malformed",
				Message: fmt.Sprintf("%d of %d chunks could not be parsed; "+
					"records they hold are not in this result",
					fileStats.ChunksFailed, fileStats.ChunksRead),
			})
		}
	}

	recordEvents(ledger, sourceByPath, records)
	if err := db.LoadEvents(sourceByPath, records); err != nil {
		return err
	}

	// The disk layout structures the Partition/Diagnostic records carry. These
	// are what tie a MountedDevices volume to the disk it sits on, and so to
	// the device: the registry names a partition identifier and no disk, and
	// this record names both.
	disks := store.DisksFromEvents(sourceByPath, records)
	if err := db.LoadDisks(disks); err != nil {
		return err
	}
	recordDisks(ledger, disks)
	manifest.EventSelection = eventSelection(eventStats)
	manifest.Counts.EventRecords = len(records)
	manifest.AddTiming("event_logs", time.Since(step),
		fmt.Sprintf("%d file(s) read, %d skipped", eventStats.FilesParsed,
			eventStats.FilesSkipped))

	phase.Finish(
		"%d record(s) from %d channel(s); read %d file(s), skipped %d",
		len(records), countChannels(records), eventStats.FilesParsed,
		eventStats.FilesSkipped)
	reportEventKinds(pr, records)

	// ---- setupapi -----------------------------------------------------
	step = time.Now()
	setupZone := setupapi.TimeZone{
		BiasMinutes:         timeZone.BiasMinutes,
		StandardBiasMinutes: timeZone.StandardBiasMinutes,
		DaylightBiasMinutes: timeZone.DaylightBiasMinutes,
		Found:               timeZone.Found,
		// The decision, not the raw bias. Passing the bias alone left the
		// SetupAPI adapter offering a daylight reading on a host that does not
		// observe it, which the SQL had already stopped doing — so provenance
		// and the timeline disagreed about the same section.
		Observes: timeZone.ObservesDaylightSaving(),
	}
	if !timeZone.Found {
		// Without the host's offset a local timestamp cannot be placed on a
		// timeline at all. Saying so is the only honest option.
		ledger.Absent("TimeZoneInformation", "",
			"the host time zone could not be read, so SetupAPI local times are "+
				"reported as written with no UTC reading")
	}

	setupSections := 0
	setupFiles := 0

	setupLogs := append(set.ByKind("SETUPAPI"), set.ByKind("SETUPAPI_ROTATED")...)
	phase = pr.Phase(6, "SetupAPI")
	phase.Expect(len(setupLogs), evidence.Bytes(setupLogs))

	for _, artefact := range setupLogs {
		phase.Item(artefact.Kind, artefact.Path, artefact.Size())
		source, err := ledger.AddSource(artefact.Path, artefact.Kind)
		if err != nil {
			ledger.Warn(provenance.Warning{
				Artefact: artefact.Kind, Path: artefact.Path,
				Severity: "failed", Message: err.Error(),
			})
			phase.Read(artefact.Kind, artefact.Path, artefact.Size(), 0)
			continue
		}

		sections, stats := setupapi.Parse(artefact.Path, setupZone)
		if stats.Err != nil {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: artefact.Kind, Path: artefact.Path,
				Severity: "malformed", Message: stats.Err.Error(),
			})
		}
		if stats.Unterminated > 0 {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: artefact.Kind, Path: artefact.Path,
				Severity: "malformed",
				Message: fmt.Sprintf("%d section(s) had no end marker and are "+
					"reported from their start alone", stats.Unterminated),
			})
		}

		setupFiles++
		setupSections += len(sections)
		recordSetupSections(ledger, source.ID, sections)

		if err := db.LoadSetupSections(source.ID, sections); err != nil {
			return err
		}
		phase.Read(artefact.Kind, artefact.Path, artefact.Size(), len(sections))
	}
	manifest.AddTiming("setupapi", time.Since(step), "")
	phase.Finish("%d USB section(s) from %d log(s)%s",
		setupSections, setupFiles, timeZoneNote(timeZone))

	// ---- file activity ------------------------------------------------
	step = time.Now()
	// Prefetch shares this phase rather than getting one of its own. It is the
	// same question — what was used, and on which volume — and renumbering the
	// ten phases so the narration reads "11" would be churn an analyst has to
	// re-learn for no gain.
	shellFiles := append(set.ByKind("LNK"), set.ByKind("JUMPLIST")...)
	prefetchFiles := set.ByKind("PREFETCH")
	phase = pr.Phase(7, "File use")
	phase.Expect(len(shellFiles)+len(prefetchFiles),
		evidence.Bytes(shellFiles)+evidence.Bytes(prefetchFiles))

	activity := readFileActivity(ledger, set, phase)
	if err := db.LoadFileTargets(activity.targets); err != nil {
		return err
	}

	runs := readPrefetch(ledger, prefetchFiles, phase)
	if err := db.LoadPrefetchRuns(runs.runs, runs.sourceIDs); err != nil {
		return err
	}

	manifest.AddTiming("file_activity", time.Since(step), "")
	manifest.Counts.ShellLinks = activity.links
	manifest.Counts.FileTargets = len(activity.targets)
	manifest.Counts.RemovableTargets = activity.removable
	manifest.Counts.PrefetchRuns = len(runs.runs)
	manifest.Counts.PrefetchExecutions = runs.executions

	phase.Finish(
		"%d shell link(s), %d jump list entr(ies); %d target(s) on removable "+
			"media; %s",
		activity.links, activity.jumpEntries, activity.removable,
		prefetchNote(prefetchFiles, runs, prefetchSetting))

	// ---- database and outputs -------------------------------------------
	//
	// The ledger is loaded last because it accumulates warnings throughout the
	// run, and a warnings table missing the last phase's warnings would be a
	// coverage claim that is quietly wrong.
	step = time.Now()
	// No files to count here: the work is the consolidation and the export,
	// which are one query each. The phase still ticks, because several seconds
	// of silence inside DuckDB looks exactly like a hung run.
	phase = pr.Phase(8, "Case data")

	// Before the ledger is loaded, and after everything that reads evidence:
	// confirm each source is still the file whose digest is recorded against
	// the observations taken from it. The hash and the parse are separate
	// opens, so on evidence that can move under the run — a live host, a share,
	// a collection still being written — nothing else would notice.
	if moved := ledger.Reverify(); moved > 0 {
		pr.Printf("%d source file(s) changed while the run was reading them; "+
			"see the limitations in the report", moved)
	}

	// The parsers attach a warning to the record it concerns, and until now
	// that was the only place it went: the ledger holds whole-file failures, so
	// a run could report one warning with hundreds of partially read shortcuts
	// behind it. Gathered by reason rather than one per record — a warning
	// naming an offset is one reason seen many times — and recorded before the
	// ledger is loaded, so the count and the report's limitations both see it.
	partial, err := db.ParseWarnings()
	if err != nil {
		return err
	}
	for _, warning := range partial {
		ledger.Warn(provenance.Warning{
			Artefact: warning.Artefact,
			Severity: "partial",
			Message: fmt.Sprintf(
				"%d %s record(s) across %d file(s) were read only in part: %s. "+
					"The records are kept; see provenance/parse-warnings.csv",
				warning.Records, warning.Artefact, warning.SourceFiles,
				warning.Example),
		})
	}

	if err := db.LoadLedger(ledger); err != nil {
		return err
	}

	// The grouping and the facts are derived from everything above, so they are
	// consolidated once here — after the last load and before the first read.
	if err := db.Consolidate(); err != nil {
		return err
	}

	outputs, err := db.ExportAll(outputDir)
	for _, output := range outputs {
		manifest.Outputs = append(manifest.Outputs, workspace.OutputFile{
			Name: output.Name, Path: output.Path, View: output.View,
			Format: output.Format, Rows: output.Rows,
			Bytes: output.Bytes, SHA256: output.SHA256,
		})
	}
	if err != nil {
		return err
	}

	devices, err := db.Devices()
	if err != nil {
		return err
	}
	manifest.Counts.Devices = len(devices)
	manifest.AddTiming("database", time.Since(step),
		fmt.Sprintf("%d output file(s)", len(outputs)))

	phase.Finish("%d device(s), %d output file(s)", len(devices), len(outputs))
	reportDevices(pr, devices)
	if err := reportCandidateLinks(pr, db); err != nil {
		return err
	}
	if err := reportRemovableVolumes(pr, db, mountEntries); err != nil {
		return err
	}
	if err := reportConnections(pr, db); err != nil {
		return err
	}
	if err := reportVolumeLinks(pr, db); err != nil {
		return err
	}
	if err := reportLetterActivity(pr, db); err != nil {
		return err
	}
	if err := reportAttribution(pr, db); err != nil {
		return err
	}
	if err := reportTimeline(pr, db, manifest); err != nil {
		return err
	}

	// ---- the report ---------------------------------------------------
	//
	// Written before the manifest so the manifest can record it, with its hash,
	// exactly as it records every other output. A report quoted later has to be
	// showable to be the file this run wrote.
	step = time.Now()
	phase = pr.Phase(9, "Report")
	if err := writeReport(phase, db, manifest, outputDir, opts); err != nil {
		return err
	}
	manifest.AddTiming("report", time.Since(step), "")

	// ---- manifest -----------------------------------------------------
	phase = pr.Phase(10, "Manifest")

	// Counted before the manifest is written, so the manifest can state what
	// became of the scratch directory rather than being written first and
	// describing a decision that had not been taken yet.
	scratch, err := work.ScratchFiles()
	if err != nil {
		return err
	}
	manifest.Run.WorkingKept = opts.keepWorking

	// The database is the last output to settle, so it is the last one recorded.
	if err := recordCaseDatabase(db, manifest, outputDir); err != nil {
		return err
	}

	manifest.Finalise(ledger, time.Now())
	manifestPath, err := work.WriteManifest(manifest)
	if err != nil {
		return err
	}

	if !opts.keepWorking {
		if err := work.DiscardScratch(); err != nil {
			return err
		}
	}

	_, observations, warnings := ledger.Counts()
	phase.Finish("%d observation(s), %d warning(s)", observations, warnings)

	// Said either way when there was something there. A recovered hive is
	// derived rather than evidence — the hive and each of its transaction logs
	// are hashed in the ledger — but removing files silently invites the
	// question of what they were.
	switch {
	case scratch > 0 && opts.keepWorking:
		pr.Printf("      %d working file(s) kept in %s\n", scratch, work.TempDir())
	case scratch > 0:
		pr.Printf("      %d recovered working file(s) removed; "+
			"-keep-working retains them\n", scratch)
	}
	pr.Printf("\nCompleted in %s.\n",
		time.Since(startedAt).Round(time.Millisecond))

	// stdout carries only the manifest path, so a caller can parse it.
	fmt.Println(manifestPath)
	return nil
}

// hashTransactionLogs records each of a hive's transaction logs as a source of
// its own.
//
// recordCaseDatabase closes the case database and puts it in the manifest.
//
// The manifest says Outputs names every file the run wrote with its hash, and
// case.duckdb was the one it did not: the exports and the report were appended
// as they were written, the database was left to a deferred close, and the
// manifest was finalised while it was still open. Every reference run therefore
// listed 34 hashed outputs beside an unhashed database.
//
// That is not bookkeeping. The exporter says in as many words that the whole
// prefetch loaded-file list exists only in the database — a CSV would carry one
// row per file for every run on the host — so the run's own evidence includes a
// file nothing in the custody record tied to it. A copy produced months later
// could not be shown to be this run's.
//
// It has to happen here and not earlier. A digest of an open DuckDB file
// attests bytes the next writer changes, so the run checkpoints, closes, and
// only then stats and hashes what settled. The deferred Close in run() is
// harmless afterwards because Store.Close is idempotent.
//
// A surviving write-ahead log is recorded rather than removed. It should not be
// there after a clean close, and if it is, the database is not the whole of the
// case: saying so is the point of the manifest.
func recordCaseDatabase(db *store.Store, manifest *workspace.Manifest,
	outputDir string) error {

	if err := db.Checkpoint(); err != nil {
		return err
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("close the case database: %w", err)
	}

	for _, name := range []string{"case.duckdb", "case.duckdb.wal"} {
		path := filepath.Join(outputDir, name)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			// The ordinary case for the write-ahead log, and never for the
			// database itself — which is why the absence is reported rather
			// than passed over.
			if name == "case.duckdb" {
				return fmt.Errorf("the case database is not at %s", path)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", name, err)
		}
		digest, err := provenance.HashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", name, err)
		}
		manifest.Outputs = append(manifest.Outputs, workspace.OutputFile{
			Name: name, Path: path, Format: "duckdb",
			Bytes: info.Size(), SHA256: digest,
		})
	}
	return nil
}

// The hive's replay_logs column already names them, which says what replay had
// available. Hashing them is what lets the claim be checked. A hive parsed with
// its logs applied is not the bytes of the hive file alone: the value read came
// out of a recovered copy, and that copy is scratch — derived, unreferenced,
// and removed at the end of the run. Hashing the two inputs is therefore the
// only thing that makes "this value is reproducible from this evidence"
// verifiable rather than asserted.
//
// Recorded before the hive is parsed, so a hive that will not load still leaves
// its logs accounted for. One artefact name for all of them: the source path
// says which hive each belongs to, and four more coverage rows would say less.
func hashTransactionLogs(ledger *provenance.Ledger, hive evidence.Artefact) {
	for _, logPath := range hive.LogPaths {
		if _, err := ledger.AddSource(logPath, "TRANSACTION_LOG"); err != nil {
			ledger.Warn(provenance.Warning{
				Artefact: "TRANSACTION_LOG", Path: logPath,
				Severity: "failed", Message: err.Error(),
			})
		}
	}
}

// recordReplay writes what replay actually did to the source record, and warns
// where the hive is not the hive Windows would have seen.
//
// The two silences it removes are different and both mattered. A recovery that
// failed leaves the hive short of its most recent writes, which was already
// warned about. A recovery that *succeeded and changed nothing* was reported as
// a replay, with every log beside the hive named as though it had contributed —
// and that is the reading a later reviewer would take from replay_logs.
func recordReplay(ledger *provenance.Ledger, source provenance.Source,
	artefact string, hive evidence.Artefact, replay registry.Replay) {

	applied := replay.Applied()
	source.Replayed = &applied
	source.ReplayLogs = replay.AppliedLogs()
	source.ReplayNote = replay.Account()
	ledger.UpdateSource(source)

	if !replay.Attempted {
		ledger.Warn(provenance.Warning{
			SourceID: source.ID, Artefact: artefact, Path: hive.Path,
			Severity: "malformed", Message: replay.Account(),
		})
		return
	}

	// A log that was found and could not contribute is worth saying once, per
	// log, with the reason: "there were two logs and neither applied" is a
	// fact about the collection, not a defect in this tool.
	for _, log := range replay.Logs {
		if log.State == registry.LogApplicable {
			continue
		}
		ledger.Warn(provenance.Warning{
			SourceID: source.ID, Artefact: "TRANSACTION_LOG", Path: log.Path,
			Severity: "absent",
			Message: fmt.Sprintf("the log beside %s was not applied (%s): %s",
				filepath.Base(hive.Path), log.State, log.Detail),
		})
	}
}

// recordDevnodes writes one observation per stored value and per stored
// property, so any reported device attribute resolves back to the key and
// value it came from.
func recordDevnodes(ledger *provenance.Ledger, sourceID string,
	devnodes []registry.Devnode) {

	observations := make([]provenance.Observation, 0, len(devnodes)*8)

	for _, devnode := range devnodes {
		keyPath := fmt.Sprintf(`%s\Enum\%s\%s\%s`, devnode.ControlSet,
			devnode.Enumerator, devnode.DeviceID, devnode.InstanceID)

		// Sorted, because ranging a Go map is deliberately randomised and the
		// order here becomes the order observation ids are handed out in. Two
		// runs over one hive were producing observations.jsonl with the same
		// 2,091 records under different ids — so obs-00000003 named a different
		// registry value each time, which is a citation that does not resolve.
		stored := devnode.StoredValues()
		fields := make([]string, 0, len(stored))
		for field := range stored {
			fields = append(fields, field)
		}
		sort.Strings(fields)

		for _, field := range fields {
			value := stored[field]
			if value == "" {
				continue
			}
			observations = append(observations, provenance.Observation{
				SourceID: sourceID,
				Locator: provenance.Locator{
					RegistryKey:   keyPath,
					RegistryValue: field,
					ControlSet:    devnode.ControlSet,
				},
				Kind:  "devnode.value",
				Field: field,
				Raw:   value,
			})
		}

		// The key's own last-write time. Not a connection time: it records the
		// last change to the key, whatever caused it.
		if devnode.RawKeyLastWrite != 0 {
			observations = append(observations, provenance.Observation{
				SourceID: sourceID,
				Locator: provenance.Locator{
					RegistryKey: keyPath,
					ControlSet:  devnode.ControlSet,
				},
				Kind:         "devnode.key_last_write",
				Field:        "LastWriteTime",
				RawTimestamp: devnode.RawKeyLastWrite,
				TimeUTC:      devnode.KeyLastWriteUTC,
			})
		}

		for _, property := range devnode.Properties {
			observation := provenance.Observation{
				SourceID: sourceID,
				Locator: provenance.Locator{
					RegistryKey: property.RegistryPath(keyPath),
					ControlSet:  devnode.ControlSet,
				},
				Kind:         "devnode.property",
				Field:        property.DisplayName(),
				Raw:          property.Raw,
				RawTimestamp: property.RawFileTime,
				TimeUTC:      property.TimeUTC,
			}
			if property.Text != "" {
				observation.Value = property.Text
			}
			observations = append(observations, observation)
		}
	}

	ledger.ObserveBatch(observations)
}

// recordMountEntries writes one observation per MountedDevices value.
func recordMountEntries(ledger *provenance.Ledger, sourceID string,
	entries []registry.MountEntry) {

	observations := make([]provenance.Observation, 0, len(entries))

	for _, entry := range entries {
		value := entry.DevicePath
		if value == "" {
			value = entry.PartitionGUID
		}
		if value == "" && entry.TargetVolumeGUID != "" {
			value = entry.TargetVolumeGUID + "#" + entry.TargetOffsetHex
		}
		if value == "" && entry.TargetKind == registry.TargetMBRSignature {
			value = fmt.Sprintf("disk_signature=%08x offset=%d",
				entry.DiskSignature, entry.PartitionOffset)
		}

		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator: provenance.Locator{
				RegistryKey:   "MountedDevices",
				RegistryValue: entry.ValueName,
			},
			Kind:  "mounted_device." + string(entry.TargetKind),
			Field: entry.ValueName,
			Raw:   entry.Raw,
			Value: value,
		})
	}

	ledger.ObserveBatch(observations)
}

// reportDeviceLinks shows the drive letters and volumes that resolve to a
// device outright, which is the strongest link in the chain.
func reportDeviceLinks(pr *progress.Reporter, entries []registry.MountEntry) {
	var direct []registry.MountEntry
	for _, entry := range entries {
		if entry.TargetKind == registry.TargetDevicePath {
			direct = append(direct, entry)
		}
	}
	if len(direct) == 0 {
		return
	}

	pr.Printf("      device links:\n")
	for _, entry := range direct {
		mount := entry.DriveLetter
		if mount != "" {
			mount += ":"
		} else {
			mount = entry.VolumeGUID
		}
		pr.Printf("        %-40s -> %s\n",
			mount, entry.DeviceInstanceID)
	}
}

// recordPortableDevices records the Windows Portable Devices list, which is
// what carries a volume label back to a device where EMDMgmt is absent.
func recordPortableDevices(ledger *provenance.Ledger, sourceID string,
	devices []registry.PortableDevice) {

	observations := make([]provenance.Observation, 0, len(devices))
	for _, device := range devices {
		target := device.DeviceInstanceID
		if target == "" && device.VolumeGUID != "" {
			target = device.VolumeGUID + "#" + device.VolumeOffsetHex
		}

		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator: provenance.Locator{
				RegistryKey:   device.RegistryPath,
				RegistryValue: "FriendlyName",
			},
			Kind: "portable_device",
			// Field names which fact within the kind and Raw is the stored
			// form of it. These were the wrong way about and neither held what
			// it says: Field carried the FriendlyName's value and Raw carried
			// the subkey name, so a consumer of observations.jsonl reading raw
			// as "the bytes the value was stored as" got a key path instead.
			// The subkey name is not lost — RegistryPath ends with it, which
			// is where a locator belongs.
			Field: "FriendlyName",
			Raw:   device.FriendlyName,
			Value: target,
		})
	}
	ledger.ObserveBatch(observations)
}

func recordEMDMgmt(ledger *provenance.Ledger, sourceID string,
	entries []registry.EMDMgmtEntry) {

	observations := make([]provenance.Observation, 0, len(entries))
	for _, entry := range entries {
		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator:  provenance.Locator{RegistryKey: entry.RegistryPath},
			Kind:     "emdmgmt.volume",
			// The subkey name is the stored form: EMDMgmt encodes the label
			// and the serial into it, and both below are decoded from it.
			// Field held the label, a value rather than the name of a fact,
			// the same inversion as the portable devices above.
			Field:   "key_name",
			Raw:     entry.KeyName,
			Value:   entry.VolumeSerialDecimal,
			Summary: "volume label " + entry.VolumeLabel,
		})
	}
	ledger.ObserveBatch(observations)
}

// recordMountPoints records per-profile volume awareness. This is context, not
// attribution: it does not say the profile's user connected the device.
func recordMountPoints(ledger *provenance.Ledger, sourceID string,
	mountPoints []registry.MountPoint) {

	observations := make([]provenance.Observation, 0, len(mountPoints))
	for _, mountPoint := range mountPoints {
		value := mountPoint.VolumeGUID
		if value == "" {
			value = mountPoint.DriveLetter
		}
		if value == "" {
			value = mountPoint.RemotePath
		}

		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator:  provenance.Locator{RegistryKey: mountPoint.RegistryPath},
			Kind:     "mount_point." + string(mountPoint.Kind),
			// The subkey name is what the hive stores; the profile is which
			// user's hive it came from, which is context rather than the name
			// of the fact.
			Field:        "key_name",
			Raw:          mountPoint.KeyName,
			Summary:      "profile " + mountPoint.Profile,
			Value:        value,
			RawTimestamp: mountPoint.RawKeyLastWrite,
			TimeUTC:      mountPoint.KeyLastWriteUTC,
		})
	}
	ledger.ObserveBatch(observations)
}

// recordDisks writes one observation per decoded disk layout.
//
// The partition identifiers are the point: each is a value MountedDevices can
// hold, so an analyst who finds one in the registry can find it here and see
// which device the disk was.
func recordDisks(ledger *provenance.Ledger, disks []store.Disk) {
	observations := make([]provenance.Observation, 0, len(disks))

	for _, disk := range disks {
		detail := []string{"disk_number=" + disk.DiskNumber}
		if disk.Model != "" {
			detail = append(detail, "model="+disk.Model)
		}
		if disk.BootRecordSignature != 0 {
			detail = append(detail,
				fmt.Sprintf("boot_record_signature=%08x", disk.BootRecordSignature))
		}

		if disk.Layout != nil {
			detail = append(detail, "style="+string(disk.Layout.Style))
			if disk.Layout.DiskGUID != "" {
				detail = append(detail, "disk_guid="+disk.Layout.DiskGUID)
			}
			if disk.Layout.DiskSignature != 0 {
				detail = append(detail,
					fmt.Sprintf("disk_signature=%08x", disk.Layout.DiskSignature))
			}
			for _, entry := range disk.Layout.Partitions {
				detail = append(detail, fmt.Sprintf(
					"partition_%d=%s offset=%d name=%q",
					entry.Number, entry.PartitionGUID, entry.StartingOffset, entry.Name))
			}
		} else {
			// The record carried the bytes and they did not decode. That is a
			// gap in the chain, not an absence of evidence.
			detail = append(detail, "layout_not_decoded")
		}
		detail = append(detail, disk.Warnings...)

		timeUTC := disk.TimeUTC
		observations = append(observations, provenance.Observation{
			SourceID: disk.SourceID,
			Locator: provenance.Locator{
				Channel:       "Microsoft-Windows-Partition/Diagnostic",
				EventRecordID: disk.RecordID,
			},
			Kind:    "disk.layout",
			Field:   disk.DiskNumber,
			Summary: strings.Join(detail, "; "),
			Value:   disk.DeviceInstanceID,
			TimeUTC: &timeUTC,
		})
	}

	ledger.ObserveBatch(observations)
}

// recordShellBags writes one observation per bag.
//
// The FAT timestamps are carried as the local wall clock they recorded, marked
// as local. Nothing in a shell item says which offset was in force, and a
// timeline that treats them as UTC is wrong by however many hours the host was
// from Greenwich.
func recordShellBags(ledger *provenance.Ledger, sourceID string,
	bags []registry.ShellBag) {

	observations := make([]provenance.Observation, 0, len(bags))
	for _, bag := range bags {
		detail := []string{"hive=" + bag.Hive, "depth=" + strconv.Itoa(bag.Depth)}
		if bag.Kind != "" {
			detail = append(detail, "item_kind="+bag.Kind)
		}
		if bag.DriveLetter != "" {
			detail = append(detail, "drive_letter="+bag.DriveLetter+":")
		}
		if bag.ModifiedLocal != nil {
			detail = append(detail,
				"item_modified_local="+bag.ModifiedLocal.Format("2006-01-02 15:04:05"))
		}
		if bag.MFTEntry != 0 {
			detail = append(detail, fmt.Sprintf("mft_entry=%d sequence=%d",
				bag.MFTEntry, bag.MFTSequence))
		}
		if bag.PathHasGap {
			// The path is a reading with something missing from the middle, not
			// a place the user visited.
			detail = append(detail, "path_incomplete")
		}
		detail = append(detail, bag.Warnings...)

		observations = append(observations, provenance.Observation{
			SourceID:     sourceID,
			Locator:      provenance.Locator{RegistryKey: bag.RegistryPath},
			Kind:         "shell_bag",
			Field:        bag.Profile,
			Summary:      strings.Join(detail, "; "),
			Value:        bag.Path,
			RawTimestamp: bag.RawKeyLastWrite,
			TimeUTC:      bag.KeyLastWriteUTC,
		})
	}
	ledger.ObserveBatch(observations)
}

// recordMRUEntries writes one observation per RecentDocs or file dialog entry.
func recordMRUEntries(ledger *provenance.Ledger, sourceID string,
	entries []registry.MRUEntry) {

	observations := make([]provenance.Observation, 0, len(entries))
	for _, entry := range entries {
		detail := []string{"list=" + entry.Source, "kind=" + entry.Kind}
		if entry.Position >= 0 {
			detail = append(detail, fmt.Sprintf("mru_position=%d", entry.Position))
		} else {
			// The entry is real, its place in the order is not known. A
			// position of zero would invent a ranking.
			detail = append(detail, "no_mru_order")
		}
		if entry.Name != "" {
			detail = append(detail, "name="+entry.Name)
		}
		if entry.DriveLetter != "" {
			detail = append(detail, "drive_letter="+entry.DriveLetter+":")
		}
		if entry.PathHasGap {
			detail = append(detail, "path_incomplete")
		}
		detail = append(detail, entry.Warnings...)

		value := entry.Path
		if value == "" {
			value = entry.Name
		}

		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator: provenance.Locator{
				RegistryKey:   entry.RegistryPath,
				RegistryValue: entry.ValueName,
			},
			Kind:         "mru." + entry.Kind,
			Field:        entry.Profile,
			Summary:      strings.Join(detail, "; "),
			Value:        value,
			RawTimestamp: entry.RawKeyLastWrite,
			TimeUTC:      entry.KeyLastWriteUTC,
		})
	}
	ledger.ObserveBatch(observations)
}

// recordUserAssist writes one observation per launch the shell recorded.
func recordUserAssist(ledger *provenance.Ledger, sourceID string,
	entries []registry.UserAssist) {

	observations := make([]provenance.Observation, 0, len(entries))
	for _, entry := range entries {
		detail := []string{"category=" + entry.Category}
		if entry.CategoryName != "" {
			detail = append(detail, "category_name="+entry.CategoryName)
		}
		// Stated even when zero. A launch count of nought beside a focus count
		// is a real shape — the shell saw the window without recording a launch
		// — and leaving the number out would make it read as unknown.
		detail = append(detail,
			fmt.Sprintf("run_count=%d", entry.RunCount),
			fmt.Sprintf("focus_count=%d", entry.FocusCount),
			fmt.Sprintf("focus_seconds=%.1f", entry.FocusTime.Seconds()))
		if entry.DriveLetter != "" {
			detail = append(detail, "drive_letter="+entry.DriveLetter+":")
		}
		if entry.Bookkeeping {
			detail = append(detail, "shell_counter_not_a_launch")
		}
		detail = append(detail, entry.Warnings...)

		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator: provenance.Locator{
				RegistryKey: entry.RegistryPath,
				// The stored name, still ROT13'd: it is what an analyst has to
				// match against the key when checking this row, and the decoded
				// name is in Value.
				RegistryValue: entry.ValueName,
			},
			Kind:         "user_assist",
			Field:        entry.Profile,
			Summary:      strings.Join(detail, "; "),
			Value:        entry.Name,
			RawTimestamp: entry.RawLastExecuted,
			TimeUTC:      entry.LastExecutedUTC,
		})
	}
	ledger.ObserveBatch(observations)
}

// recordSetupSections writes one observation per device install section.
//
// The time is carried as the local string the log wrote plus both seasonal
// readings. A single UTC value here would be a guess presented as a
// measurement, and an hour either way changes what a timeline says.
func recordSetupSections(ledger *provenance.Ledger, sourceID string,
	sections []setupapi.Section) {

	observations := make([]provenance.Observation, 0, len(sections))
	for _, section := range sections {
		detail := []string{"operation=" + section.Operation}
		if section.ExitStatus != "" {
			detail = append(detail, "exit="+section.ExitStatus)
		}
		if section.Problem != "" {
			detail = append(detail, "problem="+section.Problem)
		}
		if section.DriverINF != "" {
			detail = append(detail, "inf="+section.DriverINF)
		}
		if section.ParentDevice != "" {
			detail = append(detail, "parent="+section.ParentDevice)
		}
		detail = append(detail, "start_local="+section.StartLocal)
		for _, candidate := range section.StartUTC {
			detail = append(detail,
				candidate.Basis+"="+wintime.Format(candidate.UTC))
		}

		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator: provenance.Locator{
				LineNumber: section.LineNumber,
			},
			Kind: "setupapi." + string(section.Kind),
			// The section header names its device, and that string is the
			// stored form of the identity normalised into Value. It was in
			// Field, which is for the name of a fact rather than a value.
			Field:   "section_target",
			Raw:     section.Target,
			Summary: strings.Join(detail, "; "),
			Value:   section.DeviceInstanceID,
		})
	}
	ledger.ObserveBatch(observations)
}

func timeZoneNote(zone registry.TimeZone) string {
	if !zone.Found {
		return " (no host time zone: times are local as written)"
	}
	name := zone.KeyName
	if name == "" {
		name = zone.StandardName
	}
	return fmt.Sprintf(" (host time zone %s, bias %d min)", name, zone.BiasMinutes)
}

// fileActivity is what the shell links and jump lists said.
type fileActivity struct {
	links       int
	jumpEntries int
	failed      int
	// removable counts the targets the recording application placed on
	// removable media, which is the set that can be tied to a USB device.
	removable int
	targets   []store.FileTarget
}

// readFileActivity parses every shell link and jump list found.
//
// Whether a target was on removable media is the recording application's own
// statement, taken from the link's volume information. Boobook reports that
// statement and, separately, whether a USB device held that drive letter. It
// does not merge the two into a claim the evidence has not made.
func readFileActivity(ledger *provenance.Ledger, set *evidence.Set,
	phase *progress.Phase) fileActivity {

	var activity fileActivity

	for _, artefact := range set.ByKind("LNK") {
		phase.Item("LNK", artefact.Path, artefact.Size())
		source, err := ledger.AddSource(artefact.Path, "LNK")
		if err != nil {
			activity.failed++
			phase.Read("LNK", artefact.Path, artefact.Size(), 0)
			continue
		}

		link, err := lnk.ParseFile(artefact.Path)
		if err != nil {
			// A .lnk that is not a shell link is worth one warning, not a
			// silent omission: it may be a renamed file.
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "LNK", Path: artefact.Path,
				Severity: "malformed", Message: err.Error(),
			})
			activity.failed++
			phase.Read("LNK", artefact.Path, artefact.Size(), 0)
			continue
		}
		activity.links++
		recordLink(ledger, source.ID, link, artefact.Profile)

		target := store.FromLink(source.ID, artefact.Path, artefact.Profile, link)
		// The shortcut's own last-written time, and the directory it was found
		// in. Nothing inside the link times an opening: its three header times
		// all describe the target. The mtime can, but only where the shell is
		// the one maintaining the file, which is what the context says.
		target.SourceModifiedUTC = artefact.ModifiedUTC()
		target.LinkContext = artefact.Context
		activity.targets = append(activity.targets, target)
		if link.Removable() {
			activity.removable++
		}
		phase.Read("LNK", artefact.Path, artefact.Size(), 1)
	}

	for _, artefact := range set.ByKind("JUMPLIST") {
		phase.Item("JUMPLIST", artefact.Path, artefact.Size())
		source, err := ledger.AddSource(artefact.Path, "JUMPLIST")
		if err != nil {
			activity.failed++
			phase.Read("JUMPLIST", artefact.Path, artefact.Size(), 0)
			continue
		}

		entries, stats := jumplist.ParseFile(artefact.Path)
		if stats.Err != nil {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "JUMPLIST", Path: artefact.Path,
				Severity: "malformed", Message: stats.Err.Error(),
			})
			activity.failed++
			phase.Read("JUMPLIST", artefact.Path, artefact.Size(), 0)
			continue
		}
		for _, warning := range stats.Warnings {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "JUMPLIST", Path: artefact.Path,
				Severity: "malformed", Message: warning,
			})
		}

		for _, entry := range entries {
			activity.jumpEntries++
			recordJumpEntry(ledger, source.ID, entry, artefact.Profile)

			activity.targets = append(activity.targets,
				store.FromJumpEntry(source.ID, artefact.Path, artefact.Profile, entry))
			if entry.Link != nil && entry.Link.Removable() {
				activity.removable++
			}
		}
		phase.Read("JUMPLIST", artefact.Path, artefact.Size(), len(entries))
	}

	return activity
}

// prefetchResult is what the prefetch files said.
type prefetchResult struct {
	runs []*prefetch.Run
	// sourceIDs maps a .pf path to its ledger source, so every row loaded from
	// it resolves back to that file and its hash.
	sourceIDs  map[string]string
	executions int
	failed     int
}

// readPrefetch parses every prefetch file found.
//
// A prefetch file says a programme ran and which volumes it touched. It does
// not say who ran it, and the eight-slot limit means a high run count beside two
// recorded times is ordinary rather than a defect — both are stated on the rows
// and in the report's limitations, not asserted away here.
func readPrefetch(ledger *provenance.Ledger, artefacts []evidence.Artefact,
	phase *progress.Phase) prefetchResult {

	result := prefetchResult{sourceIDs: make(map[string]string, len(artefacts))}

	for _, artefact := range artefacts {
		phase.Item("PREFETCH", artefact.Path, artefact.Size())
		source, err := ledger.AddSource(artefact.Path, "PREFETCH")
		if err != nil {
			result.failed++
			phase.Read("PREFETCH", artefact.Path, artefact.Size(), 0)
			continue
		}

		run, err := prefetch.ParseFile(artefact.Path)
		if err != nil {
			// A .pf that will not parse is worth a warning rather than a silent
			// omission: the directory also collects files from Windows versions
			// this build has not seen, and that is worth knowing.
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "PREFETCH", Path: artefact.Path,
				Severity: "malformed", Message: err.Error(),
			})
			result.failed++
			phase.Read("PREFETCH", artefact.Path, artefact.Size(), 0)
			continue
		}
		for _, warning := range run.Warnings {
			ledger.Warn(provenance.Warning{
				SourceID: source.ID, Artefact: "PREFETCH", Path: artefact.Path,
				Severity: "malformed", Message: warning,
			})
		}

		result.sourceIDs[run.SourceFile] = source.ID
		result.runs = append(result.runs, run)
		result.executions += len(run.RunTimes)
		recordPrefetchRun(ledger, source.ID, run)

		phase.Read("PREFETCH", artefact.Path, artefact.Size(), len(run.RunTimes))
	}

	return result
}

// recordPrefetchRun observes the execution and the volumes it touched.
//
// The volumes are observed individually because the serial is the value that
// joins prefetch to a device, and an observation that cannot be pointed at is
// one an analyst cannot check.
func recordPrefetchRun(ledger *provenance.Ledger, sourceID string,
	run *prefetch.Run) {

	observation := provenance.Observation{
		SourceID: sourceID,
		Kind:     "prefetch.run",
		Field:    run.Executable,
		Summary: fmt.Sprintf("version=%s run_count=%d times=%d volumes=%d files=%d",
			run.Version, run.RunCount, len(run.RunTimes),
			len(run.Volumes), len(run.Files)),
		Value: run.ExecutablePath,
	}
	// The most recent execution dates the record. The earlier slots are
	// observed as their own rows below rather than folded into this one.
	if len(run.RunTimes) > 0 {
		observation.TimeUTC = &run.RunTimes[0]
	}
	ledger.Observe(observation)

	for _, volume := range run.Volumes {
		ledger.Observe(provenance.Observation{
			SourceID: sourceID,
			Kind:     "prefetch.volume",
			Field:    run.Executable,
			Raw:      volume.DevicePath,
			Value:    volume.SerialHex,
			TimeUTC:  volume.CreatedUTC,
		})
	}
}

// prefetchNote says what the prefetch evidence amounted to, including when
// there was none.
//
// Three absences read differently and the sentence has to distinguish them: the
// directory was not collected, prefetching was off, or it was on and the
// directory was empty. Only the last says anything about what ran.
func prefetchNote(artefacts []evidence.Artefact, result prefetchResult,
	setting registry.PrefetchSetting) string {

	if len(artefacts) == 0 {
		if setting.Found && setting.Value == 0 {
			return "no prefetch (disabled on this host)"
		}
		return "no prefetch collected"
	}

	note := fmt.Sprintf("%d prefetch file(s), %d recorded execution(s)",
		len(result.runs), result.executions)
	if result.failed > 0 {
		note += fmt.Sprintf(", %d unreadable", result.failed)
	}
	return note
}

func recordLink(ledger *provenance.Ledger, sourceID string, link *lnk.Link,
	profile string) {

	ledger.Observe(provenance.Observation{
		SourceID: sourceID,
		Kind:     "shell_link",
		Field:    profile,
		Summary:  describeLink(link),
		Value:    link.FullPath(),
		// The link header's own record of when the target was last written.
		// This describes the target, not the link, and not the access.
		RawTimestamp: link.RawTargetWritten,
		TimeUTC:      link.TargetWritten,
	})
}

func recordJumpEntry(ledger *provenance.Ledger, sourceID string,
	entry jumplist.Entry, profile string) {

	detail := []string{"app_id=" + entry.AppID}
	if entry.Present {
		detail = append(detail, fmt.Sprintf("mru_position=%d", entry.Position))
		if entry.AccessCountRecorded {
			detail = append(detail, fmt.Sprintf("access_count=%d", entry.AccessCount))
		} else {
			// Saying nothing here would read as a count of zero once the
			// observation is beside others that carry one.
			detail = append(detail, "access_count_not_recorded")
		}
		detail = append(detail,
			fmt.Sprintf("destlist_ranking_value=%g", entry.RankingValue),
			fmt.Sprintf("pinned=%t", entry.Pinned))
		if entry.RecordedPath != "" {
			detail = append(detail, "recorded_path="+entry.RecordedPath)
		}
	} else {
		// The link is real, its place in the order is not known. Reporting a
		// position of zero as if it were first would invent a ranking.
		detail = append(detail, "no_destlist_entry")
	}
	if entry.Link != nil {
		detail = append(detail, describeLink(entry.Link))
	}

	value := entry.RecordedPath
	if entry.Link != nil && entry.Link.FullPath() != "" {
		value = entry.Link.FullPath()
	}

	ledger.Observe(provenance.Observation{
		SourceID:     sourceID,
		Locator:      provenance.Locator{RegistryValue: entry.StreamName},
		Kind:         "jump_list_entry",
		Field:        profile,
		Summary:      strings.Join(detail, "; "),
		Value:        value,
		RawTimestamp: entry.RawLastAccess,
		TimeUTC:      entry.LastAccessUTC,
	})
}

// describeLink renders the volume evidence a link carried. Where a link has no
// volume information that is said outright, because "no volume information" and
// "a fixed disk" are different findings.
func describeLink(link *lnk.Link) string {
	parts := []string{}
	if link.Origin != "" {
		parts = append(parts, "origin="+link.Origin)
	}
	if !link.VolumeIDPresent {
		parts = append(parts, "volume_information=absent")
	} else {
		parts = append(parts,
			"drive_type="+lnk.DriveTypeName(link.DriveType),
			"volume_serial="+lnk.SerialHex(link.DriveSerialNumber))
		if link.VolumeLabel != "" {
			parts = append(parts, "volume_label="+link.VolumeLabel)
		}
	}
	if link.DriveLetter != "" {
		parts = append(parts, "drive_letter="+link.DriveLetter+":")
	}
	if link.MachineID != "" {
		parts = append(parts, "machine_id="+link.MachineID)
	}
	if link.TargetSizeBytes > 0 {
		parts = append(parts, fmt.Sprintf("target_size=%d", link.TargetSizeBytes))
	}
	if len(link.Warnings) > 0 {
		parts = append(parts, "incomplete_parse="+strings.Join(link.Warnings, ","))
	}
	return strings.Join(parts, "; ")
}

// reportDevices shows the inventory the way an analyst reads it: what carried
// the most evidence first, with the source of that evidence named.
//
// Read from the same view devices.csv is copied from, so the console figure and
// the file are the same answer rather than two that ought to agree.
func reportDevices(pr *progress.Reporter, devices []store.Device) {
	if len(devices) == 0 {
		return
	}

	// A registry-first inventory would not list these at all, and a device
	// missing from the report looks exactly like a device that never existed.
	eventOnly := 0
	for _, device := range devices {
		if !device.InRegistry {
			eventOnly++
		}
	}
	if eventOnly > 0 {
		pr.Printf(
			"      %d device(s) have no registry key in this collection and are "+
				"named by other evidence alone\n", eventOnly)
	}

	// One stick appears as a USB node, a USBSTOR node and a WPDBUSENUM node, and
	// counting those as three devices is the error this grouping exists to stop.
	identities, grouped := 0, 0
	for _, device := range devices {
		identities += device.IdentityCount
		if device.IdentityCount > 1 {
			grouped++
		}
	}
	if grouped > 0 {
		pr.Printf(
			"      %d identities group into %d physical device(s); "+
				"%d device(s) were named more than one way\n",
			identities, len(devices), grouped)
	}

	// Tier 1 in full, the rest counted. The whole point of tiering is that a
	// report showing sixty software-enumerated nodes beside three memory sticks
	// buries the three memory sticks.
	byTier := map[int]int{}
	review := 0
	for _, device := range devices {
		byTier[device.Tier]++
		if device.ReviewRequired {
			review++
		}
	}
	pr.Printf(
		"      tier 1 %d, tier 2 %d, tier 3 %d; %d flagged for review\n",
		byTier[1], byTier[2], byTier[3], review)

	const shown = 8
	pr.Printf("      devices by tier and relevance score:\n")

	for index, device := range devices {
		if index == shown {
			pr.Printf("        ... %d more in data/devices.csv\n",
				len(devices)-shown)
			break
		}

		detail := fmt.Sprintf("%d event(s)", device.EventCount)
		if device.ConnectEvents > 0 || device.DisconnectEvents > 0 {
			detail += fmt.Sprintf(" (%d connect, %d disconnect)",
				device.ConnectEvents, device.DisconnectEvents)
		}
		if device.SetupSections > 0 {
			detail += fmt.Sprintf(", %d install section(s)", device.SetupSections)
		}
		if !device.InRegistry {
			// The strongest thing this inventory says. A registry-first tool
			// would not list this device at all.
			detail += "; no registry key in this collection"
		}

		flag := ""
		if device.ReviewRequired {
			flag = "  [review]"
		}
		pr.Printf("        T%d %3.0f  %-28s %s%s\n",
			device.Tier, device.Score, truncate(device.Label(), 28), device.Category, flag)
		pr.Printf("          %s\n", detail)
		if device.Serial != "" {
			pr.Printf("          serial %s%s\n", device.Serial,
				letterNote(device.CurrentDriveLetters))
		}
		if device.IdentityCount > 1 {
			pr.Printf("          %d identities grouped by %s\n",
				device.IdentityCount, device.GroupingMethods)
		}
		if device.ReviewRequired {
			pr.Printf("          review: %s\n",
				truncate(device.ReviewReason, 90))
		}
	}
}

// reportCandidateLinks shows the links that were not grouped on.
//
// A serial that is a prefix of another is the case the reference evidence
// forces: the USB enumerator holds a 120 character SanDisk serial that USBSTOR
// stores as its first 63. That is almost certainly one device, and a prefix is
// still not equality — a vendor issuing sequential serials produces prefixes
// between two devices that are not the same. So the link is reported, and
// whether something else already reached the same answer is reported with it.
func reportCandidateLinks(pr *progress.Reporter, db *store.Store) error {
	links, err := db.CandidateLinks()
	if err != nil {
		return err
	}
	if len(links) == 0 {
		return nil
	}

	corroborating, open := 0, 0
	for _, link := range links {
		if link.AlreadyGrouped {
			corroborating++
			continue
		}
		open++
	}

	if corroborating > 0 {
		pr.Printf(
			"      %d candidate link(s) agree with a grouping made another way\n",
			corroborating)
	}
	if open == 0 {
		return nil
	}

	pr.Printf(
		"      %d candidate link(s) were not acted on, and these identities are "+
			"reported as separate devices:\n", open)
	const shown = 3
	listed := 0
	for _, link := range links {
		if link.AlreadyGrouped {
			continue
		}
		if listed == shown {
			pr.Printf("        ... %d more in data/device-links.csv\n",
				open-shown)
			break
		}
		// Both identities in full width: what makes the link readable is the
		// part they share, and truncating to a column would hide exactly that.
		pr.Printf("        %s\n          %s\n          %s\n",
			link.Method, truncate(link.DeviceKey, 66),
			truncate(link.OtherDeviceKey, 66))
		listed++
	}
	return nil
}

func letterNote(letters string) string {
	if letters == "" {
		return ""
	}
	return "  currently mapped to " + letters + ":"
}

// reportRemovableVolumes shows file activity on removable media beside the
// device that holds the drive letter, where MountedDevices names one.
//
// The letter is the obvious join and it is the wrong one. That MountedDevices
// records a letter for one device now says nothing about which device held it
// when the file was opened, so the device is offered as a candidate rather than
// asserted, and the correlation phase is where that gets resolved.
func reportRemovableVolumes(pr *progress.Reporter, db *store.Store,
	entries []registry.MountEntry) error {
	volumes, err := db.RemovableVolumes()
	if err != nil {
		return err
	}
	if len(volumes) == 0 {
		return nil
	}

	byLetter := map[string]string{}
	for _, entry := range entries {
		if entry.Kind == registry.MountDriveLetter && entry.DeviceInstanceID != "" {
			byLetter[entry.DriveLetter] = entry.DeviceInstanceID
		}
	}

	volumesPerLetter := map[string]int{}
	for _, volume := range volumes {
		volumesPerLetter[volume.DriveLetter]++
	}

	pr.Printf("      removable volumes named by file records:\n")
	for _, volume := range volumes {
		pr.Printf("        %s: serial %s label %-12s %d target(s)\n",
			volume.DriveLetter, volume.VolumeSerialHex,
			truncate(volume.VolumeLabel, 12), volume.TargetCount)
	}

	for letter, distinct := range volumesPerLetter {
		device := byLetter[letter]
		switch {
		case distinct > 1:
			// The letter cannot resolve this on its own, and naming the device
			// it maps to now would invite exactly the wrong conclusion.
			pr.Printf(
				"        note: %s: was used by %d different volumes; the serial "+
					"distinguishes them and the letter does not\n", letter, distinct)
		case device != "":
			pr.Printf(
				"        note: %s: is currently mapped to %s — whether it held that "+
					"device when these files were opened is not established here\n",
				letter, device)
		}
	}

	return nil
}

// reportConnections shows the intervals each device was connected.
//
// An open window and a closed one are printed differently on purpose. "still
// connected as far as the evidence goes" and "removed at 10:03" are different
// findings, and a report that renders both as a time range invites the second
// to be read where only the first was evidenced.
func reportConnections(pr *progress.Reporter, db *store.Store) error {
	connections, err := db.Connections()
	if err != nil {
		return err
	}
	if len(connections) == 0 {
		// A collection with no arrival or removal records yields no windows, and
		// that is a fact about the collection rather than about the devices. An
		// empty section with no explanation reads as "nothing was connected".
		pr.Printf(
			"      no connection windows: no arrival or removal record was "+
				"selected\n        the channels that carry them are %s\n",
			strings.Join(eventlog.StateChangeChannels(), ", "))
		return nil
	}

	const shown = 10
	pr.Printf("      connection windows:\n")

	for index, connection := range connections {
		if index == shown {
			pr.Printf("        ... %d more in data/connections.csv\n",
				len(connections)-shown)
			break
		}

		pr.Printf("        %-46s %s  (%d record(s))\n",
			truncate(connection.DeviceInstanceID, 46), describeWindow(connection),
			connection.SupportingRecords)
	}

	return nil
}

// describeWindow renders a window in words rather than as a range, so an
// unknown boundary reads as unknown instead of as a missing field.
func describeWindow(connection store.Connection) string {
	switch {
	case !connection.StartKnown:
		return "connected before the evidence begins, removed " +
			wintime.Format(*connection.EndedUTC)
	case connection.EndedBeforeUTC != nil:
		// Distinct from the case below, and the distinction is the point: the
		// device certainly went away, because it arrived again. What is missing
		// is when, not whether.
		return "connected " + wintime.Format(*connection.StartedUTC) +
			", no removal recorded, arrived again " +
			wintime.Format(*connection.EndedBeforeUTC)
	case connection.OpenEnded:
		return "connected " + wintime.Format(*connection.StartedUTC) +
			", no removal recorded"
	default:
		// "span" and not "connected for": the evidence records an arrival and,
		// later, the next removal. Whether the device stayed connected between
		// them is recorded nowhere, and a log that rolled in the middle leaves
		// exactly this shape.
		return fmt.Sprintf("%s → %s (span %s)",
			wintime.Format(*connection.StartedUTC),
			wintime.Format(*connection.EndedUTC),
			(time.Duration(*connection.SpanSeconds) * time.Second).String())
	}
}

// writeReport renders the case report and records it in the manifest.
//
// Every figure in it is read from the same views the data files are copied
// from, so the prose and the CSVs cannot disagree about the evidence.
func writeReport(phase *progress.Phase, db *store.Store,
	manifest *workspace.Manifest, outputDir string, opts options) error {

	if opts.noReport {
		phase.Finish("skipped (-no-report)")
		return nil
	}

	gathered, err := report.Gather(db, manifest)
	if err != nil {
		return err
	}
	path, err := report.Write(gathered, outputDir)
	if err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat report: %w", err)
	}
	digest, err := provenance.HashFile(path)
	if err != nil {
		return fmt.Errorf("hash report: %w", err)
	}
	manifest.Outputs = append(manifest.Outputs, workspace.OutputFile{
		Name: "report.html", Path: path, Format: "html",
		Bytes: info.Size(), SHA256: digest,
	})

	phase.Finish("%s (%d device(s) at tier 1-2, %d headline finding(s))",
		path, gathered.Summary.Significant(), len(gathered.Findings))
	return nil
}

// reportTimeline shows what the timeline holds and what it rests on.
//
// The count of entries resting on a wall clock is reported rather than buried,
// because it is the one number that says how much of the timeline is placed by
// conversion instead of by a recorded instant.
func reportTimeline(pr *progress.Reporter, db *store.Store,
	manifest *workspace.Manifest) error {
	entries, wallClock, ambiguous, earliest, latest, err := db.TimelineSpan()
	if err != nil {
		return err
	}
	manifest.Counts.TimelineEntries = entries
	manifest.Counts.WallClockEntries = wallClock

	if entries == 0 {
		pr.Printf("      timeline: no timestamped record was read\n")
		return nil
	}

	span := "an unknown span"
	if earliest != nil && latest != nil {
		span = wintime.Format(*earliest) + " → " + wintime.Format(*latest)
	}
	pr.Printf("      timeline: %d entries, %s\n", entries, span)

	zone, standard, daylight, observes, found, err := db.HostTimeZone()
	if err != nil {
		return err
	}
	switch {
	case wallClock == 0:
		// Nothing to explain: every entry carries a recorded UTC instant.
	case !found:
		pr.Printf(
			"        %d entry(s) rest on local wall clock and the host time zone "+
				"was not recovered, so they have no UTC reading and are placed by "+
				"reading the wall clock as though it were UTC\n", wallClock)
	default:
		// The daylight offset is named only where the host takes it. Windows
		// stores one for every zone that has ever had daylight saving, and
		// printing it for a host that does not change its clock offered a
		// second reading of every wall clock that no evidence supports.
		if observes {
			pr.Printf(
				"        %d entry(s) rest on local wall clock, converted with the "+
					"host zone %s (standard UTC%s, daylight UTC%s)\n",
				wallClock, zone, offsetLabel(standard), offsetLabel(daylight))
		} else {
			pr.Printf(
				"        %d entry(s) rest on local wall clock, converted with the "+
					"host zone %s (UTC%s, which does not observe daylight saving)\n",
				wallClock, zone, offsetLabel(standard))
		}
		if ambiguous > 0 {
			pr.Printf(
				"        %d of them have two readings: the record does not say "+
					"which season it was written in, so both are in time_utc "+
					"and time_utc_alt\n", ambiguous)
		}
	}

	significant, err := db.Timeline(true, 8)
	if err != nil {
		return err
	}
	if len(significant) == 0 {
		return nil
	}
	pr.Printf("      first entries for tier 1 and tier 2 devices:\n")
	for _, entry := range significant {
		moment := "     (no UTC reading)"
		if entry.SortUTC != nil {
			moment = wintime.Format(*entry.SortUTC)
		}
		pr.Printf("        %s  %-20s %s\n",
			moment, truncate(entry.Event, 20), truncate(entry.Label(), 44))
	}
	pr.Printf(
		"        ... the rest in data/timeline-significant.csv, and every " +
			"entry in data/timeline.csv\n")
	return nil
}

// offsetLabel renders a bias as the offset a reader expects. Windows counts
// minutes west of UTC, so the sign is inverted to read as UTC+/-.
func offsetLabel(biasMinutes int) string {
	offset := -biasMinutes
	sign := "+"
	if offset < 0 {
		sign, offset = "-", -offset
	}
	if offset%60 == 0 {
		return fmt.Sprintf("%s%d", sign, offset/60)
	}
	return fmt.Sprintf("%s%d:%02d", sign, offset/60, offset%60)
}

// reportVolumeLinks shows each route from a volume to a device with the
// confidence it earns.
//
// A volume reached by two independent routes is shown twice on purpose.
// Agreement between routes is worth more than either alone, and collapsing them
// to one answer throws away the corroboration along with the disagreement.
func reportVolumeLinks(pr *progress.Reporter, db *store.Store) error {
	links, err := db.VolumeLinks()
	if err != nil {
		return err
	}
	if len(links) == 0 {
		return nil
	}

	pr.Printf("      volume to device links:\n")
	for _, link := range links {
		subject := link.DriveLetter
		if subject != "" {
			subject += ":"
		} else if link.VolumeLabel != "" {
			subject = "label " + link.VolumeLabel
		} else {
			subject = truncate(link.VolumeID, 24)
		}

		pr.Printf("        %-24s %-10s %-28s %s\n",
			truncate(subject, 24), link.Confidence, link.Route,
			truncate(link.DeviceInstanceID, 46))
	}

	ambiguous, err := db.AmbiguousLabels()
	if err != nil {
		return err
	}
	for label, count := range ambiguous {
		// Naming the devices would suggest a choice between them. There is
		// none: the label does not distinguish them.
		pr.Printf(
			"        note: the label %q is recorded for %d devices and so "+
				"identifies none of them\n", label, count)
	}

	return nil
}

// reportLetterActivity shows what each drive letter carried across every
// artefact that named one.
//
// Shell bags and the MRU lists record a letter and nothing else — no volume
// serial, no device — so they cannot say which device a path was on. They are
// shown by letter because that is what they said, and tying them to a device is
// the correlation phase's job.
func reportLetterActivity(pr *progress.Reporter, db *store.Store) error {
	activity, err := db.LetterActivity()
	if err != nil {
		return err
	}
	if len(activity) == 0 {
		return nil
	}

	byLetter := map[string][]store.LetterActivity{}
	var letters []string
	for _, row := range activity {
		if _, seen := byLetter[row.DriveLetter]; !seen {
			letters = append(letters, row.DriveLetter)
		}
		byLetter[row.DriveLetter] = append(byLetter[row.DriveLetter], row)
	}
	sort.Strings(letters)

	pr.Printf("      file and folder records by drive letter:\n")
	for _, letter := range letters {
		parts := make([]string, 0, len(byLetter[letter]))
		for _, row := range byLetter[letter] {
			parts = append(parts, fmt.Sprintf("%s %d", row.Artefact, row.Records))
		}
		pr.Printf("        %s: %s\n", letter, strings.Join(parts, ", "))
	}

	return nil
}

// reportAttribution shows which file records reached a device and which did
// not.
//
// Contested records are shown first and by name. A file with two candidate
// devices is the case this whole chain exists for, and burying it in a count
// would hide exactly the thing an analyst has to decide.
func reportAttribution(pr *progress.Reporter, db *store.Store) error {
	counts, err := db.AttributionCounts()
	if err != nil {
		return err
	}
	if len(counts) == 0 {
		return nil
	}

	parts := make([]string, 0, len(counts))
	for _, confidence := range []string{
		"confirmed", "strong", "probable", "possible", "unattributed",
	} {
		if counts[confidence] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", confidence, counts[confidence]))
		}
	}
	pr.Printf("      file records attributed to a device: %s\n",
		strings.Join(parts, ", "))

	contested, unattributed, err := db.Attributions()
	if err != nil {
		return err
	}

	const shown = 6
	for index, row := range contested {
		if index == 0 {
			pr.Printf(
				"      records the evidence has not settled to one device:\n")
		}
		if index == shown {
			pr.Printf("        ... %d more in data/file-attribution-summary.csv\n",
				len(contested)-shown)
			break
		}
		pr.Printf("        %-34s %-12s %d candidates, best %s\n",
			truncate(row.Path, 34), truncate(row.Artefact, 12),
			row.CandidateDevices, row.BestConfidence)
	}

	if len(unattributed) > 0 {
		// A record that reaches no device is not a parse failure. It is a path
		// on a letter with nothing tying that letter to a USB device — usually
		// the internal disk. Grouping by letter says which case it is; a bare
		// total invites it to be read as something having gone wrong.
		byLetter, err := db.UnattributedByLetter()
		if err != nil {
			return err
		}

		letters := make([]string, 0, len(byLetter))
		for letter := range byLetter {
			letters = append(letters, letter)
		}
		sort.Strings(letters)

		parts := make([]string, 0, len(letters))
		for _, letter := range letters {
			parts = append(parts, fmt.Sprintf("%s %d", letter, byLetter[letter]))
		}
		pr.Printf(
			"      %d record(s) reach no device: no USB device is linked to "+
				"their letter (%s)\n", len(unattributed), strings.Join(parts, ", "))
	}

	return nil
}

// megabytes renders a size the way the discovery line reads best: how much
// evidence there is to get through, to one decimal place.
func megabytes(bytes int64) string {
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}

func truncate(text string, size int) string {
	if len(text) <= size {
		return text
	}
	return text[:size-1] + "…"
}

// printCatalogue prints what Boobook reads from the event logs and what it
// deliberately does not. Selection decides what an analyst is shown, so it has
// to be readable without reading the source.
func printCatalogue() {
	fmt.Println("Event log selection catalogue")
	fmt.Println()

	channel := ""
	for _, rule := range eventlog.Rules() {
		if rule.Channel != channel {
			channel = rule.Channel
			fmt.Printf("\n%s\n", channel)
		}
		fmt.Printf("  %-6d %-11s %s\n", rule.EventID, rule.Kind, rule.Meaning)
		if rule.Note != "" {
			fmt.Printf("         note: %s\n", wrap(rule.Note, 9))
		}
		for _, field := range rule.Fields {
			fmt.Printf("         %-24s %-20s %s\n", field.Name, field.Role, field.Path)
		}
		if rule.NameValue {
			fmt.Printf("         (reads the EventData\\Data Name/Value form)\n")
		}
	}

	fmt.Println("\n\nConsidered and not selected")
	for _, exclusion := range eventlog.Exclusions() {
		fmt.Printf("  %s:%d\n         %s\n",
			exclusion.Channel, exclusion.EventID, wrap(exclusion.Rationale, 9))
	}
}

// printSources prints what Boobook can read and what each location yields.
//
// Deliberately readable rather than machine-parseable: this is the answer to
// "what does this tool do", asked before there is any evidence to point it at.
// The catalogue it prints derives its channel and enumerator lists from the
// code that uses them, so it cannot quietly describe a tool that no longer
// exists.
func printSources() {
	fmt.Print(bannerText())
	fmt.Println("\nEvidence sources")
	fmt.Println()
	fmt.Println("Boobook reads a mounted Windows volume or a triage collection. The")
	fmt.Println("layout is detected by probing for a Windows directory rather than by")
	fmt.Println("trusting a directory name:")
	fmt.Println()
	for _, layout := range sources.Layouts() {
		fmt.Printf("  %-26s %s\n", layout.Name, layout.Shape)
	}

	class := ""
	for _, source := range sources.All() {
		if source.Class != class {
			class = source.Class
			fmt.Printf("\n\n%s\n", class)
		}

		fmt.Printf("\n  %s\n", source.Path)
		if source.Pattern {
			// On its own line: several of these paths are long enough that a
			// trailing marker pushed the line past any sensible terminal.
			fmt.Println("      (a shape — discovery walks to find the files themselves)")
		}
		if source.Note != "" {
			fmt.Printf("      note: %s\n", wrap(source.Note, 12))
		}
		for _, yield := range source.Yields {
			fmt.Printf("    - %s\n", wrap(yield.What, 6))
			fmt.Printf("        %s\n", wrap(yield.Where, 8))
		}
	}

	fmt.Println("\n\nNot read")
	fmt.Println("\n  Named so that silence in a report is not mistaken for absence in the")
	fmt.Println("  evidence:")
	fmt.Println()
	for _, absent := range sources.NotRead() {
		fmt.Printf("    - %s\n", wrap(absent, 6))
	}
}

// wrap breaks a rationale across lines at a fixed indent.
func wrap(text string, indent int) string {
	const width = 66

	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		// Only break a line that has something on it. A registry path longer
		// than the width is one word and cannot be broken, and breaking before
		// it emitted a blank line and then overran anyway.
		if line != "" && len(line)+len(word)+1 > width {
			lines = append(lines, line)
			line = word
			continue
		}
		if line == "" {
			line = word
		} else {
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n"+strings.Repeat(" ", indent))
}

// recordEvents writes one observation per selected event record. The locator
// names the channel and the record ID, which is what an analyst types into a
// viewer to see the original.
func recordEvents(ledger *provenance.Ledger, sourceByPath map[string]string,
	records []eventlog.Record) {

	observations := make([]provenance.Observation, 0, len(records))

	for _, record := range records {
		sourceID, ok := sourceByPath[record.SourceFile]
		if !ok {
			// The file could not be hashed, so nothing read from it can be
			// attested to. Dropping it silently would be worse than losing it.
			ledger.Warn(provenance.Warning{
				Artefact: "EVTX", Path: record.SourceFile,
				Severity: "failed",
				Message: fmt.Sprintf("record %d was parsed from a file with no "+
					"source record and is not reported", record.RecordID),
			})
			continue
		}

		parts := make([]string, 0, len(record.Fields))
		for _, field := range record.Fields {
			parts = append(parts, field.Name+"="+field.Value)
		}

		timeUTC := record.TimeUTC
		observations = append(observations, provenance.Observation{
			SourceID: sourceID,
			Locator: provenance.Locator{
				Channel:       record.Channel,
				EventRecordID: record.RecordID,
			},
			Kind:         "event." + string(record.Kind),
			Field:        record.RuleID,
			Summary:      strings.Join(parts, "; "),
			Value:        record.DeviceInstanceID(),
			RawTimestamp: record.RawFileTime,
			TimeUTC:      &timeUTC,
		})
	}

	ledger.ObserveBatch(observations)
}

// eventSelection copies the parser's accounting into the manifest.
func eventSelection(stats *eventlog.Stats) *workspace.EventSelection {
	selection := &workspace.EventSelection{
		ChannelsRead:      eventlog.Channels(),
		FilesParsed:       stats.FilesParsed,
		FilesSkipped:      stats.FilesSkipped,
		BytesParsed:       stats.BytesParsed,
		BytesSkipped:      stats.BytesSkipped,
		RecordsRead:       stats.RecordsRead,
		Retained:          stats.Retained,
		FilesFailed:       stats.Failed,
		ExcludedByReason:  stats.ExcludedByReason,
		Unselected:        stats.Unselected,
		SelectedByRule:    stats.SelectedByRule,
		ChannelMismatches: stats.ChannelMismatches,
	}

	for _, fileStats := range stats.Files {
		if !fileStats.Skipped {
			continue
		}
		selection.SkippedFiles = append(selection.SkippedFiles, workspace.SkippedFile{
			Path:    fileStats.Path,
			Channel: fileStats.Channel,
			Bytes:   fileStats.Bytes,
			Reason:  fileStats.SkipReason,
			OptIn:   fileStats.OptInSkipped,
		})
	}

	return selection
}

// reportEventKinds shows the shape of what was found: arrivals and departures
// first, since those are the timeline.
func reportEventKinds(pr *progress.Reporter, records []eventlog.Record) {
	if len(records) == 0 {
		return
	}

	counts := map[eventlog.Kind]int{}
	devices := map[string]bool{}
	for _, record := range records {
		counts[record.Kind]++
		if id := record.DeviceInstanceID(); id != "" {
			devices[strings.ToUpper(id)] = true
		}
	}

	order := []eventlog.Kind{
		eventlog.KindConnect, eventlog.KindDisconnect, eventlog.KindInstall,
		eventlog.KindInventory, eventlog.KindFault, eventlog.KindOther,
	}
	parts := make([]string, 0, len(order))
	for _, kind := range order {
		if counts[kind] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", kind, counts[kind]))
		}
	}

	pr.Printf("      %s\n", strings.Join(parts, ", "))
	pr.Printf("      %d device(s) named by event evidence\n", len(devices))
}

func countChannels(records []eventlog.Record) int {
	seen := map[string]bool{}
	for _, record := range records {
		seen[record.Channel] = true
	}
	return len(seen)
}

func presence(found bool) string {
	if found {
		return "present"
	}
	return "absent"
}

// missingKind pulls the artefact kind out of a "KIND (path)" missing entry.
func missingKind(missing string) string {
	if index := strings.Index(missing, " ("); index > 0 {
		return missing[:index]
	}
	return missing
}

// missingPath is the path out of a "KIND (path)" entry.
//
// Discovery writes the pair as one string because the narration prints it as
// one. The ledger stores the two apart, and passing the whole string as the
// path put "SETUPAPI (C:\Source\HOST\Windows\INF\setupapi.dev.log)" in a column
// beside a column already reading SETUPAPI — and, being no longer a path, it
// escaped the trim that renders every other path relative to the evidence root.
func missingPath(missing string) string {
	open := strings.Index(missing, " (")
	if open < 0 || !strings.HasSuffix(missing, ")") {
		return missing
	}
	return missing[open+2 : len(missing)-1]
}

// discoveryFailureMessage says what was not looked at and what that costs.
//
// The wording matters more than usual here. A reader meets this beside genuine
// absences, and the whole point is that the two are different: an artefact that
// was not there is a fact about the host, and one that could not be read is a
// fact about the collection, which leaves a hole where evidence may sit.
func discoveryFailureMessage(failure evidence.DiscoveryFailure) string {
	var what string
	switch failure.Why {
	case evidence.FailureBoundaryRefused:
		what = "this path resolves outside the evidence root, so it was " +
			"refused rather than followed"
	case evidence.FailureWalkFailed:
		what = "this directory could not be walked past this point, so " +
			"anything beyond it was not seen"
	default:
		what = "this could not be read"
	}
	if failure.Detail != "" {
		what += " (" + failure.Detail + ")"
	}
	return what + "; nothing here was examined, so silence about " +
		failure.Kind + " evidence in this place means nobody looked rather " +
		"than that there was nothing to find"
}
