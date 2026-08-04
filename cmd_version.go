package main

import (
	"flag"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

type versionReport struct {
	Version   string `json:"version" yaml:"version"`
	Commit    string `json:"commit" yaml:"commit"`
	BuildDate string `json:"build_date" yaml:"build_date"`
	GoVersion string `json:"go_version" yaml:"go_version"`
	OS        string `json:"os" yaml:"os"`
	Arch      string `json:"arch" yaml:"arch"`
}

func cmdVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	yamlOut := fs.Bool("yaml", false, "emit YAML")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		fatal("usage: mailops version [--json|--yaml]")
	}
	format, err := resolveOutput(*jsonOut, *yamlOut, false)
	if err != nil {
		fatal(err.Error())
	}
	report := buildVersionReport()
	switch format {
	case outputJSON:
		printJSON(report)
	case outputYAML:
		printYAMLValue(report)
	default:
		fmt.Printf("mailops %s (%s, built %s, %s %s/%s)\n", report.Version, report.Commit, report.BuildDate, report.GoVersion, report.OS, report.Arch)
	}
}

func buildVersionReport() versionReport {
	report := versionReport{
		Version:   version,
		Commit:    commit,
		BuildDate: date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if report.Version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			report.Version = strings.TrimPrefix(info.Main.Version, "v")
		}
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if report.Commit == "unknown" && setting.Value != "" {
					report.Commit = setting.Value
				}
			case "vcs.time":
				if report.BuildDate == "unknown" && setting.Value != "" {
					report.BuildDate = setting.Value
				}
			}
		}
	}
	return report
}
