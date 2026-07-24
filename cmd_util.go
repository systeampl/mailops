package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type outputFormat string

const (
	outputText outputFormat = "text"
	outputJSON outputFormat = "json"
	outputYAML outputFormat = "yaml"
	outputProm outputFormat = "prom"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

func resolveOutput(jsonOut, yamlOut, promOut bool) (outputFormat, error) {
	count := 0
	if jsonOut {
		count++
	}
	if yamlOut {
		count++
	}
	if promOut {
		count++
	}
	if count > 1 {
		return "", fmt.Errorf("--json, --yaml and --prom are mutually exclusive")
	}
	switch {
	case jsonOut:
		return outputJSON, nil
	case yamlOut:
		return outputYAML, nil
	case promOut:
		return outputProm, nil
	default:
		return outputText, nil
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}

func boolInt(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func failOnStatus(status, failOn string) bool {
	rank := map[string]int{"ok": 0, "info": 0, "warn": 1, "critical": 2, "error": 3}
	threshold, ok := rank[strings.ToLower(strings.TrimSpace(failOn))]
	if !ok {
		threshold = rank["critical"]
	}
	return rank[status] >= threshold && rank[status] > 0
}

func validFailOn(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "warn", "critical", "error":
		return true
	default:
		return false
	}
}

func normalizeFlagArgs(args []string, takesValue map[string]bool) []string {
	flags := make([]string, 0, len(args))
	positionals := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		name := arg
		if eq := strings.IndexByte(arg, '='); eq >= 0 {
			name = arg[:eq]
		}
		if takesValue[name] && !strings.Contains(arg, "=") && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func ttyStdout() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func colorEnabled() bool {
	return ttyStdout() && strings.TrimSpace(os.Getenv("NO_COLOR")) == ""
}

func colorize(s, code string) string {
	if !colorEnabled() {
		return s
	}
	return code + s + "\x1b[0m"
}

func statusColor(status string) string {
	switch strings.ToLower(status) {
	case "ok", "valid", "present", "confirmed", "enforce", "pass", "yes":
		return colorize(status, "\x1b[32m")
	case "info":
		return colorize(status, "\x1b[36m")
	case "warn", "warning", "missing", "none", "testing", "not confirmed":
		return colorize(status, "\x1b[33m")
	case "critical", "error", "fail", "failed", "invalid", "listed", "no":
		return colorize(status, "\x1b[31m")
	default:
		return status
	}
}

func padRule(width int) string {
	if width <= 0 {
		return ""
	}
	return strings.Repeat("─", width)
}

func renderTable(headers []string, rows [][]string) {
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && visibleLen(cell) > widths[i] {
				widths[i] = visibleLen(cell)
			}
		}
	}
	for i, h := range headers {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Printf("%-*s", widths[i], h)
	}
	fmt.Println()
	for i, w := range widths {
		if i > 0 {
			fmt.Print("  ")
		}
		fmt.Print(padRule(w))
	}
	fmt.Println()
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				fmt.Print("  ")
			}
			fmt.Printf("%-*s", widths[i]+len(cell)-visibleLen(cell), cell)
		}
		fmt.Println()
	}
}

func visibleLen(s string) int {
	return len(ansiPattern.ReplaceAllString(s, ""))
}

func yesNo(ok bool) string {
	if ok {
		return "yes"
	}
	return "no"
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
