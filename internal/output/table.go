package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func severityColor(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return colorRed + colorBold
	case finding.SeverityHigh:
		return colorYellow
	case finding.SeverityMedium:
		return colorCyan
	case finding.SeverityLow:
		return colorWhite
	default:
		return colorGray
	}
}

func WriteTable(w io.Writer, findings []finding.Finding) error {
	color := isTerminal()

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE ID\tFILE\tLINE\tTITLE")
	fmt.Fprintln(tw, strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 40)+"\t"+strings.Repeat("-", 4)+"\t"+strings.Repeat("-", 50))

	counts := make(map[finding.Severity]int)
	for _, f := range findings {
		counts[f.Severity]++
		line := "-"
		if f.LineStart > 0 {
			line = fmt.Sprintf("%d", f.LineStart)
		}
		sev := f.Severity.String()
		if color {
			sev = severityColor(f.Severity) + sev + colorReset
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			sev,
			f.RuleID,
			truncate(f.FilePath, 40),
			line,
			truncate(f.Title, 50),
		)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	total := len(findings)
	if total == 0 {
		fmt.Fprintln(w, "\nNo findings.")
		return nil
	}

	parts := []string{}
	for _, sev := range []finding.Severity{
		finding.SeverityCritical,
		finding.SeverityHigh,
		finding.SeverityMedium,
		finding.SeverityLow,
		finding.SeverityInfo,
	} {
		if n := counts[sev]; n > 0 {
			label := fmt.Sprintf("%d %s", n, sev.String())
			if color {
				label = severityColor(sev) + label + colorReset
			}
			parts = append(parts, label)
		}
	}
	summary := fmt.Sprintf("\n%d finding(s): %s", total, strings.Join(parts, ", "))
	fmt.Fprintln(w, summary)
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}
