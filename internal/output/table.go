package output

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/internal/finding"
)

func WriteTable(w io.Writer, findings []finding.Finding) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE ID\tFILE\tLINE\tTITLE")
	fmt.Fprintln(tw, strings.Repeat("-", 8)+"\t"+strings.Repeat("-", 10)+"\t"+strings.Repeat("-", 40)+"\t"+strings.Repeat("-", 4)+"\t"+strings.Repeat("-", 50))
	for _, f := range findings {
		line := "-"
		if f.LineStart > 0 {
			line = fmt.Sprintf("%d", f.LineStart)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			f.Severity.String(),
			f.RuleID,
			truncate(f.FilePath, 40),
			line,
			truncate(f.Title, 50),
		)
	}
	return tw.Flush()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return "..." + s[len(s)-max+3:]
}
