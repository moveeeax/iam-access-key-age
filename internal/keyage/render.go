package keyage

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
)

// WriteTable prints findings as an aligned table, oldest key first.
func WriteTable(w io.Writer, findings []Finding) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "USER\tACCESS KEY\tSTATUS\tAGE(d)\tLAST USED\tREASON")
	for _, f := range findings {
		last := "never"
		if f.LastUsedDays != nil {
			last = fmt.Sprintf("%dd ago", *f.LastUsedDays)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			f.User, f.AccessKeyID, f.Status, f.AgeDays, last, f.Reason)
	}
	tw.Flush()
}

// WriteJSON prints findings as a JSON array following the documented schema.
func WriteJSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if findings == nil {
		findings = []Finding{}
	}
	return enc.Encode(findings)
}
