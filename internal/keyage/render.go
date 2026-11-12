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
			f.User, f.AccessKeyID, f.Status, f.AgeDays, last, tableReason(f))
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

// tableReason adds the exception's state to the reason column: when a key is
// excepted, until when; when its exception lapsed, since when.
func tableReason(f Finding) string {
	switch {
	case f.Exception == nil:
		return f.Reason
	case f.excepted:
		return fmt.Sprintf("excepted (%s, until %s)", f.Exception.SuppressedReason, f.Exception.Expires)
	case f.Exception.Expired && (f.old || f.unused):
		return fmt.Sprintf("%s (exception expired %s)", f.Reason, f.Exception.Expires)
	default:
		return f.Reason
	}
}
