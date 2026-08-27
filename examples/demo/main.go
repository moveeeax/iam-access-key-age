// Command demo renders iam-access-key-age against an in-memory set of keys, so
// you can see the table and JSON output without touching a live AWS account.
//
//	go run ./examples/demo
package main

import (
	"os"
	"time"

	"github.com/moveeeax/iam-access-key-age/internal/keyage"
)

func main() {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	day := func(d int) time.Time { return now.AddDate(0, 0, -d) }
	at := func(t time.Time) *time.Time { return &t }

	keys := []keyage.Key{
		{User: "ci-deployer", AccessKeyID: "AKIAOLD0000000000001", Status: "Active", Created: day(412), LastUsed: at(day(2))},
		{User: "legacy-backup", AccessKeyID: "AKIANEVER000000000002", Status: "Active", Created: day(160), LastUsed: nil},
		{User: "app-runtime", AccessKeyID: "AKIASTALE00000000003", Status: "Active", Created: day(20), LastUsed: at(day(140))},
		{User: "developer-jane", AccessKeyID: "AKIAFRESH00000000004", Status: "Active", Created: day(9), LastUsed: at(day(1))},
		{User: "old-rotated", AccessKeyID: "AKIAINACT00000000005", Status: "Inactive", Created: day(900), LastUsed: at(day(300))},
	}

	cfg := keyage.Config{MaxAgeDays: 90, StaleDays: 90, FailOn: "old", Now: now}
	findings := keyage.Evaluate(keys, cfg)

	keyage.WriteTable(os.Stdout, findings)
	os.Stdout.WriteString("\n")
	_ = keyage.WriteJSON(os.Stdout, findings)
}
