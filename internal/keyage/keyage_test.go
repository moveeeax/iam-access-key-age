package keyage

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// now is a fixed evaluation instant so every age is deterministic.
var now = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func daysAgo(d int) time.Time    { return now.AddDate(0, 0, -d) }
func ptr(t time.Time) *time.Time { return &t }

func cfg() Config {
	return Config{MaxAgeDays: 90, StaleDays: 90, FailOn: "old", Now: now}
}

func find(findings []Finding, id string) Finding {
	for _, f := range findings {
		if f.AccessKeyID == id {
			return f
		}
	}
	panic("no finding for " + id)
}

func TestEvaluateReasons(t *testing.T) {
	keys := []Key{
		{User: "alice", AccessKeyID: "OLD", Status: "Active", Created: daysAgo(200), LastUsed: ptr(daysAgo(3))},
		{User: "bob", AccessKeyID: "FRESH", Status: "Active", Created: daysAgo(10), LastUsed: ptr(daysAgo(1))},
		{User: "carol", AccessKeyID: "INACTIVE", Status: "Inactive", Created: daysAgo(500), LastUsed: nil},
		{User: "dave", AccessKeyID: "NEVER", Status: "Active", Created: daysAgo(120), LastUsed: nil},
	}
	f := Evaluate(keys, cfg())

	if got := find(f, "OLD").Reason; got != "old" {
		t.Errorf("OLD reason = %q, want old", got)
	}
	if got := find(f, "FRESH").Reason; got != "ok" {
		t.Errorf("FRESH reason = %q, want ok", got)
	}
	if got := find(f, "INACTIVE").Reason; got != "inactive" {
		t.Errorf("INACTIVE reason = %q, want inactive", got)
	}
	// Never used AND older than the stale window -> both flags.
	if got := find(f, "NEVER").Reason; got != "old+unused" {
		t.Errorf("NEVER reason = %q, want old+unused", got)
	}
}

func TestNeverUsedButFreshIsNotUnused(t *testing.T) {
	// A brand-new key that has not been used yet must not be flagged unused.
	keys := []Key{
		{User: "eve", AccessKeyID: "NEW", Status: "Active", Created: daysAgo(2), LastUsed: nil},
	}
	f := Evaluate(keys, cfg())
	if find(f, "NEW").Reason != "ok" {
		t.Errorf("fresh never-used key = %q, want ok", find(f, "NEW").Reason)
	}
	if find(f, "NEW").LastUsedDays != nil {
		t.Error("never-used key should have nil LastUsedDays")
	}
}

func TestSortedOldestFirst(t *testing.T) {
	keys := []Key{
		{User: "a", AccessKeyID: "MID", Status: "Active", Created: daysAgo(50)},
		{User: "b", AccessKeyID: "OLDEST", Status: "Active", Created: daysAgo(300)},
		{User: "c", AccessKeyID: "NEWEST", Status: "Active", Created: daysAgo(1)},
	}
	f := Evaluate(keys, cfg())
	order := []string{f[0].AccessKeyID, f[1].AccessKeyID, f[2].AccessKeyID}
	want := []string{"OLDEST", "MID", "NEWEST"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

func TestBreachesFailOnOld(t *testing.T) {
	keys := []Key{
		{User: "alice", AccessKeyID: "OLD", Status: "Active", Created: daysAgo(200), LastUsed: ptr(daysAgo(3))},
		{User: "bob", AccessKeyID: "FRESH", Status: "Active", Created: daysAgo(10), LastUsed: ptr(daysAgo(1))},
	}
	f := Evaluate(keys, cfg())
	if b := Breaches(f, "old"); len(b) != 1 || b[0].AccessKeyID != "OLD" {
		t.Fatalf("fail-on old breaches = %+v, want just OLD", b)
	}
	if b := Breaches(f, "none"); len(b) != 0 {
		t.Fatalf("fail-on none breaches = %+v, want none", b)
	}
}

func TestBreachesFailOnUnusedIsStricter(t *testing.T) {
	keys := []Key{
		{User: "dave", AccessKeyID: "NEVER", Status: "Active", Created: daysAgo(120), LastUsed: nil},
		{User: "erin", AccessKeyID: "STALE", Status: "Active", Created: daysAgo(30), LastUsed: ptr(daysAgo(200))},
	}
	f := Evaluate(keys, cfg())
	b := Breaches(f, "unused")
	if len(b) != 2 {
		t.Fatalf("fail-on unused breaches = %d, want 2", len(b))
	}
	// STALE is recent-created but long-unused: old=false, unused=true.
	if find(f, "STALE").Old() {
		t.Error("STALE should not be old")
	}
	if !find(f, "STALE").Unused() {
		t.Error("STALE should be unused")
	}
	// Under fail-on old, STALE alone must not trip the gate.
	if len(Breaches([]Finding{find(f, "STALE")}, "old")) != 0 {
		t.Error("STALE should not breach under fail-on old")
	}
}

func TestJSONSchema(t *testing.T) {
	keys := []Key{
		{User: "dave", AccessKeyID: "NEVER", Status: "Active", Created: daysAgo(120), LastUsed: nil},
	}
	f := Evaluate(keys, cfg())
	var buf bytes.Buffer
	if err := WriteJSON(&buf, f); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	rec := arr[0]
	for _, k := range []string{"user", "access_key_id", "status", "created", "age_days", "last_used_days", "reason"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("json missing key %q", k)
		}
	}
	if rec["last_used_days"] != nil {
		t.Errorf("never-used last_used_days = %v, want null", rec["last_used_days"])
	}
}

func TestTableSortedAndHeadered(t *testing.T) {
	keys := []Key{
		{User: "a", AccessKeyID: "MID", Status: "Active", Created: daysAgo(50)},
		{User: "b", AccessKeyID: "OLDEST", Status: "Active", Created: daysAgo(300), LastUsed: ptr(daysAgo(2))},
	}
	f := Evaluate(keys, cfg())
	var buf bytes.Buffer
	WriteTable(&buf, f)
	out := buf.String()
	if !strings.Contains(out, "USER") || !strings.Contains(out, "REASON") {
		t.Error("table missing header")
	}
	if strings.Index(out, "OLDEST") > strings.Index(out, "MID") {
		t.Error("table not sorted oldest first")
	}
	if !strings.Contains(out, "2d ago") {
		t.Error("table should render last-used age")
	}
}

func TestValidFailOn(t *testing.T) {
	for _, v := range []string{"none", "old", "unused"} {
		if !ValidFailOn(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	if ValidFailOn("bogus") {
		t.Error("bogus should be invalid")
	}
}
