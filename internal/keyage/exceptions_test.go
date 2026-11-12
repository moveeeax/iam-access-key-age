package keyage

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func mustLoad(t *testing.T, src string) []Exception {
	t.Helper()
	exs, err := LoadExceptions(strings.NewReader(src))
	if err != nil {
		t.Fatalf("LoadExceptions: %v", err)
	}
	return exs
}

func TestLoadExceptions(t *testing.T) {
	exs := mustLoad(t, `
exceptions:
  - user: break-glass
    reason: emergency root-equivalent access, sealed in the safe
    expires: 2026-12-31
  - access_key_id: AKIAVENDOR0000000001
    reason: vendor cannot rotate before their Q1 release
    expires: "2027-01-15"
`)
	if len(exs) != 2 {
		t.Fatalf("got %d exceptions, want 2", len(exs))
	}
	if exs[0].User != "break-glass" || exs[0].Expires != "2026-12-31" {
		t.Errorf("first exception = %+v", exs[0])
	}
	if exs[1].AccessKeyID != "AKIAVENDOR0000000001" || exs[1].Expires != "2027-01-15" {
		t.Errorf("second exception = %+v", exs[1])
	}
}

func TestLoadExceptionsEmpty(t *testing.T) {
	if exs := mustLoad(t, ""); len(exs) != 0 {
		t.Errorf("empty file gave %d exceptions", len(exs))
	}
}

func TestLoadExceptionsRejectsBadEntries(t *testing.T) {
	cases := map[string]string{
		"no target":     "exceptions:\n  - reason: x\n    expires: 2026-12-31\n",
		"no reason":     "exceptions:\n  - user: a\n    expires: 2026-12-31\n",
		"no expires":    "exceptions:\n  - user: a\n    reason: x\n",
		"bad date":      "exceptions:\n  - user: a\n    reason: x\n    expires: 31/12/2026\n",
		"unknown field": "exceptions:\n  - user: a\n    reason: x\n    expire: 2026-12-31\n",
		"unknown top":   "exception:\n  - user: a\n    reason: x\n    expires: 2026-12-31\n",
	}
	for name, src := range cases {
		if _, err := LoadExceptions(strings.NewReader(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestExceptionExpiresAtEndOfDay(t *testing.T) {
	exs := mustLoad(t, "exceptions:\n  - user: a\n    reason: x\n    expires: 2026-08-27\n")
	e := exs[0]
	// now is 2026-08-27 12:00 UTC: the expiry day itself still counts.
	if e.Expired(now) {
		t.Error("exception should hold through its expires day")
	}
	if !e.Expired(time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)) {
		t.Error("exception should lapse at the start of the next day")
	}
}

func TestExceptionSuppressesGate(t *testing.T) {
	keys := []Key{
		{User: "break-glass", AccessKeyID: "BG", Status: "Active", Created: daysAgo(400), LastUsed: nil},
		{User: "alice", AccessKeyID: "OLD", Status: "Active", Created: daysAgo(200), LastUsed: ptr(daysAgo(3))},
	}
	c := cfg()
	c.Exceptions = mustLoad(t, "exceptions:\n  - user: break-glass\n    reason: sealed\n    expires: 2026-12-31\n")
	f := Evaluate(keys, c)

	bg := find(f, "BG")
	if bg.Reason != "excepted" || !bg.Excepted() {
		t.Errorf("BG reason = %q excepted=%v, want excepted", bg.Reason, bg.Excepted())
	}
	if !bg.Old() || !bg.Unused() {
		t.Error("an exception must not hide the underlying old/unused flags")
	}
	if bg.Exception == nil || bg.Exception.SuppressedReason != "old+unused" || bg.Exception.Expired {
		t.Errorf("BG exception = %+v", bg.Exception)
	}
	for _, failOn := range []string{"old", "unused"} {
		b := Breaches(f, failOn)
		if len(b) != 1 || b[0].AccessKeyID != "OLD" {
			t.Errorf("fail-on %s breaches = %+v, want just OLD", failOn, b)
		}
	}
}

func TestExpiredExceptionGatesAgain(t *testing.T) {
	keys := []Key{
		{User: "vendor", AccessKeyID: "VENDOR", Status: "Active", Created: daysAgo(200), LastUsed: ptr(daysAgo(1))},
	}
	c := cfg()
	c.Exceptions = mustLoad(t, "exceptions:\n  - access_key_id: VENDOR\n    reason: vendor\n    expires: 2026-08-01\n")
	f := Evaluate(keys, c)

	v := find(f, "VENDOR")
	if v.Reason != "old" || v.Excepted() {
		t.Errorf("VENDOR reason = %q excepted=%v, want old", v.Reason, v.Excepted())
	}
	if v.Exception == nil || !v.Exception.Expired {
		t.Errorf("expired exception should stay attached, got %+v", v.Exception)
	}
	if b := Breaches(f, "old"); len(b) != 1 {
		t.Errorf("expired exception should gate, breaches = %+v", b)
	}
	w := ExceptionWarnings(c.Exceptions, keys, now)
	if len(w) != 1 || !strings.Contains(w[0], "expired on 2026-08-01") {
		t.Errorf("warnings = %v, want one expiry warning", w)
	}
}

func TestExceptionMatchesUserAndKeyTogether(t *testing.T) {
	keys := []Key{
		{User: "svc", AccessKeyID: "A", Status: "Active", Created: daysAgo(200)},
		{User: "svc", AccessKeyID: "B", Status: "Active", Created: daysAgo(200)},
		{User: "other", AccessKeyID: "A2", Status: "Active", Created: daysAgo(200)},
	}
	c := cfg()
	c.Exceptions = mustLoad(t, "exceptions:\n  - user: svc\n    access_key_id: A\n    reason: x\n    expires: 2026-12-31\n")
	f := Evaluate(keys, c)
	if find(f, "A").Reason != "excepted" {
		t.Error("A should be excepted")
	}
	if find(f, "B").Reason == "excepted" || find(f, "B").Exception != nil {
		t.Error("B belongs to the same user but a different key; it must not match")
	}
}

func TestUnexpiredExceptionWinsOverExpired(t *testing.T) {
	keys := []Key{{User: "svc", AccessKeyID: "K", Status: "Active", Created: daysAgo(200)}}
	c := cfg()
	c.Exceptions = mustLoad(t, `
exceptions:
  - user: svc
    reason: first window
    expires: 2026-01-31
  - access_key_id: K
    reason: extended
    expires: 2026-12-31
`)
	k := find(Evaluate(keys, c), "K")
	if k.Reason != "excepted" || k.Exception.Reason != "extended" {
		t.Errorf("K = %q via %+v, want excepted via the unexpired entry", k.Reason, k.Exception)
	}
}

func TestExceptionOnHealthyKeyDoesNotChangeReason(t *testing.T) {
	keys := []Key{{User: "svc", AccessKeyID: "K", Status: "Active", Created: daysAgo(5), LastUsed: ptr(daysAgo(1))}}
	c := cfg()
	c.Exceptions = mustLoad(t, "exceptions:\n  - user: svc\n    reason: x\n    expires: 2026-12-31\n")
	k := find(Evaluate(keys, c), "K")
	if k.Reason != "ok" || k.Excepted() || k.Exception == nil {
		t.Errorf("healthy key = %q excepted=%v exception=%v, want ok with exception attached", k.Reason, k.Excepted(), k.Exception)
	}
}

func TestWarningForUnmatchedException(t *testing.T) {
	keys := []Key{{User: "alice", AccessKeyID: "K", Status: "Active", Created: daysAgo(5)}}
	exs := mustLoad(t, "exceptions:\n  - user: alcie\n    reason: typo\n    expires: 2026-12-31\n  - user: alice\n    reason: x\n    expires: 2026-12-31\n")
	w := ExceptionWarnings(exs, keys, now)
	if len(w) != 1 || !strings.Contains(w[0], "user alcie matches no access key") {
		t.Errorf("warnings = %v, want one unmatched warning for alcie", w)
	}
}

func TestExceptionJSONAndTable(t *testing.T) {
	keys := []Key{
		{User: "break-glass", AccessKeyID: "BG", Status: "Active", Created: daysAgo(400)},
		{User: "bob", AccessKeyID: "FRESH", Status: "Active", Created: daysAgo(10), LastUsed: ptr(daysAgo(1))},
	}
	c := cfg()
	c.Exceptions = mustLoad(t, "exceptions:\n  - user: break-glass\n    reason: sealed\n    expires: 2026-12-31\n")
	f := Evaluate(keys, c)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, f); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &arr); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	for _, rec := range arr {
		switch rec["access_key_id"] {
		case "BG":
			exc, ok := rec["exception"].(map[string]any)
			if !ok {
				t.Fatalf("BG exception = %v, want object", rec["exception"])
			}
			want := map[string]any{"user": "break-glass", "reason": "sealed", "expires": "2026-12-31", "expired": false, "suppressed_reason": "old+unused"}
			for k, v := range want {
				if exc[k] != v {
					t.Errorf("exception.%s = %v, want %v", k, exc[k], v)
				}
			}
			if _, ok := exc["access_key_id"]; ok {
				t.Error("unset access_key_id should be omitted from the exception object")
			}
		case "FRESH":
			if _, ok := rec["exception"]; ok {
				t.Error("keys without an exception should not carry an exception field")
			}
		}
	}

	buf.Reset()
	WriteTable(&buf, f)
	if !strings.Contains(buf.String(), "excepted (old+unused, until 2026-12-31)") {
		t.Errorf("table should show the exception window:\n%s", buf.String())
	}
}

func TestExampleExceptionsFileLoads(t *testing.T) {
	f, err := os.Open("../../examples/exceptions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	exs, err := LoadExceptions(f)
	if err != nil {
		t.Fatalf("examples/exceptions.yaml: %v", err)
	}
	if len(exs) == 0 {
		t.Error("example file should contain exceptions")
	}
}
