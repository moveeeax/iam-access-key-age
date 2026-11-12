package keyage

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// dateLayout is the only accepted form for an exception's expires field.
const dateLayout = "2006-01-02"

// Exception suppresses the gate for a known key (a break-glass key, a vendor
// integration) until a fixed date. It matches by user, by access key ID, or by
// both; when both are set a key must match both.
type Exception struct {
	User        string `yaml:"user"`
	AccessKeyID string `yaml:"access_key_id"`
	Reason      string `yaml:"reason"`
	Expires     string `yaml:"expires"` // YYYY-MM-DD, valid through the end of that day (UTC)

	expires time.Time // start of the day after Expires, UTC
}

// exceptionsFile is the on-disk layout of an --exceptions file.
type exceptionsFile struct {
	Exceptions []Exception `yaml:"exceptions"`
}

// ExceptionMatch is the exception attached to a finding. JSON tags match the
// documented --json schema.
type ExceptionMatch struct {
	User             string `json:"user,omitempty"`
	AccessKeyID      string `json:"access_key_id,omitempty"`
	Reason           string `json:"reason"`
	Expires          string `json:"expires"`
	Expired          bool   `json:"expired"`
	SuppressedReason string `json:"suppressed_reason"` // the reason the key would have had without the exception
}

// LoadExceptions parses an exceptions file. Every entry needs a user or an
// access key ID, a non-empty reason, and an expires date; unknown fields are
// rejected so a typo cannot silently widen or drop an exception.
func LoadExceptions(r io.Reader) ([]Exception, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f exceptionsFile
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}
	for i := range f.Exceptions {
		e := &f.Exceptions[i]
		e.User = strings.TrimSpace(e.User)
		e.AccessKeyID = strings.TrimSpace(e.AccessKeyID)
		e.Reason = strings.TrimSpace(e.Reason)
		e.Expires = strings.TrimSpace(e.Expires)
		where := fmt.Sprintf("exception %d", i+1)
		if e.User == "" && e.AccessKeyID == "" {
			return nil, fmt.Errorf("%s: set user or access_key_id", where)
		}
		if e.Reason == "" {
			return nil, fmt.Errorf("%s: reason is required", where)
		}
		if e.Expires == "" {
			return nil, fmt.Errorf("%s: expires is required (YYYY-MM-DD)", where)
		}
		d, err := time.Parse(dateLayout, e.Expires)
		if err != nil {
			return nil, fmt.Errorf("%s: expires %q is not a YYYY-MM-DD date", where, e.Expires)
		}
		e.expires = d.AddDate(0, 0, 1)
	}
	return f.Exceptions, nil
}

// Expired reports whether the exception no longer applies at now. An exception
// that expires on 2026-12-31 still holds for the whole of that day in UTC.
func (e Exception) Expired(now time.Time) bool {
	return !now.Before(e.expiresAt())
}

func (e Exception) expiresAt() time.Time {
	if !e.expires.IsZero() {
		return e.expires
	}
	// Built in code rather than loaded from a file; an unparsable date counts
	// as already expired so it can never suppress the gate.
	d, err := time.Parse(dateLayout, e.Expires)
	if err != nil {
		return time.Time{}
	}
	return d.AddDate(0, 0, 1)
}

// Label names the exception in warnings.
func (e Exception) Label() string {
	switch {
	case e.User != "" && e.AccessKeyID != "":
		return fmt.Sprintf("user %s, key %s", e.User, e.AccessKeyID)
	case e.AccessKeyID != "":
		return "key " + e.AccessKeyID
	default:
		return "user " + e.User
	}
}

func (e Exception) matches(k Key) bool {
	if e.User != "" && e.User != k.User {
		return false
	}
	if e.AccessKeyID != "" && e.AccessKeyID != k.AccessKeyID {
		return false
	}
	return true
}

// pick returns the exception that applies to k: the first unexpired match in
// file order, otherwise the first expired match, otherwise nil.
func pick(exceptions []Exception, k Key, now time.Time) *Exception {
	var expired *Exception
	for i := range exceptions {
		e := &exceptions[i]
		if !e.matches(k) {
			continue
		}
		if !e.Expired(now) {
			return e
		}
		if expired == nil {
			expired = e
		}
	}
	return expired
}

// ExceptionWarnings lists exceptions that need attention: every expired entry
// (it gates again) and every entry that matched no key in this run (it is dead
// weight, or a typo in the user or key ID).
func ExceptionWarnings(exceptions []Exception, keys []Key, now time.Time) []string {
	var out []string
	for _, e := range exceptions {
		if e.Expired(now) {
			out = append(out, fmt.Sprintf("exception for %s expired on %s and no longer suppresses the gate", e.Label(), e.Expires))
			continue
		}
		matched := false
		for _, k := range keys {
			if e.matches(k) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, fmt.Sprintf("exception for %s matches no access key", e.Label()))
		}
	}
	return out
}
