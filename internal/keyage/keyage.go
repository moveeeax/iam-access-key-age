// Package keyage evaluates AWS IAM access keys for age and staleness.
//
// It is deliberately free of any AWS SDK dependency: callers convert whatever
// their IAM client returns into a slice of Key values, and this package decides
// which keys are old, unused, and whether the run should gate CI. That keeps the
// judgement logic unit-testable without touching a live AWS account.
package keyage

import (
	"sort"
	"time"
)

// Key is a single IAM access key, already fetched from AWS.
type Key struct {
	User        string
	AccessKeyID string
	Status      string     // "Active" or "Inactive"
	Created     time.Time  // CreateDate
	LastUsed    *time.Time // nil means the key has never been used
}

// Config controls what counts as old, what counts as unused, and which of
// those trips a non-zero exit code.
type Config struct {
	MaxAgeDays int       // Active keys older than this are flagged "old"
	StaleDays  int       // Active keys not used within this window are "unused"
	FailOn     string    // "none", "old", or "unused"
	Now        time.Time // evaluation time; injected so tests are deterministic
}

// Finding is the per-key verdict. JSON tags match the documented --json schema.
type Finding struct {
	User         string    `json:"user"`
	AccessKeyID  string    `json:"access_key_id"`
	Status       string    `json:"status"`
	Created      time.Time `json:"created"`
	AgeDays      int       `json:"age_days"`
	LastUsedDays *int      `json:"last_used_days"` // nil when never used
	Reason       string    `json:"reason"`

	old    bool
	unused bool
}

// Old reports whether the key breached the max-age threshold.
func (f Finding) Old() bool { return f.old }

// Unused reports whether an active key is stale (never used or beyond StaleDays).
func (f Finding) Unused() bool { return f.unused }

func daysBetween(a, b time.Time) int {
	return int(a.Sub(b).Hours() / 24)
}

// Evaluate turns raw keys into findings, sorted oldest key first.
func Evaluate(keys []Key, cfg Config) []Finding {
	out := make([]Finding, 0, len(keys))
	for _, k := range keys {
		f := Finding{
			User:        k.User,
			AccessKeyID: k.AccessKeyID,
			Status:      k.Status,
			Created:     k.Created,
			AgeDays:     daysBetween(cfg.Now, k.Created),
		}

		active := k.Status == "Active"

		if k.LastUsed != nil {
			d := daysBetween(cfg.Now, *k.LastUsed)
			f.LastUsedDays = &d
		}

		if active && f.AgeDays > cfg.MaxAgeDays {
			f.old = true
		}
		if active {
			if k.LastUsed == nil {
				// Never used, but only stale once the key itself is old enough
				// to have had a chance to be used.
				if f.AgeDays > cfg.StaleDays {
					f.unused = true
				}
			} else if *f.LastUsedDays > cfg.StaleDays {
				f.unused = true
			}
		}

		f.Reason = reason(f, active)
		out = append(out, f)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Created.Before(out[j].Created)
	})
	return out
}

func reason(f Finding, active bool) string {
	if !active {
		return "inactive"
	}
	switch {
	case f.old && f.unused:
		return "old+unused"
	case f.old:
		return "old"
	case f.unused:
		return "unused"
	default:
		return "ok"
	}
}

// Breaches returns the findings that should turn the exit code red under cfg.FailOn.
// "unused" is the stricter gate: it trips on both old and unused keys.
func Breaches(findings []Finding, failOn string) []Finding {
	var bad []Finding
	for _, f := range findings {
		switch failOn {
		case "old":
			if f.old {
				bad = append(bad, f)
			}
		case "unused":
			if f.old || f.unused {
				bad = append(bad, f)
			}
		}
	}
	return bad
}

// ValidFailOn reports whether v is an accepted --fail-on value.
func ValidFailOn(v string) bool {
	return v == "none" || v == "old" || v == "unused"
}
