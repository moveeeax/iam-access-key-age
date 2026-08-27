// Command iam-access-key-age flags stale or never-used AWS IAM access keys and
// exits non-zero so it can gate a CI pipeline.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/moveeeax/iam-access-key-age/internal/keyage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "iam-access-key-age:", err)
		os.Exit(2)
	}
}

func run() error {
	var (
		maxAge    = flag.Int("max-age", 90, "flag active keys older than this many days")
		staleDays = flag.Int("stale-days", 90, "flag active keys not used within this many days")
		failOn    = flag.String("fail-on", "old", "what turns the exit code red: none|old|unused")
		asJSON    = flag.Bool("json", false, "emit JSON instead of a table")
	)
	flag.Parse()

	if !keyage.ValidFailOn(*failOn) {
		return fmt.Errorf("invalid --fail-on %q: want none, old, or unused", *failOn)
	}

	ctx := context.Background()
	keys, err := collect(ctx)
	if err != nil {
		return err
	}

	cfg := keyage.Config{
		MaxAgeDays: *maxAge,
		StaleDays:  *staleDays,
		FailOn:     *failOn,
		Now:        time.Now().UTC(),
	}
	findings := keyage.Evaluate(keys, cfg)

	if *asJSON {
		if err := keyage.WriteJSON(os.Stdout, findings); err != nil {
			return err
		}
	} else {
		keyage.WriteTable(os.Stdout, findings)
	}

	if breaches := keyage.Breaches(findings, *failOn); len(breaches) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d access key(s) breach the policy (--fail-on %s)\n", len(breaches), *failOn)
		os.Exit(1)
	}
	return nil
}

// collect lists every IAM user's access keys and their last-used dates.
func collect(ctx context.Context) ([]keyage.Key, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	client := iam.NewFromConfig(awsCfg)
	return listKeys(ctx, client)
}

// iamAPI is the slice of the IAM client this tool uses. It keeps the AWS
// dependency at the edge and makes the collection loop independently testable.
type iamAPI interface {
	ListUsers(ctx context.Context, in *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, in *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
}

func listKeys(ctx context.Context, client iamAPI) ([]keyage.Key, error) {
	var out []keyage.Key
	var userMarker *string
	for {
		users, err := client.ListUsers(ctx, &iam.ListUsersInput{Marker: userMarker})
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		for _, u := range users.Users {
			name := aws(u.UserName)
			keys, err := userKeys(ctx, client, name)
			if err != nil {
				return nil, err
			}
			out = append(out, keys...)
		}
		if users.IsTruncated {
			userMarker = users.Marker
			continue
		}
		break
	}
	return out, nil
}

func userKeys(ctx context.Context, client iamAPI, user string) ([]keyage.Key, error) {
	var out []keyage.Key
	var marker *string
	for {
		aks, err := client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &user, Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("list access keys for %s: %w", user, err)
		}
		for _, m := range aks.AccessKeyMetadata {
			k := keyage.Key{
				User:        user,
				AccessKeyID: aws(m.AccessKeyId),
				Status:      string(m.Status),
			}
			if m.CreateDate != nil {
				k.Created = *m.CreateDate
			}
			last, err := lastUsed(ctx, client, k.AccessKeyID)
			if err != nil {
				return nil, err
			}
			k.LastUsed = last
			out = append(out, k)
		}
		if aks.IsTruncated {
			marker = aks.Marker
			continue
		}
		break
	}
	return out, nil
}

func lastUsed(ctx context.Context, client iamAPI, keyID string) (*time.Time, error) {
	resp, err := client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("get last-used for %s: %w", keyID, err)
	}
	if resp.AccessKeyLastUsed == nil || resp.AccessKeyLastUsed.LastUsedDate == nil {
		return nil, nil
	}
	// AWS returns a sentinel service name of "N/A" when a key was never used.
	if resp.AccessKeyLastUsed.ServiceName != nil && *resp.AccessKeyLastUsed.ServiceName == "N/A" {
		return nil, nil
	}
	return resp.AccessKeyLastUsed.LastUsedDate, nil
}

func aws(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// compile-time assurance the real client satisfies our narrow interface.
var _ iamAPI = (*iam.Client)(nil)

// referenced to keep the import when only used in tests/build tags.
var _ = iamtypes.StatusTypeActive
