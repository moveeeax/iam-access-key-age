# iam-access-key-age

[![CI](https://github.com/moveeeax/iam-access-key-age/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/iam-access-key-age/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Flag stale or never-used AWS IAM access keys and **fail CI before an old credential becomes a breach.**

IAM access keys never expire. A key minted years ago for a one-off script keeps
working forever, and the older it gets the more places it has leaked to: laptops,
CI logs, chat pastes, forgotten `.env` files. AWS has no built-in "fail my
pipeline if any active key is older than 90 days." `iam-access-key-age` is that
missing gate.

## How it works

The tool lists every IAM user and their access keys, and for each **Active** key
it computes:

- **age** from `CreateDate`, and
- **days since last use** from `GetAccessKeyLastUsed`.

It then classifies each key:

| reason | meaning |
| --- | --- |
| `old` | active key older than `--max-age` (default 90d) |
| `unused` | active key never used, or last used beyond `--stale-days` |
| `old+unused` | both of the above |
| `ok` | active and within thresholds |
| `inactive` | key is disabled — reported, never gated |

Output is a table sorted **oldest key first**, or `--json` for machines. The exit
code is `1` when any key breaches the policy you selected with `--fail-on`, so a
single line in CI blocks a deploy on a rotting credential.

## Install

```sh
go install github.com/moveeeax/iam-access-key-age@latest
```

Uses the standard AWS credential chain (env vars, shared config, SSO,
instance/role). It only needs `iam:ListUsers`, `iam:ListAccessKeys`, and
`iam:GetAccessKeyLastUsed` — all read-only.

## Usage

```sh
# Human table, default 90-day threshold, gate on old keys
iam-access-key-age --max-age 90 --fail-on old

# Machine-readable
iam-access-key-age --json

# Stricter gate: any old OR long-unused active key trips the exit code
iam-access-key-age --fail-on unused --stale-days 60
```

| flag | default | meaning |
| --- | --- | --- |
| `--max-age` | `90` | active keys older than this (days) are `old` |
| `--stale-days` | `90` | active keys unused this long are `unused` |
| `--fail-on` | `old` | `none`, `old`, or `unused` — what turns the exit code red |
| `--json` | `false` | emit a JSON array instead of a table |

`--fail-on unused` is the stricter gate: it trips on both `old` and `unused` keys.

### Example output

```
USER            ACCESS KEY             STATUS    AGE(d)  LAST USED  REASON
old-rotated     AKIAINACT00000000005   Inactive  900     300d ago   inactive
ci-deployer     AKIAOLD0000000000001   Active    412     2d ago     old
legacy-backup   AKIANEVER000000000002  Active    160     never      old+unused
app-runtime     AKIASTALE00000000003   Active    20      140d ago   unused
developer-jane  AKIAFRESH00000000004   Active    9       1d ago     ok
```

The `--json` form emits one object per key:

```json
{
  "user": "legacy-backup",
  "access_key_id": "AKIANEVER000000000002",
  "status": "Active",
  "created": "2026-03-20T12:00:00Z",
  "age_days": 160,
  "last_used_days": null,
  "reason": "old+unused"
}
```

See [`examples/demo`](examples/demo) for a runnable, offline render:

```sh
go run ./examples/demo
```

## Use in CI

```yaml
- name: Fail on stale IAM keys
  run: |
    go install github.com/moveeeax/iam-access-key-age@latest
    iam-access-key-age --max-age 90 --fail-on old
```

## Development

```sh
go build ./...
go test ./...
```

The judgement logic lives in [`internal/keyage`](internal/keyage) and is free of
any AWS SDK dependency, so every classification is unit-tested against in-memory
keys — no live account required. `main.go` is the thin edge that talks to IAM.

## License

MIT — see [LICENSE](LICENSE).
