<div align="center">

# SchemaRisk

**One bad migration away from production downtime.**

SchemaRisk catches dangerous PostgreSQL migrations before they hit production.

[![Crates.io](https://img.shields.io/crates/v/schema-risk.svg)](https://crates.io/crates/schema-risk)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Keystones-Lab/Schema-risk/actions/workflows/ci.yml/badge.svg)](https://github.com/Keystones-Lab/Schema-risk/actions)

[Quick Start](#quick-start) • [Demo](#see-it-in-action) • [CI Integration](#ci-integration) • [Docs](#commands)

</div>

---

## The Problem

```sql
CREATE INDEX idx_email ON users(email);
```

This runs silently in seconds locally. On production with 10M rows? **Table locked for 8+ minutes. API down.**

```sql
ALTER TABLE users ALTER COLUMN status TYPE VARCHAR(50);
```

Looks harmless. Actually: **Full table rewrite. Lock every row. Downtime.**

```sql
ALTER TABLE orders ADD COLUMN shipped BOOLEAN NOT NULL;
```

Works on empty tables. Production? **Instant failure. Transaction rollback.**

**These are real incidents.** Every week, teams deploy migrations that silently break production.

---

## The Solution

```bash
cargo install schema-risk
```

```bash
schema-risk analyze migrations/001_add_index.sql
```

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SchemaRisk Analysis                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ File: migrations/001_add_index.sql                                          │
│ Risk: HIGH (score: 70)                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ ⚠ WARNING                                                                   │
│ CREATE INDEX on 'users' without CONCURRENTLY will hold a SHARE lock         │
│ for the duration of the index build                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ SAFE ALTERNATIVE                                                          │
│ CREATE INDEX CONCURRENTLY idx_email ON users(email);                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

**30 seconds to install. 1 command to prevent downtime.**

---

## See It in Action

```bash
# Built-in demo — see SchemaRisk catch real problems
schema-risk demo
```

Output:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SchemaRisk Demo - Real-World Migration Analysis
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Analyzing dangerous migration...

┌─────────────────────────────────────────────────────────────┐
│ CRITICAL RISK DETECTED                                      │
├─────────────────────────────────────────────────────────────┤
│ Operation: ALTER COLUMN TYPE on `users.email`               │
│ Impact:    Full table rewrite (~5M rows)                    │
│ Lock:      ACCESS EXCLUSIVE (blocks all queries)            │
│ Duration:  8-15 minutes estimated                           │
├─────────────────────────────────────────────────────────────┤
│ ✓ Zero-Downtime Alternative:                                │
│                                                             │
│   -- Step 1: Add shadow column                              │
│   ALTER TABLE users ADD COLUMN email_v2 VARCHAR(255);       │
│                                                             │
│   -- Step 2: Backfill in batches                            │
│   UPDATE users SET email_v2 = email WHERE email_v2 IS NULL  │
│   LIMIT 10000;                                              │
│                                                             │
│   -- Step 3: Atomic swap                                    │
│   ALTER TABLE users RENAME COLUMN email TO email_old;       │
│   ALTER TABLE users RENAME COLUMN email_v2 TO email;        │
│                                                             │
│   -- Step 4: Drop old column                                │
│   ALTER TABLE users DROP COLUMN email_old;                  │
└─────────────────────────────────────────────────────────────┘

→ This migration would have caused 15 minutes of downtime.
→ SchemaRisk gives you the safe path instead.
```

---

## Quick Start

### Install

```bash
# From crates.io (recommended)
cargo install schema-risk

# From source
git clone https://github.com/Keystones-Lab/Schema-risk
cd Schema-risk && cargo install --path .
```

### Analyze Your Migrations

```bash
# Single file
schema-risk analyze db/migrations/001_add_users.sql

# All migrations
schema-risk analyze "db/migrations/*.sql"

# Auto-discover and analyze everything
schema-risk doctor
```

### Get Safe Alternatives

```bash
# Preview what the safe version looks like
schema-risk fix migrations/risky.sql --dry-run

# Generate fixed migration file
schema-risk fix migrations/risky.sql --output migrations/risky_safe.sql
```

---

## CI Integration

**Block dangerous migrations at PR time.** Add one file and every PR gets automatic risk reports.

### GitHub Actions (2 minutes)

Create `.github/workflows/schema-risk.yml`:

```yaml
name: Migration Safety Check

on:
  pull_request:
    paths:
      - 'db/migrations/**'
      - 'migrations/**'
      - 'prisma/migrations/**'

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install SchemaRisk
        run: cargo install schema-risk

      - name: Analyze migrations
        run: |
          schema-risk ci-report "migrations/*.sql" \
            --format github-comment \
            --fail-on high \
            --pg-version 14
```

**Result:** Every PR with SQL changes gets a comment like:

> **⚠️ HIGH RISK** — This migration may cause production issues.
>
> | File | Risk | Score | Lock | Est. Duration |
> |------|:----:|------:|------|-------------:|
> | `001_add_index.sql` | **HIGH** | 70 | `SHARE` | ~90s |
>
> **Safe Alternative:**
> ```sql
> CREATE INDEX CONCURRENTLY idx_email ON users(email);
> ```

---

## What SchemaRisk Catches

| Operation | Risk | Why It's Dangerous |
|-----------|------|-------------------|
| `CREATE INDEX` (no `CONCURRENTLY`) |  HIGH | Blocks all writes during build |
| `ALTER COLUMN TYPE` |  HIGH | Full table rewrite, exclusive lock |
| `ADD COLUMN NOT NULL` (no default) |  HIGH | Fails on existing rows |
| `DROP TABLE` |  CRITICAL | Irreversible data loss |
| `DROP COLUMN` |  HIGH | Breaks app code still reading it |
| `RENAME COLUMN/TABLE` |  HIGH | Breaks all downstream queries |
| `SET NOT NULL` |  MEDIUM | Full table scan to validate |
| `ADD COLUMN DEFAULT` (PG < 11) |  HIGH | Table rewrite (metadata-only on PG11+) |
| `TRUNCATE` |  CRITICAL | Immediate data destruction |
| `ON DELETE CASCADE` |  MEDIUM | Silent cascading deletes |

---

## Commands

### `analyze` — Risk Assessment

```bash
schema-risk analyze migrations/001.sql
schema-risk analyze "migrations/*.sql" --format json
schema-risk analyze migrations/ --pg-version 14 --verbose
schema-risk analyze migrations/ --fail-on high  # Exit 1 if HIGH+
```

### `fix` — Safe Migration Generator

```bash
schema-risk fix migrations/001.sql --dry-run      # Preview
schema-risk fix migrations/001.sql --output safe.sql
```

### `guard` — Interactive Confirmation Gate

```bash
schema-risk guard migrations/dangerous.sql
# → Blocks execution until you confirm

# Safe pattern for scripts:
schema-risk guard migration.sql && psql -f migration.sql
```

### `doctor` — Zero-Config Analysis

```bash
schema-risk doctor              # Auto-discover and analyze all migrations
schema-risk doctor --verbose    # Show discovery details
```

### `demo` — See It In Action

```bash
schema-risk demo     # Built-in demonstration of SchemaRisk capabilities
```

### `ci-report` — PR Comments

```bash
schema-risk ci-report "migrations/*.sql" --format github-comment
schema-risk ci-report "migrations/*.sql" --format gitlab-comment
schema-risk ci-report "migrations/*.sql" --format json
```

### `discover` — Find Migrations

```bash
schema-risk discover .          # Find all migration directories
schema-risk discover . --json   # Output as JSON
```

---

## Configuration

Generate a config file:

```bash
schema-risk init
```

Example `schema-risk.yml`:

```yaml
version: 2

thresholds:
  fail_on: high      # Exit non-zero on HIGH or CRITICAL
  guard_on: medium   # Require confirmation on MEDIUM+

rules:
  disabled: []       # Rule IDs to skip: [R01, R02]
  table_overrides:
    sessions:
      ignored: true  # Skip analysis for ephemeral tables

guard:
  require_typed_confirmation: true   # "yes I am sure" for CRITICAL
  audit_log: ".schemarisk-audit.json"
  block_agents: true
  block_ci: false
```

---

## PostgreSQL Version Awareness

SchemaRisk knows PostgreSQL internals. Same SQL, different behavior:

| Operation | PG 10 | PG 11+ |
|-----------|-------|--------|
| `ADD COLUMN DEFAULT` | Full table rewrite | Metadata-only ✓ |
| `SET NOT NULL` | Long exclusive lock | CHECK constraint workaround available |

```bash
# Score accurately for your PG version
schema-risk analyze migrations/ --pg-version 10
schema-risk analyze migrations/ --pg-version 14
```

---

## Real Production Scenarios

Test these to validate SchemaRisk before rolling out to your team:

```bash
# 1. Safe migration (should pass cleanly)
schema-risk analyze examples/safe.sql

# 2. Risky operations (should flag with alternatives)
schema-risk analyze examples/risky.sql

# 3. Critical destructive ops (should block)
schema-risk guard examples/critical.sql --dry-run

# 4. Full fix generation
schema-risk fix examples/risky.sql --dry-run

# 5. CI output format
schema-risk ci-report "examples/*.sql" --format github-comment
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Safe / below threshold |
| `1` | Risk meets or exceeds `--fail-on` threshold |
| `2` | Parse or I/O error |
| `3` | Guard runtime error |
| `4` | Blocked by guard |

---

## FAQ

**Q: Does this work with my ORM?**
A: Yes. SchemaRisk analyzes raw SQL. Works with Prisma, Rails, Django, Diesel, or any tool that generates SQL migrations.

**Q: How accurate is the lock duration estimate?**
A: It's a heuristic based on table size. For precise estimates, use `--table-rows users:5000000` or connect to your database with `--db-url`.

**Q: Can I run this in my CI pipeline?**
A: Yes. That's the primary use case. Use `--fail-on high` to block PRs with dangerous migrations.

**Q: What about MySQL/SQLite?**
A: Currently PostgreSQL only. The locking and DDL behavior is Postgres-specific.

---

## Contributing

```bash
git clone https://github.com/Keystones-Lab/Schema-risk
cd Schema-risk
cargo test
cargo clippy -- -D warnings
```

---

## License

MIT

---

<div align="center">

**Stop dangerous migrations before they reach production.**

[Install Now](#quick-start) • [See Demo](#see-it-in-action) • [Report Issues](https://github.com/Keystones-Lab/Schema-risk/issues)

</div>
