# SchemaRisk

Pre-flight SQL migration risk analyser. Runs in CI or locally and tells you exactly how dangerous a database migration is **before** it touches production.

```
schema-risk analyze migrations/001_add_column.sql

Migration Risk:  HIGH   (score: 72)

  Tables affected: users, orders
  Estimated lock duration: ~30 sec
  Index rebuild required: YES
  Requires maintenance window: YES

  Warnings:
    ! Dropping column 'users.legacy_code' is irreversible ...
    ! CREATE INDEX on 'orders' without CONCURRENTLY will hold a lock...

  Recommendations:
    → Deploy in two phases: first remove app references, then drop
    → Use CREATE INDEX CONCURRENTLY to build indexes without locking
    → Schedule during a low-traffic maintenance window
```

---

## Why this exists

Teams push migrations that cause:

| Problem | Root cause |
|---------|-----------|
| Table lock / downtime | `ALTER TABLE` on millions of rows |
| Index rebuild freeze | `CREATE INDEX` without `CONCURRENTLY` |
| Cascading deletes | `ON DELETE CASCADE` FKs not reviewed |
| Breaking changes | `DROP COLUMN` / `RENAME TABLE` still in use |
| Migration fails at runtime | `NOT NULL` column with no `DEFAULT` |

`schema-risk` catches all of these **before** the migration runs.

---

## Installation

### From source (recommended right now)

```bash
git clone <this repo>
cd schema-risk
cargo build --release
# Binary is at: target/release/schema-risk
```

Move it to your PATH:

```bash
# Linux / macOS
cp target/release/schema-risk /usr/local/bin/

# Windows – add target\release\ to your PATH
# or copy schema-risk.exe to C:\Windows\System32\
```

### Pre-built binaries

> Once we tag a release on GitHub, binaries for Linux, macOS, and Windows will be
> available on the [Releases page](https://github.com/Ayuussshhh/newBase-backend/releases).

---

## Usage

### `analyze` — get a risk report

```bash
# Single file
schema-risk analyze migrations/001_add_users.sql

# Glob pattern (quote it to prevent shell expansion)
schema-risk analyze "migrations/*.sql"

# Multiple files
schema-risk analyze migrations/001.sql migrations/002.sql

# Verbose (shows every detected operation)
schema-risk analyze migrations/001.sql --verbose

# JSON output (for scripts / CI)
schema-risk analyze migrations/001.sql --format json

# Provide table row counts for accurate lock estimates
schema-risk analyze migrations/001.sql \
  --table-rows "users:5000000,orders:2000000,products:800000"

# Change the failure threshold (default: high)
# CI will exit 1 only when risk >= CRITICAL
schema-risk analyze migrations/001.sql --fail-on critical
```

### `explain` — step-by-step breakdown

```bash
schema-risk explain migrations/001.sql
schema-risk explain migrations/001.sql --table-rows "users:1000000"
```

### `graph` — schema dependency graph

```bash
# Show FK relationships across all migrations
schema-risk graph "migrations/*.sql"
```

---

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--format terminal\|json` | `terminal` | Output format |
| `--fail-on low\|medium\|high\|critical` | `high` | Exit 1 when risk ≥ this level |
| `--table-rows "table:rows,..."` | none | Row count hints for lock estimates |
| `--verbose` / `-v` | false | Show all detected operations |

---

## Risk scoring

| Score | Level | What it means |
|-------|-------|---------------|
| 0–20 | **LOW** | Safe to deploy anytime |
| 21–50 | **MEDIUM** | Review before deploying |
| 51–100 | **HIGH** | Requires maintenance window |
| 101+ | **CRITICAL** | Do not deploy without a rollback plan |

### Detected patterns and their scores

| Operation | Score | Why |
|-----------|-------|-----|
| `DROP TABLE` | 100+ | Irreversible, cascades to FKs |
| `RENAME TABLE` | 65 | Breaks all queries and ORMs |
| `RENAME COLUMN` | 55 | Breaks application code |
| `DROP COLUMN` | 60 | Irreversible |
| `ALTER COLUMN TYPE` on large table | 90 | Full table rewrite |
| `ALTER COLUMN TYPE` on small table | 40 | Table rewrite |
| `ADD PRIMARY KEY` on large table | 80 | Full index build |
| `SET NOT NULL` on large table | 45 | Full table scan |
| `ADD COLUMN NOT NULL` no default | 25–50 | Fails with existing rows |
| `CREATE INDEX` without `CONCURRENTLY` | 20–70 | SHARE lock during build |
| `ADD FOREIGN KEY` with CASCADE | 30 | Silent cascading deletes |
| `DROP CONSTRAINT` CASCADE | 25 | May drop dependent objects |
| `CREATE TABLE` | 2 | New table, safe |
| `CREATE INDEX CONCURRENTLY` | 5 | No lock |

---

## CI/CD integration

### GitHub Actions

The workflow file lives at `.github/workflows/schema-risk.yml`.

It automatically:
1. Detects which `.sql` files changed in a PR
2. Runs `schema-risk analyze` against them
3. Posts the report as a PR comment
4. Fails the check if risk ≥ HIGH

**To activate it**, push the workflow file to your repo:

```bash
git add .github/workflows/schema-risk.yml
git commit -m "ci: add SchemaRisk migration analysis"
git push
```

The next PR that touches a `.sql` file will trigger the analysis.

### Customise the failure threshold

Edit the `--fail-on` flag in the workflow:

```yaml
# Only block on CRITICAL (allow HIGH through with a warning)
--fail-on critical
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
STAGED_MIGRATIONS=$(git diff --cached --name-only | grep '\.sql$')
if [ -n "$STAGED_MIGRATIONS" ]; then
    schema-risk analyze $STAGED_MIGRATIONS --fail-on high
    if [ $? -ne 0 ]; then
        echo "❌ High-risk migration detected. Run schema-risk analyze for details."
        exit 1
    fi
fi
```

---

## Architecture

```
schema-risk/
├── src/
│   ├── main.rs      CLI entry point (clap subcommands)
│   ├── loader.rs    Reads .sql files from disk or glob
│   ├── parser.rs    sqlparser-rs wrapper → ParsedStatement enum
│   ├── graph.rs     petgraph dependency graph (tables, FKs, indexes)
│   ├── engine.rs    Risk rules engine → MigrationReport
│   ├── output.rs    Terminal (colored) and JSON renderers
│   ├── types.rs     All shared types (RiskLevel, MigrationReport, …)
│   └── error.rs     Error type
```

### Data flow

```
SQL File
  └─► loader.rs        Read bytes
        └─► parser.rs  Parse → Vec<ParsedStatement>
              └─► graph.rs   Build petgraph dependency graph
                    └─► engine.rs  Apply risk rules → MigrationReport
                          └─► output.rs  Render to terminal or JSON
```

### The graph model

```
Nodes:   Table | Column | Index
Edges:   Contains (table→column) | ForeignKey (table→table) | HasIndex (table→index)
```

`petgraph::DiGraph` is used. FK cascade analysis uses depth-first search (`petgraph::visit::Dfs`) to find all downstream tables affected by a `DROP TABLE`.

---

## Adding new rules

Every rule is a match arm in `engine.rs::evaluate()`. Add a new arm:

```rust
ParsedStatement::AlterTableSetNotNull { table, column } => {
    vec![DetectedOperation {
        description: format!("SET NOT NULL on {}.{}", table, column),
        score: 20,
        acquires_lock: true,
        warning: Some("Full table scan required".to_string()),
        // ...
    }]
}
```

---

## Performance

- Parses a 500-table migration schema in < 200 ms (measured on an M1 Mac)
- Uses `OnceLock` for compiled regex patterns
- `petgraph` adjacency list is O(V + E) for DFS
- Release binary is ~3 MB (stripped, LTO enabled)

---

## Roadmap

- [ ] `schema-risk diff old.sql new.sql` — compare two schema versions
- [ ] PostgreSQL live introspection (`--db-url postgres://...`)
- [ ] YAML rule config (`schema-risk.yml`) for per-project thresholds
- [ ] Sarif output for GitHub Code Scanning
- [ ] MySQL / SQLite dialect support
