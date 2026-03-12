# SchemaRisk v2 — Architecture Document

> **Status**: Production-ready v2.0.0  
> **Language**: Rust 2021 Edition  
> **Minimum Rust toolchain**: stable ≥ 1.75

---

## Table of Contents

1. [High-level Concept](#1-high-level-concept)
2. [Module Map](#2-module-map)
3. [End-to-End Data Flow](#3-end-to-end-data-flow)
4. [Scoring Algorithm](#4-scoring-algorithm)
5. [Lock Simulation Heuristics](#5-lock-simulation-heuristics)
6. [Query Breakage Detection](#6-query-breakage-detection)
7. [Graph Representation](#7-graph-representation)
8. [CI Integration](#8-ci-integration)
9. [Known Bugs and Limitations](#9-known-bugs-and-limitations)
10. [Improvements Backlog](#10-improvements-backlog)
11. [Missing Implementations](#11-missing-implementations)
12. [Security Considerations](#12-security-considerations)

---

## 1. High-level Concept

SchemaRisk answers one question: **"If I run this migration SQL against my production database right now, what will break and for how long?"**

It does this in five conceptual passes:

```
SQL text
  │
  ▼
[Parse]  ─── sqlparser (PostgreSQL dialect)
  │              ParsedStatement enum
  ▼
[Score]  ─── RiskEngine
  │              MigrationReport (risk level, score, lock estimate)
  ▼
[Enrich] ─── Optional live DB / LiveSchema via tokio-postgres
  │              table sizes, index names, FK graph
  ▼
[Impact] ─── ImpactScanner (rayon parallel walk)
  │              which source files reference affected tables/columns
  ▼
[Report] ─── output / ci modules
               terminal or Markdown/JSON for PRs
```

The **offline path** (no `--db-url`) gives you `RiskLevel`, a numeric `score`, and lock-time estimates based solely on heuristics. The **live path** augments every estimate with actual row counts and table sizes fetched over a read-only connection.

---

## 2. Module Map

```
src/
├── main.rs          CLI entry point — Clap subcommands, orchestration
├── engine.rs        RiskEngine: analyse() + evaluate() + scoring
├── types.rs         Core types: RiskLevel, DetectedOperation, MigrationReport
├── parser.rs        SQL → ParsedStatement via sqlparser
├── locks.rs         LockSimulator: timeline of AccessExclusive / RowExclusive events
├── db.rs            LiveSchema: async connector (feature = "db")
├── graph.rs         SchemaGraph: petgraph DiGraph of tables / FKs / indexes
├── impact.rs        ImpactScanner: rayon file-tree walk for table/column refs
├── drift.rs         DriftReport: live schema ↔ migrations on-disk delta
├── recommendation.rs Rule-based fix engine (R01–R08) + apply_fixes()
├── ci.rs            CI report formatter (GitHub / GitLab Markdown + JSON)
├── output.rs        Terminal pretty-printer (colored, comfy-table)
├── error.rs         SchemaRiskError enum (thiserror)
└── loader.rs        load_file() / load_glob() helpers
```

### Key type relationships

```
ParsedStatement  ──▶  DetectedOperation (1:N)
                            │
                            ▼
                       MigrationReport
                            │
                 ┌──────────┴────────────┐
                 │                       │
           FixSuggestion           ImpactReport
           (recommendation)          (impact)
```

---

## 3. End-to-End Data Flow

### 3.1 `analyze` subcommand (single file, offline)

```
main::Commands::Analyze
  │
  ├─ loader::load_file(path)        → String (raw SQL)
  ├─ RiskEngine::new()              → engine
  │    │
  │    └─ engine.analyze(file, sql)
  │         ├─ parser::parse(sql)   → Vec<ParsedStatement>
  │         ├─ evaluate(stmts)      → Vec<DetectedOperation>
  │         │    (score, risk_level, lock_acquired per stmt)
  │         ├─ build_recommendations() → Vec<String>
  │         └─ aggregate into MigrationReport
  │
  ├─ output::render(&report)        → terminal
  └─ exit(report.overall_risk.exit_code())
```

### 3.2 `ci-report` subcommand (multi-file, optional live DB)

```
main::Commands::CiReport
  │
  ├─ optional: db::connector::fetch(db_url)  → LiveSchema
  │
  ├─ for each file:
  │    ├─ loader::load_file()
  │    ├─ RiskEngine::with_live_schema(schema).analyze()
  │    ├─ recommendation::suggest_fixes()
  │    └─ collect affected tables + columns
  │
  ├─ optional: ImpactScanner::new(tables, cols).scan(root_dir)
  │
  ├─ ci::render_ci_report(reports, fixes, impact, format)
  └─ exit(max_risk.exit_code())
```

### 3.3 `fix` subcommand

```
main::Commands::Fix
  │
  ├─ loader::load_file(path)
  ├─ parser::parse(sql)
  ├─ recommendation::suggest_fixes(stmts, row_counts)
  ├─ output::render_fix_suggestions(&fixes)   [dry-run: print only]
  ├─ recommendation::apply_fixes(raw_sql, &fixes)
  ├─ print_sql_diff(original, fixed)
  └─ if !dry_run: fs::write(output_path, fixed)
```

---

## 4. Scoring Algorithm

Each `ParsedStatement` variant maps to a base score and a `RiskLevel`:

| Statement                        | Base score | Lock mode        | RiskLevel  |
|----------------------------------|-----------|-----------------|-----------|
| `DROP TABLE`                     | 100       | ACCESS EXCLUSIVE | Critical  |
| `DROP COLUMN` (≥100k rows est.)  | 85        | ACCESS EXCLUSIVE | Critical  |
| `ALTER COLUMN TYPE`              | 80        | ACCESS EXCLUSIVE | High      |
| `ALTER TABLE SET NOT NULL`       | 75        | ACCESS EXCLUSIVE | High      |
| `ADD COLUMN NOT NULL no DEFAULT` | 70        | ACCESS EXCLUSIVE | High      |
| `CREATE INDEX` (no CONCURRENTLY) | 60        | SHARE            | High      |
| `ADD FOREIGN KEY`                | 50        | SHARE ROW EXCL.  | Medium    |
| `DROP INDEX`                     | 40        | ACCESS EXCLUSIVE | Medium    |
| `RENAME COLUMN / TABLE`          | 30        | ACCESS EXCLUSIVE | Medium    |
| `CREATE TABLE`                   | 5         | ACCESS EXCLUSIVE | Low       |
| `ADD COLUMN` (nullable + default)| 5         | ACCESS EXCLUSIVE | Low       |

**Aggregate score** = sum of individual operation scores.  
**`RiskLevel::from_score(n)`** maps: 0–29 → Low, 30–59 → Medium, 60–89 → High, 90+ → Critical.

### Table-size multiplier (live mode only)

When `LiveSchema` is available, operations on tables where `estimated_rows > 1_000_000` get a ×1.5 multiplier applied to their base score and lock estimate. For `estimated_rows > 10_000_000` the multiplier is ×2.0.

---

## 5. Lock Simulation Heuristics

`locks::LockSimulator` produces a `MigrationTimeline` — an ordered list of `LockEvent`s, each with:

- `statement_index`: which SQL statement acquired/released the lock
- `lock_mode`: one of `LockMode::{AccessShare, RowShare, RowExclusive, ShareUpdateExclusive, Share, ShareRowExclusive, Exclusive, AccessExclusive}`
- `table`: relation name
- `estimated_duration_ms`: how long SchemaRisk expects the lock to be held

**Duration heuristics** (offline, no live schema):

| Operation | Estimate |
|-----------|---------|
| `CREATE INDEX CONCURRENTLY` | row_count × 0.05 ms (minimum 100 ms) |
| `CREATE INDEX` (blocking)   | row_count × 0.1 ms (minimum 50 ms)  |
| `ALTER TABLE ... TYPE`      | row_count × 0.5 ms |
| `ADD COLUMN NOT NULL`       | row_count × 0.3 ms |
| DDL with no data rewrite    | 10 ms flat |

When `table_rows` is not provided, a default of `0` is used and the estimate falls back to `None` in `MigrationReport.estimated_lock_seconds`.

**Important**: These are order-of-magnitude estimates only. Actual lock duration depends on autovacuum state, replication lag, connection pool size, and OID-reuse patterns — none of which SchemaRisk models.

---

## 6. Query Breakage Detection

### What is checked

The `engine::evaluate()` function inspects each `ParsedStatement` for patterns that break **existing application code** at deploy time:

| Risk | Detection method |
|------|-----------------|
| Column rename | `AlterTableRenameColumn` variant detected → flag all code referencing old name |
| Table rename | `AlterTableRenameTable` variant detected |
| Column type narrowing | `AlterTableAlterColumnType` → any type change is flagged |
| NOT NULL constraint without DEFAULT | `AlterTableAddColumn { not_null: true, default: None }` |
| CASCADE DROP | `DropTable` with `CASCADE` keyword in raw SQL via regex fallback |
| FK without index | `AlterTableAddForeignKey` without a corresponding `CreateIndex` on the FK columns |

### Impact scanning (`ImpactScanner`)

`ImpactScanner` walks the source tree with `rayon::par_iter()` over files from `walkdir`, searching for:
- table names using the regex `\b{table_name}\b`
- column names using the regex `\b{column_name}\b`

This produces an `ImpactReport` mapping each affected table/column to the files that reference it, helping engineers understand blast radius before merging.

**Limitation**: regex-based scanning produces false positives. A column named `id` will match every file that uses that common word. Future versions should parse AST-level references.

---

## 7. Graph Representation

`graph::SchemaGraph` wraps a `petgraph::graph::DiGraph<SchemaNode, SchemaEdge>`:

```
SchemaNode:
  Table(name, schema)
  Index(name, table, unique)
  Column(name, table, data_type)

SchemaEdge:
  ForeignKey { from_col, to_col, on_delete, on_update }
  HasIndex
  HasColumn
```

**Graph subcommand** (`schema-risk graph`) renders the graph as:
- **DOT format** (`--format dot`) for Graphviz / CI pipeline artefacts
- **ASCII adjacency** (default) for quick terminal inspection

The graph is built by `SchemaGraph::from_live_schema()` when live DB access is enabled, or `SchemaGraph::from_parsed()` for offline migration-file-only mode.

**Use cases**:
- Identify which tables will be transitively affected by a FK cascade (`DROP TABLE … CASCADE`)
- Find orphaned indexes (not referenced by any query plan)
- Detect circular FK dependencies that would block ordered deletion

---

## 8. CI Integration

### Report lifecycle

1. `ci::render_ci_report(reports, fixes, impact, format)` is the public entry point.
2. For `CiFormat::GithubComment` it calls `render_markdown()` internally, producing GitHub Flavored Markdown with:
   - A risk banner (`> ⚠️ HIGH risk …`)
   - A summary table (file · risk · score · lock duration · maintenance window)
   - Per-file detail sections with `<details>`/`<summary>` fold
   - A "Breaking Changes" section listing BLOCKING fixes
   - Fix suggestions with fenced SQL code blocks and migration step lists
3. For `CiFormat::Json` it serialises a `CiJsonReport` struct via `serde_json`.

### GitHub Actions workflow

The bundled workflow (`.github/workflows/schema-risk.yml`) follows this pattern:

1. Detects changed `.sql` files via `git diff --name-only --diff-filter=ACM`
2. Builds the `schema-risk` binary from source (cached with `Swatinem/rust-cache`)
3. Invokes `schema-risk ci-report` with `--format github-comment --fail-on critical`
4. POSTs/updates a single PR comment (identified by `<!-- schema-risk-report -->` marker) via `actions/github-script`
5. Exits non-zero if `--fail-on` threshold is exceeded, blocking the merge

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | No risks above threshold |
| 1    | At least one HIGH risk migration |
| 2    | At least one CRITICAL risk migration |
| 3    | Analysis error (parse failure, I/O, DB connection) |

---

## 9. Known Bugs and Limitations

### Bug B-01 — Parser fallback for complex DDL

`parser::parse()` calls `sqlparser` with `PostgreSqlDialect`. Some valid PostgreSQL DDL (e.g. `ALTER TABLE … ATTACH PARTITION`, `CREATE POLICY`, `ALTER TABLE … ENABLE ROW LEVEL SECURITY`) is not modelled by the `ParsedStatement` enum and falls through to the `Other` variant. These statements receive **zero risk score** even when they can take long locks.

**Workaround**: Grep the raw SQL for known unsafe keywords as a belt-and-suspenders check in the engine.

### Bug B-02 — `estimated_rows` always `None` in offline mode

`TableMeta.estimated_rows` is populated from `pg_class.reltuples` in live mode only. In offline mode the score multiplier is never applied, potentially under-estimating risk for large tables.

**Workaround**: Pass `--table-rows table_name=row_count` CLI flags (supported by `fix` and `ci-report` subcommands, forwarded via the `row_counts` HashMap).

### Bug B-03 — Impact scanner false positives on short identifiers

Column names shorter than 4 characters (e.g. `id`, `ts`, `at`) generate excessive false positives in `ImpactScanner`. The scanner uses whole-word boundaries (`\b`) but common language tokens share these short names.

**Workaround**: Filter out table/column names with fewer than 4 characters from impact scanning, or require explicit `--scan-columns` opt-in to include short names.

### Bug B-04 — `apply_fixes` is not transaction-aware

`recommendation::apply_fixes()` performs line-by-line text substitution. If the original SQL wraps statements in a `BEGIN`/`COMMIT` block, the rewrite may insert `CREATE INDEX CONCURRENTLY` inside a transaction, which PostgreSQL forbids.

**Workaround**: `apply_fixes` should detect transaction blocks and emit a comment warning instead of silently inserting `CONCURRENTLY` inside them.

### Bug B-05 — `render_summary_table` assumes `comfy-table` UTF8_FULL_CONDENSED preset

On Windows terminals without full Unicode support, the table borders render as question marks. The code uses `UTF8_FULL_CONDENSED` unconditionally.

**Workaround**: Detect non-UTF8 terminal capability via `std::env::var("TERM")` or the `supports-unicode` crate and fall back to `ASCII_FULL`.

---

## 10. Improvements Backlog

### P0 — Critical for production use

| ID | Description |
|----|-------------|
| I-01 | **Idempotency check**: detect if a migration has already been applied (compare against a `schema_migrations` table) to avoid re-flagging already-safe replays |
| I-02 | **Transaction block awareness**: wrap risky `apply_fixes` rewrites in a note rather than silently breaking transaction semantics |
| I-03 | **Proper configuration file** (`schema-risk.toml`): per-repo thresholds, ignored rules, table allowlists — currently all values are hardcoded |

### P1 — High value

| ID | Description |
|----|-------------|
| I-04 | **Actual PostgreSQL connection pooling** with `sqlx` vs raw `tokio-postgres`: the current `db::connector` opens a new connection per analysis run |
| I-05 | **AST-level impact scanning**: replace regex walk with a proper SQL parser walk over application query files to eliminate false positives |
| I-06 | **Lock wait simulation**: model `lock_timeout` / `statement_timeout` interactions to show how long concurrent queries will queue |
| I-07 | **Parallel multi-file analysis**: `CiReport` currently processes files sequentially. Using `rayon` here would halve wall-clock time for large migration sets |

### P2 — Nice to have

| ID | Description |
|----|-------------|
| I-08 | **Human-readable DOT graph styling**: add table cardinalities, index types (BTREE/GIN/GiST), and NOT NULL indicators to graph output |
| I-09 | **GitLab Merge Request integration**: the CI formatter supports `CiFormat::GitlabComment` but there is no corresponding `.gitlab-ci.yml` template |
| I-10 | **SARIF output format**: emit SARIF (Static Analysis Results Interchange Format) for native GitHub Code Scanning integration |
| I-11 | **`schema-risk explain` enriched output**: the `explain` subcommand dumps raw `DetectedOperation` structs; it should also call `suggest_fixes` and display auto-fix previews |

---

## 11. Missing Implementations

The following features appeared in the original v2 specification but are **not yet implemented**:

### M-01 — `sqlx`-backed live introspection

`Cargo.toml` declares the `sqlx-db` feature with `sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-native-tls", "macros"], optional = true }`, but `db.rs` still uses the `tokio-postgres` based connector under the `db` feature. No code path uses `sqlx` yet.

**Effort**: ~4 hours. Replace `tokio-postgres` connector with `sqlx::PgPool::connect()` and `sqlx::query_as!` macros for compile-time SQL checking.

### M-02 — Table-size scoring multiplier in `engine.rs`

The scoring algorithm documents a ×1.5 / ×2.0 multiplier for large tables (see §4), but `engine::evaluate()` does not currently apply it even when `LiveSchema` is present.

**Effort**: ~2 hours. In `RiskEngine::evaluate()`, after scoring each operation, look up `self.live_schema.tables.get(table_name)` and scale the score by the row-count multiplier.

### M-03 — `drift` subcommand live-vs-disk comparison

`drift.rs` defines `DriftReport` and `DriftFinding` but the reconciliation logic between `LiveSchema` and the parsed migration files is a stub returning an empty `DriftReport`.

**Effort**: ~6 hours. Fetch all table definitions from live DB, parse all migration files up to the current `schema_version`, diff column sets and constraint sets, emit `DriftFinding` entries for each discrepancy.

### M-04 — `graph` subcommand DOT export

`graph.rs` builds a `petgraph::DiGraph` but `main.rs::Commands::Graph` only renders an ASCII adjacency list. The DOT export path (`--format dot`) calls `petgraph::dot::Dot::new()` but does not customise node labels with table metadata.

**Effort**: ~3 hours. Implement a custom `Dot` formatter that includes table row counts, index types, and FK actions in node/edge labels.

### M-05 — `--watch` mode

Continuous mode that re-analyzes SQL files on save was mentioned in the v2 feature spec but the `notify` crate was never added as a dependency and no watch loop exists.

**Effort**: ~4 hours. Add `notify = "6"` to `Cargo.toml`, implement a `Commands::Watch` handler that sets up a `RecommendedWatcher` and re-runs `RiskEngine::analyze()` on each file change event.

---

## 12. Security Considerations

### Connection string handling

`--db-url` (a PostgreSQL connection string including password) is accepted as a CLI argument. On Linux/macOS this value is visible in `ps aux` output. Users should prefer the `SCHEMA_RISK_DB_URL` environment variable instead, and the GitHub Actions workflow uses `secrets.SCHEMA_RISK_DB_URL` to avoid log exposure.

The `db::connector::fetch()` function uses TLS by default (toggled by the `sslmode` parameter in the connection string). Avoid `sslmode=disable` in production.

### SQL injection in CI comment

The Markdown report posts unsanitised SQL snippets into PR comments via the GitHub API. The content is treated as Markdown, not rendered as HTML by the GitHub backend, so XSS is not a concern. However, SQL strings containing backticks will break fenced code blocks; `ci::render_markdown()` escapes triple-backtick sequences to prevent this.

### Filesystem traversal in `ImpactScanner`

`ImpactScanner::scan()` accepts an arbitrary `root_dir` path. It uses `walkdir::WalkDir` which follows symlinks by default. In environments where `schema-risk` is run with elevated privileges or in a container with mounted secrets, a malicious symlink under the source root could expose files outside the intended scan boundary.

**Mitigation**: Pass `WalkDir::new(root_dir).follow_links(false)` (already the `walkdir` default) and validate that `root_dir` is a subdirectory of the repository root.
