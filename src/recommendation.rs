//! Rule-based fix suggestion engine.
//!
//! Given a list of parsed SQL statements and optional row-count metadata,
//! this module produces structured `FixSuggestion` objects — each with a
//! corrected SQL snippet or a step-by-step zero-downtime migration plan.
//!
//! ## Rules implemented
//!
//! | ID   | Trigger                              | Severity |
//! |------|--------------------------------------|----------|
//! | R01  | CREATE INDEX without CONCURRENTLY    | Blocking |
//! | R02  | ADD COLUMN NOT NULL without DEFAULT  | Blocking |
//! | R03  | DROP COLUMN on large table           | Warning  |
//! | R04  | Missing index on foreign key column  | Warning  |
//! | R05  | RENAME COLUMN                        | Blocking |
//! | R06  | RENAME TABLE                         | Blocking |
//! | R07  | ALTER COLUMN TYPE on large table     | Blocking |
//! | R08  | Long ACCESS EXCLUSIVE lock duration  | Warning  |

use crate::parser::ParsedStatement;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────
// Core types
// ─────────────────────────────────────────────

/// Severity of a fix suggestion — used for ordering and exit-code decisions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixSeverity {
    /// A nice-to-have improvement.
    Info,
    /// May cause degraded performance or brief downtime on large tables.
    Warning,
    /// Will likely cause production downtime, data loss, or a failed migration.
    Blocking,
}

impl std::fmt::Display for FixSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FixSeverity::Info => write!(f, "INFO"),
            FixSeverity::Warning => write!(f, "WARNING"),
            FixSeverity::Blocking => write!(f, "BLOCKING"),
        }
    }
}

/// A single recommended fix for a risky migration operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    /// Short rule identifier, e.g. "R01".
    pub rule_id: String,
    /// Short, actionable title shown in the terminal and CI comments.
    pub title: String,
    /// Full explanation: what will go wrong, and why the fix helps.
    pub explanation: String,
    /// Drop-in replacement SQL (if the fix is a single-statement rewrite).
    pub fixed_sql: Option<String>,
    /// Ordered migration steps for complex zero-downtime patterns.
    pub migration_steps: Option<Vec<String>>,
    /// How serious this finding is.
    pub severity: FixSeverity,
    /// Link to relevant PostgreSQL documentation or best-practices guide.
    pub docs_url: Option<String>,
    /// `true` when `apply_fixes()` can mechanically patch the raw SQL text.
    pub auto_fixable: bool,
}

// ─────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────

/// Analyse a slice of parsed statements and return a de-duplicated,
/// severity-sorted list of `FixSuggestion`s.
///
/// `row_counts` maps table name → estimated row count. May be empty in
/// offline mode; rules will fall back to heuristic thresholds.
pub fn suggest_fixes(
    statements: &[ParsedStatement],
    row_counts: &HashMap<String, u64>,
) -> Vec<FixSuggestion> {
    let mut suggestions: Vec<FixSuggestion> = Vec::new();

    for stmt in statements {
        match stmt {
            // ── R01: CREATE INDEX without CONCURRENTLY ────────────────────
            ParsedStatement::CreateIndex {
                table,
                columns,
                concurrently,
                index_name,
                unique,
            } => {
                if !concurrently {
                    let rows = row_counts.get(table).copied().unwrap_or(0);
                    let col_list = columns.join(", ");
                    let unique_kw = if *unique { "UNIQUE " } else { "" };
                    let name = index_name.as_deref().unwrap_or("idx_name");
                    suggestions.push(rule_r01_index_concurrently(
                        table, &col_list, unique_kw, name, rows,
                    ));
                }
            }

            // ── R02: ADD COLUMN NOT NULL without DEFAULT ──────────────────
            ParsedStatement::AlterTableAddColumn { table, column } => {
                if !column.nullable && !column.has_default {
                    let rows = row_counts.get(table).copied().unwrap_or(0);
                    suggestions.push(rule_r02_add_not_null(
                        table,
                        &column.name,
                        &column.data_type,
                        rows,
                    ));
                }
            }

            // ── R03: DROP COLUMN ──────────────────────────────────────────
            ParsedStatement::AlterTableDropColumn { table, column, .. } => {
                let rows = row_counts.get(table).copied().unwrap_or(0);
                suggestions.push(rule_r03_drop_column(table, column, rows));
            }

            // ── R04: ADD FOREIGN KEY without index on FK column ───────────
            ParsedStatement::AlterTableAddForeignKey { table, fk } => {
                suggestions.push(rule_r04_missing_fk_index(table, &fk.columns));
            }

            // ── R05: RENAME COLUMN ────────────────────────────────────────
            ParsedStatement::AlterTableRenameColumn { table, old, new } => {
                suggestions.push(rule_r05_rename_column(table, old, new));
            }

            // ── R06: RENAME TABLE ─────────────────────────────────────────
            ParsedStatement::AlterTableRenameTable { old, new } => {
                suggestions.push(rule_r06_rename_table(old, new));
            }

            // ── R07: ALTER COLUMN TYPE on a non-trivial table ─────────────
            ParsedStatement::AlterTableAlterColumnType {
                table,
                column,
                new_type,
            } => {
                let rows = row_counts.get(table).copied().unwrap_or(0);
                // Always emit for type changes — even small tables deserve a warning
                suggestions.push(rule_r07_alter_column_type(table, column, new_type, rows));
            }

            // ── R08: Long ACCESS EXCLUSIVE lock (catch-all for other DDL) ─
            ParsedStatement::DropTable { tables, .. } => {
                for t in tables {
                    let rows = row_counts.get(t).copied().unwrap_or(0);
                    let est = estimate_lock_secs(rows);
                    if est > 5 {
                        suggestions.push(rule_r08_long_lock(
                            &format!("DROP TABLE {t}"),
                            est,
                        ));
                    }
                }
            }

            _ => {}
        }
    }

    // Sort so most severe issues appear first
    suggestions.sort_by(|a, b| b.severity.cmp(&a.severity));
    suggestions
}

/// Rewrite the raw SQL text, applying all auto-fixable suggestions in-place.
///
/// Currently handles:
/// - **R01**: Inserts `CONCURRENTLY` after `CREATE [UNIQUE] INDEX`
///
/// Returns the modified SQL string. Lines not matched by any rule are
/// passed through unchanged.
pub fn apply_fixes(sql: &str, suggestions: &[FixSuggestion]) -> String {
    let has_r01 = suggestions.iter().any(|s| s.rule_id == "R01" && s.auto_fixable);
    if !has_r01 {
        return sql.to_string();
    }
    rewrite_index_concurrent(sql)
}

// ─────────────────────────────────────────────
// Rule implementations
// ─────────────────────────────────────────────

/// R01 — CREATE INDEX without CONCURRENTLY.
fn rule_r01_index_concurrently(
    table: &str,
    columns: &str,
    unique_kw: &str,
    name: &str,
    rows: u64,
) -> FixSuggestion {
    let rows_note = if rows > 0 {
        format!(
            " The table has approximately {} rows — index build will take roughly {} seconds.",
            fmt_rows(rows),
            rows / 500_000 + 1
        )
    } else {
        String::new()
    };
    FixSuggestion {
        rule_id: "R01".to_string(),
        title: "Use CREATE INDEX CONCURRENTLY to avoid blocking writes".to_string(),
        explanation: format!(
            "CREATE INDEX without CONCURRENTLY acquires a SHARE lock that blocks all \
             INSERT, UPDATE, and DELETE statements for the entire duration of the index \
             build.{rows_note} Using CONCURRENTLY performs two table scans and allows \
             DML to continue throughout, at the cost of a longer total build time. \
             Note: CONCURRENTLY cannot run inside a transaction block."
        ),
        fixed_sql: Some(format!(
            "CREATE {unique_kw}INDEX CONCURRENTLY {name}\n  ON {table}({columns});"
        )),
        migration_steps: None,
        severity: FixSeverity::Blocking,
        docs_url: Some(
            "https://www.postgresql.org/docs/current/sql-createindex.html#SQL-CREATEINDEX-CONCURRENTLY"
                .to_string(),
        ),
        auto_fixable: true,
    }
}

/// R02 — ADD COLUMN NOT NULL without DEFAULT.
fn rule_r02_add_not_null(
    table: &str,
    column: &str,
    data_type: &str,
    rows: u64,
) -> FixSuggestion {
    let rows_note = if rows > 0 {
        format!(" (~{} rows)", fmt_rows(rows))
    } else {
        String::new()
    };
    FixSuggestion {
        rule_id: "R02".to_string(),
        title: format!(
            "Adding NOT NULL column '{column}' without DEFAULT will fail on non-empty tables"
        ),
        explanation: format!(
            "ALTER TABLE {table}{rows_note} ADD COLUMN {column} {data_type} NOT NULL \
             fails immediately if the table contains any existing rows — PostgreSQL \
             cannot assign a value to the new column for those rows. Use the \
             three-step pattern below for a zero-downtime migration that works on \
             PostgreSQL 11+ (which stores the DEFAULT without rewriting the table)."
        ),
        fixed_sql: None,
        migration_steps: Some(vec![
            "-- Step 1: Add the column with a sensible DEFAULT (instant on PG ≥ 11 for constant defaults)".to_string(),
            format!("ALTER TABLE {table}"),
            format!("  ADD COLUMN {column} {data_type} NOT NULL DEFAULT 'YOUR_DEFAULT_VALUE';"),
            String::new(),
            "-- Step 2: Back-fill outdated rows in batches (avoids long lock)".to_string(),
            format!("-- Run this in a loop until 0 rows are updated:"),
            format!("UPDATE {table}"),
            format!("  SET {column} = 'YOUR_REAL_VALUE'"),
            format!("  WHERE {column} = 'YOUR_DEFAULT_VALUE'"),
            format!("  LIMIT 10000;"),
            String::new(),
            "-- Step 3: Remove the synthetic default (optional) once all rows are back-filled".to_string(),
            format!("ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT;"),
        ]),
        severity: FixSeverity::Blocking,
        docs_url: Some(
            "https://www.postgresql.org/docs/current/sql-altertable.html".to_string(),
        ),
        auto_fixable: false,
    }
}

/// R03 — DROP COLUMN; advise two-phase deployment.
fn rule_r03_drop_column(table: &str, column: &str, rows: u64) -> FixSuggestion {
    let rows_note = if rows > 1_000_000 {
        format!(" The table has ~{} rows.", fmt_rows(rows))
    } else {
        String::new()
    };
    let severity = if rows > 1_000_000 {
        FixSeverity::Blocking
    } else {
        FixSeverity::Warning
    };
    FixSuggestion {
        rule_id: "R03".to_string(),
        title: format!("Deploy app changes before dropping column '{column}' from '{table}'"),
        explanation: format!(
            "DROP COLUMN is irreversible and holds an ACCESS EXCLUSIVE lock for the \
             duration of the catalog update.{rows_note}  Any in-flight query or \
             transaction referencing this column will fail.  Use the two-phase \
             deployment pattern to ensure zero application downtime."
        ),
        fixed_sql: None,
        migration_steps: Some(vec![
            format!("-- Phase 1 — Application deploy (no DB change yet)"),
            format!("-- Remove all code that reads or writes '{column}' from '{table}'"),
            format!("-- Verify no ORM model, query, or migration references this column"),
            String::new(),
            format!("-- Phase 2 — Run this migration AFTER the app is fully deployed"),
            format!("ALTER TABLE {table} DROP COLUMN IF EXISTS {column};"),
            String::new(),
            format!("-- Optional: create a backup before dropping"),
            format!("-- CREATE TABLE {table}_{column}_backup AS"),
            format!("--   SELECT id, {column} FROM {table};"),
        ]),
        severity,
        docs_url: Some(
            "https://www.postgresql.org/docs/current/sql-altertable.html".to_string(),
        ),
        auto_fixable: false,
    }
}

/// R04 — ADD FOREIGN KEY with no index on the referencing column.
fn rule_r04_missing_fk_index(table: &str, fk_columns: &[String]) -> FixSuggestion {
    let col_list = fk_columns.join(", ");
    let col_snake = fk_columns.join("_");
    FixSuggestion {
        rule_id: "R04".to_string(),
        title: format!(
            "Add an index on FK column(s) ({col_list}) to prevent sequential scans"
        ),
        explanation: format!(
            "PostgreSQL does NOT automatically create an index on foreign key columns. \
             Without an index on '{table}.({col_list})', every DELETE or UPDATE on the \
             referenced parent table triggers a full sequential scan of '{table}' to \
             check referential integrity. This is catastrophic on tables larger than \
             10k rows and grows linearly with table size."
        ),
        fixed_sql: Some(format!(
            "CREATE INDEX CONCURRENTLY idx_{table}_{col_snake}\n  ON {table}({col_list});"
        )),
        migration_steps: None,
        severity: FixSeverity::Warning,
        docs_url: Some(
            "https://www.postgresql.org/docs/current/indexes-intro.html".to_string(),
        ),
        auto_fixable: false,
    }
}

/// R05 — RENAME COLUMN; suggest expand-contract pattern.
fn rule_r05_rename_column(table: &str, old: &str, new: &str) -> FixSuggestion {
    FixSuggestion {
        rule_id: "R05".to_string(),
        title: format!(
            "Use expand-contract pattern to rename '{old}' → '{new}' without downtime"
        ),
        explanation: format!(
            "Renaming column '{old}' in '{table}' is a **breaking change** for every \
             piece of application code, ORM model, stored procedure, view, and query \
             that references the old column name. The expand-contract (aka \
             parallel-change) pattern lets you rename a column while keeping both \
             names alive during the transition window, giving you a zero-downtime \
             path."
        ),
        fixed_sql: None,
        migration_steps: Some(vec![
            format!("-- Migration A: Add new column and sync data"),
            format!("ALTER TABLE {table} ADD COLUMN {new} <same_type_as_{old}>;"),
            format!("UPDATE {table} SET {new} = {old};"),
            String::new(),
            format!("-- Application deploy: Dual-write to both '{old}' and '{new}'"),
            format!("--   (reads still come from '{old}')"),
            String::new(),
            format!("-- Application deploy: Switch reads to '{new}'"),
            format!("--   (still write to both)"),
            String::new(),
            format!("-- Application deploy: Stop writing to '{old}'"),
            String::new(),
            format!("-- Migration B: Drop old column"),
            format!("ALTER TABLE {table} DROP COLUMN {old};"),
        ]),
        severity: FixSeverity::Blocking,
        docs_url: Some(
            "https://martinfowler.com/bliki/ParallelChange.html".to_string(),
        ),
        auto_fixable: false,
    }
}

/// R06 — RENAME TABLE; suggest view-based transition.
fn rule_r06_rename_table(old: &str, new: &str) -> FixSuggestion {
    FixSuggestion {
        rule_id: "R06".to_string(),
        title: format!(
            "Renaming table '{old}' → '{new}' breaks all downstream code instantly"
        ),
        explanation: format!(
            "Renaming table '{old}' invalidates ALL queries, ORM models, foreign key \
             constraints, views, triggers, and stored procedures that reference the old \
             name. This is one of the most dangerous DDL operations. Use a transitional \
             compatibility view (Option A) or the full expand-contract pattern (Option B) \
             to provide a zero-downtime migration path."
        ),
        fixed_sql: None,
        migration_steps: Some(vec![
            format!("-- ── Option A: Rename + leave compatibility view ────────────────"),
            format!("ALTER TABLE {old} RENAME TO {new};"),
            format!("-- Create a view using the old name so existing queries still work:"),
            format!("CREATE VIEW {old} AS SELECT * FROM {new};"),
            format!("-- Remove the view after all app code has been updated to use '{new}'"),
            String::new(),
            format!("-- ── Option B: Full expand-contract ────────────────────────────"),
            format!("-- Step 1: Create new table '{new}' with identical schema"),
            format!("-- Step 2: Create triggers to sync writes from '{old}' → '{new}'"),
            format!("-- Step 3: Back-fill '{new}' from '{old}' for historical rows"),
            format!("-- Step 4: Deploy app to write to '{new}', read from both"),
            format!("-- Step 5: Deploy app to read only from '{new}'"),
            format!("-- Step 6: Drop triggers + old table '{old}'"),
        ]),
        severity: FixSeverity::Blocking,
        docs_url: Some(
            "https://braintreepayments.com/blog/safe-operations-for-high-volume-postgresql/"
                .to_string(),
        ),
        auto_fixable: false,
    }
}

/// R07 — ALTER COLUMN TYPE; advise shadow-column pattern.
fn rule_r07_alter_column_type(
    table: &str,
    column: &str,
    new_type: &str,
    rows: u64,
) -> FixSuggestion {
    let rows_clause = if rows > 0 {
        format!(" (~{} rows)", fmt_rows(rows))
    } else {
        String::new()
    };
    FixSuggestion {
        rule_id: "R07".to_string(),
        title: format!(
            "Type change on '{table}.{column}' triggers full table rewrite under ACCESS EXCLUSIVE lock"
        ),
        explanation: format!(
            "Changing the type of column '{column}' in '{table}'{rows_clause} causes \
             PostgreSQL to rewrite the entire table while holding an ACCESS EXCLUSIVE \
             lock. All reads and writes are blocked for the entire duration. For \
             large tables this can mean minutes of downtime. Use the shadow-column \
             pattern to perform the type change online."
        ),
        fixed_sql: None,
        migration_steps: Some(vec![
            format!("-- Step 1: Add shadow column with new type"),
            format!("ALTER TABLE {table} ADD COLUMN {column}_v2 {new_type};"),
            String::new(),
            format!("-- Step 2: Back-fill in batches (prevents long lock)"),
            format!("-- Run in a loop until UPDATE returns 0 rows:"),
            format!("UPDATE {table}"),
            format!("  SET {column}_v2 = {column}::{new_type}"),
            format!("  WHERE {column}_v2 IS NULL"),
            format!("  LIMIT 10000;"),
            String::new(),
            format!("-- Step 3: Deploy app to write to both columns"),
            String::new(),
            format!("-- Step 4: Atomically swap column names"),
            format!("ALTER TABLE {table}"),
            format!("  RENAME COLUMN {column}    TO {column}_old;"),
            format!("ALTER TABLE {table}"),
            format!("  RENAME COLUMN {column}_v2 TO {column};"),
            String::new(),
            format!("-- Step 5: Drop old column after verifying app health"),
            format!("ALTER TABLE {table} DROP COLUMN {column}_old;"),
        ]),
        severity: FixSeverity::Blocking,
        docs_url: Some(
            "https://www.postgresql.org/docs/current/sql-altertable.html".to_string(),
        ),
        auto_fixable: false,
    }
}

/// R08 — Long ACCESS EXCLUSIVE lock; suggest lock_timeout + pg_repack.
fn rule_r08_long_lock(description: &str, est_secs: u64) -> FixSuggestion {
    FixSuggestion {
        rule_id: "R08".to_string(),
        title: format!(
            "ACCESS EXCLUSIVE lock held for ~{est_secs}s — protect with lock_timeout"
        ),
        explanation: format!(
            "The operation '{}' acquires ACCESS EXCLUSIVE lock for an estimated \
             ~{est_secs} seconds. During this window every query, transaction, and \
             connection waiting to access the table is queued. A single long-running \
             transaction before the migration can turn a 30-second lock into minutes \
             of application downtime. Set lock_timeout to prevent lock pile-up.",
            shorten_desc(description, 80)
        ),
        fixed_sql: None,
        migration_steps: Some(vec![
            "-- Wrap your migration in a lock_timeout guard:".to_string(),
            "BEGIN;".to_string(),
            "  SET lock_timeout = '3s';        -- abort if lock is not acquired in 3s".to_string(),
            "  SET statement_timeout = '120s'; -- abort if statement runs > 2 min".to_string(),
            String::new(),
            "  -- YOUR MIGRATION HERE".to_string(),
            String::new(),
            "COMMIT;".to_string(),
            String::new(),
            "-- For tables > 1GB, consider pg_repack for zero-downtime online rewrites:".to_string(),
            "-- https://github.com/reorg/pg_repack".to_string(),
            "-- pg_repack --dbname=<db_url> --table=<table_name>".to_string(),
        ]),
        severity: FixSeverity::Warning,
        docs_url: Some("https://github.com/reorg/pg_repack".to_string()),
        auto_fixable: false,
    }
}

// ─────────────────────────────────────────────
// SQL rewriting
// ─────────────────────────────────────────────

/// Rewrite raw SQL: insert `CONCURRENTLY` after every `CREATE [UNIQUE] INDEX`
/// that does not already have it.
///
/// This preserves all other SQL untouched and is safe to apply repeatedly.
pub fn rewrite_index_concurrent(sql: &str) -> String {
    sql.lines()
        .map(|line| {
            let upper = line.to_uppercase();
            // Already concurrent — leave alone
            if upper.contains("CONCURRENTLY") {
                return line.to_string();
            }

            // CREATE UNIQUE INDEX <name> → CREATE UNIQUE INDEX CONCURRENTLY <name>
            if let Some(pos) = upper.find("CREATE UNIQUE INDEX") {
                let after = pos + "CREATE UNIQUE INDEX".len();
                let prefix = &line[..after];
                let rest = line[after..].trim_start();
                return format!("{prefix} CONCURRENTLY {rest}");
            }

            // CREATE INDEX <name> → CREATE INDEX CONCURRENTLY <name>
            if let Some(pos) = upper.find("CREATE INDEX") {
                let after = pos + "CREATE INDEX".len();
                let prefix = &line[..after];
                let rest = line[after..].trim_start();
                return format!("{prefix} CONCURRENTLY {rest}");
            }

            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ─────────────────────────────────────────────
// Formatting helpers
// ─────────────────────────────────────────────

/// Format a row count as a human-readable string (e.g. "187.2M").
fn fmt_rows(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Rough estimate: seconds an ACCESS EXCLUSIVE lock will be held, based on
/// estimated row count at ~500k rows/second.
fn estimate_lock_secs(rows: u64) -> u64 {
    if rows < 500_000 {
        1
    } else {
        rows / 500_000
    }
}

/// Truncate a description string to `max` chars with an ellipsis.
fn shorten_desc(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

// ─────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn test_r01_triggers_for_non_concurrent_index() {
        let sql = "CREATE INDEX idx_users_email ON users(email);";
        let stmts = parser::parse(sql).expect("parse");
        let fixes = suggest_fixes(&stmts, &HashMap::new());
        assert!(fixes.iter().any(|f| f.rule_id == "R01"));
        assert!(fixes.iter().any(|f| f.auto_fixable));
    }

    #[test]
    fn test_r01_skipped_for_concurrent_index() {
        let sql = "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);";
        let stmts = parser::parse(sql).expect("parse");
        let fixes = suggest_fixes(&stmts, &HashMap::new());
        assert!(fixes.iter().all(|f| f.rule_id != "R01"));
    }

    #[test]
    fn test_r02_triggers_for_not_null_no_default() {
        let sql = "ALTER TABLE users ADD COLUMN verified BOOLEAN NOT NULL;";
        let stmts = parser::parse(sql).expect("parse");
        let fixes = suggest_fixes(&stmts, &HashMap::new());
        assert!(fixes.iter().any(|f| f.rule_id == "R02"));
    }

    #[test]
    fn test_rewrite_concurrent() {
        let sql = "CREATE INDEX idx_a ON t(col);";
        let result = rewrite_index_concurrent(sql);
        assert!(result.contains("CONCURRENTLY"), "got: {result}");
    }

    #[test]
    fn test_rewrite_concurrent_idempotent() {
        let sql = "CREATE INDEX CONCURRENTLY idx_a ON t(col);";
        let result = rewrite_index_concurrent(sql);
        // Should not double-insert CONCURRENTLY
        let count = result.matches("CONCURRENTLY").count();
        assert_eq!(count, 1, "got: {result}");
    }
}
