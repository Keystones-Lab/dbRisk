//! Lock simulation and migration execution timeline.
//!
//! PostgreSQL has a well-defined lock hierarchy.  Every DDL operation acquires
//! a specific lock mode.  This module encodes those rules so the tool can tell
//! the user exactly what will be blocked — and for how long.

use crate::parser::ParsedStatement;
use crate::types::RiskLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────
// PostgreSQL lock hierarchy (8 modes)
// ─────────────────────────────────────────────
//
// Strongest → weakest:
//   ACCESS EXCLUSIVE  — blocks everything (ALTER TABLE, DROP, TRUNCATE)
//   EXCLUSIVE         — blocks reads + writes (rare in DDL)
//   SHARE ROW EXCLUSIVE
//   SHARE UPDATE EXCLUSIVE — used by VACUUM, ANALYZE
//   SHARE             — blocks writes; CREATE INDEX (non-concurrent)
//   ROW SHARE         — SELECT FOR UPDATE
//   ROW EXCLUSIVE     — DML (INSERT, UPDATE, DELETE)
//   ACCESS SHARE      — plain SELECT
//
// Conflict matrix summary we care about:
//   ACCESS EXCLUSIVE conflicts with everything.
//   SHARE conflicts with ROW EXCLUSIVE and stronger.
//   ACCESS SHARE conflicts only with ACCESS EXCLUSIVE.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LockMode {
    AccessShare,           // 1 — SELECT
    RowShare,              // 2 — SELECT FOR UPDATE
    RowExclusive,          // 3 — DML
    ShareUpdateExclusive,  // 4 — VACUUM, CREATE INDEX CONCURRENTLY phase 1
    Share,                 // 5 — CREATE INDEX (blocking)
    ShareRowExclusive,     // 6 — CREATE TRIGGER
    Exclusive,             // 7 — rare
    AccessExclusive,       // 8 — ALTER TABLE, DROP, TRUNCATE
}

impl LockMode {
    pub fn name(&self) -> &'static str {
        match self {
            LockMode::AccessShare => "ACCESS SHARE",
            LockMode::RowShare => "ROW SHARE",
            LockMode::RowExclusive => "ROW EXCLUSIVE",
            LockMode::ShareUpdateExclusive => "SHARE UPDATE EXCLUSIVE",
            LockMode::Share => "SHARE",
            LockMode::ShareRowExclusive => "SHARE ROW EXCLUSIVE",
            LockMode::Exclusive => "EXCLUSIVE",
            LockMode::AccessExclusive => "ACCESS EXCLUSIVE",
        }
    }

    /// Does this lock block ordinary reads (SELECT)?
    pub fn blocks_reads(&self) -> bool {
        *self >= LockMode::AccessExclusive
    }

    /// Does this lock block ordinary writes (INSERT / UPDATE / DELETE)?
    pub fn blocks_writes(&self) -> bool {
        *self >= LockMode::Share
    }

    /// Human-readable impact string.
    pub fn impact(&self) -> &'static str {
        match self {
            LockMode::AccessShare => "no blocking",
            LockMode::RowShare => "blocks ACCESS EXCLUSIVE only",
            LockMode::RowExclusive => "blocks SHARE and stronger",
            LockMode::ShareUpdateExclusive => "blocks DDL; allows reads+writes",
            LockMode::Share => "blocks writes (DML blocked)",
            LockMode::ShareRowExclusive => "blocks writes + most DDL",
            LockMode::Exclusive => "blocks reads + writes",
            LockMode::AccessExclusive => "blocks ALL access (reads + writes)",
        }
    }
}

// ─────────────────────────────────────────────
// Lock event for a single statement
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockEvent {
    /// SQL statement description
    pub statement: String,
    /// Affected table(s)
    pub tables: Vec<String>,
    /// The lock mode acquired
    pub lock_mode: LockMode,
    /// True if ordinary SELECT queries will be blocked
    pub blocks_reads: bool,
    /// True if INSERT/UPDATE/DELETE will be blocked
    pub blocks_writes: bool,
    /// Human-readable impact
    pub impact: String,
    /// Estimated hold duration in seconds
    pub estimated_hold_secs: u64,
    /// Safety recommendation for this specific operation
    pub safe_alternative: Option<String>,
}

// ─────────────────────────────────────────────
// Timeline step
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineStep {
    /// Offset from migration start in seconds
    pub offset_secs: u64,
    /// Human-readable event description
    pub event: String,
    /// Which lock is held at this moment (None = free)
    pub lock: Option<LockMode>,
    /// Which tables are affected
    pub tables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationTimeline {
    /// Total estimated duration in seconds
    pub total_secs: u64,
    pub steps: Vec<TimelineStep>,
    pub lock_events: Vec<LockEvent>,
    /// Risk assessment of the whole lock pattern
    pub lock_risk: RiskLevel,
    /// Maximum concurrent lock hold duration  
    pub max_lock_hold_secs: u64,
}

// ─────────────────────────────────────────────
// The simulator
// ─────────────────────────────────────────────

pub struct LockSimulator {
    /// row_counts: table_name → estimated rows
    row_counts: HashMap<String, u64>,
}

impl LockSimulator {
    pub fn new(row_counts: HashMap<String, u64>) -> Self {
        Self { row_counts }
    }

    /// Simulate the full migration and return a timeline.
    pub fn simulate(&self, statements: &[ParsedStatement]) -> MigrationTimeline {
        let mut lock_events: Vec<LockEvent> = Vec::new();
        for stmt in statements {
            if let Some(ev) = self.lock_for(stmt) {
                lock_events.push(ev);
            }
        }

        let timeline = self.build_timeline(&lock_events);
        let total_secs = timeline.last().map(|s| s.offset_secs).unwrap_or(0);
        let max_lock_hold_secs = lock_events.iter().map(|e| e.estimated_hold_secs).max().unwrap_or(0);

        let lock_risk = self.assess_lock_risk(&lock_events, max_lock_hold_secs);

        MigrationTimeline {
            total_secs,
            steps: timeline,
            lock_events,
            lock_risk,
            max_lock_hold_secs,
        }
    }

    // ── Derive the lock event for a single parsed statement ──────────────

    fn lock_for(&self, stmt: &ParsedStatement) -> Option<LockEvent> {
        match stmt {
            // ── DROP TABLE: ACCESS EXCLUSIVE ──────────────────────────────
            ParsedStatement::DropTable { tables, .. } => {
                let hold = self.row_based_hold(tables, 1, 5);
                Some(LockEvent {
                    statement: format!("DROP TABLE {}", tables.join(", ")),
                    tables: tables.clone(),
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: None, // DROP TABLE has no safe alternative
                })
            }

            // ── ALTER TABLE ADD COLUMN ─────────────────────────────────────
            ParsedStatement::AlterTableAddColumn { table, column } => {
                // In PG 11+ adding a NOT NULL column with a volatile default
                // requires a full table rewrite → long ACCESS EXCLUSIVE lock.
                // Adding a nullable/defaulted column is instant in PG 11+.
                let is_instant = column.nullable || column.has_default;
                let hold = if is_instant {
                    1
                } else {
                    self.row_based_hold(std::slice::from_ref(table), 1, 8)
                };
                Some(LockEvent {
                    statement: format!("ALTER TABLE {} ADD COLUMN {}", table, column.name),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: if !column.nullable && !column.has_default {
                        Some(format!(
                            "ALTER TABLE {} ADD COLUMN {} {} DEFAULT <expr> NOT NULL; \
                             -- then in a separate migration: ALTER TABLE {} ALTER COLUMN {} DROP DEFAULT",
                            table, column.name, column.data_type, table, column.name
                        ))
                    } else {
                        None
                    },
                })
            }

            // ── ALTER TABLE DROP COLUMN ───────────────────────────────────
            ParsedStatement::AlterTableDropColumn { table, column, .. } => {
                let hold = self.row_based_hold(std::slice::from_ref(table), 1, 10);
                Some(LockEvent {
                    statement: format!("ALTER TABLE {} DROP COLUMN {}", table, column),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: Some(
                        "Phase 1: remove all app code that reads this column → deploy. \
                         Phase 2: run this DROP COLUMN in the next migration."
                            .to_string(),
                    ),
                })
            }

            // ── ALTER COLUMN TYPE ─────────────────────────────────────────
            // Full table rewrite → long ACCESS EXCLUSIVE.
            ParsedStatement::AlterTableAlterColumnType { table, column, new_type } => {
                let hold = self.row_based_hold(std::slice::from_ref(table), 2, 15);
                Some(LockEvent {
                    statement: format!(
                        "ALTER TABLE {} ALTER COLUMN {} TYPE {}",
                        table, column, new_type
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: Some(format!(
                        "Background migration: \
                         1. ADD COLUMN {col}_new {ty} \
                         2. Backfill in batches: UPDATE {tbl} SET {col}_new = {col}::text LIMIT 10000 \
                         3. Deploy app with dual-read \
                         4. DROP COLUMN {col}; RENAME COLUMN {col}_new TO {col}",
                        col = column, ty = new_type, tbl = table
                    )),
                })
            }

            // ── SET NOT NULL ──────────────────────────────────────────────
            // PostgreSQL must scan every row → can be slow.
            ParsedStatement::AlterTableSetNotNull { table, column } => {
                let hold = self.row_based_hold(std::slice::from_ref(table), 1, 10);
                Some(LockEvent {
                    statement: format!(
                        "ALTER TABLE {} ALTER COLUMN {} SET NOT NULL",
                        table, column
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: Some(format!(
                        "Use a NOT VALID CHECK constraint first: \
                         ALTER TABLE {tbl} ADD CONSTRAINT {col}_not_null CHECK ({col} IS NOT NULL) NOT VALID; \
                         -- validate in background: \
                         ALTER TABLE {tbl} VALIDATE CONSTRAINT {col}_not_null;",
                        tbl = table, col = column
                    )),
                })
            }

            // ── CREATE INDEX (blocking) ───────────────────────────────────
            ParsedStatement::CreateIndex {
                index_name,
                table,
                columns,
                unique,
                concurrently,
            } if !concurrently => {
                let hold = self.row_based_hold(std::slice::from_ref(table), 1, 20);
                let name = index_name.as_deref().unwrap_or("unnamed");
                Some(LockEvent {
                    statement: format!(
                        "CREATE {}INDEX {} ON {} ({})",
                        if *unique { "UNIQUE " } else { "" },
                        name,
                        table,
                        columns.join(", ")
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::Share,
                    blocks_reads: false,
                    blocks_writes: true,
                    impact: LockMode::Share.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: Some(format!(
                        "CREATE {}INDEX CONCURRENTLY {} ON {} ({});",
                        if *unique { "UNIQUE " } else { "" },
                        name,
                        table,
                        columns.join(", ")
                    )),
                })
            }

            // ── CREATE INDEX CONCURRENTLY ─────────────────────────────────
            ParsedStatement::CreateIndex {
                index_name,
                table,
                columns,
                unique,
                concurrently: true,
            } => {
                // CONCURRENTLY takes SHARE UPDATE EXCLUSIVE (allows reads+writes)
                let hold = self.row_based_hold(std::slice::from_ref(table), 2, 30);
                let name = index_name.as_deref().unwrap_or("unnamed");
                Some(LockEvent {
                    statement: format!(
                        "CREATE {}INDEX CONCURRENTLY {} ON {} ({})",
                        if *unique { "UNIQUE " } else { "" },
                        name,
                        table,
                        columns.join(", ")
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::ShareUpdateExclusive,
                    blocks_reads: false,
                    blocks_writes: false,
                    impact: LockMode::ShareUpdateExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: None, // already optimal
                })
            }

            // ── ADD FOREIGN KEY ───────────────────────────────────────────
            ParsedStatement::AlterTableAddForeignKey { table, fk } => {
                let hold = self.row_based_hold(&[table.clone(), fk.ref_table.clone()], 1, 5);
                Some(LockEvent {
                    statement: format!(
                        "ALTER TABLE {} ADD FOREIGN KEY ({}) REFERENCES {}({})",
                        table,
                        fk.columns.join(", "),
                        fk.ref_table,
                        fk.ref_columns.join(", ")
                    ),
                    tables: vec![table.clone(), fk.ref_table.clone()],
                    lock_mode: LockMode::ShareRowExclusive,
                    blocks_reads: false,
                    blocks_writes: true,
                    impact: LockMode::ShareRowExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: Some(format!(
                        "ALTER TABLE {} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {}({}) NOT VALID; \
                         -- then in a separate session (low traffic): \
                         ALTER TABLE {} VALIDATE CONSTRAINT {};",
                        table,
                        fk.constraint_name.as_deref().unwrap_or("fk_name"),
                        fk.columns.join(", "),
                        fk.ref_table,
                        fk.ref_columns.join(", "),
                        table,
                        fk.constraint_name.as_deref().unwrap_or("fk_name"),
                    )),
                })
            }

            // ── RENAME TABLE ──────────────────────────────────────────────
            ParsedStatement::AlterTableRenameTable { old, new } => {
                Some(LockEvent {
                    statement: format!("ALTER TABLE {} RENAME TO {}", old, new),
                    tables: vec![old.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: 1,
                    safe_alternative: Some(format!(
                        "Create a view: CREATE VIEW {} AS SELECT * FROM {}; \
                         then migrate app code to use the new name before dropping the view.",
                        new, old
                    )),
                })
            }

            // ── RENAME COLUMN ─────────────────────────────────────────────
            ParsedStatement::AlterTableRenameColumn { table, old, new } => {
                Some(LockEvent {
                    statement: format!(
                        "ALTER TABLE {} RENAME COLUMN {} TO {}",
                        table, old, new
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: 1,
                    safe_alternative: Some(format!(
                        "Phase 1: ADD COLUMN {new} type; sync writes in app code to both columns. \
                         Phase 2: backfill. Phase 3: remove old references. Phase 4: DROP COLUMN {old}.",
                        old = old, new = new
                    )),
                })
            }

            // ── DROP INDEX ────────────────────────────────────────────────
            ParsedStatement::DropIndex { names, concurrently, .. } => {
                Some(LockEvent {
                    statement: format!("DROP INDEX {}", names.join(", ")),
                    tables: vec![],
                    lock_mode: if *concurrently {
                        LockMode::ShareUpdateExclusive
                    } else {
                        LockMode::AccessExclusive
                    },
                    blocks_reads: !concurrently,
                    blocks_writes: true,
                    impact: if *concurrently {
                        LockMode::ShareUpdateExclusive.impact().to_string()
                    } else {
                        LockMode::AccessExclusive.impact().to_string()
                    },
                    estimated_hold_secs: 1,
                    safe_alternative: if !concurrently {
                        Some(format!("DROP INDEX CONCURRENTLY {};", names.join(", ")))
                    } else {
                        None
                    },
                })
            }

            // ── ANYTHING ELSE that touches a table ────────────────────────
            ParsedStatement::AlterTableDropConstraint { table, constraint, .. } => {
                Some(LockEvent {
                    statement: format!(
                        "ALTER TABLE {} DROP CONSTRAINT {}",
                        table, constraint
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: 1,
                    safe_alternative: None,
                })
            }

            ParsedStatement::AlterTableAddPrimaryKey { table, columns } => {
                let hold = self.row_based_hold(std::slice::from_ref(table), 2, 25);
                Some(LockEvent {
                    statement: format!(
                        "ALTER TABLE {} ADD PRIMARY KEY ({})",
                        table,
                        columns.join(", ")
                    ),
                    tables: vec![table.clone()],
                    lock_mode: LockMode::AccessExclusive,
                    blocks_reads: true,
                    blocks_writes: true,
                    impact: LockMode::AccessExclusive.impact().to_string(),
                    estimated_hold_secs: hold,
                    safe_alternative: Some(format!(
                        "CREATE UNIQUE INDEX CONCURRENTLY pkey_idx ON {} ({});\n\
                         ALTER TABLE {} ADD CONSTRAINT {}_pkey PRIMARY KEY USING INDEX pkey_idx;",
                        table,
                        columns.join(", "),
                        table,
                        table,
                    )),
                })
            }

            // CREATE TABLE, Other — no lock events worth surfacing
            _ => None,
        }
    }

    // ── Row-count-based hold time heuristic ──────────────────────────────
    // base_secs: minimum hold regardless of rows
    // secs_per_million: how many extra seconds per million rows
    fn row_based_hold(&self, tables: &[String], base_secs: u64, secs_per_million: u64) -> u64 {
        let max_rows: u64 = tables
            .iter()
            .filter_map(|t| self.row_counts.get(t))
            .max()
            .copied()
            .unwrap_or(0);

        let millions = max_rows / 1_000_000;
        base_secs + millions * secs_per_million
    }

    // ── Build the human-readable timeline from lock events ───────────────
    fn build_timeline(&self, events: &[LockEvent]) -> Vec<TimelineStep> {
        let mut steps: Vec<TimelineStep> = Vec::new();
        let mut offset: u64 = 0;

        steps.push(TimelineStep {
            offset_secs: 0,
            event: "Migration started".to_string(),
            lock: None,
            tables: vec![],
        });

        for ev in events {
            // Acquire lock
            steps.push(TimelineStep {
                offset_secs: offset,
                event: format!("Acquire {} lock — {}", ev.lock_mode.name(), ev.statement),
                lock: Some(ev.lock_mode),
                tables: ev.tables.clone(),
            });

            // Execute statement (halfway through hold time)
            let exec_offset = offset + ev.estimated_hold_secs / 2 + 1;
            steps.push(TimelineStep {
                offset_secs: exec_offset,
                event: format!("Execute: {}", ev.statement),
                lock: Some(ev.lock_mode),
                tables: ev.tables.clone(),
            });

            // Release lock
            offset += ev.estimated_hold_secs;
            steps.push(TimelineStep {
                offset_secs: offset,
                event: format!("Release {} lock", ev.lock_mode.name()),
                lock: None,
                tables: ev.tables.clone(),
            });

            offset += 1; // 1s pause between statements
        }

        steps.push(TimelineStep {
            offset_secs: offset,
            event: "Migration complete".to_string(),
            lock: None,
            tables: vec![],
        });

        steps
    }

    // ── Overall lock risk assessment ─────────────────────────────────────
    fn assess_lock_risk(&self, events: &[LockEvent], max_hold: u64) -> RiskLevel {
        let has_read_block = events.iter().any(|e| e.blocks_reads);
        let has_write_block = events.iter().any(|e| e.blocks_writes);

        match (has_read_block, has_write_block, max_hold) {
            (true, _, secs) if secs > 30 => RiskLevel::Critical,
            (true, _, _) => RiskLevel::High,
            (false, true, secs) if secs > 60 => RiskLevel::High,
            (false, true, _) => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
}
