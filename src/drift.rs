//! Schema drift detection.
//!
//! `schema-risk diff --db-url postgres://...` connects to a live database and
//! compares what the database actually contains against what you would expect
//! based on the migration files you have.
//!
//! This answers the question: "Has someone edited the production schema by
//! hand, or are there migrations that haven't run yet?"
//!
//! Compiled unconditionally; the actual DB connection is feature-gated.

use crate::db::LiveSchema;
use crate::graph::SchemaGraph;
use crate::types::RiskLevel;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────
// Drift finding types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DriftFinding {
    /// Table exists in the DB but not in any migration file
    ExtraTable { table: String },
    /// Table is in migration files but not in the DB (migration not run yet)
    MissingTable { table: String },
    /// Column type in DB doesn't match the migration definition
    ColumnTypeMismatch {
        table: String,
        column: String,
        in_migration: String,
        in_database: String,
    },
    /// Column exists in DB but not in migration
    ExtraColumn { table: String, column: String },
    /// Column is in migration but not in DB
    MissingColumn { table: String, column: String },
    /// Index exists in DB but the migration never created it
    ExtraIndex { table: String, index: String },
    /// Migration creates an index that isn't in the DB (not applied)
    MissingIndex { table: String, index: String },
    /// Nullable mismatch
    NullableMismatch {
        table: String,
        column: String,
        in_migration: bool,
        in_database: bool,
    },
}

impl DriftFinding {
    pub fn severity(&self) -> RiskLevel {
        match self {
            DriftFinding::ExtraTable { .. } => RiskLevel::High,
            DriftFinding::MissingTable { .. } => RiskLevel::Critical,
            DriftFinding::ColumnTypeMismatch { .. } => RiskLevel::Critical,
            DriftFinding::ExtraColumn { .. } => RiskLevel::Low,
            DriftFinding::MissingColumn { .. } => RiskLevel::High,
            DriftFinding::ExtraIndex { .. } => RiskLevel::Low,
            DriftFinding::MissingIndex { .. } => RiskLevel::Medium,
            DriftFinding::NullableMismatch { .. } => RiskLevel::Medium,
        }
    }

    pub fn description(&self) -> String {
        match self {
            DriftFinding::ExtraTable { table } => {
                format!("Table '{}' exists in the database but not in any migration file", table)
            }
            DriftFinding::MissingTable { table } => {
                format!("Table '{}' is defined in migrations but not found in the live database", table)
            }
            DriftFinding::ColumnTypeMismatch { table, column, in_migration, in_database } => {
                format!(
                    "Column '{}.{}': migration says '{}' but database has '{}'",
                    table, column, in_migration, in_database
                )
            }
            DriftFinding::ExtraColumn { table, column } => {
                format!("Column '{}.{}' exists in database but not in migration files", table, column)
            }
            DriftFinding::MissingColumn { table, column } => {
                format!("Column '{}.{}' is in migration files but not in the database", table, column)
            }
            DriftFinding::ExtraIndex { table, index } => {
                format!("Index '{}' on '{}' exists in database but not in migration files", index, table)
            }
            DriftFinding::MissingIndex { table, index } => {
                format!("Index '{}' on '{}' is in migration files but not in the database", index, table)
            }
            DriftFinding::NullableMismatch { table, column, in_migration, in_database } => {
                format!(
                    "Nullable mismatch on '{}.{}': migration says nullable={}, database says nullable={}",
                    table, column, in_migration, in_database
                )
            }
        }
    }
}

// ─────────────────────────────────────────────
// Drift report
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub overall_drift: RiskLevel,
    pub total_findings: usize,
    pub findings: Vec<DriftFinding>,
    pub migration_tables: Vec<String>,
    pub database_tables: Vec<String>,
    pub in_sync: bool,
}

impl DriftReport {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

// ─────────────────────────────────────────────
// Diff engine
// ─────────────────────────────────────────────

/// Compare the schema graph inferred from migration files against the live
/// database snapshot.
pub fn diff(migration_graph: &SchemaGraph, live: &LiveSchema) -> DriftReport {
    let mut findings: Vec<DriftFinding> = Vec::new();

    let migration_tables: Vec<String> = migration_graph.all_tables();
    let database_tables: Vec<String> = live.tables.keys().cloned().collect();

    // Tables in DB but not in migrations
    for db_table in &database_tables {
        if !migration_tables.iter().any(|t| t.eq_ignore_ascii_case(db_table)) {
            findings.push(DriftFinding::ExtraTable { table: db_table.clone() });
        }
    }

    // Tables in migrations but not in DB
    for mig_table in &migration_tables {
        if !database_tables.iter().any(|t| t.eq_ignore_ascii_case(mig_table)) {
            findings.push(DriftFinding::MissingTable { table: mig_table.clone() });
        }
    }

    // For tables that exist in both, check columns and indexes
    for mig_table in &migration_tables {
        let live_meta = database_tables
            .iter()
            .find(|t| t.eq_ignore_ascii_case(mig_table))
            .and_then(|t| live.tables.get(t));

        let Some(live_meta) = live_meta else { continue };

        // Get migration columns from the graph
        let mig_column_keys: Vec<String> = migration_graph
            .column_index
            .keys()
            .filter(|k| k.starts_with(&format!("{}.", mig_table)))
            .map(|k| k.split('.').nth(1).unwrap_or("").to_string())
            .collect();

        // Columns in DB but not in migration
        for live_col in &live_meta.columns {
            if !mig_column_keys
                .iter()
                .any(|c| c.eq_ignore_ascii_case(&live_col.name))
            {
                findings.push(DriftFinding::ExtraColumn {
                    table: mig_table.clone(),
                    column: live_col.name.clone(),
                });
            }
        }

        // Columns in migration but not in DB
        for mig_col in &mig_column_keys {
            let live_col = live_meta
                .columns
                .iter()
                .find(|c| c.name.eq_ignore_ascii_case(mig_col));

            if live_col.is_none() {
                findings.push(DriftFinding::MissingColumn {
                    table: mig_table.clone(),
                    column: mig_col.clone(),
                });
                continue;
            }

            // Check nullable mismatch against graph node
            let key = format!("{}.{}", mig_table, mig_col);
            if let Some(&node_idx) = migration_graph.column_index.get(&key) {
                if let crate::graph::SchemaNode::Column {
                    nullable: mig_nullable,
                    ..
                } = &migration_graph.graph[node_idx]
                {
                    let db_nullable = live_col.unwrap().is_nullable;
                    if *mig_nullable != db_nullable {
                        findings.push(DriftFinding::NullableMismatch {
                            table: mig_table.clone(),
                            column: mig_col.clone(),
                            in_migration: *mig_nullable,
                            in_database: db_nullable,
                        });
                    }
                }
            }
        }

        // Indexes: check DB indexes that don't appear in migration
        for (idx_name, idx_meta) in &live.indexes {
            if idx_meta.table.eq_ignore_ascii_case(mig_table)
                && !idx_meta.is_primary
                && !migration_graph.index_index.contains_key(idx_name)
            {
                findings.push(DriftFinding::ExtraIndex {
                    table: mig_table.clone(),
                    index: idx_name.clone(),
                });
            }
        }

        // Indexes in migration but not in DB
        for (idx_name, &_idx_node) in &migration_graph.index_index {
            let table_prefix_match = live
                .indexes
                .values()
                .any(|i| i.table.eq_ignore_ascii_case(mig_table) && i.name.eq_ignore_ascii_case(idx_name));

            if !table_prefix_match {
                // Check if this index belongs to the current table
                let migration_idx_node = migration_graph.index_index.get(idx_name);
                if let Some(&node) = migration_idx_node {
                    if let crate::graph::SchemaNode::Index { table, .. } = &migration_graph.graph[node] {
                        if table.eq_ignore_ascii_case(mig_table) {
                            findings.push(DriftFinding::MissingIndex {
                                table: mig_table.clone(),
                                index: idx_name.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    let overall_drift = findings
        .iter()
        .map(|f| f.severity())
        .max()
        .unwrap_or(RiskLevel::Low);

    let total_findings = findings.len();

    DriftReport {
        overall_drift,
        total_findings,
        findings,
        migration_tables,
        database_tables,
        in_sync: total_findings == 0,
    }
}
