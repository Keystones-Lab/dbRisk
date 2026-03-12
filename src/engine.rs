//! Risk analysis engine.
//!
//! Each rule is a pure function that inspects one `ParsedStatement` and
//! returns a `DetectedOperation`.  The engine aggregates them into a final
//! `MigrationReport`.

use crate::db::LiveSchema;
use crate::graph::SchemaGraph;
use crate::parser::ParsedStatement;
use crate::types::{DetectedOperation, FkImpact, MigrationReport, RiskLevel};
use chrono::Utc;

// ─────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────

pub struct RiskEngine {
    /// Estimated rows per table – supplied by the user via --table-rows flag
    /// OR imported from the live database via --db-url.
    pub row_counts: std::collections::HashMap<String, u64>,
    /// Optional live schema snapshot fetched via --db-url.
    pub live_schema: Option<LiveSchema>,
}

impl RiskEngine {
    pub fn new(row_counts: std::collections::HashMap<String, u64>) -> Self {
        Self { row_counts, live_schema: None }
    }

    /// Create an engine seeded from a live database snapshot.
    /// Row counts from `live` override any manually provided `row_counts`.
    pub fn with_live_schema(
        mut row_counts: std::collections::HashMap<String, u64>,
        live: LiveSchema,
    ) -> Self {
        // Merge live row counts (live wins)
        for (name, meta) in &live.tables {
            row_counts.insert(name.clone(), meta.estimated_rows.max(0) as u64);
        }
        Self { row_counts, live_schema: Some(live) }
    }

    /// Run every rule against the parsed statements and build a graph, then
    /// return the final report for the file.
    pub fn analyze(
        &self,
        file: &str,
        statements: &[ParsedStatement],
    ) -> MigrationReport {
        let mut graph = SchemaGraph::new();
        let mut operations: Vec<DetectedOperation> = Vec::new();
        let mut fk_impacts: Vec<FkImpact> = Vec::new();

        // ── Pass 1: populate the schema graph ────────────────────────────
        for stmt in statements {
            self.populate_graph(&mut graph, stmt);
        }

        // ── Pass 2: evaluate every rule ──────────────────────────────────
        for stmt in statements {
            let ops = self.evaluate(stmt, &graph, &mut fk_impacts);
            operations.extend(ops);
        }

        // ── Aggregate results ────────────────────────────────────────────
        let score: u32 = operations.iter().map(|o| o.score).sum();
        let overall_risk = RiskLevel::from_score(score);

        let mut affected_tables: Vec<String> = operations
            .iter()
            .flat_map(|o| o.tables.iter().cloned())
            .collect();
        affected_tables.sort();
        affected_tables.dedup();

        let index_rebuild_required = operations.iter().any(|o| o.index_rebuild);
        let requires_maintenance_window = overall_risk >= RiskLevel::High;

        let warnings: Vec<String> = operations
            .iter()
            .filter_map(|o| o.warning.clone())
            .collect();

        let recommendations =
            self.build_recommendations(&operations, &affected_tables, overall_risk);

        // Lock estimate: rough heuristic based on table size
        let estimated_lock_seconds = self.estimate_lock_seconds(&operations, &affected_tables);

        MigrationReport {
            file: file.to_string(),
            overall_risk,
            score,
            affected_tables,
            operations,
            warnings,
            recommendations,
            fk_impacts,
            estimated_lock_seconds,
            index_rebuild_required,
            requires_maintenance_window,
            analyzed_at: Utc::now().to_rfc3339(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Graph population pass
    // ─────────────────────────────────────────────────────────────────────

    fn populate_graph(&self, graph: &mut SchemaGraph, stmt: &ParsedStatement) {
        match stmt {
            ParsedStatement::CreateTable {
                table,
                columns,
                foreign_keys,
                ..
            } => {
                let rows = self.row_counts.get(table).copied();
                graph.add_table(table, rows);
                for col in columns {
                    graph.add_column(table, &col.name, &col.data_type, col.nullable);
                }
                for fk in foreign_keys {
                    graph.add_foreign_key(
                        table,
                        &fk.ref_table,
                        fk.constraint_name.clone(),
                        fk.columns.clone(),
                        fk.ref_columns.clone(),
                        fk.on_delete_cascade,
                        fk.on_update_cascade,
                    );
                }
            }
            ParsedStatement::AlterTableAddForeignKey { table, fk } => {
                graph.add_foreign_key(
                    table,
                    &fk.ref_table,
                    fk.constraint_name.clone(),
                    fk.columns.clone(),
                    fk.ref_columns.clone(),
                    fk.on_delete_cascade,
                    fk.on_update_cascade,
                );
            }
            ParsedStatement::CreateIndex {
                index_name,
                table,
                unique,
                ..
            } => {
                let name = index_name
                    .clone()
                    .unwrap_or_else(|| format!("unnamed_idx_{}", table));
                graph.add_table(table, self.row_counts.get(table).copied());
                graph.add_index(&name, table, *unique);
            }
            _ => {}
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Rule evaluation pass
    // ─────────────────────────────────────────────────────────────────────

    fn evaluate(
        &self,
        stmt: &ParsedStatement,
        graph: &SchemaGraph,
        fk_impacts: &mut Vec<FkImpact>,
    ) -> Vec<DetectedOperation> {
        match stmt {
            // ── DROP TABLE  ──────────────────────────────────────────────────
            ParsedStatement::DropTable { tables, cascade, .. } => {
                let mut ops = Vec::new();
                for table in tables {
                    // Who references this table?
                    let refs = graph.tables_referencing(table);
                    let ref_count = refs.len();
                    let downstream = graph.fk_downstream(table);

                    let mut score = 100u32;
                    let mut extra = String::new();

                    if ref_count > 0 {
                        score += (ref_count as u32) * 20;
                        extra = format!(
                            " Referenced by {} table(s): {}",
                            ref_count,
                            refs.join(", ")
                        );
                        for r in &refs {
                            fk_impacts.push(FkImpact {
                                constraint_name: format!("{}_fk", r),
                                from_table: r.clone(),
                                to_table: table.clone(),
                                cascade: *cascade,
                            });
                        }
                    }
                    if !downstream.is_empty() {
                        score += (downstream.len() as u32) * 10;
                    }

                    ops.push(DetectedOperation {
                        description: format!("DROP TABLE {}{}", table, extra),
                        tables: vec![table.clone()],
                        risk_level: RiskLevel::from_score(score),
                        score,
                        warning: Some(format!(
                            "Dropping '{}' is irreversible. Cascade: {}.{}",
                            table,
                            cascade,
                            if !downstream.is_empty() {
                                format!(" Downstream tables affected: {}", downstream.join(", "))
                            } else {
                                String::new()
                            }
                        )),
                        acquires_lock: true,
                        index_rebuild: false,
                    });
                }
                ops
            }

            // ── DROP COLUMN  ─────────────────────────────────────────────────
            ParsedStatement::AlterTableDropColumn { table, column, .. } => {
                vec![DetectedOperation {
                    description: format!("ALTER TABLE {} DROP COLUMN {}", table, column),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::High,
                    score: 60,
                    warning: Some(format!(
                        "Dropping column '{}.{}' is irreversible and may break application code",
                        table, column
                    )),
                    acquires_lock: true,
                    index_rebuild: false,
                }]
            }

            // ── ALTER COLUMN TYPE ────────────────────────────────────────────
            ParsedStatement::AlterTableAlterColumnType {
                table,
                column,
                new_type,
            } => {
                let rows = self.row_counts.get(table).copied().unwrap_or(0);
                let score = if rows > 1_000_000 { 90 } else { 40 };
                let row_note = if rows > 0 {
                    format!(" (~{} rows)", rows)
                } else {
                    String::new()
                };
                vec![DetectedOperation {
                    description: format!(
                        "ALTER TABLE {} ALTER COLUMN {} TYPE {}{}",
                        table, column, new_type, row_note
                    ),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning: Some(format!(
                        "Type change on '{}.{}' may cause data loss and requires a full table rewrite{}",
                        table, column, row_note
                    )),
                    acquires_lock: true,
                    index_rebuild: true,
                }]
            }

            // ── ADD COLUMN (NOT NULL, no default)  ───────────────────────────
            ParsedStatement::AlterTableAddColumn { table, column } => {
                if !column.nullable && !column.has_default {
                    let rows = self.row_counts.get(table).copied().unwrap_or(0);
                    let score = if rows > 0 { 50 } else { 25 };
                    vec![DetectedOperation {
                        description: format!(
                            "ALTER TABLE {} ADD COLUMN {} {} NOT NULL (no default)",
                            table, column.name, column.data_type
                        ),
                        tables: vec![table.clone()],
                        risk_level: RiskLevel::from_score(score),
                        score,
                        warning: Some(format!(
                            "Adding NOT NULL column '{}.{}' without a DEFAULT will fail if the table has existing rows",
                            table, column.name
                        )),
                        acquires_lock: true,
                        index_rebuild: false,
                    }]
                } else {
                    vec![DetectedOperation {
                        description: format!(
                            "ALTER TABLE {} ADD COLUMN {} {}",
                            table, column.name, column.data_type
                        ),
                        tables: vec![table.clone()],
                        risk_level: RiskLevel::Low,
                        score: 5,
                        warning: None,
                        acquires_lock: false,
                        index_rebuild: false,
                    }]
                }
            }

            // ── CREATE INDEX (without CONCURRENTLY) ──────────────────────────
            ParsedStatement::CreateIndex {
                index_name,
                table,
                unique,
                concurrently,
                columns,
            } => {
                let name = index_name.as_deref().unwrap_or("unnamed");
                let rows = self.row_counts.get(table).copied().unwrap_or(0);
                let score: u32 = if *concurrently {
                    5
                } else if rows > 1_000_000 {
                    70
                } else {
                    20
                };

                let warning = if !concurrently {
                    Some(format!(
                        "CREATE INDEX on '{}' without CONCURRENTLY will hold a SHARE lock for the duration of the build (cols: {})",
                        table, columns.join(", ")
                    ))
                } else {
                    None
                };

                vec![DetectedOperation {
                    description: format!(
                        "CREATE {}INDEX {} ON {} ({})",
                        if *unique { "UNIQUE " } else { "" },
                        name,
                        table,
                        columns.join(", ")
                    ),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning,
                    acquires_lock: !concurrently,
                    index_rebuild: true,
                }]
            }

            // ── DROP INDEX ───────────────────────────────────────────────────
            ParsedStatement::DropIndex { names, concurrently, .. } => {
                let score: u32 = if *concurrently { 2 } else { 10 };
                let warning = if !concurrently {
                    Some(format!(
                        "DROP INDEX without CONCURRENTLY acquires an ACCESS EXCLUSIVE lock: {}",
                        names.join(", ")
                    ))
                } else {
                    None
                };
                vec![DetectedOperation {
                    description: format!("DROP INDEX {}", names.join(", ")),
                    tables: vec![],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning,
                    acquires_lock: !concurrently,
                    index_rebuild: false,
                }]
            }

            // ── ADD FOREIGN KEY ──────────────────────────────────────────────
            ParsedStatement::AlterTableAddForeignKey { table, fk } => {
                let cascade_note = if fk.on_delete_cascade {
                    " (ON DELETE CASCADE)"
                } else {
                    ""
                };
                let score = if fk.on_delete_cascade { 30 } else { 15 };
                fk_impacts.push(FkImpact {
                    constraint_name: fk
                        .constraint_name
                        .clone()
                        .unwrap_or_else(|| format!("{}_fk", table)),
                    from_table: table.clone(),
                    to_table: fk.ref_table.clone(),
                    cascade: fk.on_delete_cascade,
                });
                vec![DetectedOperation {
                    description: format!(
                        "ADD FOREIGN KEY {}.({}) → {}.({}){}",
                        table,
                        fk.columns.join(", "),
                        fk.ref_table,
                        fk.ref_columns.join(", "),
                        cascade_note
                    ),
                    tables: vec![table.clone(), fk.ref_table.clone()],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning: if fk.on_delete_cascade {
                        Some(format!(
                            "ON DELETE CASCADE on '{}.{}' can silently delete rows in '{}' when the parent is deleted",
                            table, fk.columns.join(", "), fk.ref_table
                        ))
                    } else {
                        None
                    },
                    acquires_lock: true,
                    index_rebuild: false,
                }]
            }

            // ── DROP CONSTRAINT ──────────────────────────────────────────────
            ParsedStatement::AlterTableDropConstraint { table, constraint, cascade } => {
                let score = if *cascade { 25 } else { 10 };
                vec![DetectedOperation {
                    description: format!(
                        "ALTER TABLE {} DROP CONSTRAINT {}{}",
                        table,
                        constraint,
                        if *cascade { " CASCADE" } else { "" }
                    ),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning: if *cascade {
                        Some(format!(
                            "Dropping constraint '{}' with CASCADE may drop dependent objects",
                            constraint
                        ))
                    } else {
                        None
                    },
                    acquires_lock: true,
                    index_rebuild: false,
                }]
            }

            // ── RENAME COLUMN ────────────────────────────────────────────────
            ParsedStatement::AlterTableRenameColumn { table, old, new } => {
                vec![DetectedOperation {
                    description: format!(
                        "ALTER TABLE {} RENAME COLUMN {} TO {}",
                        table, old, new
                    ),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::High,
                    score: 55,
                    warning: Some(format!(
                        "Renaming column '{}.{}' is a breaking change for any downstream code that references the old name",
                        table, old
                    )),
                    acquires_lock: true,
                    index_rebuild: false,
                }]
            }

            // ── RENAME TABLE ─────────────────────────────────────────────────
            ParsedStatement::AlterTableRenameTable { old, new } => {
                vec![DetectedOperation {
                    description: format!("ALTER TABLE {} RENAME TO {}", old, new),
                    tables: vec![old.clone(), new.clone()],
                    risk_level: RiskLevel::High,
                    score: 65,
                    warning: Some(format!(
                        "Renaming table '{}' to '{}' breaks all queries, ORMs, and FK constraints referencing the old name",
                        old, new
                    )),
                    acquires_lock: true,
                    index_rebuild: false,
                }]
            }

            // ── SET NOT NULL ─────────────────────────────────────────────────
            ParsedStatement::AlterTableSetNotNull { table, column } => {
                let rows = self.row_counts.get(table).copied().unwrap_or(0);
                let score = if rows > 1_000_000 { 45 } else { 20 };
                vec![DetectedOperation {
                    description: format!(
                        "ALTER TABLE {} ALTER COLUMN {} SET NOT NULL",
                        table, column
                    ),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning: Some(format!(
                        "SET NOT NULL on '{}.{}' requires a full table scan to validate existing rows",
                        table, column
                    )),
                    acquires_lock: true,
                    index_rebuild: false,
                }]
            }

            // ── CREATE TABLE ─────────────────────────────────────────────────
            ParsedStatement::CreateTable { table, .. } => {
                vec![DetectedOperation {
                    description: format!("CREATE TABLE {}", table),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::Low,
                    score: 2,
                    warning: None,
                    acquires_lock: false,
                    index_rebuild: false,
                }]
            }

            // ── ADD PRIMARY KEY ──────────────────────────────────────────────
            ParsedStatement::AlterTableAddPrimaryKey { table, columns } => {
                let rows = self.row_counts.get(table).copied().unwrap_or(0);
                let score = if rows > 1_000_000 { 80 } else { 35 };
                vec![DetectedOperation {
                    description: format!(
                        "ALTER TABLE {} ADD PRIMARY KEY ({})",
                        table,
                        columns.join(", ")
                    ),
                    tables: vec![table.clone()],
                    risk_level: RiskLevel::from_score(score),
                    score,
                    warning: Some(format!(
                        "Adding PRIMARY KEY to '{}' builds an index over the entire table",
                        table
                    )),
                    acquires_lock: true,
                    index_rebuild: true,
                }]
            }

            ParsedStatement::Other { .. } => vec![],
            _ => vec![],
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Recommendation engine
    // ─────────────────────────────────────────────────────────────────────

    fn build_recommendations(
        &self,
        ops: &[DetectedOperation],
        _tables: &[String],
        overall: RiskLevel,
    ) -> Vec<String> {
        let mut rec = Vec::new();

        let has_drop_table = ops
            .iter()
            .any(|o| o.description.contains("DROP TABLE"));
        let has_drop_column = ops
            .iter()
            .any(|o| o.description.contains("DROP COLUMN"));
        let has_type_change = ops
            .iter()
            .any(|o| o.description.contains("TYPE ") && o.acquires_lock);
        let has_index_without_concurrent = ops.iter().any(|o| {
            o.description.contains("CREATE") && o.index_rebuild && o.acquires_lock
        });
        let has_not_null_no_default = ops
            .iter()
            .any(|o| o.description.contains("NOT NULL (no default)"));
        let has_rename = ops
            .iter()
            .any(|o| o.description.contains("RENAME"));
        let has_cascade = ops
            .iter()
            .any(|o| o.description.contains("CASCADE"));

        if has_drop_table || has_drop_column {
            rec.push("Deploy in two phases: first deploy app code that no longer reads the column/table, then drop it in a later migration".to_string());
            rec.push("Take a full database backup before running this migration".to_string());
        }

        if has_type_change {
            rec.push("Use a background migration: add a new column with the new type, backfill in batches, then swap and drop the old column".to_string());
        }

        if has_index_without_concurrent {
            rec.push("Use CREATE INDEX CONCURRENTLY to build indexes without locking the table for writes".to_string());
        }

        if has_not_null_no_default {
            rec.push("Add a DEFAULT value first, deploy the app change, then remove the default in a follow-up migration if needed".to_string());
        }

        if has_rename {
            rec.push("Avoid renaming tables/columns in a single step; use a backward-compatible alias or view transition strategy".to_string());
        }

        if has_cascade {
            rec.push("Review all ON DELETE CASCADE constraints — a single delete can silently remove rows across many tables".to_string());
        }

        if overall >= RiskLevel::High {
            rec.push("Schedule this migration during a low-traffic maintenance window".to_string());
            rec.push("Test this migration on a staging environment with production-sized data".to_string());
        }

        if overall >= RiskLevel::Medium {
            let large: Vec<&str> = self
                .row_counts
                .iter()
                .filter(|(_, &v)| v > 100_000)
                .map(|(k, _)| k.as_str())
                .collect();
            if !large.is_empty() {
                rec.push(format!(
                    "Large tables detected ({}): consider batching long-running operations",
                    large.join(", ")
                ));
            }
        }

        if rec.is_empty() {
            rec.push("No specific recommendations – this migration looks safe to deploy".to_string());
        }

        // Live-schema-aware additions
        if let Some(live) = &self.live_schema {
            for table in _tables {
                if let Some(meta) = live.tables.get(table) {
                    let mb = meta.total_size_bytes / (1024 * 1024);
                    if mb > 1000 {
                        rec.push(format!(
                            "Table '{}' is {} on disk — ensure you have at least 2× free disk space for any rewrite operations",
                            table, meta.total_size_pretty
                        ));
                    }
                }
            }
        }

        rec
    }

    // ─────────────────────────────────────────────────────────────────────
    // Lock duration heuristic
    // ─────────────────────────────────────────────────────────────────────

    fn estimate_lock_seconds(
        &self,
        ops: &[DetectedOperation],
        _tables: &[String],
    ) -> Option<u64> {
        let locking_ops: Vec<&DetectedOperation> =
            ops.iter().filter(|o| o.acquires_lock).collect();

        if locking_ops.is_empty() {
            return None;
        }

        // Rough model: 1s base + 1s per 100k rows for rebuild/type-change ops
        let mut total_secs: u64 = 0;
        for op in &locking_ops {
            let mut secs = 1u64;
            for table in &op.tables {
                if let Some(&rows) = self.row_counts.get(table) {
                    let row_factor = rows / 100_000;
                    if op.index_rebuild {
                        secs += row_factor * 5; // index builds ~5s / 100k rows
                    } else {
                        secs += row_factor;
                    }
                }
            }
            total_secs += secs;
        }

        Some(total_secs.max(1))
    }
}
