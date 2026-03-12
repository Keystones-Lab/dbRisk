//! Thin wrapper around sqlparser-rs.
//!
//! Normalises the raw AST into our own `ParsedStatement` enum so the rest of
//! the tool never needs to import sqlparser types directly.

use crate::error::Result;
use sqlparser::ast::{
    AlterTableOperation, ColumnOption, ObjectType, Statement,
    TableConstraint,
};
use sqlparser::dialect::PostgreSqlDialect;
use sqlparser::parser::Parser;

// ─────────────────────────────────────────────
// Public normalised representation
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub has_default: bool,
    pub is_primary_key: bool,
}

#[derive(Debug, Clone)]
pub struct ForeignKeyInfo {
    pub columns: Vec<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
    pub on_delete_cascade: bool,
    pub on_update_cascade: bool,
    pub constraint_name: Option<String>,
}

/// Normalised view of every SQL statement we care about.
#[derive(Debug, Clone)]
pub enum ParsedStatement {
    CreateTable {
        table: String,
        columns: Vec<ColumnInfo>,
        foreign_keys: Vec<ForeignKeyInfo>,
        has_primary_key: bool,
    },
    DropTable {
        tables: Vec<String>,
        if_exists: bool,
        cascade: bool,
    },
    AlterTableAddColumn {
        table: String,
        column: ColumnInfo,
    },
    AlterTableDropColumn {
        table: String,
        column: String,
        if_exists: bool,
    },
    AlterTableAlterColumnType {
        table: String,
        column: String,
        new_type: String,
    },
    AlterTableSetNotNull {
        table: String,
        column: String,
    },
    AlterTableAddForeignKey {
        table: String,
        fk: ForeignKeyInfo,
    },
    AlterTableDropConstraint {
        table: String,
        constraint: String,
        cascade: bool,
    },
    AlterTableRenameColumn {
        table: String,
        old: String,
        new: String,
    },
    AlterTableRenameTable {
        old: String,
        new: String,
    },
    CreateIndex {
        index_name: Option<String>,
        table: String,
        columns: Vec<String>,
        unique: bool,
        concurrently: bool,
    },
    DropIndex {
        names: Vec<String>,
        concurrently: bool,
        if_exists: bool,
    },
    AlterTableAddPrimaryKey {
        table: String,
        columns: Vec<String>,
    },
    AlterTableDropPrimaryKey {
        table: String,
    },
    AlterTableAlterColumnDefault {
        table: String,
        column: String,
        drop_default: bool,
    },
    /// Catch-all for statements we don't inspect in detail.
    Other {
        raw: String,
    },
}

// ─────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────

/// Parse a full SQL string into a list of `ParsedStatement`s.
///
/// Fault-tolerant: unparseable statements (e.g. PL/pgSQL functions, custom
/// extensions) are returned as `ParsedStatement::Other` rather than causing
/// the whole file to fail.
pub fn parse(sql: &str) -> Result<Vec<ParsedStatement>> {
    let segments = split_into_segments(sql);
    let dialect = PostgreSqlDialect {};
    let mut results = Vec::new();

    for seg in segments {
        let trimmed = seg.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Ensure the segment ends with a semicolon for sqlparser
        let to_parse = if trimmed.ends_with(';') {
            trimmed.to_string()
        } else {
            format!("{};", trimmed)
        };

        match Parser::parse_sql(&dialect, &to_parse) {
            Ok(stmts) => {
                for stmt in stmts {
                    results.push(lower_to_parsed(stmt));
                }
            }
            Err(_) => {
                // Emit as Other so we don't lose the statement entirely
                results.push(ParsedStatement::Other {
                    raw: trimmed.chars().take(80).collect(),
                });
            }
        }
    }

    Ok(results)
}

/// Split a SQL file into statement segments.
///
/// Strategy:
/// 1. Respect dollar-quoted strings ($$…$$) — never split inside them.
/// 2. Split on `;` outside dollar-quotes.
/// 3. Also recognise statements that are separated only by blank lines
///    (no trailing `;`) and normalise them.
fn split_into_segments(sql: &str) -> Vec<String> {
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_dollar_quote = false;
    let mut dollar_tag = String::new();
    let chars: Vec<char> = sql.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Detect start/end of dollar-quoted string
        if chars[i] == '$' {
            // Try to read a dollar tag: $tag$ or $$
            let mut j = i + 1;
            while j < len && chars[j] != '$' && chars[j].is_alphanumeric() || (j < len && chars[j] == '_') {
                j += 1;
            }
            if j < len && chars[j] == '$' {
                let tag: String = chars[i..=j].iter().collect();
                if !in_dollar_quote {
                    in_dollar_quote = true;
                    dollar_tag = tag.clone();
                    current.push_str(&tag);
                    i = j + 1;
                    continue;
                } else if tag == dollar_tag {
                    in_dollar_quote = false;
                    current.push_str(&tag);
                    dollar_tag.clear();
                    i = j + 1;
                    continue;
                }
            }
        }

        if !in_dollar_quote && chars[i] == ';' {
            current.push(';');
            let seg = current.trim().to_string();
            if !seg.is_empty() && seg != ";" {
                segments.push(seg);
            }
            current.clear();
            i += 1;
            continue;
        }

        current.push(chars[i]);
        i += 1;
    }

    // Handle any trailing content without a semicolon
    let leftover = current.trim();
    if !leftover.is_empty() {
        // Split leftover by blank lines (no-semicolon style)
        for block in leftover.split("\n\n") {
            let b = block.trim();
            if !b.is_empty() {
                segments.push(b.to_string());
            }
        }
    }

    segments
}

// ─────────────────────────────────────────────
// Normalisation helpers
// ─────────────────────────────────────────────

fn lower_to_parsed(stmt: Statement) -> ParsedStatement {
    match stmt {
        // ── CREATE TABLE ──────────────────────────────────────────────────
        Statement::CreateTable(ct) => {
            let table = ct.name.to_string();
            let mut columns = Vec::new();
            let mut foreign_keys = Vec::new();
            let mut has_primary_key = false;

            for col_def in &ct.columns {
                let mut nullable = true;
                let mut has_default = false;
                let mut is_pk = false;

                for opt in &col_def.options {
                    match &opt.option {
                        ColumnOption::NotNull => nullable = false,
                        ColumnOption::Default(_) => has_default = true,
                        ColumnOption::Unique { is_primary, .. } if *is_primary => {
                            is_pk = true;
                            has_primary_key = true;
                            nullable = false;
                        }
                        ColumnOption::ForeignKey {
                            foreign_table,
                            referred_columns,
                            on_delete,
                            on_update,
                            ..
                        } => {
                            foreign_keys.push(ForeignKeyInfo {
                                columns: vec![col_def.name.to_string()],
                                ref_table: foreign_table.to_string(),
                                ref_columns: referred_columns
                                    .iter()
                                    .map(|c| c.to_string())
                                    .collect(),
                                on_delete_cascade: on_delete
                                    .as_ref()
                                    .map(|a| a.to_string().to_uppercase().contains("CASCADE"))
                                    .unwrap_or(false),
                                on_update_cascade: on_update
                                    .as_ref()
                                    .map(|a| a.to_string().to_uppercase().contains("CASCADE"))
                                    .unwrap_or(false),
                                constraint_name: None,
                            });
                        }
                        _ => {}
                    }
                }

                columns.push(ColumnInfo {
                    name: col_def.name.to_string(),
                    data_type: col_def.data_type.to_string(),
                    nullable,
                    has_default,
                    is_primary_key: is_pk,
                });
            }

            // Table-level constraints
            for constraint in &ct.constraints {
                match constraint {
                    TableConstraint::ForeignKey {
                        name,
                        columns: fk_cols,
                        foreign_table,
                        referred_columns,
                        on_delete,
                        on_update,
                        ..
                    } => {
                        foreign_keys.push(ForeignKeyInfo {
                            columns: fk_cols.iter().map(|c| c.to_string()).collect(),
                            ref_table: foreign_table.to_string(),
                            ref_columns: referred_columns
                                .iter()
                                .map(|c| c.to_string())
                                .collect(),
                            on_delete_cascade: on_delete
                                .as_ref()
                                .map(|a| a.to_string().to_uppercase().contains("CASCADE"))
                                .unwrap_or(false),
                            on_update_cascade: on_update
                                .as_ref()
                                .map(|a| a.to_string().to_uppercase().contains("CASCADE"))
                                .unwrap_or(false),
                            constraint_name: name.as_ref().map(|n| n.to_string()),
                        });
                    }
                    TableConstraint::PrimaryKey { .. } | TableConstraint::Unique { .. } => {
                        has_primary_key = true;
                    }
                    _ => {}
                }
            }

            ParsedStatement::CreateTable {
                table,
                columns,
                foreign_keys,
                has_primary_key,
            }
        }

        // ── DROP TABLE ────────────────────────────────────────────────────
        Statement::Drop {
            object_type: ObjectType::Table,
            names,
            if_exists,
            cascade,
            ..
        } => ParsedStatement::DropTable {
            tables: names.iter().map(|n| n.to_string()).collect(),
            if_exists,
            cascade,
        },

        // ── DROP INDEX ────────────────────────────────────────────────────
        Statement::Drop {
            object_type: ObjectType::Index,
            names,
            if_exists,
            ..
        } => {
            let raw = names.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
            // Check if CONCURRENTLY keyword appears; sqlparser puts it in name
            let concurrently = raw.to_uppercase().contains("CONCURRENTLY");
            ParsedStatement::DropIndex {
                names: names.iter().map(|n| n.to_string()).collect(),
                concurrently,
                if_exists,
            }
        }

        // ── CREATE INDEX ──────────────────────────────────────────────────
        Statement::CreateIndex(ci) => {
            let table = ci.table_name.to_string();
            let columns = ci
                .columns
                .iter()
                .map(|c| c.expr.to_string())
                .collect();
            ParsedStatement::CreateIndex {
                index_name: ci.name.as_ref().map(|n| n.to_string()),
                table,
                columns,
                unique: ci.unique,
                concurrently: ci.concurrently,
            }
        }

        // ── ALTER TABLE ───────────────────────────────────────────────────
        Statement::AlterTable { name, operations, .. } => {
            let table = name.to_string();

            // We handle the first meaningful operation; one ALTER TABLE
            // per statement is the common case.
            for op in &operations {
                match op {
                    // ADD COLUMN
                    AlterTableOperation::AddColumn { column_def, .. } => {
                        let mut nullable = true;
                        let mut has_default = false;
                        let mut is_pk = false;

                        for opt in &column_def.options {
                            match &opt.option {
                                ColumnOption::NotNull => nullable = false,
                                ColumnOption::Default(_) => has_default = true,
                                ColumnOption::Unique { is_primary, .. } if *is_primary => {
                                    is_pk = true;
                                }
                                _ => {}
                            }
                        }

                        return ParsedStatement::AlterTableAddColumn {
                            table,
                            column: ColumnInfo {
                                name: column_def.name.to_string(),
                                data_type: column_def.data_type.to_string(),
                                nullable,
                                has_default,
                                is_primary_key: is_pk,
                            },
                        };
                    }

                    // DROP COLUMN
                    AlterTableOperation::DropColumn { column_name, if_exists, .. } => {
                        return ParsedStatement::AlterTableDropColumn {
                            table,
                            column: column_name.to_string(),
                            if_exists: *if_exists,
                        };
                    }

                    // ALTER COLUMN TYPE
                    AlterTableOperation::AlterColumn { column_name, op } => {
                        use sqlparser::ast::AlterColumnOperation;
                        match op {
                            AlterColumnOperation::SetDataType { data_type, .. } => {
                                return ParsedStatement::AlterTableAlterColumnType {
                                    table,
                                    column: column_name.to_string(),
                                    new_type: data_type.to_string(),
                                };
                            }
                            AlterColumnOperation::SetNotNull => {
                                return ParsedStatement::AlterTableSetNotNull {
                                    table,
                                    column: column_name.to_string(),
                                };
                            }
                            AlterColumnOperation::DropDefault => {
                                return ParsedStatement::AlterTableAlterColumnDefault {
                                    table,
                                    column: column_name.to_string(),
                                    drop_default: true,
                                };
                            }
                            AlterColumnOperation::SetDefault { .. } => {
                                return ParsedStatement::AlterTableAlterColumnDefault {
                                    table,
                                    column: column_name.to_string(),
                                    drop_default: false,
                                };
                            }
                            _ => {}
                        }
                    }

                    // ADD CONSTRAINT (FK, PK, unique)
                    AlterTableOperation::AddConstraint(constraint) => {
                        match constraint {
                            TableConstraint::ForeignKey {
                                name,
                                columns: fk_cols,
                                foreign_table,
                                referred_columns,
                                on_delete,
                                on_update,
                                ..
                            } => {
                                return ParsedStatement::AlterTableAddForeignKey {
                                    table,
                                    fk: ForeignKeyInfo {
                                        columns: fk_cols.iter().map(|c| c.to_string()).collect(),
                                        ref_table: foreign_table.to_string(),
                                        ref_columns: referred_columns
                                            .iter()
                                            .map(|c| c.to_string())
                                            .collect(),
                                        on_delete_cascade: on_delete
                                            .as_ref()
                                            .map(|a| a.to_string().to_uppercase().contains("CASCADE"))
                                            .unwrap_or(false),
                                        on_update_cascade: on_update
                                            .as_ref()
                                            .map(|a| a.to_string().to_uppercase().contains("CASCADE"))
                                            .unwrap_or(false),
                                        constraint_name: name.as_ref().map(|n| n.to_string()),
                                    },
                                };
                            }
                            TableConstraint::PrimaryKey { columns, .. } => {
                                return ParsedStatement::AlterTableAddPrimaryKey {
                                    table,
                                    columns: columns.iter().map(|c| c.to_string()).collect(),
                                };
                            }
                            _ => {}
                        }
                    }

                    // DROP CONSTRAINT
                    AlterTableOperation::DropConstraint { name, cascade, .. } => {
                        return ParsedStatement::AlterTableDropConstraint {
                            table,
                            constraint: name.to_string(),
                            cascade: *cascade,
                        };
                    }

                    // RENAME COLUMN
                    AlterTableOperation::RenameColumn { old_column_name, new_column_name } => {
                        return ParsedStatement::AlterTableRenameColumn {
                            table,
                            old: old_column_name.to_string(),
                            new: new_column_name.to_string(),
                        };
                    }

                    // RENAME TABLE
                    AlterTableOperation::RenameTable { table_name } => {
                        return ParsedStatement::AlterTableRenameTable {
                            old: table,
                            new: table_name.to_string(),
                        };
                    }

                    _ => {}
                }
            }

            // Unrecognised ALTER TABLE operation
            ParsedStatement::Other {
                raw: format!("ALTER TABLE {}", name),
            }
        }

        other => ParsedStatement::Other {
            raw: other.to_string().chars().take(80).collect(),
        },
    }
}
