//! Live PostgreSQL schema introspection.
//!
//! When the user passes `--db-url postgres://...` the engine fetches real
//! metadata (table sizes, row counts, index definitions, FK constraints) and
//! merges it into the risk analysis so scores are accurate instead of
//! guesswork.
//!
//! Compiled only when the `db` feature is enabled.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────
// Live schema snapshot from a running database
// ─────────────────────────────────────────────

/// Everything we know about the live database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiveSchema {
    /// table_name → metadata
    pub tables: HashMap<String, TableMeta>,
    /// index_name → metadata
    pub indexes: HashMap<String, IndexMeta>,
    /// constraint_name → FK metadata
    pub foreign_keys: Vec<FkMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableMeta {
    pub name: String,
    pub schema: String,
    /// pg_class.reltuples estimate (may be stale between VACUUMs)
    pub estimated_rows: i64,
    /// actual disk size in bytes (pg_total_relation_size)
    pub total_size_bytes: i64,
    /// human-readable (e.g. "42 MB")
    pub total_size_pretty: String,
    pub columns: Vec<ColumnMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnMeta {
    pub name: String,
    pub data_type: String,
    pub is_nullable: bool,
    pub column_default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexMeta {
    pub name: String,
    pub table: String,
    pub definition: String,
    pub is_unique: bool,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FkMeta {
    pub constraint_name: String,
    pub from_schema: String,
    pub from_table: String,
    pub from_column: String,
    pub to_schema: String,
    pub to_table: String,
    pub to_column: String,
    pub on_delete: String,
    pub on_update: String,
}

// ─────────────────────────────────────────────
// Feature-gated connector
// ─────────────────────────────────────────────

#[cfg(feature = "db")]
pub mod connector {
    use super::*;
    use crate::error::SchemaRiskError;
    use tokio_postgres::{Client, NoTls};

    /// Connect to PostgreSQL and return a full `LiveSchema`.
    pub async fn fetch(db_url: &str) -> Result<LiveSchema, SchemaRiskError> {
        let (client, connection) = tokio_postgres::connect(db_url, NoTls)
            .await
            .map_err(|e| SchemaRiskError::DbConnect(e.to_string()))?;

        // Drive the connection in the background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("db connection error: {}", e);
            }
        });

        let tables = fetch_tables(&client).await?;
        let indexes = fetch_indexes(&client).await?;
        let foreign_keys = fetch_foreign_keys(&client).await?;

        Ok(LiveSchema { tables, indexes, foreign_keys })
    }

    // ── table sizes & row counts ──────────────────────────────────────────

    async fn fetch_tables(client: &Client) -> Result<HashMap<String, TableMeta>, SchemaRiskError> {
        // pg_class.reltuples is a float estimate updated by VACUUM/ANALYZE.
        // pg_total_relation_size includes toast + indexes.
        let rows = client
            .query(
                r#"
SELECT
    t.table_schema            AS schema,
    t.table_name              AS name,
    COALESCE(c.reltuples, 0)::bigint  AS estimated_rows,
    pg_total_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name))
                              AS total_size_bytes,
    pg_size_pretty(pg_total_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name)))
                              AS total_size_pretty
FROM information_schema.tables t
LEFT JOIN pg_class c
    ON c.relname = t.table_name
    AND c.relnamespace = (
        SELECT oid FROM pg_namespace WHERE nspname = t.table_schema
    )
WHERE t.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND t.table_type = 'BASE TABLE'
ORDER BY t.table_schema, t.table_name
                "#,
                &[],
            )
            .await
            .map_err(|e| SchemaRiskError::DbQuery(e.to_string()))?;

        let mut tables: HashMap<String, TableMeta> = HashMap::new();

        for row in &rows {
            let schema: String = row.get("schema");
            let name: String = row.get("name");
            let estimated_rows: i64 = row.get("estimated_rows");
            let total_size_bytes: i64 = row.get("total_size_bytes");
            let total_size_pretty: String = row.get("total_size_pretty");

            // Fetch columns for this table
            tables.insert(
                name.clone(),
                TableMeta {
                    name: name.clone(),
                    schema,
                    estimated_rows,
                    total_size_bytes,
                    total_size_pretty,
                    columns: vec![], // filled below
                },
            );
        }

        // Fetch columns in a single bulk query (avoids N+1)
        let col_rows = client
            .query(
                r#"
SELECT
    table_schema,
    table_name,
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY table_name, ordinal_position
                "#,
                &[],
            )
            .await
            .map_err(|e| SchemaRiskError::DbQuery(e.to_string()))?;

        for row in &col_rows {
            let table_name: String = row.get("table_name");
            let col = ColumnMeta {
                name: row.get("column_name"),
                data_type: row.get("data_type"),
                is_nullable: row.get::<_, &str>("is_nullable") == "YES",
                column_default: row.get("column_default"),
            };
            if let Some(t) = tables.get_mut(&table_name) {
                t.columns.push(col);
            }
        }

        Ok(tables)
    }

    // ── indexes ───────────────────────────────────────────────────────────

    async fn fetch_indexes(client: &Client) -> Result<HashMap<String, IndexMeta>, SchemaRiskError> {
        let rows = client
            .query(
                r#"
SELECT
    i.indexname        AS name,
    i.tablename        AS tablename,
    i.indexdef         AS definition,
    ix.indisunique     AS is_unique,
    ix.indisprimary    AS is_primary
FROM pg_indexes i
JOIN pg_class c   ON c.relname = i.indexname
JOIN pg_index ix  ON ix.indexrelid = c.oid
WHERE i.schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY i.tablename, i.indexname
                "#,
                &[],
            )
            .await
            .map_err(|e| SchemaRiskError::DbQuery(e.to_string()))?;

        let mut indexes = HashMap::new();
        for row in &rows {
            let name: String = row.get("name");
            indexes.insert(
                name.clone(),
                IndexMeta {
                    name,
                    table: row.get("tablename"),
                    definition: row.get("definition"),
                    is_unique: row.get("is_unique"),
                    is_primary: row.get("is_primary"),
                },
            );
        }
        Ok(indexes)
    }

    // ── foreign keys ──────────────────────────────────────────────────────

    async fn fetch_foreign_keys(client: &Client) -> Result<Vec<FkMeta>, SchemaRiskError> {
        let rows = client
            .query(
                r#"
SELECT
    tc.constraint_name,
    tc.table_schema     AS from_schema,
    tc.table_name       AS from_table,
    kcu.column_name     AS from_column,
    ccu.table_schema    AS to_schema,
    ccu.table_name      AS to_table,
    ccu.column_name     AS to_column,
    rc.delete_rule      AS on_delete,
    rc.update_rule      AS on_update
FROM information_schema.table_constraints       AS tc
JOIN information_schema.key_column_usage        AS kcu
    ON tc.constraint_name = kcu.constraint_name
    AND tc.table_schema   = kcu.table_schema
JOIN information_schema.referential_constraints AS rc
    ON tc.constraint_name = rc.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
    ON ccu.constraint_name = rc.unique_constraint_name
    AND ccu.table_schema   = rc.unique_constraint_schema
WHERE tc.constraint_type = 'FOREIGN KEY'
ORDER BY tc.table_name, tc.constraint_name
                "#,
                &[],
            )
            .await
            .map_err(|e| SchemaRiskError::DbQuery(e.to_string()))?;

        let fks = rows
            .iter()
            .map(|r| FkMeta {
                constraint_name: r.get("constraint_name"),
                from_schema: r.get("from_schema"),
                from_table: r.get("from_table"),
                from_column: r.get("from_column"),
                to_schema: r.get("to_schema"),
                to_table: r.get("to_table"),
                to_column: r.get("to_column"),
                on_delete: r.get("on_delete"),
                on_update: r.get("on_update"),
            })
            .collect();

        Ok(fks)
    }
}

// ─────────────────────────────────────────────
// Stub for builds without the `db` feature
// ─────────────────────────────────────────────

#[cfg(not(feature = "db"))]
pub mod connector {
    use super::*;
    use crate::error::SchemaRiskError;

    pub async fn fetch(_db_url: &str) -> Result<LiveSchema, SchemaRiskError> {
        Err(SchemaRiskError::FeatureDisabled(
            "Database introspection requires the `db` feature. \
             Rebuild with: cargo build --features db"
                .to_string(),
        ))
    }
}

// ─────────────────────────────────────────────
// Convert LiveSchema into the row_counts map
// ─────────────────────────────────────────────

impl LiveSchema {
    /// Produce the `HashMap<table → rows>` that `RiskEngine` expects.
    pub fn to_row_counts(&self) -> HashMap<String, u64> {
        self.tables
            .values()
            .map(|t| (t.name.clone(), t.estimated_rows.max(0) as u64))
            .collect()
    }

    /// Total size in bytes for a given table (0 if unknown).
    pub fn table_size_bytes(&self, table: &str) -> i64 {
        self.tables
            .get(table)
            .map(|t| t.total_size_bytes)
            .unwrap_or(0)
    }
}
