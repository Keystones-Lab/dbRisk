//! Reads migration SQL files from disk.

use crate::error::{Result, SchemaRiskError};
use std::path::{Path, PathBuf};

/// A loaded migration file ready for parsing.
#[derive(Debug, Clone)]
pub struct MigrationFile {
    pub path: PathBuf,
    pub name: String,
    pub sql: String,
}

/// Load a single migration file.
pub fn load_file(path: impl AsRef<Path>) -> Result<MigrationFile> {
    let path = path.as_ref().to_path_buf();
    if !path.exists() {
        return Err(SchemaRiskError::InvalidMigration(format!(
            "File not found: {}",
            path.display()
        )));
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if !["sql", "psql", "pg"].contains(&ext) {
        return Err(SchemaRiskError::InvalidMigration(format!(
            "Expected a .sql file, got: {}",
            path.display()
        )));
    }

    let sql = std::fs::read_to_string(&path).map_err(SchemaRiskError::Io)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    Ok(MigrationFile { path, name, sql })
}

/// Load all SQL files matching a glob pattern (e.g. `migrations/*.sql`).
pub fn load_glob(pattern: &str) -> Result<Vec<MigrationFile>> {
    let paths: Vec<PathBuf> = glob::glob(pattern)
        .map_err(|e| SchemaRiskError::InvalidMigration(e.to_string()))?
        .filter_map(|entry| entry.ok())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| ["sql", "psql", "pg"].contains(&e))
                .unwrap_or(false)
        })
        .collect();

    if paths.is_empty() {
        return Err(SchemaRiskError::NoFilesFound(pattern.to_string()));
    }

    paths.iter().map(load_file).collect()
}
