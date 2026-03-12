//! Query impact detection.
//!
//! Scans source files in a given directory for SQL string literals and ORM
//! query patterns that reference tables or columns being modified by the
//! migration.  Reports which files contain queries likely affected by the
//! pending schema change.
//!
//! Uses `rayon` for parallel directory traversal.

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};


// ─────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactedFile {
    /// Relative path from the scan root
    pub path: String,
    /// Tables mentioned in this file that overlap with the migration
    pub tables_referenced: Vec<String>,
    /// Columns mentioned in this file that overlap with the migration's
    /// dropped / renamed / type-changed columns
    pub columns_referenced: Vec<String>,
    /// Relevant lines of code (file:line → snippet)
    pub hits: Vec<QueryHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryHit {
    pub line: usize,
    pub snippet: String,
    pub match_type: MatchType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchType {
    /// Plain SQL string literal containing the table/column name
    SqlLiteral,
    /// ORM query builder reference (Sequelize, Prisma, SQLAlchemy, Diesel…)
    OrmReference,
    /// An `include:` / `select:` key that contains the column name
    FieldReference,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImpactReport {
    /// Number of source files scanned
    pub files_scanned: usize,
    /// Files that reference affected schema objects
    pub impacted_files: Vec<ImpactedFile>,
    /// Table → list of files that reference it
    pub table_file_map: HashMap<String, Vec<String>>,
    /// Column → list of files that reference it
    pub column_file_map: HashMap<String, Vec<String>>,
}

// ─────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────

/// Source file extensions we want to look inside.
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "go", "py", "js", "ts", "jsx", "tsx", "rb", "java", "cs", "php",
    "sql", "graphql",
];

pub struct ImpactScanner {
    /// Tables to look for (lowercased)
    tables: Vec<String>,
    /// Columns to look for (lowercased)
    columns: Vec<String>,
}

impl ImpactScanner {
    pub fn new(tables: Vec<String>, columns: Vec<String>) -> Self {
        Self {
            tables: tables.iter().map(|t| t.to_lowercase()).collect(),
            columns: columns.iter().map(|c| c.to_lowercase()).collect(),
        }
    }

    /// Walk `root_dir` recursively, scan all source files in parallel, return
    /// an `ImpactReport`.
    pub fn scan(&self, root_dir: &Path) -> ImpactReport {
        // Collect all source file paths first
        let paths = collect_source_files(root_dir);
        let total = paths.len();

        let impacted_files: Vec<ImpactedFile> = paths
            .par_iter()
            .filter_map(|path| self.scan_file(path))
            .collect();

        // Build lookup maps
        let mut table_file_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut column_file_map: HashMap<String, Vec<String>> = HashMap::new();
        for f in &impacted_files {
            for t in &f.tables_referenced {
                table_file_map.entry(t.clone()).or_default().push(f.path.clone());
            }
            for c in &f.columns_referenced {
                column_file_map.entry(c.clone()).or_default().push(f.path.clone());
            }
        }

        ImpactReport {
            files_scanned: total,
            impacted_files,
            table_file_map,
            column_file_map,
        }
    }

    // ── Per-file scan ─────────────────────────────────────────────────────

    fn scan_file(&self, path: &Path) -> Option<ImpactedFile> {
        let content = std::fs::read_to_string(path).ok()?;
        let content_lower = content.to_lowercase();

        let mut tables_found: Vec<String> = Vec::new();
        let mut columns_found: Vec<String> = Vec::new();
        let mut hits: Vec<QueryHit> = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_lower = line.to_lowercase();

            for table in &self.tables {
                if line_lower.contains(table.as_str()) {
                    if !tables_found.contains(table) {
                        tables_found.push(table.clone());
                    }
                    let match_type = classify_match(&line_lower, table);
                    hits.push(QueryHit {
                        line: line_idx + 1,
                        snippet: line.trim().chars().take(200).collect(),
                        match_type,
                    });
                }
            }

            for col in &self.columns {
                if line_lower.contains(col.as_str()) && !content_lower.contains(&format!("-- {}", col)) {
                    if !columns_found.contains(col) {
                        columns_found.push(col.clone());
                    }
                    // Avoid duplicate hits on the same line
                    if !hits.iter().any(|h| h.line == line_idx + 1) {
                        let match_type = classify_match(&line_lower, col);
                        hits.push(QueryHit {
                            line: line_idx + 1,
                            snippet: line.trim().chars().take(200).collect(),
                            match_type,
                        });
                    }
                }
            }
        }

        if tables_found.is_empty() && columns_found.is_empty() {
            return None;
        }

        let rel_path = path.to_string_lossy().to_string();

        Some(ImpactedFile {
            path: rel_path,
            tables_referenced: tables_found,
            columns_referenced: columns_found,
            hits,
        })
    }
}

// ── Classify what kind of reference this line contains ───────────────────

fn classify_match(line: &str, token: &str) -> MatchType {
    // ORM patterns
    let orm_patterns = [
        "select(",
        "where(",
        "findone",
        "findall",
        "findmany",
        "create(",
        "update(",
        "delete(",
        "include:",
        "prisma.",
        "model.",
        ".query(",
        "execute(",
        "from(",
        "join(",
        "diesel::",
        "querybuilder",
        "activerecord",
        "sqlalchemy",
    ];

    let field_patterns = ["include:", "select:", "fields:", "columns:", "attributes:"];

    if field_patterns.iter().any(|p| line.contains(p)) {
        return MatchType::FieldReference;
    }

    if orm_patterns.iter().any(|p| line.contains(p)) {
        return MatchType::OrmReference;
    }

    // Raw SQL string heuristic: the token appears between quotes or after FROM/JOIN/INTO
    let sql_keywords = ["from ", "join ", "into ", "update ", "\"", "'", "`"];
    if sql_keywords.iter().any(|k| {
        if let Some(pos) = line.find(k) {
            line[pos..].contains(token)
        } else {
            false
        }
    }) {
        return MatchType::SqlLiteral;
    }

    MatchType::OrmReference
}

// ── Collect all source files under a directory ───────────────────────────

fn collect_source_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_recursive(root, &mut files);
    files
}

fn collect_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };

    for entry in entries.flatten() {
        let path = entry.path();

        // Skip hidden dirs and common build/vendor dirs
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name.starts_with('.') || matches!(name, "node_modules" | "target" | "dist" | "build" | "vendor" | "__pycache__" | ".git") {
            continue;
        }

        if path.is_dir() {
            collect_recursive(&path, out);
        } else if let Some(ext) = path.extension().and_then(OsStr::to_str) {
            if SOURCE_EXTENSIONS.contains(&ext) {
                out.push(path);
            }
        }
    }
}
