//! Schema graph – represents tables, columns, and their dependencies.
//!
//! We use `petgraph::DiGraph` where:
//!   - Each node is a `SchemaNode` (Table or Column)
//!   - Each edge is a `SchemaEdge` (ForeignKey, Contains, DependsOn)
//!
//! The graph lets us answer questions like:
//!   "If I drop table X, what else breaks?"

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────
// Node types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchemaNode {
    Table { name: String, estimated_rows: Option<u64> },
    Column { table: String, name: String, data_type: String, nullable: bool },
    Index { name: String, table: String, unique: bool },
}

impl SchemaNode {
    pub fn label(&self) -> String {
        match self {
            SchemaNode::Table { name, .. } => name.clone(),
            SchemaNode::Column { table, name, .. } => format!("{}.{}", table, name),
            SchemaNode::Index { name, table, .. } => format!("idx:{}@{}", name, table),
        }
    }
}

// ─────────────────────────────────────────────
// Edge types
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SchemaEdge {
    /// Table → Column  (table contains this column)
    Contains,
    /// Table → Table   (foreign key relationship)
    ForeignKey {
        constraint_name: Option<String>,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        cascade_delete: bool,
        cascade_update: bool,
    },
    /// Table → Index
    HasIndex,
}

// ─────────────────────────────────────────────
// The graph structure
// ─────────────────────────────────────────────

pub struct SchemaGraph {
    pub graph: DiGraph<SchemaNode, SchemaEdge>,
    /// table_name -> NodeIndex
    pub table_index: HashMap<String, NodeIndex>,
    /// "table.column" -> NodeIndex
    pub column_index: HashMap<String, NodeIndex>,
    /// index_name -> NodeIndex
    pub index_index: HashMap<String, NodeIndex>,
}

impl SchemaGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            table_index: HashMap::new(),
            column_index: HashMap::new(),
            index_index: HashMap::new(),
        }
    }

    // ── Insertion helpers ─────────────────────────────────────────────────

    pub fn add_table(&mut self, name: &str, estimated_rows: Option<u64>) -> NodeIndex {
        if let Some(&idx) = self.table_index.get(name) {
            return idx;
        }
        let idx = self.graph.add_node(SchemaNode::Table {
            name: name.to_string(),
            estimated_rows,
        });
        self.table_index.insert(name.to_string(), idx);
        idx
    }

    pub fn add_column(
        &mut self,
        table: &str,
        name: &str,
        data_type: &str,
        nullable: bool,
    ) -> NodeIndex {
        let key = format!("{}.{}", table, name);
        if let Some(&idx) = self.column_index.get(&key) {
            return idx;
        }
        let idx = self.graph.add_node(SchemaNode::Column {
            table: table.to_string(),
            name: name.to_string(),
            data_type: data_type.to_string(),
            nullable,
        });
        self.column_index.insert(key, idx);

        // Connect table → column
        if let Some(&tidx) = self.table_index.get(table) {
            self.graph.add_edge(tidx, idx, SchemaEdge::Contains);
        }
        idx
    }

    pub fn add_index(&mut self, index_name: &str, table: &str, unique: bool) -> NodeIndex {
        if let Some(&idx) = self.index_index.get(index_name) {
            return idx;
        }
        let idx = self.graph.add_node(SchemaNode::Index {
            name: index_name.to_string(),
            table: table.to_string(),
            unique,
        });
        self.index_index.insert(index_name.to_string(), idx);

        // Connect table → index
        if let Some(&tidx) = self.table_index.get(table) {
            self.graph.add_edge(tidx, idx, SchemaEdge::HasIndex);
        }
        idx
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_foreign_key(
        &mut self,
        from_table: &str,
        to_table: &str,
        constraint_name: Option<String>,
        from_columns: Vec<String>,
        to_columns: Vec<String>,
        cascade_delete: bool,
        cascade_update: bool,
    ) {
        // Make sure both tables exist as nodes (create ghost nodes if not yet seen)
        let from_idx = self.add_table(from_table, None);
        let to_idx = self.add_table(to_table, None);
        self.graph.add_edge(
            from_idx,
            to_idx,
            SchemaEdge::ForeignKey {
                constraint_name,
                from_columns,
                to_columns,
                cascade_delete,
                cascade_update,
            },
        );
    }

    // ── Query helpers ─────────────────────────────────────────────────────

    /// Returns all tables that hold a foreign key pointing TO the given table.
    pub fn tables_referencing(&self, table: &str) -> Vec<String> {
        let Some(&tidx) = self.table_index.get(table) else {
            return Vec::new();
        };

        use petgraph::Direction;
        self.graph
            .edges_directed(tidx, Direction::Incoming)
            .filter_map(|e| {
                if matches!(e.weight(), SchemaEdge::ForeignKey { .. }) {
                    if let SchemaNode::Table { name, .. } = &self.graph[e.source()] {
                        return Some(name.clone());
                    }
                }
                None
            })
            .collect()
    }

    /// Depth-first search: all tables reachable from `table` via FK edges.
    pub fn fk_downstream(&self, table: &str) -> Vec<String> {
        let Some(&tidx) = self.table_index.get(table) else {
            return Vec::new();
        };

        use petgraph::visit::Dfs;
        let mut dfs = Dfs::new(&self.graph, tidx);
        let mut result = Vec::new();
        while let Some(nx) = dfs.next(&self.graph) {
            if nx == tidx {
                continue;
            }
            if let SchemaNode::Table { name, .. } = &self.graph[nx] {
                result.push(name.clone());
            }
        }
        result
    }

    /// List all tables in the graph.
    pub fn all_tables(&self) -> Vec<String> {
        self.table_index.keys().cloned().collect()
    }

    /// Produces a plain-text adjacency summary of the graph.
    pub fn text_summary(&self) -> String {
        let mut lines = Vec::new();
        for (name, &idx) in &self.table_index {
            let refs: Vec<String> = self
                .graph
                .edges(idx)
                .filter_map(|e| {
                    if let SchemaEdge::ForeignKey { constraint_name, .. } = e.weight() {
                        if let SchemaNode::Table { name: tname, .. } = &self.graph[e.target()] {
                            let cn = constraint_name
                                .as_deref()
                                .unwrap_or("unnamed");
                            return Some(format!("  FK({}) → {}", cn, tname));
                        }
                    }
                    None
                })
                .collect();

            if refs.is_empty() {
                lines.push(format!("[Table] {}", name));
            } else {
                lines.push(format!("[Table] {}", name));
                lines.extend(refs);
            }
        }
        lines.sort();
        lines.join("\n")
    }

    // ── Graph export ──────────────────────────────────────────────────────

    /// Export the schema as a Mermaid ER diagram.
    ///
    /// Output can be embedded in a Markdown file and rendered by GitHub,
    /// GitLab, Notion, etc.
    ///
    /// Example:
    /// ```mermaid
    /// erDiagram
    ///     users {
    ///         uuid id PK
    ///         text email
    ///     }
    ///     orders ||--o{ users : "user_id"
    /// ```
    pub fn export_mermaid(&self) -> String {
        let mut out = String::from("erDiagram\n");

        // ── Table definitions ─────────────────────────────────────────────
        for (table_name, &table_idx) in &self.table_index {
            out.push_str(&format!("    {} {{\n", sanitise_id(table_name)));

            // Columns that belong to this table
            let mut col_lines: Vec<String> = self
                .column_index
                .iter()
                .filter(|(key, _)| key.starts_with(&format!("{}.", table_name)))
                .filter_map(|(_, &col_idx)| {
                    if let SchemaNode::Column { name, data_type, .. } = &self.graph[col_idx] {
                        // Detect primary key by checking if the column name is "id" or
                        // if the table has an index that covers only this column.
                        let is_pk = name == "id";
                        let pk_marker = if is_pk { " PK" } else { "" };
                        Some(format!(
                            "        {} {}{}",
                            mermaid_type(data_type),
                            sanitise_id(name),
                            pk_marker
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            col_lines.sort();
            for line in col_lines {
                out.push_str(&line);
                out.push('\n');
            }

            // Row estimate comment
            if let SchemaNode::Table { estimated_rows: Some(rows), .. } = &self.graph[table_idx] {
                out.push_str(&format!("        string __rows \"~{}\"\n", human_rows(*rows)));
            }

            out.push_str("    }\n");
        }

        // ── Relationships ─────────────────────────────────────────────────
        for &table_idx in self.table_index.values() {
            for edge in self.graph.edges(table_idx) {
                if let SchemaEdge::ForeignKey {
                    constraint_name,
                    from_columns,
                    ..
                } = edge.weight()
                {
                    // Determine source and target table names
                    let source = if let SchemaNode::Table { name, .. } = &self.graph[edge.source()] {
                        name.clone()
                    } else {
                        continue;
                    };
                    let target = if let SchemaNode::Table { name, .. } = &self.graph[edge.target()] {
                        name.clone()
                    } else {
                        continue;
                    };

                    let label = constraint_name
                        .as_deref()
                        .unwrap_or_else(|| from_columns.first().map(|s| s.as_str()).unwrap_or("fk"));

                    out.push_str(&format!(
                        "    {} }}o--|| {} : \"{}\"\n",
                        sanitise_id(&source),
                        sanitise_id(&target),
                        label
                    ));
                }
            }
        }

        out
    }

    /// Export the schema as a Graphviz DOT document.
    ///
    /// Pipe to `dot -Tsvg -o schema.svg` or `dot -Tpng -o schema.png`.
    pub fn export_graphviz(&self) -> String {
        let mut out = String::from(
            "digraph schema {\n  \
             rankdir=LR;\n  \
             node [shape=record, fontsize=11, fontname=\"Helvetica\"];\n  \
             edge [fontsize=9];\n\n",
        );

        // ── Table nodes (record shape with column list) ───────────────────
        for (table_name, &table_idx) in &self.table_index {
            let row_info =
                if let SchemaNode::Table { estimated_rows: Some(rows), .. } = &self.graph[table_idx]
                {
                    format!(" (~{})", human_rows(*rows))
                } else {
                    String::new()
                };

            let col_labels: Vec<String> = self
                .column_index
                .iter()
                .filter(|(key, _)| key.starts_with(&format!("{}.", table_name)))
                .filter_map(|(_, &col_idx)| {
                    if let SchemaNode::Column { name, data_type, nullable, .. } =
                        &self.graph[col_idx]
                    {
                        let null_marker = if *nullable { "?" } else { "" };
                        Some(format!(
                            "{{{}{}|{}}}",
                            dot_escape(name),
                            null_marker,
                            mermaid_type(data_type)
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            let columns_str = if col_labels.is_empty() {
                String::new()
            } else {
                format!("|{}", col_labels.join("|"))
            };

            out.push_str(&format!(
                "  {} [label=\"{{{}{}{}}}\" fillcolor=\"#dae8fc\" style=filled];\n",
                sanitise_id(table_name),
                dot_escape(table_name),
                row_info,
                columns_str,
            ));
        }

        out.push('\n');

        // ── FK edges ─────────────────────────────────────────────────────
        for &table_idx in self.table_index.values() {
            for edge in self.graph.edges(table_idx) {
                if let SchemaEdge::ForeignKey {
                    constraint_name,
                    from_columns,
                    cascade_delete,
                    ..
                } = edge.weight()
                {
                    let source =
                        if let SchemaNode::Table { name, .. } = &self.graph[edge.source()] {
                            name.clone()
                        } else {
                            continue;
                        };
                    let target =
                        if let SchemaNode::Table { name, .. } = &self.graph[edge.target()] {
                            name.clone()
                        } else {
                            continue;
                        };

                    let label = constraint_name
                        .as_deref()
                        .unwrap_or_else(|| from_columns.first().map(|s| s.as_str()).unwrap_or("fk"));

                    let style = if *cascade_delete { "dashed" } else { "solid" };

                    out.push_str(&format!(
                        "  {} -> {} [label=\"{}\" style=\"{}\"];\n",
                        sanitise_id(&source),
                        sanitise_id(&target),
                        dot_escape(label),
                        style,
                    ));
                }
            }
        }

        out.push_str("}\n");
        out
    }
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/// Sanitise a table/column name for use as a Mermaid or DOT identifier.
/// Both formats disallow spaces, hyphens, and special characters in raw IDs.
fn sanitise_id(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Escape a string for embedding inside DOT label double-quotes.
fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace('<', "\\<")
        .replace('>', "\\>")
        .replace('|', "\\|")
}

/// Collapse verbose PostgreSQL type names to a short Mermaid-friendly form.
fn mermaid_type(pg_type: &str) -> &str {
    let lower = pg_type.to_lowercase();
    if lower.contains("bigint") || lower.contains("int8") {
        "bigint"
    } else if lower.contains("int") {
        "int"
    } else if lower.contains("bool") {
        "boolean"
    } else if lower.contains("text") || lower.contains("varchar") || lower.contains("char") {
        "string"
    } else if lower.contains("timestamp") || lower.contains("date") {
        "datetime"
    } else if lower.contains("uuid") {
        "uuid"
    } else if lower.contains("json") {
        "json"
    } else if lower.contains("float") || lower.contains("real") || lower.contains("double") || lower.contains("numeric") || lower.contains("decimal") {
        "float"
    } else if lower.contains("bytea") {
        "bytes"
    } else {
        "string"
    }
}

/// Human-readable row count (e.g. 1_400_000 → "1.4M").
fn human_rows(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

impl Default for SchemaGraph {
    fn default() -> Self {
        Self::new()
    }
}
