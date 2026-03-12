#![allow(dead_code)]

use schema_risk::ci;
use schema_risk::db;
use schema_risk::drift;
use schema_risk::engine::RiskEngine;
use schema_risk::graph;
use schema_risk::impact::ImpactScanner;
use schema_risk::loader::{self, load_file, load_glob};
use schema_risk::locks::LockSimulator;
use schema_risk::output;
use schema_risk::parser;
use schema_risk::recommendation;
use schema_risk::types::RiskLevel;

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::HashMap;
use std::path::Path;
use std::process;

// ─────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────

/// SchemaRisk — pre-flight SQL migration risk analyzer
#[derive(Parser, Debug)]
#[command(
    name = "schema-risk",
    version,
    author,
    about = "Analyze SQL migration files for production risks before they run",
    long_about = None,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Analyze one or more SQL migration files and report risk
    Analyze {
        /// Path(s) or glob pattern to SQL file(s)
        #[arg(required = true, num_args = 1..)]
        files: Vec<String>,

        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: OutputFormat,

        /// Fail the process (exit 1) if risk is at or above this level
        #[arg(long, default_value = "high")]
        fail_on: FailLevel,

        /// Table row estimates to improve lock duration and scoring
        /// Format: "users:5000000,orders:2000000"
        #[arg(long)]
        table_rows: Option<String>,

        /// Show all detected operations (verbose)
        #[arg(short, long)]
        verbose: bool,

        /// Connect to a live PostgreSQL database to fetch real row counts and
        /// table sizes.  Requires the `db` feature:
        ///   cargo build --features db
        /// Example: postgres://user:password@host:5432/dbname
        #[arg(long)]
        db_url: Option<String>,

        /// Show lock simulation and execution timeline
        #[arg(long)]
        show_locks: bool,

        /// Scan source files in this directory for queries that reference
        /// tables/columns being changed by the migration.
        #[arg(long)]
        scan_dir: Option<String>,
    },

    /// Provide a detailed step-by-step explanation of each SQL statement
    Explain {
        /// Path to the SQL migration file
        #[arg(required = true)]
        file: String,

        /// Table row estimates (format: "table:rows,table:rows")
        #[arg(long)]
        table_rows: Option<String>,
    },

    /// Print the schema dependency graph (tables and FK relationships)
    Graph {
        /// Path(s) or glob pattern to SQL file(s)
        #[arg(required = true, num_args = 1..)]
        files: Vec<String>,

        /// Output format: text, mermaid, or graphviz (dot)
        #[arg(long, default_value = "text")]
        format: GraphFormat,

        /// Table row estimates (format: "table:rows,table:rows")
        #[arg(long)]
        table_rows: Option<String>,
    },

    /// Compare migration files against a live database to detect schema drift
    Diff {
        /// Path(s) or glob pattern to SQL migration file(s) to use as the
        /// "expected" schema baseline
        #[arg(required = true, num_args = 1..)]
        files: Vec<String>,

        /// PostgreSQL connection URL for the live database.
        /// Requires the `db` feature: cargo build --features db
        #[arg(long, required = true)]
        db_url: String,

        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: OutputFormat,
    },

    /// Auto-fix risky SQL in a migration file and write the result to disk.
    ///
    /// Currently auto-fixes:
    ///   - CREATE INDEX without CONCURRENTLY (Rule R01)
    ///
    /// For all other rules, shows a detailed migration plan to apply manually.
    Fix {
        /// Path to the SQL migration file to fix
        #[arg(required = true)]
        file: String,

        /// Write fixed SQL to this file (default: overwrite the input file)
        #[arg(short, long)]
        output: Option<String>,

        /// Show diff without writing — useful in CI to preview changes
        #[arg(long)]
        dry_run: bool,

        /// Table row estimates to improve size-aware suggestions (format: "users:5000000")
        #[arg(long)]
        table_rows: Option<String>,
    },

    /// Generate a CI/CD report for posting as a PR comment.
    ///
    /// Outputs GitHub-Flavored Markdown to stdout. Pipe to a file and post
    /// via `actions/github-script` or the GitLab MR Notes API.
    CiReport {
        /// Path(s) or glob pattern to SQL file(s)
        #[arg(required = true, num_args = 1..)]
        files: Vec<String>,

        /// Output format for the CI comment
        #[arg(long, default_value = "github-comment")]
        format: CiReportFormat,

        /// PostgreSQL database URL for live row-count and table-size data
        #[arg(long)]
        db_url: Option<String>,

        /// Scan this directory for queries referencing affected schema objects
        #[arg(long)]
        scan_dir: Option<String>,

        /// Table row estimates (format: "table:rows,table:rows")
        #[arg(long)]
        table_rows: Option<String>,

        /// Exit with code 1 if the highest risk level reaches this threshold
        #[arg(long, default_value = "critical")]
        fail_on: FailLevel,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
enum GraphFormat {
    Text,
    Mermaid,
    Graphviz,
}

#[derive(Debug, Clone, ValueEnum)]
enum CiReportFormat {
    GithubComment,
    GitlabComment,
    Json,
}

impl From<CiReportFormat> for ci::CiFormat {
    fn from(f: CiReportFormat) -> ci::CiFormat {
        match f {
            CiReportFormat::GithubComment => ci::CiFormat::GithubComment,
            CiReportFormat::GitlabComment => ci::CiFormat::GitlabComment,
            CiReportFormat::Json => ci::CiFormat::Json,
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum FailLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailLevel> for RiskLevel {
    fn from(f: FailLevel) -> RiskLevel {
        match f {
            FailLevel::Low => RiskLevel::Low,
            FailLevel::Medium => RiskLevel::Medium,
            FailLevel::High => RiskLevel::High,
            FailLevel::Critical => RiskLevel::Critical,
        }
    }
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Initialise structured logging.  RUST_LOG controls verbosity, e.g.:
    //   RUST_LOG=schema_risk=debug schema-risk analyze migration.sql
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        // ── schema-risk analyze ───────────────────────────────────────────
        Commands::Analyze {
            files,
            format,
            fail_on,
            table_rows,
            verbose,
            db_url,
            show_locks,
            scan_dir,
        } => {
            let row_counts = parse_row_counts(table_rows.as_deref());
            let fail_level: RiskLevel = fail_on.into();

            // Optionally fetch live schema from the database
            let engine = if let Some(url) = &db_url {
                match fetch_live_schema(url).await {
                    Ok(live) => {
                        eprintln!("info: Connected to database, fetched {} tables", live.tables.len());
                        RiskEngine::with_live_schema(row_counts, live)
                    }
                    Err(e) => {
                        eprintln!("warning: Could not fetch live schema: {}", e);
                        RiskEngine::new(row_counts)
                    }
                }
            } else {
                RiskEngine::new(row_counts)
            };

            let mut reports = Vec::new();
            let mut all_stmts: Vec<parser::ParsedStatement> = Vec::new();
            let mut affected_tables_global: Vec<String> = Vec::new();
            let mut affected_columns_global: Vec<String> = Vec::new();

            for pattern in &files {
                let loaded = load_pattern(pattern);
                for migration in loaded {
                    let stmts = match parser::parse(&migration.sql) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("parse error in {}: {}", migration.name, e);
                            process::exit(2);
                        }
                    };
                    let report = engine.analyze(&migration.name, &stmts);

                    // Collect affected objects for impact scanning
                    affected_tables_global.extend(report.affected_tables.clone());
                    collect_column_names(&stmts, &mut affected_columns_global);

                    // Lock simulation
                    if show_locks {
                        let sim = LockSimulator::new(engine.row_counts.clone());
                        let timeline = sim.simulate(&stmts);
                        output::render_timeline(&timeline);
                    }

                    all_stmts.extend(stmts);
                    reports.push(report);
                }
            }

            // Query impact detection
            if let Some(dir) = &scan_dir {
                affected_tables_global.sort();
                affected_tables_global.dedup();
                affected_columns_global.sort();
                affected_columns_global.dedup();

                let scanner = ImpactScanner::new(
                    affected_tables_global.clone(),
                    affected_columns_global.clone(),
                );
                let impact_report = scanner.scan(Path::new(dir));
                output::render_impact(&impact_report);
            }

            // Output reports
            match format {
                OutputFormat::Terminal => {
                    for report in &reports {
                        output::render(report, verbose);
                    }
                    if reports.len() > 1 {
                        output::render_summary_table(&reports);
                    }
                }
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&reports).unwrap_or_default();
                    println!("{}", json);
                }
            }

            // CI exit code
            let max_risk = reports
                .iter()
                .map(|r| r.overall_risk)
                .max()
                .unwrap_or(RiskLevel::Low);

            process::exit(max_risk.exit_code(fail_level));
        }

        // ── schema-risk explain ───────────────────────────────────────────
        Commands::Explain { file, table_rows } => {
            let row_counts = parse_row_counts(table_rows.as_deref());
            let engine = RiskEngine::new(row_counts);

            let migration = match load_file(&file) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(2);
                }
            };

            let stmts = match parser::parse(&migration.sql) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("parse error: {}", e);
                    process::exit(2);
                }
            };

            let report = engine.analyze(&migration.name, &stmts);
            output::render(&report, /* verbose = */ true);

            // Print detailed statement-by-statement breakdown
            use colored::Colorize;
            println!(
                "\n  {}\n",
                "Statement-by-Statement Breakdown".bold().underline()
            );
            for (i, (stmt, op)) in stmts
                .iter()
                .zip(report.operations.iter().chain(std::iter::repeat(&schema_risk::types::DetectedOperation {
                    description: String::new(),
                    tables: vec![],
                    risk_level: RiskLevel::Low,
                    score: 0,
                    warning: None,
                    acquires_lock: false,
                    index_rebuild: false,
                })))
                .enumerate()
            {
                println!(
                    "  [{:02}] {}",
                    i + 1,
                    format!("{:?}", stmt)
                        .chars()
                        .take(120)
                        .collect::<String>()
                );
                if !op.description.is_empty() {
                    println!("       → {}", op.description.cyan());
                    if let Some(w) = &op.warning {
                        println!("       ⚠  {}", w.yellow());
                    }
                }
                println!();
            }
        }

        // ── schema-risk graph ─────────────────────────────────────────────
        Commands::Graph { files, format, table_rows } => {
            let row_counts = parse_row_counts(table_rows.as_deref());
            let engine = RiskEngine::new(row_counts);
            let mut combined_graph = graph::SchemaGraph::new();

            for pattern in &files {
                let loaded = load_pattern(pattern);
                for migration in loaded {
                    let stmts = match parser::parse(&migration.sql) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("parse error in {}: {}", migration.name, e);
                            process::exit(2);
                        }
                    };
                    for stmt in &stmts {
                        build_graph_for_display(&mut combined_graph, stmt, &engine.row_counts);
                    }
                }
            }

            use colored::Colorize;
            match format {
                GraphFormat::Text => {
                    println!(
                        "\n  {}\n",
                        "Schema Dependency Graph".bold().underline()
                    );
                    println!("{}", combined_graph.text_summary());
                    println!(
                        "\n  Total tables: {}\n",
                        combined_graph.all_tables().len().to_string().cyan()
                    );
                }
                GraphFormat::Mermaid => {
                    println!("{}", combined_graph.export_mermaid());
                }
                GraphFormat::Graphviz => {
                    println!("{}", combined_graph.export_graphviz());
                }
            }
        }

        // ── schema-risk diff ──────────────────────────────────────────────
        Commands::Diff { files, db_url, format } => {
            // Build schema graph from migration files
            let row_counts = HashMap::new();
            let engine = RiskEngine::new(row_counts);
            let mut migration_graph = graph::SchemaGraph::new();

            for pattern in &files {
                let loaded = load_pattern(pattern);
                for migration in loaded {
                    let stmts = match parser::parse(&migration.sql) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("parse error in {}: {}", migration.name, e);
                            process::exit(2);
                        }
                    };
                    for stmt in &stmts {
                        build_graph_for_display(&mut migration_graph, stmt, &engine.row_counts);
                    }
                }
            }

            // Fetch live schema
            let live = match fetch_live_schema(&db_url).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: Failed to connect to database: {}", e);
                    process::exit(2);
                }
            };

            let drift_report = drift::diff(&migration_graph, &live);

            match format {
                OutputFormat::Terminal => {
                    output::render_drift(&drift_report);
                }
                OutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&drift_report).unwrap_or_default();
                    println!("{}", json);
                }
            }

            if drift_report.is_clean() {
                process::exit(0);
            } else {
                process::exit(1);
            }
        }

        // ── schema-risk fix ───────────────────────────────────────────────
        Commands::Fix {
            file,
            output,
            dry_run,
            table_rows,
        } => {
            use colored::Colorize;
            let row_counts = parse_row_counts(table_rows.as_deref());

            let migration = match load_file(&file) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: {}", e);
                    process::exit(2);
                }
            };

            let stmts = match parser::parse(&migration.sql) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("parse error: {}", e);
                    process::exit(2);
                }
            };

            // Gather fix suggestions
            let fixes = recommendation::suggest_fixes(&stmts, &row_counts);

            if fixes.is_empty() {
                println!(
                    "\n  {} No risky patterns found in {}\n",
                    "✓".green().bold(),
                    file.cyan()
                );
                process::exit(0);
            }

            // Print all suggestions
            output::render_fix_suggestions(&fixes);

            // Apply auto-fixable rules to the raw SQL
            let fixed_sql = recommendation::apply_fixes(&migration.sql, &fixes);

            // Show diff between original and fixed
            let auto_fixes: Vec<_> = fixes.iter().filter(|f| f.auto_fixable).collect();
            if !auto_fixes.is_empty() {
                println!(
                    "\n  {}\n",
                    "Auto-fixable changes (diff)".bold().underline()
                );
                print_sql_diff(&migration.sql, &fixed_sql);
            }

            if dry_run {
                println!(
                    "\n  {} Dry-run mode: no files written. Run without --dry-run to apply.\n",
                    "ℹ".cyan()
                );
            } else {
                let out_path = output.as_deref().unwrap_or(&file);
                match std::fs::write(out_path, &fixed_sql) {
                    Ok(()) => {
                        println!(
                            "\n  {} Fixed SQL written to: {}\n",
                            "✓".green().bold(),
                            out_path.cyan()
                        );
                    }
                    Err(e) => {
                        eprintln!("error: failed to write {}: {}", out_path, e);
                        process::exit(2);
                    }
                }
            }
        }

        // ── schema-risk ci-report ─────────────────────────────────────────
        Commands::CiReport {
            files,
            format,
            db_url,
            scan_dir,
            table_rows,
            fail_on,
        } => {
            let row_counts = parse_row_counts(table_rows.as_deref());
            let fail_level: RiskLevel = fail_on.into();

            // Build engine with optional live schema
            let engine = if let Some(url) = &db_url {
                match fetch_live_schema(url).await {
                    Ok(live) => {
                        eprintln!("info: Connected to DB, fetched {} tables", live.tables.len());
                        RiskEngine::with_live_schema(row_counts, live)
                    }
                    Err(e) => {
                        eprintln!("warning: DB connection failed (offline mode): {}", e);
                        RiskEngine::new(row_counts)
                    }
                }
            } else {
                RiskEngine::new(row_counts)
            };

            let mut reports = Vec::new();
            let mut all_fixes: HashMap<String, Vec<recommendation::FixSuggestion>> =
                HashMap::new();
            let mut affected_tables: Vec<String> = Vec::new();
            let mut affected_columns: Vec<String> = Vec::new();

            for pattern in &files {
                for migration in load_pattern(pattern) {
                    let stmts = match parser::parse(&migration.sql) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("parse error in {}: {}", migration.name, e);
                            process::exit(2);
                        }
                    };
                    let report = engine.analyze(&migration.name, &stmts);
                    let fixes = recommendation::suggest_fixes(&stmts, &engine.row_counts);
                    affected_tables.extend(report.affected_tables.clone());
                    collect_column_names(&stmts, &mut affected_columns);
                    all_fixes.insert(migration.name.clone(), fixes);
                    reports.push(report);
                }
            }

            // Optional codebase scan for breaking changes
            let impact_report = scan_dir.as_ref().map(|dir| {
                affected_tables.sort();
                affected_tables.dedup();
                affected_columns.sort();
                affected_columns.dedup();
                let scanner = ImpactScanner::new(
                    affected_tables.clone(),
                    affected_columns.clone(),
                );
                scanner.scan(Path::new(dir))
            });

            // Render CI report
            let ci_format: ci::CiFormat = format.into();
            let report_text = ci::render_ci_report(
                &reports,
                &all_fixes,
                impact_report.as_ref(),
                ci_format,
            );
            println!("{}", report_text);

            // Exit code for CI
            let max_risk = reports
                .iter()
                .map(|r| r.overall_risk)
                .max()
                .unwrap_or(RiskLevel::Low);
            process::exit(max_risk.exit_code(fail_level));
        }
    }
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

fn parse_row_counts(raw: Option<&str>) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    let Some(s) = raw else { return map };
    for pair in s.split(',') {
        let parts: Vec<&str> = pair.splitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(n) = parts[1].trim().parse::<u64>() {
                map.insert(parts[0].trim().to_string(), n);
            }
        }
    }
    map
}

/// Load files from a path or glob pattern, exiting on error.
fn load_pattern(pattern: &str) -> Vec<loader::MigrationFile> {
    if pattern.contains('*') || pattern.contains('?') {
        match load_glob(pattern) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(2);
            }
        }
    } else {
        match load_file(pattern) {
            Ok(f) => vec![f],
            Err(e) => {
                eprintln!("error: {}", e);
                process::exit(2);
            }
        }
    }
}

/// Collect column names from statements for impact scanning.
fn collect_column_names(stmts: &[parser::ParsedStatement], out: &mut Vec<String>) {
    for stmt in stmts {
        match stmt {
            parser::ParsedStatement::AlterTableDropColumn { column, .. } => {
                out.push(column.clone());
            }
            parser::ParsedStatement::AlterTableRenameColumn { old, new, .. } => {
                out.push(old.clone());
                out.push(new.clone());
            }
            parser::ParsedStatement::AlterTableAlterColumnType { column, .. } => {
                out.push(column.clone());
            }
            _ => {}
        }
    }
}

/// Fetch live schema from PostgreSQL — routes through feature-gated connector.
async fn fetch_live_schema(db_url: &str) -> schema_risk::error::Result<db::LiveSchema> {
    #[cfg(feature = "db")]
    {
        db::connector::fetch(db_url).await
    }
    #[cfg(not(feature = "db"))]
    {
        let _ = db_url;
        Err(schema_risk::error::SchemaRiskError::FeatureDisabled(
            "db".to_string(),
        ))
    }
}

/// Mirrors `engine.populate_graph` but operates on a user-provided graph.
fn build_graph_for_display(
    graph: &mut graph::SchemaGraph,
    stmt: &parser::ParsedStatement,
    row_counts: &HashMap<String, u64>,
) {
    match stmt {
        parser::ParsedStatement::CreateTable {
            table,
            columns,
            foreign_keys,
            ..
        } => {
            let rows = row_counts.get(table).copied();
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
        parser::ParsedStatement::AlterTableAddForeignKey { table, fk } => {
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
        _ => {}
    }
}

/// Print a side-by-side diff of two SQL strings (changed lines only).
fn print_sql_diff(original: &str, fixed: &str) {
    use colored::Colorize;
    let orig_lines: Vec<&str> = original.lines().collect();
    let fixed_lines: Vec<&str> = fixed.lines().collect();
    let max_len = orig_lines.len().max(fixed_lines.len());
    let mut changed = 0;
    for i in 0..max_len {
        match (orig_lines.get(i), fixed_lines.get(i)) {
            (Some(a), Some(b)) if a != b => {
                println!("  {} {}", "-".red().bold(), a.red());
                println!("  {} {}", "+".green().bold(), b.green());
                changed += 1;
            }
            (Some(a), None) => {
                println!("  {} {}", "-".red().bold(), a.red());
                changed += 1;
            }
            (None, Some(b)) => {
                println!("  {} {}", "+".green().bold(), b.green());
                changed += 1;
            }
            _ => {}
        }
    }
    if changed == 0 {
        println!("  (no changes)");
    }
}
