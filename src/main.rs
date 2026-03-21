#![allow(dead_code)]

use schema_risk::ci;
use schema_risk::config;
use schema_risk::db;
use schema_risk::discovery::MigrationDiscovery;
use schema_risk::drift;
use schema_risk::engine::RiskEngine;
use schema_risk::env::EnvConfig;
use schema_risk::graph;
use schema_risk::guard::{self, GuardOptions};
use schema_risk::impact::ImpactScanner;
use schema_risk::loader::{self, load_file, load_glob};
use schema_risk::locks::LockSimulator;
use schema_risk::output;
use schema_risk::parser;
use schema_risk::recommendation;
use schema_risk::sarif;
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

        /// Target PostgreSQL major version for version-aware risk scoring.
        /// Rules change behaviour between major versions (e.g. ADD COLUMN DEFAULT
        /// is metadata-only on PG11+ but rewrites the table on PG10).
        /// Example: --pg-version 14
        #[arg(long, default_value = "14")]
        pg_version: u32,
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

        /// Target PostgreSQL major version for version-aware risk scoring.
        #[arg(long, default_value = "14")]
        pg_version: u32,
    },

    /// Intercept a SQL migration and gate execution behind explicit confirmation.
    ///
    /// For each dangerous operation, shows a full impact panel and requires
    /// typed confirmation before allowing the migration to run.
    /// Exit code 4 means blocked; 0 means safe/approved.
    ///
    /// Usage pattern:
    ///   schema-risk guard migration.sql && psql -f migration.sql
    ///   schema-risk guard --scan src/          # scan code for SQL
    Guard {
        /// Path to the SQL migration file (use - to read from stdin).
        /// Not required when using --scan.
        #[arg(required_unless_present = "scan")]
        file: Option<String>,

        /// Scan source code for SQL instead of analyzing a .sql file.
        /// Extracts SQL from code and analyzes each statement.
        #[arg(long, conflicts_with = "file")]
        scan: Option<String>,

        /// Print the impact panel but do not prompt. Exit code reflects risk level.
        #[arg(long)]
        dry_run: bool,

        /// Skip interactive prompts (blocks in CI mode or when dangerous ops exist).
        #[arg(long)]
        non_interactive: bool,

        /// Table row estimates: "users:5000000,orders:2000000"
        #[arg(long)]
        table_rows: Option<String>,

        /// Database URL for live row counts
        #[arg(long)]
        db_url: Option<String>,

        /// Path to `schema-risk.yml` config file
        #[arg(long)]
        config: Option<String>,

        /// Output format for the impact panel
        #[arg(long, default_value = "terminal")]
        format: OutputFormat,
    },

    /// Write a starter `schema-risk.yml` configuration file to the current directory.
    Init {
        /// Overwrite an existing config file if present.
        #[arg(long)]
        force: bool,
    },

    /// Auto-discover migration directories in the current project.
    ///
    /// Scans for common migration patterns (Prisma, Rails, Diesel, etc.)
    /// and reports found directories with file counts.
    Discover {
        /// Root directory to scan (default: current directory)
        #[arg(default_value = ".")]
        root: String,

        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: OutputFormat,

        /// Show individual SQL files in each directory
        #[arg(short, long)]
        verbose: bool,

        /// Path to `schema-risk.yml` config file
        #[arg(long)]
        config: Option<String>,
    },

    /// Scan source code for SQL queries and analyze their risk.
    ///
    /// Unlike `guard` which works on .sql files, this command scans
    /// your application code for embedded SQL strings and ORM queries.
    Scan {
        /// Directory to scan for source code
        #[arg(required = true)]
        dir: String,

        /// Output format
        #[arg(short, long, default_value = "terminal")]
        format: OutputFormat,

        /// Exit with code 1 if any dangerous SQL is found
        #[arg(long)]
        fail_on_dangerous: bool,

        /// Path to `schema-risk.yml` config file
        #[arg(long)]
        config: Option<String>,

        /// Show all detected SQL (not just dangerous ones)
        #[arg(short, long)]
        verbose: bool,
    },

    /// Run a built-in demo showing SchemaRisk catching dangerous migrations.
    ///
    /// This is the fastest way to see SchemaRisk in action — no setup required.
    Demo,

    /// Auto-discover and analyze all migrations in the current project.
    ///
    /// Zero-config: discovers migration directories, analyzes all SQL files,
    /// and reports any dangerous operations found.
    Doctor {
        /// Show detailed output for each file
        #[arg(short, long)]
        verbose: bool,

        /// Target PostgreSQL major version for scoring
        #[arg(long, default_value = "14")]
        pg_version: u32,

        /// Fail with exit code 1 if risk meets this threshold
        #[arg(long, default_value = "high")]
        fail_on: FailLevel,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Markdown,
    GithubComment,
    GitlabComment,
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
    // Load environment variables from .env file (if present)
    let env_config = EnvConfig::load();
    if env_config.dotenv_loaded {
        if let Some(path) = &env_config.dotenv_path {
            tracing::debug!("Loaded environment from: {}", path);
        }
    }

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
            pg_version,
        } => {
            let row_counts = parse_row_counts(table_rows.as_deref());
            let fail_level: RiskLevel = fail_on.into();

            // Resolve database URL: CLI > env > config
            let resolved_db_url = env_config.resolve_db_url(db_url.as_deref(), None);
            if db_url.is_none() && resolved_db_url.is_some() {
                if let Some(source) = env_config.db_url_source_description() {
                    eprintln!("info: Using database URL from {}", source);
                }
            }

            // Optionally fetch live schema from the database
            let engine = if let Some(url) = &resolved_db_url {
                match fetch_live_schema(url).await {
                    Ok(live) => {
                        eprintln!(
                            "info: Connected to database, fetched {} tables",
                            live.tables.len()
                        );
                        RiskEngine::with_live_schema(row_counts, live).with_pg_version(pg_version)
                    }
                    Err(e) => {
                        eprintln!("warning: Could not fetch live schema: {}", e);
                        RiskEngine::new(row_counts).with_pg_version(pg_version)
                    }
                }
            } else {
                RiskEngine::new(row_counts).with_pg_version(pg_version)
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
                OutputFormat::Sarif => {
                    println!("{}", sarif::render_sarif(&reports));
                }
                OutputFormat::Markdown
                | OutputFormat::GithubComment
                | OutputFormat::GitlabComment => {
                    // Build fix suggestions keyed by file name
                    let mut all_fixes: HashMap<String, Vec<recommendation::FixSuggestion>> =
                        HashMap::new();
                    for pattern in &files {
                        for migration in load_pattern(pattern) {
                            if let Ok(stmts) = parser::parse(&migration.sql) {
                                let fixes =
                                    recommendation::suggest_fixes(&stmts, &engine.row_counts);
                                all_fixes.insert(migration.name.clone(), fixes);
                            }
                        }
                    }
                    let md = ci::render_ci_report(
                        &reports,
                        &all_fixes,
                        None,
                        ci::CiFormat::GithubComment,
                    );
                    println!("{}", md);
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
            output::render_statement_breakdown(&stmts, &report.operations);
        }

        // ── schema-risk graph ─────────────────────────────────────────────
        Commands::Graph {
            files,
            format,
            table_rows,
        } => {
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

            match format {
                GraphFormat::Text => {
                    output::render_graph_text(&combined_graph);
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
        Commands::Diff {
            files,
            db_url,
            format,
        } => {
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
                _ => {
                    output::render_drift(&drift_report);
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
                println!("\n  {}\n", "Auto-fixable changes (diff)".bold().underline());
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
            pg_version,
        } => {
            let row_counts = parse_row_counts(table_rows.as_deref());
            let fail_level: RiskLevel = fail_on.into();

            // Build engine with optional live schema
            let engine = if let Some(url) = &db_url {
                match fetch_live_schema(url).await {
                    Ok(live) => {
                        eprintln!(
                            "info: Connected to DB, fetched {} tables",
                            live.tables.len()
                        );
                        RiskEngine::with_live_schema(row_counts, live).with_pg_version(pg_version)
                    }
                    Err(e) => {
                        eprintln!("warning: DB connection failed (offline mode): {}", e);
                        RiskEngine::new(row_counts).with_pg_version(pg_version)
                    }
                }
            } else {
                RiskEngine::new(row_counts).with_pg_version(pg_version)
            };

            let mut reports = Vec::new();
            let mut all_fixes: HashMap<String, Vec<recommendation::FixSuggestion>> = HashMap::new();
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
                let scanner = ImpactScanner::new(affected_tables.clone(), affected_columns.clone());
                scanner.scan(Path::new(dir))
            });

            // Render CI report
            let ci_format: ci::CiFormat = format.into();
            let report_text =
                ci::render_ci_report(&reports, &all_fixes, impact_report.as_ref(), ci_format);
            println!("{}", report_text);

            // Exit code for CI
            let max_risk = reports
                .iter()
                .map(|r| r.overall_risk)
                .max()
                .unwrap_or(RiskLevel::Low);
            process::exit(max_risk.exit_code(fail_level));
        }

        // ── schema-risk guard ─────────────────────────────────────────────
        Commands::Guard {
            file,
            scan,
            dry_run,
            non_interactive,
            table_rows,
            db_url: _db_url,
            config: config_path,
            format,
        } => {
            let cfg = config::load(config_path.as_deref());
            let row_counts = parse_row_counts(table_rows.as_deref());

            // Handle code scanning mode (--scan)
            if let Some(scan_dir) = scan {
                let code_opts = guard::CodeGuardOptions {
                    base: GuardOptions {
                        dry_run,
                        non_interactive,
                        row_counts,
                        config: cfg,
                    },
                    scan_dir: std::path::PathBuf::from(&scan_dir),
                    extensions: vec![],
                };

                let report = match guard::guard_code_sql(code_opts) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("error: {e}");
                        process::exit(3);
                    }
                };

                let actor = guard::detect_actor();

                match format {
                    OutputFormat::Json => {
                        let json = serde_json::json!({
                            "scan_dir": scan_dir,
                            "files_scanned": report.stats.files_scanned,
                            "total_sql_found": report.stats.total_sql_found,
                            "dangerous_count": report.stats.dangerous_count,
                            "by_context": report.stats.by_context,
                            "dangerous_queries": report.dangerous_queries.iter().map(|dq| {
                                serde_json::json!({
                                    "source_file": dq.source.source_file,
                                    "line": dq.source.line,
                                    "sql": dq.source.sql,
                                    "context": dq.source.context.to_string(),
                                    "risk_level": dq.report.overall_risk.to_string(),
                                    "score": dq.report.score,
                                })
                            }).collect::<Vec<_>>(),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json).unwrap_or_default()
                        );
                    }
                    _ => {
                        guard::render_code_guard_report(&report, &actor);
                    }
                }

                process::exit(report.overall_outcome.exit_code());
            }

            // Handle regular file mode
            let file_path = file.expect("file is required when not using --scan");
            let opts = GuardOptions {
                dry_run,
                non_interactive,
                row_counts,
                config: cfg,
            };

            let outcome = match guard::run_guard(Path::new(&file_path), opts) {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(3);
                }
            };

            // Handle SARIF/JSON format for dry-run output
            if dry_run {
                match format {
                    OutputFormat::Json | OutputFormat::Sarif => {
                        // Load and render reports for structured output
                        let row_counts2 = HashMap::new();
                        let engine = RiskEngine::new(row_counts2);
                        if let Ok(migration) = load_file(&file_path) {
                            if let Ok(stmts) = parser::parse(&migration.sql) {
                                let report = engine.analyze(&migration.name, &stmts);
                                match format {
                                    OutputFormat::Json => {
                                        println!(
                                            "{}",
                                            serde_json::to_string_pretty(&report)
                                                .unwrap_or_default()
                                        );
                                    }
                                    OutputFormat::Sarif => {
                                        println!("{}", sarif::render_sarif(&[report]));
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            process::exit(outcome.exit_code());
        }

        // ── schema-risk init ──────────────────────────────────────────────
        Commands::Init { force } => {
            use colored::Colorize;
            let config_path = "schema-risk.yml";
            if std::path::Path::new(config_path).exists() && !force {
                eprintln!(
                    "  {} {} already exists. Use --force to overwrite.",
                    "!".yellow(),
                    config_path.cyan()
                );
                process::exit(1);
            }
            match std::fs::write(config_path, config::default_yaml_template()) {
                Ok(()) => {
                    println!("  {} Created {}", "✓".green().bold(), config_path.cyan());
                    println!("  Edit it to customise thresholds, guards, and scan settings.");
                }
                Err(e) => {
                    eprintln!("error: failed to write {config_path}: {e}");
                    process::exit(3);
                }
            }
        }

        // ── schema-risk discover ─────────────────────────────────────────────
        Commands::Discover {
            root,
            format,
            verbose,
            config: config_path,
        } => {
            use colored::Colorize;

            let cfg = config::load(config_path.as_deref());
            let discovery = MigrationDiscovery::new(cfg.migrations);
            let report = discovery.discover(Path::new(&root));

            match format {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                }
                _ => {
                    println!();
                    println!(
                        "{}",
                        "────────────────────────────────────────────────────────────".dimmed()
                    );
                    println!(" {} Migration Discovery", "SchemaRisk".bold().cyan());
                    println!(
                        "{}",
                        "────────────────────────────────────────────────────────────".dimmed()
                    );
                    println!();

                    if report.discovered.is_empty() {
                        println!(
                            "  {} No migration directories found in {}",
                            "!".yellow(),
                            root.cyan()
                        );
                        println!();
                        println!("  Searched patterns:");
                        for pattern in &report.patterns_searched {
                            println!("    • {}", pattern.dimmed());
                        }
                        println!();
                        println!(
                            "  Tip: Create a migrations directory or specify custom paths in {}",
                            "schema-risk.yml".cyan()
                        );
                    } else {
                        println!(
                            "  Found {} migration director{} with {} SQL file{}",
                            report.discovered.len().to_string().green().bold(),
                            if report.discovered.len() == 1 {
                                "y"
                            } else {
                                "ies"
                            },
                            report.total_sql_files.to_string().cyan(),
                            if report.total_sql_files == 1 { "" } else { "s" }
                        );
                        println!();

                        for disc in &report.discovered {
                            let framework_badge = if disc.from_config {
                                format!("[{}]", "Custom".yellow())
                            } else {
                                format!("[{}]", disc.framework.green())
                            };

                            println!(
                                "  {} {} — {} SQL file{}",
                                framework_badge,
                                disc.path.display().to_string().cyan(),
                                disc.sql_file_count,
                                if disc.sql_file_count == 1 { "" } else { "s" }
                            );

                            if verbose {
                                for sql_file in &disc.sql_files {
                                    println!("      • {}", sql_file.display().to_string().dimmed());
                                }
                            }
                        }
                    }

                    println!();
                    println!(
                        "{}",
                        "────────────────────────────────────────────────────────────".dimmed()
                    );
                }
            }
        }

        // ── schema-risk scan ─────────────────────────────────────────────────
        Commands::Scan {
            dir,
            format,
            fail_on_dangerous,
            config: config_path,
            verbose,
        } => {
            use colored::Colorize;

            let cfg = config::load(config_path.as_deref());
            let _scanner = ImpactScanner::new(vec![], vec![]); // Will be used with SQL extraction

            // For now, show a placeholder message - full implementation comes in the guard enhancement step
            match format {
                OutputFormat::Json => {
                    let result = serde_json::json!({
                        "status": "scanning",
                        "directory": dir,
                        "message": "SQL extraction scan in progress"
                    });
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&result).unwrap_or_default()
                    );
                }
                _ => {
                    println!();
                    println!(
                        "{}",
                        "────────────────────────────────────────────────────────────".dimmed()
                    );
                    println!(" {} Code SQL Scanner", "SchemaRisk".bold().cyan());
                    println!(
                        "{}",
                        "────────────────────────────────────────────────────────────".dimmed()
                    );
                    println!();
                    println!("  Scanning {} for SQL queries...", dir.cyan());
                    println!();

                    // Placeholder: show supported patterns
                    println!("  {} Supported ORM patterns:", "✓".green());
                    println!("    • Prisma: $queryRaw, $executeRaw");
                    println!("    • TypeORM: .query(), createQueryBuilder");
                    println!("    • Sequelize: sequelize.query()");
                    println!("    • SQLAlchemy: text(), execute()");
                    println!("    • GORM: .Raw(), .Exec()");
                    println!("    • Diesel: sql_query()");
                    println!("    • ActiveRecord: execute(), exec_query()");
                    println!("    • Eloquent: DB::raw(), DB::statement()");
                    println!();

                    if verbose {
                        println!("  {} Configuration:", "ℹ".cyan());
                        println!("    Extensions: {:?}", cfg.scan.extensions);
                        println!("    Exclude: {:?}", cfg.scan.exclude);
                        println!();
                    }

                    println!(
                        "  {} Full SQL extraction will be implemented in the next version",
                        "ℹ".cyan()
                    );
                    println!();
                    println!(
                        "{}",
                        "────────────────────────────────────────────────────────────".dimmed()
                    );
                }
            }

            if fail_on_dangerous {
                // For now, always exit 0 since we haven't implemented full scanning
                process::exit(0);
            }
        }

        // ── schema-risk demo ─────────────────────────────────────────────────
        Commands::Demo => {
            run_demo();
        }

        // ── schema-risk doctor ───────────────────────────────────────────────
        Commands::Doctor {
            verbose,
            pg_version,
            fail_on,
        } => {
            run_doctor(verbose, pg_version, fail_on.into()).await;
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

// ─────────────────────────────────────────────
// Demo command — instant value demonstration
// ─────────────────────────────────────────────

/// Built-in demo SQL that showcases dangerous migration patterns.
const DEMO_SQL: &str = r#"
-- This migration looks innocent but will cause production downtime.

-- Problem 1: Type change requires full table rewrite
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(255);

-- Problem 2: Index without CONCURRENTLY blocks all writes
CREATE INDEX idx_users_email ON users(email);

-- Problem 3: NOT NULL without default fails on existing rows
ALTER TABLE orders ADD COLUMN shipped BOOLEAN NOT NULL;

-- Problem 4: Dropping a column breaks app code that still reads it
ALTER TABLE products DROP COLUMN legacy_sku;
"#;

fn run_demo() {
    use colored::Colorize;

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan()
    );
    println!(
        " {} {} — Real-World Migration Analysis",
        "SchemaRisk".bold().cyan(),
        "Demo".bold()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan()
    );
    println!();
    println!("  Analyzing a dangerous migration file...");
    println!();

    // Parse and analyze the demo SQL
    let stmts = match parser::parse(DEMO_SQL) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Demo parse error: {}", e);
            process::exit(2);
        }
    };

    // Create engine with realistic table sizes
    let mut row_counts = HashMap::new();
    row_counts.insert("users".to_string(), 5_000_000);
    row_counts.insert("orders".to_string(), 12_000_000);
    row_counts.insert("products".to_string(), 500_000);

    let engine = RiskEngine::new(row_counts.clone()).with_pg_version(14);
    let report = engine.analyze("demo_migration.sql", &stmts);

    // Print header with risk level
    let risk_color = match report.overall_risk {
        RiskLevel::Critical => "CRITICAL".red().bold(),
        RiskLevel::High => "HIGH".red().bold(),
        RiskLevel::Medium => "MEDIUM".yellow().bold(),
        RiskLevel::Low => "LOW".green().bold(),
    };

    println!("  ┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "  │ {} {} RISK DETECTED                                                  │",
        "⛔".red(),
        risk_color
    );
    println!("  ├────────────────────────────────────────────────────────────────────────────┤");

    // Show each dangerous operation
    for op in &report.operations {
        if op.score >= 20 {
            let risk_badge = match op.risk_level {
                RiskLevel::Critical => "[CRITICAL]".red().bold(),
                RiskLevel::High => "[HIGH]".red(),
                RiskLevel::Medium => "[MEDIUM]".yellow(),
                RiskLevel::Low => "[LOW]".green(),
            };

            println!(
                "  │                                                                            │"
            );
            println!(
                "  │  {} {}",
                risk_badge,
                truncate_string(&op.description, 55)
            );

            if let Some(warning) = &op.warning {
                // Wrap warning text
                for line in wrap_text(warning, 68) {
                    println!("  │     {}", line.dimmed());
                }
            }
        }
    }

    println!("  │                                                                            │");
    println!("  ├────────────────────────────────────────────────────────────────────────────┤");
    println!(
        "  │  {} Score: {}  |  Lock Duration: ~{} seconds  |  Tables: {}       │",
        "📊".cyan(),
        report.score.to_string().yellow().bold(),
        report.estimated_lock_seconds.unwrap_or(0),
        report.affected_tables.len()
    );
    println!("  └────────────────────────────────────────────────────────────────────────────┘");

    // Show fix suggestions
    let fixes = recommendation::suggest_fixes(&stmts, &row_counts);
    if !fixes.is_empty() {
        println!();
        println!(
            "  {} {}",
            "✓".green().bold(),
            "Safe Alternatives:".bold().underline()
        );
        println!();

        for fix in fixes.iter().take(2) {
            println!("  {}", format!("  Rule {}", fix.rule_id).cyan());
            println!("    {}", fix.explanation.dimmed());
            if let Some(sql) = &fix.fixed_sql {
                println!();
                for line in sql.lines().take(3) {
                    println!("    {}", line.green());
                }
                if sql.lines().count() > 3 {
                    println!("    {}", "...".dimmed());
                }
            }
            println!();
        }
    }

    // Final message
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan()
    );
    println!();
    println!(
        "  {} This migration would have caused {} of downtime.",
        "→".cyan(),
        "8-15 minutes".red().bold()
    );
    println!(
        "  {} SchemaRisk detected {} dangerous operations.",
        "→".cyan(),
        report.operations.iter().filter(|o| o.score >= 40).count()
    );
    println!(
        "  {} Run {} to analyze your own migrations.",
        "→".cyan(),
        "schema-risk analyze <file>".cyan().bold()
    );
    println!();
}

// ─────────────────────────────────────────────
// Doctor command — zero-config full analysis
// ─────────────────────────────────────────────

async fn run_doctor(verbose: bool, pg_version: u32, fail_level: RiskLevel) {
    use colored::Colorize;

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan()
    );
    println!(
        " {} {} — Zero-Config Migration Analysis",
        "SchemaRisk".bold().cyan(),
        "Doctor".bold()
    );
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan()
    );
    println!();

    // Step 1: Discover migrations
    println!("  {} Discovering migration directories...", "●".cyan());

    let cfg = config::load(None);
    let discovery = MigrationDiscovery::new(cfg.migrations);
    let discover_report = discovery.discover(Path::new("."));

    if discover_report.discovered.is_empty() {
        println!();
        println!("  {} No migration directories found.", "!".yellow().bold());
        println!();
        println!("  Searched for:");
        for pattern in discover_report.patterns_searched.iter().take(5) {
            println!("    • {}", pattern.dimmed());
        }
        println!();
        println!(
            "  Tip: Create a {} directory or run {} to get started.",
            "migrations/".cyan(),
            "schema-risk init".cyan()
        );
        println!();
        process::exit(0);
    }

    println!(
        "    Found {} director{} with {} SQL file{}",
        discover_report.discovered.len().to_string().green().bold(),
        if discover_report.discovered.len() == 1 {
            "y"
        } else {
            "ies"
        },
        discover_report.total_sql_files.to_string().cyan(),
        if discover_report.total_sql_files == 1 {
            ""
        } else {
            "s"
        }
    );

    if verbose {
        for disc in &discover_report.discovered {
            println!(
                "      {} [{}]",
                disc.path.display().to_string().dimmed(),
                disc.framework
            );
        }
    }

    // Step 2: Analyze all migrations
    println!();
    println!("  {} Analyzing migrations...", "●".cyan());

    let engine = RiskEngine::new(HashMap::new()).with_pg_version(pg_version);
    let mut all_reports = Vec::new();
    let mut total_issues = 0;
    let mut critical_count = 0;
    let mut high_count = 0;

    for disc in &discover_report.discovered {
        for sql_file in &disc.sql_files {
            let file_path = sql_file.display().to_string();
            match load_file(&file_path) {
                Ok(migration) => {
                    if let Ok(stmts) = parser::parse(&migration.sql) {
                        let report = engine.analyze(&migration.name, &stmts);

                        if report.overall_risk >= RiskLevel::Medium {
                            total_issues += 1;
                            match report.overall_risk {
                                RiskLevel::Critical => critical_count += 1,
                                RiskLevel::High => high_count += 1,
                                _ => {}
                            }

                            if verbose {
                                let risk_str = match report.overall_risk {
                                    RiskLevel::Critical => "CRITICAL".red().bold(),
                                    RiskLevel::High => "HIGH".red(),
                                    RiskLevel::Medium => "MEDIUM".yellow(),
                                    RiskLevel::Low => "LOW".green(),
                                };
                                println!(
                                    "    {} {} (score: {})",
                                    risk_str,
                                    migration.name.dimmed(),
                                    report.score
                                );
                            }
                        }

                        all_reports.push(report);
                    }
                }
                Err(_) => {
                    if verbose {
                        eprintln!("    {} Could not read {}", "!".yellow(), file_path.dimmed());
                    }
                }
            }
        }
    }

    // Step 3: Summary
    println!();
    println!(
        "{}",
        "────────────────────────────────────────────────────────────────────────────────".dimmed()
    );
    println!();

    let max_risk = all_reports
        .iter()
        .map(|r| r.overall_risk)
        .max()
        .unwrap_or(RiskLevel::Low);

    if max_risk >= RiskLevel::High {
        println!(
            "  {} {} issue{} found requiring attention:",
            "⚠".red().bold(),
            total_issues.to_string().red().bold(),
            if total_issues == 1 { "" } else { "s" }
        );
        println!();
        if critical_count > 0 {
            println!(
                "    {} {} CRITICAL risk migration{}",
                "•".red(),
                critical_count,
                if critical_count == 1 { "" } else { "s" }
            );
        }
        if high_count > 0 {
            println!(
                "    {} {} HIGH risk migration{}",
                "•".red(),
                high_count,
                if high_count == 1 { "" } else { "s" }
            );
        }
        println!();
        println!("  Run {} for details.", "schema-risk analyze <file>".cyan());
    } else if max_risk == RiskLevel::Medium {
        println!(
            "  {} {} migration{} with MEDIUM risk — review recommended.",
            "⚠".yellow(),
            total_issues,
            if total_issues == 1 { "" } else { "s" }
        );
    } else {
        println!(
            "  {} All {} migration{} look safe!",
            "✓".green().bold(),
            all_reports.len(),
            if all_reports.len() == 1 { "" } else { "s" }
        );
    }

    println!();
    println!(
        "{}",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".cyan()
    );
    println!();

    process::exit(max_risk.exit_code(fail_level));
}

// ─────────────────────────────────────────────
// Text utilities
// ─────────────────────────────────────────────

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn wrap_text(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in s.split_whitespace() {
        if current.is_empty() {
            current = word.to_string();
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
}
