//! Terminal output renderer – pretty-prints analysis results to stdout.

use crate::drift::DriftReport;
use crate::impact::ImpactReport;
use crate::locks::{LockMode, MigrationTimeline};
use crate::recommendation::{FixSeverity, FixSuggestion};
use crate::types::{MigrationReport, RiskLevel};
use colored::Colorize;

// ─────────────────────────────────────────────
// Colours
// ─────────────────────────────────────────────

fn risk_color(level: RiskLevel) -> colored::ColoredString {
    match level {
        RiskLevel::Low => level.to_string().green().bold(),
        RiskLevel::Medium => level.to_string().yellow().bold(),
        RiskLevel::High => level.to_string().truecolor(255, 140, 0).bold(),
        RiskLevel::Critical => level.to_string().red().bold(),
    }
}

// ─────────────────────────────────────────────
// Main render function
// ─────────────────────────────────────────────

pub fn render(report: &MigrationReport, verbose: bool) {
    let separator = "─".repeat(60);

    println!("\n{}", separator.dimmed());
    println!(
        "{}  {}",
        " SchemaRisk Analysis".bold(),
        report.file.cyan()
    );
    println!("{}", separator.dimmed());

    // Overall risk badge
    println!(
        "\n  Migration Risk:  {}   (score: {})",
        risk_color(report.overall_risk),
        report.score.to_string().bold()
    );

    // Affected tables
    if !report.affected_tables.is_empty() {
        println!(
            "\n  {} {}",
            "Tables affected:".bold(),
            report.affected_tables.join(", ").cyan()
        );
    }

    // Lock estimate
    if let Some(secs) = report.estimated_lock_seconds {
        let lock_str = if secs >= 60 {
            format!("~{} min {} sec", secs / 60, secs % 60)
        } else {
            format!("~{} sec", secs)
        };
        let colored = if secs > 30 {
            lock_str.red()
        } else if secs > 5 {
            lock_str.yellow()
        } else {
            lock_str.green()
        };
        println!("  {} {}", "Estimated lock duration:".bold(), colored);
    }

    // Index rebuild
    if report.index_rebuild_required {
        println!(
            "  {} {}",
            "Index rebuild required:".bold(),
            "YES".red().bold()
        );
    }

    // Maintenance window
    if report.requires_maintenance_window {
        println!(
            "  {} {}",
            "Requires maintenance window:".bold(),
            "YES".red().bold()
        );
    }

    // Foreign key impacts
    if !report.fk_impacts.is_empty() {
        println!("\n  {}:", "Foreign Key Impact".bold().underline());
        for fk in &report.fk_impacts {
            let cascade_note = if fk.cascade {
                " (ON DELETE CASCADE!)".red().to_string()
            } else {
                String::new()
            };
            println!(
                "    {} {} → {}{}",
                "•".dimmed(),
                fk.constraint_name.yellow(),
                fk.to_table.cyan(),
                cascade_note
            );
        }
    }

    // Detected operations
    if verbose && !report.operations.is_empty() {
        println!("\n  {}:", "Detected Operations".bold().underline());
        for op in &report.operations {
            println!(
                "    {} [{}] {}",
                "•".dimmed(),
                risk_color(op.risk_level),
                op.description
            );
            if op.acquires_lock {
                println!("       {} acquires table lock", "⚠".yellow());
            }
            if op.index_rebuild {
                println!("       {} triggers index rebuild", "⟳".yellow());
            }
        }
    }

    // Warnings
    if !report.warnings.is_empty() {
        println!("\n  {}:", "Warnings".bold().underline());
        for w in &report.warnings {
            println!("    {} {}", "!".yellow().bold(), w);
        }
    }

    // Recommendations
    if !report.recommendations.is_empty() {
        println!("\n  {}:", "Recommendations".bold().underline());
        for r in &report.recommendations {
            println!("    {} {}", "→".green(), r);
        }
    }

    println!("\n{}", separator.dimmed());

    // Summary line for CI logs
    let stamp = if report.requires_maintenance_window {
        "  ⛔ This migration should NOT be deployed without review".red()
    } else if report.overall_risk >= RiskLevel::Medium {
        "  ⚠  Review recommended before deploying".yellow()
    } else {
        "  ✓  Migration looks safe".green()
    };
    println!("{}\n", stamp);
}

// ─────────────────────────────────────────────
// Multi-file summary table
// ─────────────────────────────────────────────

/// Render an aligned summary table using `comfy-table` for multi-file analysis.
pub fn render_summary_table(reports: &[MigrationReport]) {
    use comfy_table::{
        presets::UTF8_FULL_CONDENSED, Attribute, Cell, CellAlignment, Color, ContentArrangement,
        Table,
    };

    println!();
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("File").add_attribute(Attribute::Bold),
            Cell::new("Risk").add_attribute(Attribute::Bold),
            Cell::new("Score")
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Right),
            Cell::new("Lock Duration")
                .add_attribute(Attribute::Bold)
                .set_alignment(CellAlignment::Right),
            Cell::new("Maint. Window").add_attribute(Attribute::Bold),
            Cell::new("Tables").add_attribute(Attribute::Bold),
        ]);

    for r in reports {
        let (risk_text, risk_color) = match r.overall_risk {
            RiskLevel::Critical => ("CRITICAL", Color::Red),
            RiskLevel::High => ("HIGH", Color::Yellow),
            RiskLevel::Medium => ("MEDIUM", Color::Cyan),
            RiskLevel::Low => ("LOW", Color::Green),
        };
        let duration = r
            .estimated_lock_seconds
            .map(|s| {
                if s >= 60 {
                    format!("~{}m {}s", s / 60, s % 60)
                } else {
                    format!("~{}s", s)
                }
            })
            .unwrap_or_else(|| "—".to_string());
        let window = if r.requires_maintenance_window {
            Cell::new("YES").fg(Color::Red).add_attribute(Attribute::Bold)
        } else {
            Cell::new("no").fg(Color::Green)
        };
        let tables_str = if r.affected_tables.is_empty() {
            "—".to_string()
        } else {
            r.affected_tables.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                + if r.affected_tables.len() > 3 { " …" } else { "" }
        };
        table.add_row(vec![
            Cell::new(shorten(&r.file, 40)),
            Cell::new(risk_text).fg(risk_color).add_attribute(Attribute::Bold),
            Cell::new(r.score.to_string()).set_alignment(CellAlignment::Right),
            Cell::new(duration).set_alignment(CellAlignment::Right),
            window,
            Cell::new(tables_str),
        ]);
    }

    println!("{table}");

    let max_risk = reports
        .iter()
        .map(|r| r.overall_risk)
        .max()
        .unwrap_or(RiskLevel::Low);
    println!(
        "\n  Highest risk across all files: {}\n",
        risk_color(max_risk)
    );
}

fn shorten(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("…{}", &s[s.len().saturating_sub(max - 1)..])
    }
}

// ─────────────────────────────────────────────
// Lock table & timeline renderer
// ─────────────────────────────────────────────

pub fn render_timeline(timeline: &MigrationTimeline) {
    let sep = "─".repeat(70);
    println!("\n{}", sep.dimmed());
    println!("  {}", "Lock Simulation & Migration Timeline".bold());
    println!("{}", sep.dimmed());

    println!(
        "\n  Lock Risk:         {}",
        risk_color(timeline.lock_risk)
    );
    println!(
        "  Total duration:    ~{} sec",
        timeline.total_secs.to_string().cyan()
    );
    println!(
        "  Max lock hold:     {} sec",
        if timeline.max_lock_hold_secs > 30 {
            timeline.max_lock_hold_secs.to_string().red().bold()
        } else if timeline.max_lock_hold_secs > 5 {
            timeline.max_lock_hold_secs.to_string().yellow()
        } else {
            timeline.max_lock_hold_secs.to_string().green()
        }
    );

    // Per-operation lock table
    if !timeline.lock_events.is_empty() {
        println!("\n  {}:", "Operations and their locks".bold().underline());
        println!(
            "  {:<45} {:<26} {:<8} {}",
            "Statement".dimmed(),
            "Lock Mode".dimmed(),
            "Hold(s)".dimmed(),
            "Impact".dimmed()
        );
        println!("  {}", "·".repeat(110).dimmed());

        for ev in &timeline.lock_events {
            let stmt = shorten(&ev.statement, 44);
            let lock_str = lock_mode_color(ev.lock_mode);
            let hold_str = if ev.estimated_hold_secs > 30 {
                ev.estimated_hold_secs.to_string().red().bold()
            } else if ev.estimated_hold_secs > 5 {
                ev.estimated_hold_secs.to_string().yellow()
            } else {
                ev.estimated_hold_secs.to_string().green()
            };

            println!(
                "  {:<45} {:<35} {:<8} {}",
                stmt, lock_str, hold_str, ev.impact
            );

            if let Some(alt) = &ev.safe_alternative {
                println!(
                    "    {} {}",
                    "Safe alternative:".green().bold(),
                    alt.lines().next().unwrap_or(alt)
                );
                for extra_line in alt.lines().skip(1) {
                    println!("      {}", extra_line.dimmed());
                }
            }
        }
    }

    // Timeline steps
    println!("\n  {}:", "Execution timeline".bold().underline());
    for step in &timeline.steps {
        let lock_badge = match step.lock {
            Some(LockMode::AccessExclusive) => " [LOCKED: reads+writes]".red().to_string(),
            Some(LockMode::Share) => " [LOCKED: writes only]".yellow().to_string(),
            Some(LockMode::ShareUpdateExclusive) => " [LOCK: allows reads+writes]".cyan().to_string(),
            Some(m) => format!(" [{}]", m.name()).dimmed().to_string(),
            None => String::new(),
        };
        println!(
            "  {:>6}s  {}{}",
            step.offset_secs,
            step.event.dimmed(),
            lock_badge
        );
    }

    println!("\n{}", sep.dimmed());
}

fn lock_mode_color(mode: LockMode) -> colored::ColoredString {
    match mode {
        LockMode::AccessExclusive => mode.name().red().bold(),
        LockMode::Exclusive => mode.name().red(),
        LockMode::ShareRowExclusive | LockMode::Share => mode.name().yellow(),
        LockMode::ShareUpdateExclusive => mode.name().cyan(),
        _ => mode.name().green(),
    }
}

// ─────────────────────────────────────────────
// Query impact renderer
// ─────────────────────────────────────────────

pub fn render_impact(report: &ImpactReport) {
    let sep = "─".repeat(70);
    println!("\n{}", sep.dimmed());
    println!("  {}", "Query Impact Report".bold());
    println!("{}", sep.dimmed());

    println!(
        "\n  Files scanned:      {}",
        report.files_scanned.to_string().cyan()
    );
    println!(
        "  Impacted files:     {}",
        if report.impacted_files.is_empty() {
            "0 (none found)".green().to_string()
        } else {
            report.impacted_files.len().to_string().yellow().bold().to_string()
        }
    );

    if report.impacted_files.is_empty() {
        println!("\n  {} No source files reference the affected schema objects.", "✓".green());
    } else {
        println!("\n  {}:", "Impacted files".bold().underline());
        for f in &report.impacted_files {
            println!("\n    {}", f.path.yellow().bold());
            if !f.tables_referenced.is_empty() {
                println!("      Tables:  {}", f.tables_referenced.join(", ").cyan());
            }
            if !f.columns_referenced.is_empty() {
                println!("      Columns: {}", f.columns_referenced.join(", ").cyan());
            }
            // Show up to 5 hits
            for hit in f.hits.iter().take(5) {
                println!(
                    "      {:>5}: {}",
                    format!("L{}", hit.line).dimmed(),
                    hit.snippet.dimmed()
                );
            }
            if f.hits.len() > 5 {
                println!(
                    "      {} more matches…",
                    (f.hits.len() - 5).to_string().dimmed()
                );
            }
        }
    }

    println!("\n{}", sep.dimmed());
}

// ─────────────────────────────────────────────
// Drift report renderer
// ─────────────────────────────────────────────

pub fn render_drift(report: &DriftReport) {
    let sep = "─".repeat(70);
    println!("\n{}", sep.dimmed());
    println!("  {}", "Schema Drift Report".bold());
    println!("{}", sep.dimmed());

    if report.in_sync {
        println!("\n  {} Schema is in sync — no drift detected.\n", "✓".green().bold());
        println!("{}", sep.dimmed());
        return;
    }

    println!(
        "\n  Overall drift:    {}",
        risk_color(report.overall_drift)
    );
    println!(
        "  Total findings:   {}\n",
        report.total_findings.to_string().red().bold()
    );

    // Print findings grouped by severity
    for (label, severity, bullet_str) in [
        ("CRITICAL", RiskLevel::Critical, "✗"),
        ("HIGH", RiskLevel::High, "!"),
        ("MEDIUM", RiskLevel::Medium, "·"),
        ("LOW", RiskLevel::Low, "·"),
    ] {
        let items: Vec<_> = report.findings.iter().filter(|f| f.severity() == severity).collect();
        if items.is_empty() {
            continue;
        }
        let label_colored = match severity {
            RiskLevel::Critical => label.red().bold().to_string(),
            RiskLevel::High => label.truecolor(255, 140, 0).bold().to_string(),
            RiskLevel::Medium => label.yellow().to_string(),
            _ => label.dimmed().to_string(),
        };
        println!("  {}:", label_colored);
        for finding in items {
            let bullet = match severity {
                RiskLevel::Critical => bullet_str.red().to_string(),
                RiskLevel::High => bullet_str.yellow().to_string(),
                _ => bullet_str.dimmed().to_string(),
            };
            println!("    {} {}", bullet, finding.description());
        }
        println!();
    }

    println!("{}", sep.dimmed());
}

// ─────────────────────────────────────────────
// Fix suggestion renderer
// ─────────────────────────────────────────────

/// Pretty-print a list of `FixSuggestion`s from the recommendation engine.
pub fn render_fix_suggestions(fixes: &[FixSuggestion]) {
    use comfy_table::{
        presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, ContentArrangement, Table,
    };

    let sep = "─".repeat(70);
    println!("\n{}", sep.dimmed());
    println!("  {}", "Fix Suggestions".bold());
    println!("{}", sep.dimmed());

    // ── Compact summary table ─────────────────────────────────────────────
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("ID").add_attribute(Attribute::Bold),
            Cell::new("Severity").add_attribute(Attribute::Bold),
            Cell::new("Title").add_attribute(Attribute::Bold),
            Cell::new("Auto-Fix").add_attribute(Attribute::Bold),
        ]);

    for fix in fixes {
        let (sev_text, sev_color) = match fix.severity {
            FixSeverity::Blocking => ("BLOCKING", Color::Red),
            FixSeverity::Warning => ("WARNING", Color::Yellow),
            FixSeverity::Info => ("INFO", Color::Cyan),
        };
        let auto_fix = if fix.auto_fixable {
            Cell::new("yes").fg(Color::Green)
        } else {
            Cell::new("manual").fg(Color::Yellow)
        };
        table.add_row(vec![
            Cell::new(&fix.rule_id),
            Cell::new(sev_text)
                .fg(sev_color)
                .add_attribute(Attribute::Bold),
            Cell::new(&fix.title),
            auto_fix,
        ]);
    }
    println!("{table}\n");

    // ── Full detail for each fix ──────────────────────────────────────────
    for fix in fixes {
        let severity_badge = match fix.severity {
            FixSeverity::Blocking => format!("[{}]", "BLOCKING".red().bold()),
            FixSeverity::Warning => format!("[{}]", "WARNING".yellow().bold()),
            FixSeverity::Info => format!("[{}]", "INFO".cyan()),
        };

        println!(
            "  {} {} {}",
            fix.rule_id.bold(),
            severity_badge,
            fix.title.bold()
        );
        println!();
        // Wrap long explanation at 72 chars
        for chunk in wrap_text(&fix.explanation, 72) {
            println!("    {chunk}");
        }
        println!();

        if let Some(sql) = &fix.fixed_sql {
            println!("  {}", "Fixed SQL:".green().bold());
            for line in sql.lines() {
                println!("    {}", line.green());
            }
            println!();
        }

        if let Some(steps) = &fix.migration_steps {
            println!("  {}", "Migration steps:".cyan().bold());
            for step in steps {
                if step.is_empty() {
                    println!();
                } else {
                    println!("    {}", step.dimmed());
                }
            }
            println!();
        }

        if let Some(url) = &fix.docs_url {
            println!("  {} {}", "Docs:".dimmed(), url.dimmed());
            println!();
        }

        println!("{}", sep.dimmed());
    }
}

/// Word-wrap a string at `width` columns, returning a vector of lines.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for paragraph in text.split("\n") {
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if line.is_empty() {
                line.push_str(word);
            } else if line.len() + 1 + word.len() <= width {
                line.push(' ');
                line.push_str(word);
            } else {
                lines.push(line.clone());
                line = word.to_string();
            }
        }
        if !line.is_empty() {
            lines.push(line);
        }
    }
    lines
}
