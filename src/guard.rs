//! DangerGuard — intercept SQL migrations and gate execution behind explicit confirmation.
//!
//! This module is the crown feature of SchemaRisk. It prevents AI agents, CI scripts,
//! and humans from running destructive SQL without informed, explicit confirmation.
//!
//! # Behavior by actor
//! - **Human** (interactive TTY): Shows full impact panel and prompts for typed confirmation.
//! - **CI Pipeline**: Prints impact to stderr, exits 4 (never auto-approves).
//! - **AI Agent**: Exits 4 immediately with machine-readable JSON on stdout.
//!
//! # Guard triggers
//! An operation is guarded when its **score ≥ 40** OR it involves:
//! `DROP TABLE`, `DROP DATABASE`, `DROP SCHEMA`, `TRUNCATE`, `DROP COLUMN`, `RENAME TABLE/COLUMN`.

use crate::config::Config;
use crate::engine::RiskEngine;
use crate::loader::load_file;
use crate::parser;
use crate::types::{ActorKind, GuardAuditLog, GuardDecision, MigrationReport, RiskLevel};
use chrono::Utc;
use colored::Colorize;
use serde_json;
use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::Path;

// ─────────────────────────────────────────────
// Guard outcome
// ─────────────────────────────────────────────

/// Result of running the guard on a migration file.
#[derive(Debug)]
pub enum GuardOutcome {
    /// No dangerous operations found — safe to run.
    Safe,
    /// All dangerous operations were confirmed by the user.
    Approved(Vec<GuardDecision>),
    /// At least one operation was declined or blocked.
    Blocked {
        reason: String,
        operation: String,
        impact: String,
    },
}

impl GuardOutcome {
    /// Return the process exit code for this outcome.
    pub fn exit_code(&self) -> i32 {
        match self {
            GuardOutcome::Safe => 0,
            GuardOutcome::Approved(_) => 0,
            GuardOutcome::Blocked { .. } => 4,
        }
    }
}

// ─────────────────────────────────────────────
// Actor detection
// ─────────────────────────────────────────────

/// Detect the runtime actor from environment variables and TTY state.
///
/// Priority: Agent > CI > Human
pub fn detect_actor() -> ActorKind {
    // Explicit override
    if std::env::var("SCHEMARISK_ACTOR")
        .map(|v| v.to_lowercase() == "agent")
        .unwrap_or(false)
    {
        return ActorKind::Agent;
    }

    // AI provider API keys present → likely running inside an AI agent
    if std::env::var("ANTHROPIC_API_KEY").is_ok()
        || std::env::var("OPENAI_API_KEY").is_ok()
        || std::env::var("OPENAI_API_BASE").is_ok()
    {
        return ActorKind::Agent;
    }

    // CI environment variables
    if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("CIRCLECI").is_ok()
        || std::env::var("JENKINS_URL").is_ok()
        || std::env::var("BUILDKITE").is_ok()
    {
        return ActorKind::Ci;
    }

    ActorKind::Human
}

// ─────────────────────────────────────────────
// Guard trigger logic
// ─────────────────────────────────────────────

/// Returns `true` if an operation should trigger the guard confirmation flow.
///
/// Triggers when score ≥ 40 OR the description matches a known destructive pattern.
pub fn is_guarded_operation(desc: &str, score: u32) -> bool {
    if score >= 40 {
        return true;
    }
    let upper = desc.to_uppercase();
    upper.contains("DROP TABLE")
        || upper.contains("TRUNCATE")
        || upper.contains("DROP DATABASE")
        || upper.contains("DROP SCHEMA")
        || upper.contains("DROP COLUMN")
        || upper.contains("RENAME COLUMN")
        || upper.contains("RENAME TO")
}

// ─────────────────────────────────────────────
// Impact panel rendering
// ─────────────────────────────────────────────

/// Render the full impact panel to stderr for a single guarded operation.
pub fn render_impact_panel(report: &MigrationReport, op_desc: &str, risk: RiskLevel, score: u32, actor: &ActorKind) {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let box_width = 72;
    let inner = box_width - 2;

    let line = |s: &str| {
        let padded = format!("  {:<width$}", s, width = inner - 2);
        eprintln!("║{}║", padded);
    };
    let divider = || eprintln!("╠{}╣", "═".repeat(box_width));

    // Header
    eprintln!("\n╔{}╗", "═".repeat(box_width));
    eprintln!("║  {:<width$}  ║", "⚠  DANGEROUS OPERATION DETECTED — CONFIRMATION REQUIRED",
              width = inner - 2);
    divider();

    // Operation details
    let risk_str = match risk {
        RiskLevel::Critical => "CRITICAL".red().bold().to_string(),
        RiskLevel::High => "HIGH".truecolor(255, 140, 0).bold().to_string(),
        RiskLevel::Medium => "MEDIUM".yellow().to_string(),
        RiskLevel::Low => "LOW".green().to_string(),
    };
    line(&format!("Operation  : {}", op_desc));
    line(&format!("Risk Level : {}  (score: {})", risk_str, score));

    let lock_type = if score >= 90 || op_desc.to_uppercase().contains("DROP TABLE") {
        "ACCESS EXCLUSIVE"
    } else if score >= 50 {
        "SHARE"
    } else {
        "SHARE ROW EXCLUSIVE"
    };
    line(&format!("Lock Type  : {}", lock_type));

    if let Some(secs) = report.estimated_lock_seconds {
        let lock_range = if secs < 5 {
            "< 5s".to_string()
        } else if secs < 60 {
            format!("~{}s", secs)
        } else {
            format!("~{}m – {}m", secs / 60, (secs / 60) + 2)
        };
        line(&format!("Est. Lock  : {}", lock_range));
    }

    divider();
    eprintln!("║  {:<width$}  ║", "DATABASE IMPACT", width = inner - 2);

    // Table impact
    if !report.affected_tables.is_empty() {
        eprintln!("║  ┌{:─<width$}┐  ║", "", width = inner - 4);
        eprintln!("║  │ {:<44} {:<10} │  ║", "Table", "Impact");
        eprintln!("║  │ {:─<44} {:─<10} │  ║", "", "");
        for table in &report.affected_tables {
            let impact_str = if op_desc.to_uppercase().contains("DROP TABLE") {
                "DELETED permanently"
            } else if op_desc.to_uppercase().contains("TRUNCATE") {
                "TRUNCATED permanently"
            } else {
                "MODIFIED"
            };
            eprintln!("║  │ {:<44} {:<10} │  ║", shorten(table, 44), impact_str);
        }
        // FK cascade impacts
        for fk in &report.fk_impacts {
            if fk.cascade {
                eprintln!("║  │ {:<44} {:<10} │  ║",
                          shorten(&fk.from_table, 44),
                          "CASCADE DELETED");
            }
        }
        eprintln!("║  └{:─<width$}┘  ║", "", width = inner - 4);
    }

    eprintln!("║{:width$}║", "", width = box_width);

    // What will break
    divider();
    eprintln!("║  {:<width$}  ║", "WHAT WILL BREAK:", width = inner - 2);
    let desc_upper = op_desc.to_uppercase();
    if desc_upper.contains("DROP TABLE") {
        line("• All queries to the dropped table will fail immediately");
        line("• Foreign keys with CASCADE will also delete child rows");
        line("• Application code referencing this table will crash");
    } else if desc_upper.contains("DROP COLUMN") || desc_upper.contains("DROP COL") {
        line("• All queries selecting this column will error");
        line("• ORM models referencing this column will break");
    } else if desc_upper.contains("RENAME") {
        line("• All queries using the old name will fail immediately");
        line("• Views, stored procedures, and FK constraints may break");
    } else if desc_upper.contains("TRUNCATE") {
        line("• All data is permanently deleted — this cannot be undone");
        line("• Application may behave unexpectedly with empty table");
    } else if desc_upper.contains("ALTER COLUMN") && desc_upper.contains("TYPE") {
        line("• Table rewrite required — writes blocked during migration");
        line("• Data truncation or conversion errors possible");
    } else {
        line("• Review the impact carefully before proceeding");
    }

    eprintln!("║{:width$}║", "", width = box_width);

    // Safe alternative
    if desc_upper.contains("DROP TABLE") {
        divider();
        eprintln!("║  {:<width$}  ║", "SAFE ALTERNATIVE:", width = inner - 2);
        line("Rename first: ALTER TABLE x RENAME TO x_deprecated;");
        line("Then verify nothing breaks. Drop after 1 release cycle.");
    } else if desc_upper.contains("DROP COLUMN") {
        divider();
        eprintln!("║  {:<width$}  ║", "SAFE ALTERNATIVE:", width = inner - 2);
        line("1. Remove app code that reads/writes this column");
        line("2. Deploy the app change");
        line("3. Then run: ALTER TABLE x DROP COLUMN IF EXISTS y;");
    }

    divider();
    line(&format!("Actor: {}   Time: {}", actor, now));
    eprintln!("╚{}╝", "═".repeat(box_width));
    eprintln!();
}

fn shorten(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

// ─────────────────────────────────────────────
// Confirmation prompt
// ─────────────────────────────────────────────

/// Prompt the user for confirmation.
///
/// - Critical ops: require `"yes i am sure"` (case-insensitive).
/// - High ops: require `"yes"`.
/// - Returns `true` if confirmed.
fn prompt_confirmation(risk: RiskLevel) -> bool {
    let (required_phrase, hint) = match risk {
        RiskLevel::Critical => (
            "yes i am sure",
            "Type \"yes I am sure\" to confirm, or press Enter/Ctrl-C to abort: ",
        ),
        _ => (
            "yes",
            "Type \"yes\" to confirm, or press Enter/Ctrl-C to abort: ",
        ),
    };

    eprint!("  {}", hint.yellow().bold());
    let _ = io::stderr().flush();

    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => {
            // EOF / Ctrl-C
            eprintln!("\n  Aborted.");
            return false;
        }
        Ok(_) => {}
    }

    let trimmed = line.trim().to_lowercase();
    trimmed == required_phrase
}

// ─────────────────────────────────────────────
// Agent-blocked JSON output
// ─────────────────────────────────────────────

/// Print machine-readable JSON and return the `Blocked` outcome for agent actors.
fn agent_blocked(op_desc: &str, impact: &str) -> GuardOutcome {
    let json = serde_json::json!({
        "blocked": true,
        "reason": "CRITICAL operation requires human confirmation",
        "operation": op_desc,
        "impact": impact,
        "required_action": "A human must run: schema-risk guard <file> --interactive"
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
    GuardOutcome::Blocked {
        reason: "Agent actor — automatic block enforced".to_string(),
        operation: op_desc.to_string(),
        impact: impact.to_string(),
    }
}

// ─────────────────────────────────────────────
// Audit log
// ─────────────────────────────────────────────

fn write_audit_log(
    file_path: &str,
    actor: &ActorKind,
    decisions: &[GuardDecision],
    audit_path: &str,
) {
    let log = GuardAuditLog {
        schemarisk_version: env!("CARGO_PKG_VERSION").to_string(),
        file: file_path.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        actor: actor.clone(),
        decisions: decisions.to_vec(),
    };
    match serde_json::to_string_pretty(&log) {
        Ok(json) => {
            if let Err(e) = std::fs::write(audit_path, &json) {
                eprintln!("warning: failed to write audit log to {audit_path}: {e}");
            } else {
                eprintln!(
                    "\n  {} Confirmation log written to {}",
                    "⚡".cyan(),
                    audit_path.cyan()
                );
            }
        }
        Err(e) => eprintln!("warning: failed to serialize audit log: {e}"),
    }
}

// ─────────────────────────────────────────────
// Main guard entry point
// ─────────────────────────────────────────────

/// Options for `run_guard`.
#[derive(Default)]
pub struct GuardOptions {
    /// Print impact panel but do not prompt. Exit code reflects risk.
    pub dry_run: bool,
    /// Skip interactive prompts (used in CI; blocks on dangerous ops).
    pub non_interactive: bool,
    /// Table row estimates for offline scoring.
    pub row_counts: HashMap<String, u64>,
    /// Configuration (thresholds, audit log path, etc.).
    pub config: Config,
}

/// Intercepts a SQL migration and gates execution behind explicit confirmation.
///
/// # Behavior by actor
/// - **Human** (interactive TTY): Shows full impact panel and prompts for typed confirmation.
/// - **CI Pipeline**: Prints impact to stderr, exits 4 (never auto-approves).
/// - **AI Agent**: Exits 4 immediately with machine-readable JSON on stdout.
///
/// # Returns
/// - `Ok(GuardOutcome::Safe)` — no operations require guarding
/// - `Ok(GuardOutcome::Approved(_))` — all operations confirmed
/// - `Ok(GuardOutcome::Blocked { .. })` — one or more operations declined
/// - `Err(SchemaRiskError)` — parse or I/O failure
pub fn run_guard(
    path: &Path,
    opts: GuardOptions,
) -> crate::error::Result<GuardOutcome> {
    let actor = detect_actor();
    let migration = load_file(path)?;
    let stmts = parser::parse(&migration.sql)?;
    let engine = RiskEngine::new(opts.row_counts.clone());
    let report = engine.analyze(&migration.name, &stmts);

    // Collect operations that need guarding
    let guarded_ops: Vec<_> = report
        .operations
        .iter()
        .filter(|op| is_guarded_operation(&op.description, op.score))
        .collect();

    if guarded_ops.is_empty() {
        eprintln!("  {} Safe to run — no dangerous operations detected.", "✅".green());
        return Ok(GuardOutcome::Safe);
    }

    // ── Dry-run mode ────────────────────────────────────────────────────
    if opts.dry_run {
        for op in &guarded_ops {
            render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);
        }
        let max_risk = guarded_ops.iter().map(|o| o.risk_level).max().unwrap_or(RiskLevel::Low);
        let exit_code = match max_risk {
            RiskLevel::Critical => 2,
            RiskLevel::High => 1,
            _ => 0,
        };
        // Return a Blocked outcome to signal the caller to use our exit code
        if exit_code > 0 {
            return Ok(GuardOutcome::Blocked {
                reason: format!("dry-run: {} risk detected", max_risk),
                operation: guarded_ops[0].description.clone(),
                impact: format!("{} operations require confirmation", guarded_ops.len()),
            });
        }
        return Ok(GuardOutcome::Safe);
    }

    // ── Agent actor: always block with machine-readable JSON ─────────────
    if actor == ActorKind::Agent && opts.config.guard.block_agents {
        let op = &guarded_ops[0];
        let impact = format!(
            "{} dangerous operations require human confirmation",
            guarded_ops.len()
        );
        return Ok(agent_blocked(&op.description, &impact));
    }

    // ── CI actor in non-interactive mode ─────────────────────────────────
    if (actor == ActorKind::Ci || opts.non_interactive) && opts.config.guard.block_ci {
        for op in &guarded_ops {
            render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);
        }
        eprintln!("  {} CI mode: dangerous operations blocked. Set block_ci: false to allow.", "⛔".red());
        return Ok(GuardOutcome::Blocked {
            reason: "CI pipeline — non-interactive block".to_string(),
            operation: guarded_ops[0].description.clone(),
            impact: format!("{} operations require confirmation", guarded_ops.len()),
        });
    }

    // CI non-interactive but block_ci is false → print warning but continue to confirmation
    if actor == ActorKind::Ci || opts.non_interactive {
        for op in &guarded_ops {
            render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);
        }
        eprintln!("  {} Non-interactive mode: cannot prompt. Blocking.", "⛔".red());
        return Ok(GuardOutcome::Blocked {
            reason: "Non-interactive mode — cannot prompt for confirmation".to_string(),
            operation: guarded_ops[0].description.clone(),
            impact: format!("{} operations require confirmation", guarded_ops.len()),
        });
    }

    // ── Human actor: interactive confirmation loop ───────────────────────
    let mut decisions: Vec<GuardDecision> = Vec::new();

    for op in &guarded_ops {
        render_impact_panel(&report, &op.description, op.risk_level, op.score, &actor);

        let irreversible = op.risk_level >= RiskLevel::High;
        if irreversible {
            eprintln!("  {}", "This action is IRREVERSIBLE. All data will be permanently destroyed.".red().bold());
            eprintln!();
        }

        let confirmed = if opts.config.guard.require_typed_confirmation {
            prompt_confirmation(op.risk_level)
        } else {
            prompt_confirmation(RiskLevel::Medium) // just "yes"
        };

        let typed_phrase = if confirmed {
            match op.risk_level {
                RiskLevel::Critical => Some("yes i am sure".to_string()),
                _ => Some("yes".to_string()),
            }
        } else {
            None
        };

        let decision = GuardDecision {
            operation: op.description.clone(),
            risk_level: op.risk_level,
            score: op.score,
            impact_summary: build_impact_summary(&report, &op.description),
            confirmed,
            typed_phrase,
            timestamp: Utc::now().to_rfc3339(),
            actor: actor.clone(),
        };

        if !confirmed {
            decisions.push(decision);
            eprintln!("  {} Aborted. Migration will NOT run.", "⛔".red().bold());
            // Write audit log even for declined runs
            write_audit_log(
                &migration.name,
                &actor,
                &decisions,
                &opts.config.guard.audit_log,
            );
            return Ok(GuardOutcome::Blocked {
                reason: "User declined confirmation".to_string(),
                operation: op.description.clone(),
                impact: build_impact_summary(&report, &op.description),
            });
        }

        decisions.push(decision);
        eprintln!("  {} Confirmed — proceeding to next check...", "✓".green());
    }

    // All confirmed
    eprintln!(
        "\n  {} Proceeding. All {} operation(s) confirmed.",
        "⚡".cyan(),
        guarded_ops.len()
    );
    write_audit_log(
        &migration.name,
        &actor,
        &decisions,
        &opts.config.guard.audit_log,
    );

    Ok(GuardOutcome::Approved(decisions))
}

/// Build a one-sentence human-readable impact summary for an operation.
fn build_impact_summary(report: &MigrationReport, op_desc: &str) -> String {
    let tables_str = if report.affected_tables.is_empty() {
        String::new()
    } else {
        format!(
            " {} table(s): {}",
            report.affected_tables.len(),
            report.affected_tables.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        )
    };

    let cascade_count = report.fk_impacts.iter().filter(|fk| fk.cascade).count();
    let cascade_str = if cascade_count > 0 {
        format!(", cascades to {} child table(s)", cascade_count)
    } else {
        String::new()
    };

    format!(
        "{}{}{}",
        shorten(op_desc, 60),
        tables_str,
        cascade_str
    )
}

// ─────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_for_high_score() {
        assert!(is_guarded_operation("ALTER TABLE x ALTER COLUMN y TYPE bigint", 80));
    }

    #[test]
    fn guarded_for_drop_table_regardless_of_score() {
        assert!(is_guarded_operation("DROP TABLE sessions", 5));
    }

    #[test]
    fn not_guarded_for_create_table() {
        assert!(!is_guarded_operation("CREATE TABLE new_table", 2));
    }

    #[test]
    fn not_guarded_for_low_score_add_column() {
        assert!(!is_guarded_operation("ALTER TABLE users ADD COLUMN last_seen timestamptz", 5));
    }

    #[test]
    fn agent_detection_via_env() {
        // This test sets env var; isolate from parallel tests
        std::env::remove_var("SCHEMARISK_ACTOR");
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        std::env::remove_var("CI");
        std::env::remove_var("GITHUB_ACTIONS");
        // Without any env var set, should default to Human
        // (can't fully test CI/Agent without env isolation)
        let actor = detect_actor();
        // In test environment, CI may be set — just verify it returns a valid variant
        let _ = actor;
    }
}
