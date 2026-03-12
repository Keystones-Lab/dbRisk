//! CI/CD integration — GitHub and GitLab PR comment formatters.
//!
//! `schema-risk ci-report` outputs analysis results as GitHub-Flavored
//! Markdown suitable for posting as a PR comment via `actions/github-script`
//! or the GitLab Merge Request Notes API.
//!
//! ## Usage
//! ```text
//! schema-risk ci-report migrations/*.sql --format github-comment
//! ```
//!
//! The output is printed to **stdout** so it can be captured in CI:
//! ```yaml
//! # .github/workflows/schema-risk.yml
//! - name: Run SchemaRisk
//!   id: schema_risk
//!   run: |
//!     schema-risk ci-report $CHANGED_FILES --format github-comment > /tmp/schema_risk_report.md
//! ```

use crate::impact::ImpactReport;
use crate::recommendation::FixSuggestion;
use crate::types::{MigrationReport, RiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─────────────────────────────────────────────
// Format selector
// ─────────────────────────────────────────────

/// Output format for `ci-report`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CiFormat {
    /// GitHub-flavored Markdown — post as a PR comment.
    GithubComment,
    /// GitLab-flavored Markdown — post as MR note.
    GitlabComment,
    /// Machine-readable JSON (same as `schema-risk analyze --output json`).
    Json,
}

impl std::str::FromStr for CiFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "github-comment" => Ok(CiFormat::GithubComment),
            "gitlab-comment" => Ok(CiFormat::GitlabComment),
            "json" => Ok(CiFormat::Json),
            other => Err(format!("unknown CI format: '{other}' — valid: github-comment, gitlab-comment, json")),
        }
    }
}

// ─────────────────────────────────────────────
// Main render function
// ─────────────────────────────────────────────

/// Generate a CI report in the requested format.
///
/// # Arguments
/// - `reports`  — one `MigrationReport` per analyzed SQL file.
/// - `fixes`    — `FixSuggestion`s keyed by the report's `file` field.
/// - `impact`   — optional query impact report from `--scan-dir`.
/// - `format`   — target format.
pub fn render_ci_report(
    reports: &[MigrationReport],
    fixes: &HashMap<String, Vec<FixSuggestion>>,
    impact: Option<&ImpactReport>,
    format: CiFormat,
) -> String {
    match format {
        CiFormat::GithubComment | CiFormat::GitlabComment => {
            render_markdown(reports, fixes, impact)
        }
        CiFormat::Json => {
            serde_json::to_string_pretty(reports).unwrap_or_default()
        }
    }
}

// ─────────────────────────────────────────────
// Markdown renderer
// ─────────────────────────────────────────────

fn render_markdown(
    reports: &[MigrationReport],
    fixes: &HashMap<String, Vec<FixSuggestion>>,
    impact: Option<&ImpactReport>,
) -> String {
    let mut md = String::with_capacity(4096);

    let max_risk = reports
        .iter()
        .map(|r| r.overall_risk)
        .max()
        .unwrap_or(RiskLevel::Low);

    // ── Title ─────────────────────────────────────────────────────────────
    md.push_str("## 🔍 SchemaRisk v2 — Migration Safety Report\n\n");

    // ── Risk banner ───────────────────────────────────────────────────────
    let banner = match max_risk {
        RiskLevel::Critical => {
            "> [!CAUTION]\n> 🚨 **CRITICAL RISK** — one or more migrations will cause production downtime.\n> **Do not merge without a detailed review and a maintenance window plan.**"
        }
        RiskLevel::High => {
            "> [!WARNING]\n> ⚠️ **HIGH RISK** — significant impact on database availability.\n> Review all findings carefully before merging."
        }
        RiskLevel::Medium => {
            "> [!IMPORTANT]\n> 🔶 **MEDIUM RISK** — deploy during a low-traffic window.\n> Some operations may briefly degrade performance."
        }
        RiskLevel::Low => {
            "> [!TIP]\n> ✅ **LOW RISK** — migrations look safe to deploy."
        }
    };
    md.push_str(banner);
    md.push_str("\n\n");

    // ── Summary table ─────────────────────────────────────────────────────
    md.push_str(
        "| File | Risk | Score | Lock | Est. Duration | Breaking Changes |\n\
         |------|:----:|------:|------|--------------:|:-----------------|\n",
    );

    for r in reports {
        let risk_badge = risk_badge(r.overall_risk);
        // Find worst lock across all operations
        let lock_str = if r.operations.iter().any(|o| o.acquires_lock) {
            "ACCESS EXCLUSIVE"
        } else {
            "—"
        };
        let duration = r
            .estimated_lock_seconds
            .map(|s| format_duration(s))
            .unwrap_or_else(|| "—".to_string());
        let breaks = impact
            .map(|i| i.impacted_files.len())
            .unwrap_or(0);
        let breaks_str = if breaks > 0 {
            format!("⚠️ {} file(s)", breaks)
        } else {
            "—".to_string()
        };
        let file_short = short_name(&r.file);
        md.push_str(&format!(
            "| `{file_short}` | {risk_badge} | {} | `{lock_str}` | {duration} | {breaks_str} |\n",
            r.score
        ));
    }
    md.push('\n');

    // ── Per-file detail sections ──────────────────────────────────────────
    for r in reports {
        render_file_section(&mut md, r, fixes, impact);
    }

    // ── Footer ────────────────────────────────────────────────────────────
    md.push_str(
        "---\n*Generated by [SchemaRisk v2](https://github.com/Ayuussshhh/newBase-backend) \
         — Production-grade PostgreSQL migration safety analyzer*\n",
    );

    md
}

/// Render a detailed section for a single migration file.
fn render_file_section(
    md: &mut String,
    r: &MigrationReport,
    fixes: &HashMap<String, Vec<FixSuggestion>>,
    impact: Option<&ImpactReport>,
) {
    let emoji = risk_emoji(r.overall_risk);
    md.push_str(&format!("\n### {emoji} `{}`\n\n", r.file));

    // ── Metadata line ──────────────────────────────────────────────────────
    if !r.affected_tables.is_empty() {
        let tables: Vec<String> = r
            .affected_tables
            .iter()
            .map(|t| format!("`{t}`"))
            .collect();
        md.push_str(&format!("**Tables affected:** {}\n\n", tables.join(", ")));
    }

    if let Some(secs) = r.estimated_lock_seconds {
        let duration = format_duration(secs);
        let warning = if secs > 30 {
            " — ⚠️ **This is a long lock!**"
        } else {
            ""
        };
        md.push_str(&format!(
            "**Estimated lock duration:** {duration}{warning}\n\n"
        ));
    }

    // ── Operations ────────────────────────────────────────────────────────
    if !r.operations.is_empty() {
        md.push_str("**Operations detected:**\n\n");
        for op in &r.operations {
            let op_emoji = if op.risk_level >= RiskLevel::High {
                "🚨"
            } else if op.risk_level >= RiskLevel::Medium {
                "⚠️"
            } else {
                "✅"
            };
            md.push_str(&format!("- {op_emoji} `{}`\n", op.description));
            if let Some(w) = &op.warning {
                md.push_str(&format!("  > _{w}_\n"));
            }
            if op.acquires_lock {
                md.push_str("  > 🔒 Acquires **ACCESS EXCLUSIVE** table lock\n");
            }
        }
        md.push('\n');
    }

    // ── Warnings from engine ──────────────────────────────────────────────
    if !r.warnings.is_empty() {
        md.push_str("**Warnings:**\n\n");
        for w in &r.warnings {
            md.push_str(&format!("- ⚠️ {w}\n"));
        }
        md.push('\n');
    }

    // ── Breaking changes from codebase scan ───────────────────────────────
    if let Some(impact_report) = impact {
        if !impact_report.impacted_files.is_empty() {
            md.push_str("#### ⚠️ Breaking Changes — Codebase References\n\n");
            md.push_str(
                "The following files contain queries or code referencing \
                 schema objects affected by this migration:\n\n",
            );
            for f in impact_report.impacted_files.iter().take(15) {
                for hit in f.hits.iter().take(3) {
                    let snippet = hit
                        .snippet
                        .chars()
                        .take(100)
                        .collect::<String>();
                    md.push_str(&format!(
                        "- [`{}:{}`]({}) — `{snippet}`\n",
                        f.path, hit.line, f.path
                    ));
                }
            }
            if impact_report.impacted_files.len() > 15 {
                md.push_str(&format!(
                    "\n_... and {} more files_\n",
                    impact_report.impacted_files.len() - 15
                ));
            }
            md.push('\n');
        }
    }

    // ── Fix suggestions ───────────────────────────────────────────────────
    let no_fixes = Vec::new();
    let file_fixes = fixes.get(&r.file).unwrap_or(&no_fixes);
    if !file_fixes.is_empty() {
        md.push_str("#### ✅ Suggested Fixes\n\n");
        for fix in file_fixes.iter().take(6) {
            let sev_badge = match fix.severity {
                crate::recommendation::FixSeverity::Blocking => "🚨 BLOCKING",
                crate::recommendation::FixSeverity::Warning => "⚠️ WARNING",
                crate::recommendation::FixSeverity::Info => "ℹ️ INFO",
            };
            md.push_str(&format!(
                "**[{}] {}** `{sev_badge}`\n\n",
                fix.rule_id, fix.title
            ));
            md.push_str(&format!("{}\n\n", fix.explanation));

            if let Some(sql) = &fix.fixed_sql {
                md.push_str("```sql\n");
                md.push_str(sql);
                md.push_str("\n```\n\n");
            }

            if let Some(steps) = &fix.migration_steps {
                md.push_str("<details>\n<summary>📋 Zero-downtime migration steps</summary>\n\n```sql\n");
                for step in steps {
                    md.push_str(step);
                    md.push('\n');
                }
                md.push_str("```\n\n</details>\n\n");
            }

            if let Some(url) = &fix.docs_url {
                md.push_str(&format!("📖 [PostgreSQL docs]({url})\n\n"));
            }
        }
    }

    // ── Engine recommendations ────────────────────────────────────────────
    if !r.recommendations.is_empty() {
        md.push_str("#### 💡 Recommendations\n\n");
        for rec in &r.recommendations {
            md.push_str(&format!("- {rec}\n"));
        }
        md.push('\n');
    }

    md.push_str("---\n");
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/// GitHub badge string for a risk level.
fn risk_badge(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "🚨 **CRITICAL**",
        RiskLevel::High => "🔴 **HIGH**",
        RiskLevel::Medium => "🟡 **MEDIUM**",
        RiskLevel::Low => "🟢 LOW",
    }
}

/// Single emoji for a risk level.
fn risk_emoji(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "🚨",
        RiskLevel::High => "🔴",
        RiskLevel::Medium => "🟡",
        RiskLevel::Low => "🟢",
    }
}

/// Format seconds as a human-readable duration string.
fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("~{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("~{}m {}s", secs / 60, secs % 60)
    } else {
        format!("~{}s", secs)
    }
}

/// Return the filename portion of a path, or the full path if no slash.
fn short_name(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
}

// ─────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DetectedOperation, RiskLevel};

    fn make_report(file: &str, risk: RiskLevel) -> MigrationReport {
        MigrationReport {
            file: file.to_string(),
            overall_risk: risk,
            score: risk as u32 * 25,
            affected_tables: vec!["users".to_string()],
            operations: vec![DetectedOperation {
                description: "CREATE INDEX idx_users_email ON users(email)".to_string(),
                tables: vec!["users".to_string()],
                risk_level: risk,
                score: risk as u32 * 25,
                warning: Some("No CONCURRENTLY keyword".to_string()),
                acquires_lock: true,
                index_rebuild: true,
            }],
            warnings: vec!["No CONCURRENTLY".to_string()],
            recommendations: vec!["Use CREATE INDEX CONCURRENTLY".to_string()],
            fk_impacts: vec![],
            estimated_lock_seconds: Some(36),
            index_rebuild_required: true,
            requires_maintenance_window: true,
            analyzed_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_github_comment_contains_table_header() {
        let reports = vec![make_report("migrations/0042_add_index.sql", RiskLevel::Critical)];
        let fixes = HashMap::new();
        let output = render_ci_report(&reports, &fixes, None, CiFormat::GithubComment);
        assert!(output.contains("SchemaRisk v2"));
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("0042_add_index.sql"));
    }

    #[test]
    fn test_json_output_is_valid_json() {
        let reports = vec![make_report("test.sql", RiskLevel::Low)];
        let fixes = HashMap::new();
        let json = render_ci_report(&reports, &fixes, None, CiFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed.is_array());
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(0), "~0s");
        assert_eq!(format_duration(36), "~36s");
        assert_eq!(format_duration(90), "~1m 30s");
        assert_eq!(format_duration(3661), "~1h 1m");
    }
}
