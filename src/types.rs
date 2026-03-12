//! All shared types used across the tool.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─────────────────────────────────────────────
// Risk levels
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl RiskLevel {
    /// Convert a numeric score to a risk level.
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=20 => RiskLevel::Low,
            21..=50 => RiskLevel::Medium,
            51..=100 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Returns an exit code suitable for CI: non-zero when risk >= threshold.
    pub fn exit_code(self, fail_on: RiskLevel) -> i32 {
        if self >= fail_on { 1 } else { 0 }
    }
}

// ─────────────────────────────────────────────
// Detected schema operations
// ─────────────────────────────────────────────

/// A single high-level action the migration performs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedOperation {
    /// Human-readable summary of what the SQL does.
    pub description: String,
    /// Which table(s) are touched (may be empty for DROP INDEX etc.).
    pub tables: Vec<String>,
    /// Risk contribution of this single operation.
    pub risk_level: RiskLevel,
    /// Score contribution (additive).
    pub score: u32,
    /// One-line warning emitted for this operation.
    pub warning: Option<String>,
    /// Whether this op acquires a full table lock.
    pub acquires_lock: bool,
    /// Whether this op triggers an index rebuild.
    pub index_rebuild: bool,
}

// ─────────────────────────────────────────────
// Foreign-key impact
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FkImpact {
    pub constraint_name: String,
    pub from_table: String,
    pub to_table: String,
    pub cascade: bool,
}

// ─────────────────────────────────────────────
// The final report produced for one SQL file
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationReport {
    pub file: String,
    pub overall_risk: RiskLevel,
    pub score: u32,
    pub affected_tables: Vec<String>,
    pub operations: Vec<DetectedOperation>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
    pub fk_impacts: Vec<FkImpact>,
    pub estimated_lock_seconds: Option<u64>,
    pub index_rebuild_required: bool,
    pub requires_maintenance_window: bool,
    pub analyzed_at: String,
}
