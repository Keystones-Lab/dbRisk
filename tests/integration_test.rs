//! Integration tests for SchemaRisk v2.
//!
//! These tests cover the five most critical paths through the tool:
//!   1. Non-concurrent index detection
//!   2. NOT NULL column without DEFAULT detection
//!   3. DROP TABLE risk scoring
//!   4. CI report markdown generation
//!   5. Auto-fix SQL rewriting (apply_fixes idempotency)

use schema_risk::{
    ci, engine::RiskEngine, parser, recommendation, types::RiskLevel,
};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn parse(sql: &str) -> Vec<parser::ParsedStatement> {
    parser::parse(sql).expect("SQL should parse without error")
}

fn analyze(sql: &str) -> schema_risk::types::MigrationReport {
    let stmts = parse(sql);
    RiskEngine::new(HashMap::new()).analyze("test.sql", &stmts)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Non-concurrent index detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_non_concurrent_index_is_detected() {
    let stmts = parse("CREATE INDEX idx_users_email ON users(email);");
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());

    let r01 = fixes.iter().find(|f| f.rule_id == "R01");
    assert!(r01.is_some(), "R01 (non-concurrent index) should be detected");
    let fix = r01.unwrap();
    assert_eq!(fix.severity, recommendation::FixSeverity::Blocking);
    assert!(fix.auto_fixable, "R01 should be auto-fixable");
}

#[test]
fn test_concurrent_index_is_not_flagged() {
    let stmts = parse("CREATE INDEX CONCURRENTLY idx_users_email ON users(email);");
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());

    assert!(
        !fixes.iter().any(|f| f.rule_id == "R01"),
        "CONCURRENTLY index must not trigger R01"
    );
}

#[test]
fn test_non_concurrent_index_fix_sql_contains_concurrently() {
    let stmts = parse("CREATE INDEX idx_orders ON orders(created_at);");
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let r01 = fixes.iter().find(|f| f.rule_id == "R01").unwrap();
    let fixed = r01.fixed_sql.as_ref().expect("R01 must have fixed_sql");
    let upper = fixed.to_uppercase();
    assert!(
        upper.contains("CONCURRENTLY"),
        "fixed_sql must contain CONCURRENTLY, got: {fixed}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. ADD COLUMN NOT NULL without DEFAULT
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_add_column_not_null_no_default_detected() {
    let sql = "ALTER TABLE orders ADD COLUMN user_id INTEGER NOT NULL;";
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());

    let r02 = fixes.iter().find(|f| f.rule_id == "R02");
    assert!(
        r02.is_some(),
        "R02 (NOT NULL without DEFAULT) should be detected"
    );
    assert_eq!(r02.unwrap().severity, recommendation::FixSeverity::Blocking);
}

#[test]
fn test_add_column_with_default_not_flagged() {
    let sql = "ALTER TABLE orders ADD COLUMN notes TEXT DEFAULT '';";
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    assert!(
        !fixes.iter().any(|f| f.rule_id == "R02"),
        "Column with DEFAULT must not trigger R02"
    );
}

#[test]
fn test_add_column_nullable_not_flagged() {
    let sql = "ALTER TABLE orders ADD COLUMN notes TEXT;";
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    assert!(
        !fixes.iter().any(|f| f.rule_id == "R02"),
        "Nullable column without DEFAULT must not trigger R02"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. DROP TABLE risk scoring
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_drop_table_is_critical_or_high() {
    let report = analyze("DROP TABLE orders;");
    assert!(
        report.overall_risk >= RiskLevel::High,
        "DROP TABLE should be at least HIGH risk, got {:?}",
        report.overall_risk
    );
}

#[test]
fn test_drop_table_score_above_threshold() {
    let report = analyze("DROP TABLE users;");
    assert!(
        report.score >= 50,
        "DROP TABLE should score >= 50, got {}",
        report.score
    );
}

#[test]
fn test_drop_table_populates_affected_tables() {
    let report = analyze("DROP TABLE sessions;");
    assert!(
        report.affected_tables.contains(&"sessions".to_string()),
        "affected_tables must include 'sessions'"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. CI report markdown generation
// ─────────────────────────────────────────────────────────────────────────────

fn sample_report() -> schema_risk::types::MigrationReport {
    analyze("CREATE INDEX idx_tmp ON users(name); ALTER TABLE orders ADD COLUMN total NUMERIC NOT NULL;")
}

fn sample_fixes(sql: &str) -> std::collections::HashMap<String, Vec<recommendation::FixSuggestion>> {
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let mut map = std::collections::HashMap::new();
    map.insert("test.sql".to_string(), fixes);
    map
}

#[test]
fn test_ci_report_markdown_contains_risk_header() {
    let report = sample_report();
    let fixes = sample_fixes("CREATE INDEX idx_tmp ON users(name); ALTER TABLE orders ADD COLUMN total NUMERIC NOT NULL;");
    let md = ci::render_ci_report(&[report], &fixes, None, ci::CiFormat::GithubComment);
    assert!(
        md.contains("SchemaRisk") || md.contains("schema"),
        "CI report must mention SchemaRisk tool"
    );
    assert!(
        md.contains("##") || md.contains('#'),
        "CI report must contain Markdown headings"
    );
}

#[test]
fn test_ci_report_markdown_lists_files() {
    let report = sample_report();
    let fixes = sample_fixes("CREATE INDEX idx_tmp ON users(name);");
    let md = ci::render_ci_report(&[report], &fixes, None, ci::CiFormat::GithubComment);
    assert!(
        md.contains("test.sql"),
        "CI report must reference the migration file"
    );
}

#[test]
fn test_ci_report_json_is_valid() {
    let report = sample_report();
    let fixes = sample_fixes("DROP TABLE tmp;");
    let json_str = ci::render_ci_report(&[report], &fixes, None, ci::CiFormat::Json);
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("CI JSON output must be valid JSON");
    assert!(
        parsed.is_object() || parsed.is_array(),
        "CI JSON must be an object or array"
    );
}

#[test]
fn test_ci_report_includes_blocking_fixes() {
    let report = sample_report();
    let fix_sql = "CREATE INDEX idx_tmp ON users(name);";
    let stmts = parse(fix_sql);
    let fixes_vec = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let has_blocking = fixes_vec
        .iter()
        .any(|f| f.severity == recommendation::FixSeverity::Blocking);
    if has_blocking {
        let fixes = sample_fixes(fix_sql);
        let md = ci::render_ci_report(&[report], &fixes, None, ci::CiFormat::GithubComment);
        assert!(
            md.to_lowercase().contains("blocking")
                || md.contains("R01")
                || md.contains("CONCURRENTLY"),
            "CI report should highlight blocking issues"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Auto-fix SQL rewriting and idempotency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_apply_fixes_rewrites_non_concurrent_index() {
    let original = "CREATE INDEX idx_users_email ON users(email);";
    let stmts = parse(original);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let fixed = recommendation::apply_fixes(original, &fixes);
    assert!(
        fixed.to_uppercase().contains("CONCURRENTLY"),
        "apply_fixes must add CONCURRENTLY to index creation, got: {fixed}"
    );
}

#[test]
fn test_apply_fixes_is_idempotent() {
    let original = "CREATE INDEX idx_users_email ON users(email);";
    let stmts = parse(original);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let once = recommendation::apply_fixes(original, &fixes);
    // Re-analyse the fixed SQL and apply fixes again
    let stmts2 = parse(&once);
    let fixes2 = recommendation::suggest_fixes(&stmts2, &HashMap::new());
    let twice = recommendation::apply_fixes(&once, &fixes2);
    assert_eq!(
        once.to_uppercase().contains("CONCURRENTLY"),
        twice.to_uppercase().contains("CONCURRENTLY"),
        "apply_fixes must be idempotent"
    );
    // The second pass should not produce a different CONCURRENTLY-less result
    assert!(
        !fixes2.iter().any(|f| f.rule_id == "R01"),
        "After rewrite, CONCURRENTLY index must not trigger R01 again"
    );
}

#[test]
fn test_apply_fixes_preserves_concurrent_index_unchanged() {
    let already_correct = "CREATE INDEX CONCURRENTLY idx_users_email ON users(email);";
    let stmts = parse(already_correct);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let result = recommendation::apply_fixes(already_correct, &fixes);
    // Should not duplicate CONCURRENTLY
    let count = result
        .to_uppercase()
        .matches("CONCURRENTLY")
        .count();
    assert_eq!(
        count, 1,
        "CONCURRENTLY must appear exactly once, got {count} times in: {result}"
    );
}

#[test]
fn test_no_fixes_for_safe_migration() {
    let sql = "CREATE TABLE audit_log (id SERIAL PRIMARY KEY, action TEXT, created_at TIMESTAMPTZ DEFAULT now());";
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let blocking: Vec<_> = fixes
        .iter()
        .filter(|f| f.severity == recommendation::FixSeverity::Blocking)
        .collect();
    assert!(
        blocking.is_empty(),
        "Safe CREATE TABLE must not produce BLOCKING fixes, got: {blocking:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional: parser round-trip sanity checks
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_parser_handles_multi_statement() {
    let sql = r#"
        BEGIN;
        ALTER TABLE users ADD COLUMN avatar_url TEXT;
        CREATE INDEX CONCURRENTLY idx_users_avatar ON users(avatar_url);
        COMMIT;
    "#;
    let stmts = parse(sql);
    assert!(
        stmts.len() >= 2,
        "Parser must return at least 2 meaningful statements"
    );
}

#[test]
fn test_parser_empty_input() {
    let stmts = parser::parse("").expect("Empty input should not error");
    assert!(stmts.is_empty(), "Empty SQL must produce zero statements");
}

#[test]
fn test_rename_column_detected() {
    let sql = "ALTER TABLE users RENAME COLUMN email TO email_address;";
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let r05 = fixes.iter().find(|f| f.rule_id == "R05");
    assert!(r05.is_some(), "R05 (RENAME COLUMN) should be detected");
}

#[test]
fn test_alter_column_type_detected() {
    let sql = "ALTER TABLE orders ALTER COLUMN amount TYPE NUMERIC(18,4);";
    let stmts = parse(sql);
    let fixes = recommendation::suggest_fixes(&stmts, &HashMap::new());
    let r07 = fixes.iter().find(|f| f.rule_id == "R07");
    assert!(
        r07.is_some(),
        "R07 (ALTER COLUMN TYPE) should be detected"
    );
}
