use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchemaRiskError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQL parse error: {0}")]
    Parse(String),

    #[error("Invalid migration file: {0}")]
    InvalidMigration(String),

    #[error("Analysis failed: {0}")]
    Analysis(String),

    #[error("No SQL files found matching: {0}")]
    NoFilesFound(String),

    #[error("Database connection failed: {0}")]
    DbConnect(String),

    #[error("Database query failed: {0}")]
    DbQuery(String),

    #[error("Feature '{0}' is not enabled — rebuild with `--features {0}`")]
    FeatureDisabled(String),
}

pub type Result<T> = std::result::Result<T, SchemaRiskError>;
