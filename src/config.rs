//! Application configuration.
//!
//! **This is the single source of truth for all runtime configuration.**
//! No other module in this codebase should call [`std::env::var`] directly —
//! everything goes through [`Config::from_env`] at startup.

use anyhow::{anyhow, Result};

/// All configuration values required to run Shieldgrid Core.
///
/// Populated from environment variables at startup via [`Config::from_env`].
// Fields consumed progressively across tickets — suppress premature dead_code
// lint until each field is wired to a connector or route.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Config {
    /// TCP port the API server will listen on (e.g. `3000`).
    pub port: u16,

    /// PostgreSQL connection URL
    /// (e.g. `postgres://user:pass@localhost:5432/shieldgrid`).
    pub database_url: String,

    /// OpenSearch/Elasticsearch base URL, **no trailing slash**
    /// (e.g. `http://localhost:9200`).
    pub opensearch_url: String,

    /// Basic-auth username for OpenSearch.
    pub opensearch_user: String,

    /// Basic-auth password for OpenSearch.
    pub opensearch_pass: String,

    /// Secret key used to sign and verify JWT tokens.
    pub jwt_secret: String,

    /// Optional email address to seed the first admin user on startup.
    /// Defaults to `admin@shieldgrid.local` if password is provided but email is not.
    pub admin_seed_email: Option<String>,

    /// Optional password to seed the first admin user on startup.
    /// If provided, an admin user is created/updated with this password on startup.
    pub admin_seed_password: Option<String>,
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Calls [`dotenvy::dotenv`] first so a `.env` file is honoured when
    /// present; a missing `.env` is silently ignored (env vars may come from
    /// the shell or a container orchestrator).
    ///
    /// # Errors
    ///
    /// Returns a descriptive error of the form `"missing required env var: KEY"`
    /// if any required variable is absent or cannot be parsed.
    pub fn from_env() -> Result<Self> {
        // Silently ignore a missing .env — real env vars take precedence anyway.
        dotenvy::dotenv().ok();

        Ok(Config {
            port: require_var("PORT")?
                .parse()
                .map_err(|_| anyhow!("PORT must be a valid u16"))?,
            database_url: require_var("DATABASE_URL")?,
            opensearch_url: require_var("OPENSEARCH_URL")?,
            opensearch_user: require_var("OPENSEARCH_USER")?,
            opensearch_pass: require_var("OPENSEARCH_PASS")?,
            jwt_secret: require_var("JWT_SECRET")?,
            admin_seed_email: std::env::var("ADMIN_SEED_EMAIL").ok(),
            admin_seed_password: std::env::var("ADMIN_SEED_PASSWORD").ok(),
        })
    }
}

/// Return the value of `key` from the environment, or a clear error message.
fn require_var(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("missing required env var: {key}"))
}
