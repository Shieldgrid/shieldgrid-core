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
#[derive(Clone)]
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

    /// Email address to seed the first admin user on startup.
    pub admin_seed_email: String,

    /// Password to seed the first admin user on startup.
    /// An admin user is created/updated with this password on startup.
    pub admin_seed_password: String,

    /// Path to the Velociraptor api_client.yaml configuration file.
    pub velociraptor_api_client_yaml: String,

    /// Comma-separated list of allowed CORS origins
    /// (e.g. `http://localhost:5173`).
    pub allowed_origin: String,

    /// Comma-separated list of static API tokens for service accounts / MCP integration.
    pub api_tokens: Vec<String>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("database_url", &self.database_url)
            .field("opensearch_url", &self.opensearch_url)
            .field("opensearch_user", &self.opensearch_user)
            .field("opensearch_pass", &"[REDACTED]")
            .field("jwt_secret", &"[REDACTED]")
            .field("admin_seed_email", &self.admin_seed_email)
            .field("admin_seed_password", &"[REDACTED]")
            .field(
                "velociraptor_api_client_yaml",
                &self.velociraptor_api_client_yaml,
            )
            .field("allowed_origin", &self.allowed_origin)
            .field("api_tokens", &"[REDACTED]")
            .finish()
    }
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
            admin_seed_email: require_var("ADMIN_SEED_EMAIL")?,
            admin_seed_password: require_var("ADMIN_SEED_PASSWORD")?,
            velociraptor_api_client_yaml: require_var("VELOCIRAPTOR_CONFIG_PATH")?,
            allowed_origin: std::env::var("ALLOWED_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
            api_tokens: std::env::var("API_TOKENS")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
        })
    }
}

/// Return the value of `key` from the environment, or a clear error message.
fn require_var(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow!("missing required env var: {key}"))
}
