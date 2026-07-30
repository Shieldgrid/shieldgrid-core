// Shieldgrid Core — entry point.
//
// Initialises tracing, loads config from the environment, builds the Axum
// router and starts the HTTP listener.  All config is read via `config.rs`;
// nothing else in the codebase should call `std::env::var` directly.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

mod config;
mod connectors;
mod middleware;
mod models;
mod routes;
mod services;

use connectors::velociraptor::VelociraptorConnector;
use connectors::wazuh::WazuhConnector;
use routes::AppState;

#[tokio::main]
async fn main() {
    // Structured logging — default to INFO, overridable via RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::from_env().unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });

    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&cfg.database_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to connect to database: {e}");
            std::process::exit(1);
        });

    info!("Running database migrations...");
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to run migrations: {e}");
            std::process::exit(1);
        });
    info!("Database migrations complete.");

    // Seed Admin User
    let email = &cfg.admin_seed_email;
    info!("Seeding admin user with email: {}", email);

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(cfg.admin_seed_password.as_bytes(), &salt)
        .expect("Failed to hash seed password")
        .to_string();

    let user_id = Uuid::new_v4();

    let result = sqlx::query!(
        "INSERT INTO users (id, email, password_hash, role) 
         VALUES ($1, $2, $3, 'admin')
         ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash",
        user_id,
        email,
        password_hash
    )
    .execute(&db)
    .await;

    if let Err(e) = result {
        warn!("Failed to seed admin user: {e}");
    } else {
        info!("Admin user successfully seeded/updated.");
    }

    // Build the connector registry.
    let wazuh = WazuhConnector::new(
        cfg.opensearch_url.clone(),
        cfg.opensearch_user.clone(),
        cfg.opensearch_pass.clone(),
    );

    let velociraptor = VelociraptorConnector::new(&cfg).await.unwrap_or_else(|e| {
        eprintln!("Failed to initialize Velociraptor connector: {e}");
        std::process::exit(1);
    });

    let state = AppState {
        connectors: vec![Arc::new(wazuh), Arc::new(velociraptor)],
        db,
        config: Arc::new(cfg.clone()),
    };

    let app = routes::build_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    info!("listening on {}", addr);

    axum::serve(listener, app).await.unwrap();
}
