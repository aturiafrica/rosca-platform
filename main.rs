// src/main.rs
// Entry point for the ROSCA Platform API

use axum::Server;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use tracing_subscriber;

mod handlers;
mod config;

use config::{AppConfig, ConfigError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let config = AppConfig::from_env()
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("Configuration error: {}", e)))?;

    // Set tracing level based on environment
    let log_level = match config.env.as_str() {
        "dev" => tracing::Level::DEBUG,
        "uat" => tracing::Level::INFO,
        "prod" => tracing::Level::INFO,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    // Database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(match config.env.as_str() {
            "dev" => 5,
            "uat" => 10,
            "prod" => 20,
            _ => 5,
        })
        .connect(&config.database_url)
        .await
        .map_err(|e| format!("Failed to connect to the database: {}", e))?;

    // Create the router with the database pool and config
    let app = handlers::router::create_router(pool)
        .with_state((pool, config.clone()));

    // Server address
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting server in {} environment on {}", config.env, addr);

    // Start the server
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
