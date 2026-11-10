use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
        .context("connect to postgres")?;

    // Both binaries run migrations. sqlx takes an advisory lock, so the API
    // and worker can start in any order without racing.
    sqlx::migrate!("../migrations")
        .run(&pool)
        .await
        .context("run database migrations")?;

    Ok(pool)
}
