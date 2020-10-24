use sqlx::postgres::{PgPool, PgPoolOptions};
use warp::Filter;

/// Filter to inject the `PgPool` into the request handler.
pub fn with_db(
    db: PgPool,
) -> impl Filter<Extract = (PgPool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

/// Create a postgres database pool.
///
/// The `DATABASE_URL` environment variable must be present, otherwise, this will blow up. If it
/// fails to create the database pool, it will also blow up.
pub async fn create_db_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("No DATABASE_URL environment variable");
    tracing::info!("url={}", url);
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Failed to create Pg connection pool")
}
