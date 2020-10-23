use sqlx::postgres::{PgPool, PgPoolOptions};
use warp::Filter;

pub fn with_db(
    db: PgPool,
) -> impl Filter<Extract = (PgPool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

pub async fn create_db_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("No DATABASE_URL environment variable");
    tracing::info!("url={}", url);
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Failed to create Pg connection pool")
}
