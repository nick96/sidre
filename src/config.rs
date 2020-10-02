use warp::{Reply, Rejection};

pub async fn config_handler(id: String) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    Ok(warp::reply())
}