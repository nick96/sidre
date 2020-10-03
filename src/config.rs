use warp::{Rejection, Reply};

#[tracing::instrument(level = "info")]
pub async fn config_handler(id: String) -> Result<impl Reply, Rejection> {
    Ok(warp::reply())
}
