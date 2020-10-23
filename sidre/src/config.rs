use warp::{Rejection, Reply};

#[tracing::instrument(level = "info")]
pub async fn idp_config_handler(id: String) -> Result<impl Reply, Rejection> {
    Ok(warp::reply())
}

#[tracing::instrument(level = "info")]
pub async fn idp_sp_config_handler(idp_id: String, sp_id: String) -> Result<impl Reply, Rejection> {
    Ok(warp::reply())
}
