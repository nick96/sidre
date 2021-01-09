use warp::{http::Response, Rejection, Reply};

#[tracing::instrument(level = "info")]
pub async fn ping_handler() -> Result<impl Reply, Rejection> {
    Ok(Response::builder().status(200).body(""))
}
