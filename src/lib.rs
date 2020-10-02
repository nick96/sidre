mod x509;
mod identity_provider;
mod service_provider;
mod db;
mod templates;
mod error;
mod config;
mod login;

use warp::{Filter, Reply, Rejection};
use sqlx::postgres::PgPoolOptions;
use crate::{
    identity_provider::get_idp_metadata_handler,
    service_provider::upsert_sp_metadata_handler,
    db::with_db,
    login::{LoginRequestParams, login_handler},
    config::config_handler,
};
use tracing_subscriber::fmt::format::FmtSpan;

pub async fn app() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,sider=debug".to_owned());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .try_init();

    let url = std::env::var("DATABASE_URL").expect("No DATABASE_URL environment variable");
    tracing::info!("url={}", url);
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Failed to create Pg connection pool");

    let idp_metadata = warp::get().and(
        warp::path!(String / "metadata")
            .and(warp::header("Host"))
            .and(with_db(db.clone()))
            .and_then(get_idp_metadata_handler)
            .with(warp::trace::named("get-idp-metadata")),
    );

    let sp_metadata = warp::post().and(
        warp::path!(String / String / "metadata")
            .and(with_db(db.clone()))
            .and(warp::body::bytes())
            .and_then(upsert_sp_metadata_handler)
            .with(warp::trace::named("upsert-sp-metadata")),
    );

    let login = warp::get().and(
        warp::path!(String / "sso")
            .and(warp::query::<LoginRequestParams>())
            .and_then(login_handler)
            .with(warp::trace::named("login")),
    );

    let config = warp::post().and(
        warp::path!(String / "config")
            .and_then(config_handler)
            .with(warp::trace::named("config")),
    );

    idp_metadata.or(login).or(config).or(sp_metadata)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn test_metadata_same_idp_id_same_metadata() {
        let idp_id = random_string();
        let filter = app().await;
        let first_resp = warp::test::request()
            .header("Host", "http://localhost:8080")
            .path(&format!("/{}/metadata", idp_id))
            .reply(&filter)
            .await;
        let second_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;

        assert_eq!(first_resp.status(), 200);
        assert_eq!(second_resp.status(), 200);
        assert_eq!(first_resp.body(), second_resp.body());
    }

    #[tokio::test]
    async fn test_metadata_different_idp_different_metadata() {
        let idp_id = random_string();
        let idp2_id = random_string();
        let filter = app().await;
        let first_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;
        let second_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp2_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;

        assert_eq!(first_resp.status(), 200);
        assert_eq!(second_resp.status(), 200);
        assert_ne!(first_resp.body(), second_resp.body());
    }
}
