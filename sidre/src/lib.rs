mod config;
mod db;
mod error;
mod identity_provider;
mod login;
mod service_provider;

use crate::{
    config::{idp_config_handler, idp_sp_config_handler},
    db::{create_db_pool, with_db},
    identity_provider::get_idp_metadata_handler,
    login::{login_handler, LoginRequestParams},
    service_provider::upsert_sp_metadata_handler,
};
use tracing_subscriber::fmt::format::FmtSpan;
use warp::{Filter, Rejection, Reply};

/// Return a warp app with everything wired up.
///
/// This will setup:
///     - Logging and tracing
///     - Database pool injection
///     - Routing
#[tracing::instrument(level = "info")]
pub async fn app() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,sider=debug".to_owned());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .try_init();

    let db = create_db_pool().await;

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
            .and(with_db(db))
            .and_then(login_handler)
            .with(warp::trace::named("login")),
    );

    let config = warp::post()
        .and(
            warp::path!(String / "config")
                .and_then(idp_config_handler)
                .with(warp::trace::named("config-idp")),
        )
        .or(warp::path!(String / String / "config")
            .and_then(idp_sp_config_handler)
            .with(warp::trace::named("config-idp-sp")));

    idp_metadata
        .or(login)
        .or(config)
        .or(sp_metadata)
        .with(warp::trace::request())
}

// These tests are intended to make sure the routing is correct and the general high level logic is correct.
// More fine grained stuff should be saved for the unit tests.
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

    #[tokio::test]
    async fn test_register_sp() {
        // TODO-test: Test util to build SP metadata
    }

    #[tokio::test]
    async fn test_sp_login() {
        // TODO-test: Test util to build authn request
    }

    #[tokio::test]
    async fn test_idp_config() {
        let db = db::create_db_pool().await;
        let idp_id = random_string();
        let _ = identity_provider::ensure_idp(&db, &random_string(), &random_string());
        let filter = app().await;
        let resp = warp::test::request()
            .path(&format!("/{}/config", idp_id))
            .method("POST")
            .reply(&filter)
            .await;
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_idp_sp_config() {
        let idp_id = random_string();
        let sp_id = random_string();
        let filter = app().await;
        let resp = warp::test::request()
            .path(&format!("/{}/{}/config", idp_id, sp_id))
            .method("POST")
            .reply(&filter)
            .await;
        assert_eq!(resp.status(), 200);
    }
}
