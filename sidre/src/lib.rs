mod config;
mod error;
mod generation;
mod identity_provider;
mod login;
mod ping;
mod service_provider;
pub mod store;

use anyhow::anyhow;
use store::Store;
use tracing_subscriber::fmt::format::FmtSpan;
use warp::{Filter, Rejection, Reply};

use crate::{
    config::{
        idp_config_handler, idp_sp_config_handler, IdentityProviderConfig,
    },
    identity_provider::get_idp_metadata_handler,
    login::{login_handler, LoginRequestParams},
    ping::ping_handler,
    service_provider::upsert_sp_metadata_handler,
    store::with_store,
};

pub fn try_init_tracing() -> anyhow::Result<()> {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "tracing=info,sidre=debug".to_owned());

    Ok(tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .try_init()
        .map_err(|e| anyhow!("tracing initialisation failed: {}", e))?)
}

/// Return a warp app with everything wired up.
///
/// This will setup:
///     - Logging and tracing
///     - Store injection
///     - Routing
#[tracing::instrument(level = "info", skip(store))]
pub async fn app<S: Store + Send + Sync + Clone>(
    store: S,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    if let Err(e) = try_init_tracing() {
        tracing::warn!(
            "Failed to initialise tracing, it has probably already been \
             initialised: {}",
            e
        )
    }

    let ping = warp::path!("ping")
        .and_then(ping_handler)
        .with(warp::trace::named("ping"));

    let idp_metadata = warp::get().and(
        // TODO: Make IdP entity ID a get param
        warp::path!(String / "metadata")
            .and(warp::header("Host"))
            .and(with_store(store.clone()))
            .and_then(get_idp_metadata_handler)
            .with(warp::trace::named("get-idp-metadata")),
    );

    let sp_metadata = warp::post().and(
        // TODO: Make SP and IdP entity IDs get params
        warp::path!(String / String / "metadata")
            .and(with_store(store.clone()))
            .and(warp::body::bytes())
            .and_then(upsert_sp_metadata_handler)
            .with(warp::trace::named("upsert-sp-metadata")),
    );

    let login = warp::get().and(
        // TODO: Make IdP ID a get param
        warp::path!(String / "sso")
            .and(warp::query::<LoginRequestParams>())
            .and(with_store(store.clone()))
            .and_then(login_handler)
            .with(warp::trace::named("login")),
    );

    let config = warp::post()
        .and(
            // TODO: Make IdP entity ID a get param
            warp::path!(String / "config")
                .and(with_store(store))
                .and(warp::body::json::<IdentityProviderConfig>())
                .and_then(idp_config_handler::<S>)
                .with(warp::trace::named("config-idp")),
        )
        // TODO: Make IdP and SP entity ID a get param
        .or(warp::path!(String / String / "config")
            .and_then(idp_sp_config_handler)
            .with(warp::trace::named("config-idp-sp")));

    ping.or(idp_metadata)
        .or(login)
        .or(config)
        .or(sp_metadata)
        .with(warp::trace::request())
}

// These tests are intended to make sure the routing is correct and the general
// high level logic is correct. More fine grained stuff should be saved for the
// unit tests.
#[cfg(test)]
mod test {
    use pretty_assertions::assert_eq;
    use rand::Rng;
    use store::get_store_for_test;

    use super::*;

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .map(char::from)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn test_metadata_same_idp_id_same_metadata() {
        let idp_entity_id = random_string();
        let store = get_store_for_test();
        let filter = app(store).await;
        let first_resp = warp::test::request()
            .header("Host", "http://localhost:8080")
            .path(&format!("/{}/metadata", idp_entity_id))
            .reply(&filter)
            .await;
        let second_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp_entity_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;

        assert_eq!(first_resp.status(), 200);
        assert_eq!(second_resp.status(), 200);
        assert_eq!(first_resp.body(), second_resp.body());
    }

    #[tokio::test]
    async fn test_metadata_different_idp_different_metadata() {
        let idp_entity_id = random_string();
        let idp2_entity_id = random_string();
        let store = get_store_for_test();
        let filter = app(store).await;
        let first_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp_entity_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;
        let second_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp2_entity_id))
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
        // TODO-test: Reenable this once config is implemented
        // let db = db::create_db_pool().await;
        // let idp_id = random_string();
        // let _ = identity_provider::ensure_idp(&db, &random_string(),
        // &random_string()); let filter = app().await;
        // let resp = warp::test::request()
        //     .path(&format!("/{}/config", idp_id))
        //     .method("POST")
        //     .reply(&filter)
        //     .await;
        // assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn test_idp_sp_config() {
        // TODO-test: Reenable this once config is implemented
        // let idp_id = random_string();
        // let sp_id = random_string();
        // let filter = app().await;
        // let resp = warp::test::request()
        //     .path(&format!("/{}/{}/config", idp_id, sp_id))
        //     .method("POST")
        //     .reply(&filter)
        //     .await;
        // assert_eq!(resp.status(), 200);
    }
}
