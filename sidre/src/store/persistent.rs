pub struct Store {}

impl crate::store::Store for Store {
    async fn get_service_provider(
        &mut self,
        entity_id: &str,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        // sqlx::query_as("SELECT * FROM sps WHERE entity_id = $1")
        // .bind(issuer.clone())
        // .fetch_one(store)
        todo!()
    }

    async fn service_provider_exists(&self, entity_id: &str) -> super::Result<bool> {
        todo!()
    }

    async fn upsert_service_provider(
        &mut self,
        service_provider: crate::service_provider::ServiceProvider,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        todo!()
    }

    async fn get_identity_provider(
        &self,
        entity_id: &str,
    ) -> super::Result<crate::identity_provider::IdP> {
        // sqlx::query_as!(
        //     IdP,
        //     "
        //     SELECT id
        //         , private_key
        //         , entity_id
        //         , metadata_valid_until
        //         , certificate
        //         , name_id_format
        //         , redirect_url
        //         FROM idps WHERE id = $1",
        //     id
        // )
        // .fetch_one(store)
        todo!()
    }

    async fn identity_provider_exists(&self, entity_id: &str) -> super::Result<bool> {
        todo!()
    }

    async fn ensure_identity_provider(
        &mut self,
        identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        todo!()
    }

    async fn create_service_provider(
        &mut self,
        service_provider: crate::service_provider::ServiceProvider,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        todo!()
    }

    async fn create_identity_provider(
        &mut self,
        identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        todo!()
    }
}

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
    PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Failed to create Pg connection pool")
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_with_db_injects_given_pool() {
        let pool = create_db_pool().await;
        let filter = with_db(pool);
        warp::test::request().filter(&filter).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_db_pool_creates_pool() {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must exist for this test");
        let _ = create_db_pool();
    }

    // TODO-test: Check that `create_db_pool` blows up when the env var isn't there
    //  the code below breaks tests that use `create_db_pool` after it.
    // Set DATABASE_URL to its old value once the test has run.
    // struct RestoreDatabaseUrlEnvVar(String);
    // impl Drop for RestoreDatabaseUrlEnvVar {
    //     fn drop(&mut self) {
    //         std::env::set_var("DATABASE_URL", self.0.clone());
    //     }
    // }

    // #[tokio::test]
    // #[should_panic]
    // async fn test_create_db_pool_blows_up_without_env_var() {
    //     let _restore = if let Ok(old_val) = std::env::var("DATABASE_URL") {
    //         Some(RestoreDatabaseUrlEnvVar(old_val))
    //     } else {
    //         None
    //     };
    //     std::env::remove_var("DATABASE_URL");
    //     let _ = create_db_pool().await;
    // }
}
