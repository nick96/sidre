//! Storage module
//!
//! This module defines a trait for what it means to be a store. Based on the
//! specified features a store implementing that interface is exported.
use async_trait::async_trait;
use thiserror::Error;
use warp::Filter;

/// Possible errors returned by the store. The important thing is that we're
/// diffentiating between not found, a client error, and other failures, a
/// server error.
#[derive(Error, Debug)]
pub enum Error {
    /// Entity was not found.
    #[error("Could not find entity with ID {0}")]
    NotFound(String),
    /// Some other error prevented us from performing the action.
    #[error("Could not retrieve entity: {0}")]
    Failure(#[from] Box<dyn std::error::Error>),
}

/// Result of a store action.
pub type Result<T> = std::result::Result<T, Error>;

#[async_trait]
pub trait Store {
    /// Get the service provider by their `entity_id`.
    async fn get_service_provider(
        &mut self,
        entity_id: &str,
    ) -> Result<service_provider::ServiceProvider>;

    /// Check the service provider exists by their `entity_id`.
    async fn service_provider_exists(&self, entity_id: &str) -> Result<bool>;

    /// Insert the service provider if it doesn't exist, otherwise create it.
    async fn upsert_service_provider(
        &mut self,
        service_provider: service_provider::ServiceProvider,
    ) -> Result<service_provider::ServiceProvider>;

    async fn create_service_provider(
        &mut self,
        service_provider: service_provider::ServiceProvider,
    ) -> Result<service_provider::ServiceProvider>;

    /// Get the identity provider by their `entity_id`.
    async fn get_identity_provider(&self, entity_id: &str) -> Result<identity_provider::IdP>;

    /// Check the identity provider exists by their `entity_id`.
    async fn identity_provider_exists(&self, entity_id: &str) -> Result<bool>;

    /// Ensure the identity provider exists. If it does, just return it, otherwise
    /// create it using the defaults and return it.
    async fn ensure_identity_provider(
        &mut self,
        identity_provider: identity_provider::IdP,
    ) -> Result<identity_provider::IdP>;

    async fn create_identity_provider(
        &mut self,
        identity_provider: identity_provider::IdP,
    ) -> Result<identity_provider::IdP>;
}

// Make sure things are configured correctl. We need either `data-in-memory` OR `postgres-persistent`.
#[cfg(all(feature = "data-in-memory", feature = "postgres-persistent"))]
compile_error!("Either dadta-in-memory or postgres-peristent must be enabled, not both");

#[cfg(feature = "postgres-persistent")]
compile_error!("Not implemented");

#[cfg(feature = "data-in-memory")]
mod memory;

#[cfg(feature = "data-in-memory")]
pub use memory::Store as MemoryStore;

#[cfg(feature = "postgres-persistent")]
mod persistent;

#[cfg(feature = "postgres-persistent")]
pub use persistent::Store as PersistentStore;

use crate::{identity_provider, service_provider};

/// Filter to inject the `PgPool` into the request handler.
pub fn with_store<S: Store + Send + Sync + Clone>(
    store: S,
) -> impl Filter<Extract = (S,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || store.clone())
}
