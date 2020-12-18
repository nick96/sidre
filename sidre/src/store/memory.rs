use async_trait::async_trait;

pub struct Store {}

#[async_trait]
impl crate::store::Store for Store {
    async fn get_service_provider(
        &mut self,
        entity_id: &str,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
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

impl Store {
    pub fn new() -> Self {
        todo!()
    }
}
