use crate::store::Result;
use async_trait::async_trait;
use prost::Message;

use super::Error;

pub mod service_provider {
    use samael::metadata;

    use crate::service_provider;

    include!(concat!(env!("OUT_DIR"), "/sidre.rs"));

    impl Into<String> for NameIdFormat {
        fn into(self) -> String {
            match self {
                NameIdFormat::EmailAddress => {
                    metadata::NameIdFormat::EmailAddressNameIDFormat
                        .value()
                        .to_string()
                }
            }
        }
    }

    impl Into<service_provider::ServiceProvider> for ServiceProvider {
        fn into(self) -> service_provider::ServiceProvider {
            service_provider::ServiceProvider {
                id: self.entity_id.clone(),
                entity_id: self.entity_id,
                name_id_format: NameIdFormat::from_i32(self.name_id_format)
                    .expect("Invalid NameIdFormat")
                    .into(),
                consume_endpoint: self.consume_endpoint,
                keys: self
                    .base64_keys
                    .iter()
                    .map(|k| k.as_bytes().to_owned())
                    .collect(),
            }
        }
    }
}

#[derive(Clone)]
pub struct Store {
    db: sled::Db,
}

#[async_trait]
impl crate::store::Store for Store {
    async fn get_service_provider(
        &self,
        entity_id: &str,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        let data = self
            .db
            .get(&entity_id)?
            .ok_or_else(|| Error::NotFound(entity_id.to_string()))?;
        let sp = service_provider::ServiceProvider::decode(&*data)
            .expect("Failed to decode service provider protobuf");
        Ok(sp.into())
    }

    async fn service_provider_exists(
        &self,
        entity_id: &str,
    ) -> super::Result<bool> {
        todo!()
    }

    async fn upsert_service_provider(
        &self,
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

    async fn identity_provider_exists(
        &self,
        entity_id: &str,
    ) -> super::Result<bool> {
        todo!()
    }

    async fn ensure_identity_provider(
        &self,
        identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        todo!()
    }

    async fn create_service_provider(
        &self,
        service_provider: crate::service_provider::ServiceProvider,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        todo!()
    }

    async fn create_identity_provider(
        &self,
        identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        todo!()
    }
}

impl Store {
    pub fn new() -> Result<Self> {
        // Open it in the tmp dir because we want this to be ephemeral.
        let db = sled::open("/tmp/sidre-db")?;
        Ok(Self { db })
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::{service_provider, store::Store};

    use super::service_provider::{NameIdFormat, ServiceProvider};
    use super::Result;
    use super::Store as MemoryStore;
    use prost::{
        bytes::{Buf, BytesMut},
        Message,
    };

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn get_service_provider_exists() -> Result<()> {
        let entity_id = "";
        let consume_endpoint = "";
        let service_provider = ServiceProvider {
            entity_id: entity_id.into(),
            consume_endpoint: consume_endpoint.into(),
            name_id_format: NameIdFormat::EmailAddress as i32,
            base64_keys: vec![],
        };
        let mut encoded_service_provider = BytesMut::new();
        service_provider
            .encode(&mut encoded_service_provider)
            .unwrap();

        let store = MemoryStore::new()?;
        store
            .db
            .insert(entity_id.as_bytes(), encoded_service_provider.bytes())?;
        let retrieved_service_provider =
            store.get_service_provider(entity_id).await.unwrap();
        let expected_service_provider: service_provider::ServiceProvider =
            service_provider.into();
        assert_eq!(expected_service_provider, retrieved_service_provider);
        Ok(())
    }

    #[tokio::test]
    async fn get_service_provider_not_exists() {
        todo!()
    }
}
