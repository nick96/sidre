use std::path::PathBuf;

use async_trait::async_trait;
use bytes::BytesMut;
use prost::Message;

use super::Error;
use crate::store::Result;

pub mod service_provider {
    use samael::metadata;

    use crate::service_provider;

    include!(concat!(env!("OUT_DIR"), "/sidre.rs"));

    impl From<String> for NameIdFormat {
        fn from(name_id_format: String) -> Self {
            let email_address_name_id_format =
                metadata::NameIdFormat::EmailAddressNameIDFormat
                    .value()
                    .to_string();
            if name_id_format == email_address_name_id_format {
                NameIdFormat::EmailAddress
            } else {
                panic!(format!("unknown name ID format: {}", name_id_format))
            }
        }
    }

    impl From<NameIdFormat> for String {
        fn from(name_id_format: NameIdFormat) -> Self {
            match name_id_format {
                NameIdFormat::EmailAddress => {
                    metadata::NameIdFormat::EmailAddressNameIDFormat
                        .value()
                        .to_string()
                },
            }
        }
    }

    impl From<service_provider::ServiceProvider> for ServiceProvider {
        fn from(service_provider: service_provider::ServiceProvider) -> Self {
            let name_id_format: NameIdFormat =
                service_provider.name_id_format.into();
            Self {
                entity_id: service_provider.entity_id,
                name_id_format: name_id_format as i32,
                consume_endpoint: service_provider.consume_endpoint,
                base64_keys: service_provider
                    .keys
                    .iter()
                    .map(base64::encode)
                    .collect(),
            }
        }
    }

    impl From<ServiceProvider> for service_provider::ServiceProvider {
        fn from(service_provider: ServiceProvider) -> Self {
            Self {
                id: service_provider.entity_id.clone(),
                entity_id: service_provider.entity_id,
                name_id_format: NameIdFormat::from_i32(
                    service_provider.name_id_format,
                )
                .unwrap()
                .into(),
                consume_endpoint: service_provider.consume_endpoint,
                keys: service_provider
                    .base64_keys
                    .iter()
                    .filter_map(|k| base64::decode(k).ok())
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
        let sp = service_provider::ServiceProvider::decode(&*data)?;
        Ok(sp.into())
    }

    async fn service_provider_exists(
        &self,
        entity_id: &str,
    ) -> super::Result<bool> {
        let exists = self.db.contains_key(&entity_id)?;
        Ok(exists)
    }

    async fn upsert_service_provider(
        &self,
        service_provider: crate::service_provider::ServiceProvider,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        let proto_service_provider: service_provider::ServiceProvider =
            service_provider.into();

        let data = self
            .db
            .update_and_fetch(
                &proto_service_provider.entity_id,
                |maybe_existing| {
                    if let Some(_) = maybe_existing {
                        tracing::info!(
                            "Service provider with entity ID {} found, \
                             updating",
                            &proto_service_provider.entity_id
                        );
                    } else {
                        tracing::info!(
                            "No service provider with entity ID {}, inserting",
                            &proto_service_provider.entity_id
                        );
                    }
                    let mut buf = BytesMut::default();
                    if let Err(e) = proto_service_provider.encode(&mut buf) {
                        tracing::error!(
                            "failed to insert service provider into store: {}",
                            e
                        );
                        return None;
                    }

                    if let Err(e) =
                        self.db.insert(&proto_service_provider.entity_id, &*buf)
                    {
                        tracing::info!(
                            "Failed to insert service provider: {}",
                            e
                        );
                        return None;
                    }

                    match self.db.get(&proto_service_provider.entity_id) {
                        Ok(val) => val,
                        Err(e) => {
                            tracing::info!(
                                "Failed to get service provider: {}",
                                e
                            );
                            None
                        },
                    }
                },
            )?
            .ok_or_else(|| {
                crate::store::Error::GenericFailure(
                    "failed to upsert service provider".into(),
                )
            })?;
        let sp = service_provider::ServiceProvider::decode(&*data)?;
        Ok(sp.into())
    }

    async fn get_identity_provider(
        &self,
        _entity_id: &str,
    ) -> super::Result<crate::identity_provider::IdP> {
        todo!()
    }

    async fn identity_provider_exists(
        &self,
        _entity_id: &str,
    ) -> super::Result<bool> {
        todo!()
    }

    async fn ensure_identity_provider(
        &self,
        _identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        todo!()
    }

    async fn create_service_provider(
        &self,
        service_provider: crate::service_provider::ServiceProvider,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        let proto_service_provider: service_provider::ServiceProvider =
            service_provider.into();
        let mut buf = bytes::BytesMut::default();
        proto_service_provider.encode(&mut buf)?;
        self.db.insert(&proto_service_provider.entity_id, &*buf)?;
        let inserted_data = self
            .db
            .get(&proto_service_provider.entity_id)?
            .ok_or_else(|| {
                Error::GenericFailure(
                    "getting previously inserted service provider returned \
                     None"
                        .into(),
                )
            })?;
        let inserted_sp =
            service_provider::ServiceProvider::decode(&*inserted_data)?;
        Ok(inserted_sp.into())
    }

    async fn create_identity_provider(
        &self,
        _identity_provider: crate::identity_provider::IdP,
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
pub fn memory_store_for_test() -> Store {
    fn random_db_path() -> PathBuf {
        let dir = std::env::temp_dir();
        dir.join(uuid::Uuid::new_v4().to_string())
    }

    let db_path = random_db_path();
    Store {
        db: sled::open(&db_path).unwrap_or_else(|_| {
            panic!("failed to open db at {}", db_path.display())
        }),
    }
}

#[cfg(test)]
mod test {
    use prost::{
        bytes::{Buf, BytesMut},
        Message,
    };
    use rand::Rng;

    use super::{
        memory_store_for_test,
        service_provider::{NameIdFormat, ServiceProvider},
        Error, Result,
    };
    use crate::{service_provider, store::Store};

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn get_service_provider_exists() -> Result<()> {
        let entity_id = random_string();
        let consume_endpoint = random_string();
        let service_provider = ServiceProvider {
            entity_id: entity_id.clone(),
            consume_endpoint,
            name_id_format: NameIdFormat::EmailAddress as i32,
            base64_keys: vec![],
        };
        let mut encoded_service_provider = BytesMut::new();
        service_provider
            .encode(&mut encoded_service_provider)
            .unwrap();

        let store = memory_store_for_test();
        store
            .db
            .insert(entity_id.as_bytes(), encoded_service_provider.bytes())?;
        let retrieved_service_provider =
            store.get_service_provider(&entity_id).await.unwrap();
        let expected_service_provider: service_provider::ServiceProvider =
            service_provider.into();
        assert_eq!(expected_service_provider, retrieved_service_provider);
        Ok(())
    }

    #[tokio::test]
    async fn get_service_provider_not_exists() -> Result<()> {
        let entity_id = random_string();
        let store = memory_store_for_test();
        let error = store.get_service_provider(&entity_id).await.unwrap_err();
        assert_eq!(error, Error::NotFound(entity_id));
        Ok(())
    }
}
