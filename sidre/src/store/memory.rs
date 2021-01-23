use async_trait::async_trait;
use prost_sled::ProtoDb;

use super::Error;
use crate::store::Result;

pub mod encoding {
    use chrono::TimeZone;
    use samael::metadata;

    use crate::{identity_provider, service_provider};

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

    impl From<identity_provider::IdP> for IdentityProvider {
        fn from(identity_provider: identity_provider::IdP) -> Self {
            let name_id_format: NameIdFormat =
                identity_provider.name_id_format.into();
            Self {
                entity_id: identity_provider.entity_id,
                name_id_format: name_id_format as i32,
                redirect_url: identity_provider.redirect_url,
                base64_certificate: base64::encode(
                    identity_provider.certificate,
                ),
                base64_private_key: base64::encode(
                    identity_provider.private_key,
                ),
                metadata_valid_until: identity_provider
                    .metadata_valid_until
                    .timestamp(),
            }
        }
    }

    impl From<IdentityProvider> for identity_provider::IdP {
        fn from(identity_provider: IdentityProvider) -> Self {
            let naive_metdata_valid_until =
                chrono::NaiveDateTime::from_timestamp(
                    identity_provider.metadata_valid_until,
                    0,
                );
            Self {
                entity_id: identity_provider.entity_id,
                name_id_format: NameIdFormat::from_i32(
                    identity_provider.name_id_format,
                )
                .unwrap()
                .into(),
                redirect_url: identity_provider.redirect_url,
                certificate: base64::decode(
                    identity_provider.base64_certificate,
                )
                .expect("invalid base64 IdP certificate"),
                private_key: base64::decode(
                    identity_provider.base64_private_key,
                )
                .expect("invalid base64 IdP private key"),
                metadata_valid_until: chrono::Utc
                    .from_utc_datetime(&naive_metdata_valid_until),
            }
        }
    }
}

#[derive(Clone)]
pub struct Store {
    db: ProtoDb,
}

#[async_trait]
impl crate::store::Store for Store {
    async fn get_service_provider(
        &self,
        entity_id: &str,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        let sp: encoding::ServiceProvider = self
            .db
            .get(&entity_id)?
            .ok_or_else(|| Error::NotFound(entity_id.to_string()))?;
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
        let proto_service_provider: encoding::ServiceProvider =
            service_provider.into();

        let sp: encoding::ServiceProvider = self
            .db
            .update_and_fetch(
                &proto_service_provider.entity_id,
                |maybe_existing| {
                    if maybe_existing.is_some() {
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
                    Some(proto_service_provider.clone())
                },
            )?
            .ok_or_else(|| {
                crate::store::Error::GenericFailure(
                    "failed to upsert service provider".into(),
                )
            })?;
        Ok(sp.into())
    }

    async fn get_identity_provider(
        &self,
        entity_id: &str,
    ) -> super::Result<crate::identity_provider::IdP> {
        let idp: encoding::IdentityProvider = self
            .db
            .get(entity_id)?
            .ok_or_else(|| Error::NotFound(entity_id.into()))?;
        Ok(idp.into())
    }

    async fn identity_provider_exists(
        &self,
        entity_id: &str,
    ) -> super::Result<bool> {
        let exists = self.db.contains_key(entity_id)?;
        Ok(exists)
    }

    async fn ensure_identity_provider(
        &self,
        identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        let proto_identity_provider: encoding::IdentityProvider =
            identity_provider.into();

        let idp: encoding::IdentityProvider = self
            .db
            .update_and_fetch(
                &proto_identity_provider.entity_id,
                |maybe_existing| {
                    if maybe_existing.is_some() {
                        tracing::info!(
                            "Identity provider with entity ID {} found, \
                             updating",
                            &proto_identity_provider.entity_id
                        );
                    } else {
                        tracing::info!(
                            "No identity provider with entity ID {}, inserting",
                            &proto_identity_provider.entity_id
                        );
                    }
                    Some(proto_identity_provider.clone())
                },
            )?
            .ok_or_else(|| {
                crate::store::Error::GenericFailure(
                    "failed to upsert identity provider".into(),
                )
            })?;
        Ok(idp.into())
    }

    async fn create_service_provider(
        &self,
        service_provider: crate::service_provider::ServiceProvider,
    ) -> super::Result<crate::service_provider::ServiceProvider> {
        let proto_service_provider: encoding::ServiceProvider =
            service_provider.into();
        let _: Option<encoding::ServiceProvider> = self.db.insert(
            &proto_service_provider.entity_id,
            proto_service_provider.clone(),
        )?;
        let inserted_sp: encoding::ServiceProvider = self
            .db
            .get(&proto_service_provider.entity_id)?
            .ok_or_else(|| {
                Error::GenericFailure(
                    "getting previously inserted service provider returned \
                     None"
                        .into(),
                )
            })?;
        Ok(inserted_sp.into())
    }

    async fn create_identity_provider(
        &self,
        identity_provider: crate::identity_provider::IdP,
    ) -> super::Result<crate::identity_provider::IdP> {
        let proto_identity_provider: encoding::IdentityProvider =
            identity_provider.into();
        let _: Option<encoding::IdentityProvider> = self.db.insert(
            &proto_identity_provider.entity_id,
            proto_identity_provider.clone(),
        )?;
        let inserted_idp: encoding::IdentityProvider = self
            .db
            .get(&proto_identity_provider.entity_id)?
            .ok_or_else(|| {
                Error::GenericFailure(
                    "getting previously inserted identity provider returned \
                     None"
                        .into(),
                )
            })?;
        Ok(inserted_idp.into())
    }
}

impl Store {
    pub fn new() -> Result<Self> {
        // Open it in the tmp dir because we want this to be ephemeral.
        let db = prost_sled::open("/tmp/sidre-db")?;
        Ok(Self { db })
    }
}

#[cfg(test)]
pub fn memory_store_for_test() -> Store {
    use std::path::PathBuf;

    fn random_db_path() -> PathBuf {
        let dir = std::env::temp_dir();
        dir.join(uuid::Uuid::new_v4().to_string())
    }

    let db_path = random_db_path();
    Store {
        db: prost_sled::open(&db_path).unwrap_or_else(|_| {
            panic!("failed to open db at {}", db_path.display())
        }),
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use super::{
        encoding::{NameIdFormat, ServiceProvider},
        memory_store_for_test, Error, Result,
    };
    use crate::{service_provider, store::Store};

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .map(char::from)
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

        let store = memory_store_for_test();
        let _: Option<super::encoding::ServiceProvider> = store
            .db
            .insert(entity_id.as_bytes(), service_provider.clone())?;
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
