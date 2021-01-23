use std::{fmt::Debug, str::FromStr};

use samael::metadata::{EntityDescriptor, NameIdFormat};
use warp::{
    http::Response,
    hyper::body::{Buf, Bytes},
    Rejection, Reply,
};

use crate::{error::Error, identity_provider::ensure_idp, store::Store};

#[derive(PartialEq)]
pub struct ServiceProvider {
    /// Entity ID used in the metadata.
    pub entity_id: String,
    /// Name ID format the service provider expects.
    pub name_id_format: String,
    /// Endpoint to send the assertion to. Currently it's assumed to be a HTTP
    /// POST endpoint but future configuration options may allow for more.
    pub consume_endpoint: String,
    /// Keys (certificates) associated with the service provider.
    pub keys: Vec<Vec<u8>>,
}

/// Custom [Debug] impl that prints the [ServiceProvider.keys] in base64.
impl Debug for ServiceProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys_repr: Vec<String> =
            self.keys.iter().map(base64::encode).collect();
        write!(
            f,
            r#"ServiceProvider {{ entity_id: {:?}, name_id_format: {:?}, consume_endpoint: {:?}, keys: {:?} }}"#,
            self.entity_id,
            self.name_id_format,
            self.consume_endpoint,
            keys_repr
        )
    }
}

/// Create the servide provider from the specified attributes and link it to
/// the identity provider identified by `idp_id`.
#[allow(clippy::unit_arg)] // TODO: Figure out what's causing this lint error.
#[tracing::instrument(level = "info", skip(store, certificates), err)]
pub async fn create_service_provider<S: Store + Clone>(
    store: S,
    idp_entity_id: &str,
    sp_entity_id: &str,
    name_id_format: &str,
    consume_endpoint: &str,
    certificates: Vec<&str>,
) -> Result<ServiceProvider, Error> {
    ensure_idp(
        store.clone(),
        idp_entity_id,
        &std::env::var("HOST").unwrap_or_else(|_| "localhost:8080".into()),
    )
    .await?;
    let sp = store
        .upsert_service_provider(ServiceProvider {
            entity_id: sp_entity_id.into(),
            name_id_format: name_id_format.into(),
            consume_endpoint: consume_endpoint.into(),
            keys: certificates
                .iter()
                .map(|cert| cert.as_bytes().to_owned())
                .collect(),
        })
        .await?;
    Ok(sp)
}

fn dig_name_id_format(metadata: &EntityDescriptor) -> Result<String, Error> {
    let descriptors = metadata
        .to_owned()
        .sp_sso_descriptors
        .ok_or_else(|| Error::MissingField("SPSSODescriptor".to_string()))?;
    let descriptor = descriptors
        .first()
        .ok_or_else(|| Error::MissingField("SPSSODescriptor".to_string()))?
        .to_owned();
    let name_id_formats = descriptor
        .name_id_formats
        .or_else(|| {
            Some(vec![NameIdFormat::EmailAddressNameIDFormat
                .value()
                .to_string()])
        })
        .unwrap();
    let default = &NameIdFormat::EmailAddressNameIDFormat.value().to_string();
    let name_id_format = name_id_formats.first().or(Some(default)).unwrap();
    Ok(name_id_format.to_owned())
}

fn dig_consume_endpoint(metadata: &EntityDescriptor) -> Result<String, Error> {
    let descriptors = metadata
        .to_owned()
        .sp_sso_descriptors
        .ok_or_else(|| Error::MissingField("SPSSODescriptor".to_string()))?;
    let descriptor = descriptors
        .first()
        .ok_or_else(|| Error::MissingField("SPSSODescriptor".to_string()))?;
    let asc = descriptor
        .assertion_consumer_services
        .first()
        .ok_or_else(|| {
            Error::MissingField("AssertionConsumerService".to_string())
        })?
        .to_owned();
    // TODO-correctness: Associate the binding as well. At the moment we're just
    // assuming HTTP-POST.
    Ok(asc.location)
}

fn dig_certificate(metadata: &EntityDescriptor) -> Result<String, Error> {
    let descriptors = metadata
        .to_owned()
        .sp_sso_descriptors
        .ok_or_else(|| Error::MissingField("KeyInfo".to_string()))?;
    let descriptor = descriptors
        .first()
        .ok_or_else(|| Error::MissingField("KeyInfo".to_string()))?
        .to_owned();
    let key_descriptors = descriptor
        .key_descriptors
        .ok_or_else(|| Error::MissingField("KeyInfo".to_string()))?;
    let key_descriptor = key_descriptors
        .first()
        .ok_or_else(|| Error::MissingField("KeyInfo".to_string()))?
        .to_owned();
    let cert_data = key_descriptor
        .key_info
        .x509_data
        .ok_or_else(|| Error::MissingField("X509Data".to_string()))?;
    cert_data
        .certificate
        .ok_or_else(|| Error::MissingField("Certificate".to_string()))
}

fn dig_entity_id(metadata: &EntityDescriptor) -> Result<String, Error> {
    metadata
        .to_owned()
        .entity_id
        .ok_or_else(|| Error::MissingField("entityID".to_string()))
}

/// Upsert the servide provider metadata.
///
/// If the SP doesn't alreay exists it is created but if it does, then it is
/// just updated.
#[tracing::instrument(level = "info", skip(store, body))]
pub async fn upsert_sp_metadata<S: Store + Clone>(
    idp_entity_id: &str,
    sp_entity_id: &str,
    store: S,
    body: Bytes,
) -> Result<ServiceProvider, Error> {
    let metadata =
        EntityDescriptor::from_str(std::str::from_utf8(body.bytes())?)?;
    let entity_id = dig_entity_id(&metadata)?;
    assert_eq!(sp_entity_id, entity_id);
    // TODO-correctness: Store all the different name ID formats for the
    // different descriptors.
    let name_id_format = dig_name_id_format(&metadata)?;
    // TODO-correctness: Store all the different consumer service endpoints for
    // the different descriptors.
    let consume_endpoint = dig_consume_endpoint(&metadata)?;
    // TODO-correctness: Retrieve all the keys, not just the first, and store
    // metadata such as "use".
    let b64_sp_cert = dig_certificate(&metadata)?;

    // TODO-correctness: Actually upsert SP.
    let sp = create_service_provider(
        store,
        idp_entity_id,
        sp_entity_id,
        &name_id_format,
        &consume_endpoint,
        vec![&b64_sp_cert],
    )
    .await?;
    Ok(sp)
}

/// Handle upserting service provider metadata.
///
/// This is the handler for the endpoint that handles upserting the service
/// provider metadata and linking it to the identity provider specified by
/// `idp_id`. Currently the IdP must already exist but in the interest of making
/// setup easy, it might be worth looking into ensuring the IdP exists here.
#[tracing::instrument(level = "info", skip(store, body))]
pub async fn upsert_sp_metadata_handler<S: Store + Clone>(
    idp_entity_id: String,
    sp_entity_id: String,
    store: S,
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    match upsert_sp_metadata(&idp_entity_id, &sp_entity_id, store, body).await {
        Ok(_) => Ok(Response::builder().status(201).body("")),
        Err(err @ Error::SamaelEntityDescriptorError(_)) => {
            tracing::warn!("Received invalid XML doc for SP metadata: {}", err);
            Ok(Response::builder().status(400).body(""))
        }
        Err(err @ Error::MissingField(_)) => {
            tracing::warn!("Received SP metadata with missing field: {}", err);
            Ok(Response::builder().status(400).body(""))
        }
        Err(e) => {
            tracing::error!("Upserting SP metadata failed: {}", e);
            Ok(Response::builder().status(500).body(""))
        }
    }
}

#[cfg(test)]
mod test {
    use chrono::{DateTime, Utc};
    use rand::Rng;

    use super::create_service_provider;
    use crate::store::{get_store_for_test, Store};

    #[derive(PartialEq, Debug)]
    struct CreatedAtAndModifiedAt {
        created_at: DateTime<Utc>,
        modified_at: DateTime<Utc>,
    }

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .map(char::from)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn test_creates_sp_if_it_does_not_exist() {
        let store = get_store_for_test();
        let idp_id = random_string();
        let sp_id = random_string();
        let name_id_format =
            samael::metadata::NameIdFormat::EmailAddressNameIDFormat
                .value()
                .to_string();
        let consume_endpoint = random_string();
        let exists = store.service_provider_exists(&sp_id).await.unwrap();
        assert!(!exists);
        create_service_provider(
            store.clone(),
            &idp_id,
            &sp_id,
            &name_id_format,
            &consume_endpoint,
            vec![],
        )
        .await
        .expect("failed to create service provider");
        let exists = store.service_provider_exists(&sp_id).await.unwrap();
        assert!(exists);
    }

    // #[tokio::test]
    // async fn test_updates_sp_if_it_exists() {
    //     let pool = create_db_pool().await;
    //     let idp_id = random_string();
    //     let sp_id = random_string();
    //     let entity_id = random_string();
    //     let name_id_format =
    // samael::metadata::NameIdFormat::EmailAddressNameIDFormat
    //         .value()
    //         .to_string();
    //     let consume_endpoint = random_string();
    //     let db = create_db_pool().await;
    //     create_service_provider(
    //         &pool,
    //         &idp_id,
    //         &sp_id,
    //         &entity_id,
    //         &name_id_format,
    //         &consume_endpoint,
    //         vec![],
    //     )
    //     .await
    //     .expect("failed to create service provider");
    //     let after_creation = sqlx::query_as!(
    //         CreatedAtAndModifiedAt,
    //         "SELECT created_at, modified_at FROM sps WHERE id = $1",
    //         sp_id
    //     )
    //     .fetch_one(&db)
    //     .await
    //     .unwrap();

    //     let entity_id = random_string();
    //     let consume_endpoint = random_string();
    //     create_service_provider(
    //         &pool,
    //         &idp_id,
    //         &sp_id,
    //         &entity_id,
    //         &name_id_format,
    //         &consume_endpoint,
    //         vec![],
    //     )
    //     .await
    //     .expect("failed to create service provider");

    //     let after_updation = sqlx::query_as!(
    //         CreatedAtAndModifiedAt,
    //         "SELECT created_at, modified_at FROM sps WHERE id = $1",
    //         sp_id
    //     )
    //     .fetch_one(&db)
    //     .await
    //     .unwrap();

    //     assert_eq!(after_creation.created_at, after_updation.created_at);
    //     assert!(after_creation.modified_at < after_updation.modified_at);
    // }
}
