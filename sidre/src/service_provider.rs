use crate::{error::Error, identity_provider::ensure_idp};
use bytes::{Buf, Bytes};
use samael::metadata::EntityDescriptor;
use sqlx::postgres::PgPool;
use std::str::FromStr;
use warp::{http::Response, Rejection, Reply};

/// Row in the `sps` table.
#[derive(sqlx::FromRow)]
pub struct ServideProviderRow {
    /// ID uniquely identifying the servide provider. This is what is used to
    /// reference the SP in the URL.
    pub id: String,
    /// Entity ID used in the metadata.
    pub entity_id: String,
    /// Name ID format the service provider expects.
    pub name_id_format: String,
    /// Endpoint to send the assertion to. Currently it's assumed to be a HTTP
    /// POST endpoint but future configuration options may allow for more.
    pub consume_endpoint: String,
    /// Keys (certificates) associated with the service provider.
    #[sqlx(default)]
    pub keys: Vec<Vec<u8>>,
}

/// Create the servide provider from the specified attributes and link it to
/// the identity provider identified by `idp_id`.
#[tracing::instrument(level = "info", skip(db, certificates), err)]
async fn create_service_provider(
    db: &PgPool,
    idp_id: &str,
    sp_id: &str,
    entity_id: &str,
    name_id_format: &str,
    consume_endpoint: &str,
    certificates: Vec<&str>,
) -> Result<(), Error> {
    let mut tx = db.begin().await?;
    ensure_idp(
        db,
        idp_id,
        &std::env::var("HOST").unwrap_or_else(|_| "localhost:8080".into()),
    )
    .await?;
    sqlx::query!(
        r#"INSERT INTO sps VALUES ($1, $2, $3, $4)"#,
        sp_id,
        entity_id,
        name_id_format,
        consume_endpoint
    )
    .execute(&mut tx)
    .await?;

    for key in certificates {
        let der_key = base64::decode(key)?;
        sqlx::query!(
            r#"INSERT INTO sp_keys(sp_id, key) VALUES ($1, $2)"#,
            sp_id,
            der_key
        )
        .execute(&mut tx)
        .await?;
    }

    sqlx::query!(
        r#"INSERT INTO idps_x_sps(idp_id, sp_id) VALUES ($1, $2)"#,
        idp_id,
        sp_id
    )
    .execute(&mut tx)
    .await?;

    tx.commit().await?;

    Ok(())
}

fn dig_name_id_format(metadata: &EntityDescriptor) -> Result<String, Error> {
    let descriptors = metadata
        .to_owned()
        .sp_sso_descriptors
        .ok_or_else(|| Error::MissingField("NameIDFormat".to_string()))?;
    let descriptor = descriptors
        .first()
        .ok_or_else(|| Error::MissingField("NameIDFormat".to_string()))?
        .to_owned();
    let name_id_formats = descriptor
        .name_id_formats
        .ok_or_else(|| Error::MissingField("NameIDFormat".to_string()))?;
    let name_id_format = name_id_formats
        .first()
        .ok_or_else(|| Error::MissingField("NameIDFormat".to_string()))?;
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
        .ok_or_else(|| Error::MissingField("AssertionConsumerService".to_string()))?
        .to_owned();
    // TODO-correctness: Associate the binding as well. At the moment we're just assuming HTTP-POST.
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
#[tracing::instrument(level = "info", skip(db, body))]
async fn upsert_sp_metadata(
    idp_id: &str,
    sp_id: &str,
    db: &PgPool,
    body: Bytes,
) -> Result<(), Error> {
    let metadata = EntityDescriptor::from_str(std::str::from_utf8(body.bytes())?)?;
    let entity_id = dig_entity_id(&metadata)?;
    // TODO-correctness: Store all the different name ID formats for the different descriptors.
    let name_id_format = dig_name_id_format(&metadata)?;
    // TODO-correctness: Store all the different consumer service endpoints for the different descriptors.
    let consume_endpoint = dig_consume_endpoint(&metadata)?;
    // TODO-correctness: Retrieve all the keys, not just the first, and store metadata such as "use".
    let b64_sp_cert = dig_certificate(&metadata)?;

    create_service_provider(
        db,
        idp_id,
        sp_id,
        &entity_id,
        &name_id_format,
        &consume_endpoint,
        vec![&b64_sp_cert],
    )
    .await?;

    Ok(())
}

/// Handle upserting service provider metadata.
///
/// This is the handler for the endpoint that handles upserting the service
/// provider metadata and linking it to the identity provider specified by
/// `idp_id`. Currently the IdP must already exist but in the interest of making
/// setup easy, it might be worth looking into ensuring the IdP exists here.
#[tracing::instrument(level = "info", skip(db, body))]
pub async fn upsert_sp_metadata_handler(
    idp_id: String,
    sp_id: String,
    db: PgPool,
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    match upsert_sp_metadata(&idp_id, &sp_id, &db, body).await {
        Ok(()) => Ok(Response::builder().status(201).body("")),
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
