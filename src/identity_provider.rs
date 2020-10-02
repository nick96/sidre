use warp::{http::Response, Rejection, Reply};
use sqlx::postgres::{PgPool};
use crate::{templates::{Metadata, NameIDFormat, Template}, x509::generate_cert, error::Error};
use chrono::{DateTime, Utc};
use std::str::FromStr;

struct IdP {
    id: String,
    private_key: Vec<u8>,
    entity_id: String,
    metadata_valid_until: DateTime<Utc>,
    certificate: Vec<u8>,
    name_id_format: String,
    redirect_url: String,
}


async fn ensure_idp(db: &PgPool, id: &str, host: &str) -> Result<IdP, Error> {
    match sqlx::query_as!(IdP, "SELECT * FROM idps WHERE id = $1", id)
        .fetch_one(db)
        .await
    {
        Ok(idp) => Ok(idp),
        Err(sqlx::Error::RowNotFound) => {
            let (certificate, private_key, metadata_valid_until) = generate_cert()?;
            let entity_id = format!("https://{}/{}", host, id);
            let name_id_format = NameIDFormat::EmailAddress;
            let redirect_url = format!("https://{}/{}/sso", host, id);

            sqlx::query!(
                r#"
                INSERT INTO idps(id, certificate, private_key, entity_id, metadata_valid_until, name_id_format, redirect_url)
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7
                )
                "#,
                id, certificate.to_der()?, private_key, entity_id, metadata_valid_until, name_id_format.to_string(), redirect_url
            ).execute(db).await?;

            Ok(IdP {
                id: id.into(),
                private_key,
                certificate: certificate.to_der()?,
                entity_id,
                metadata_valid_until,
                name_id_format: name_id_format.to_string(),
                redirect_url,
            })
        }
        Err(e) => Err(e.into()),
    }
}

pub async fn get_idp_metadata_handler(
    id: String,
    host: String,
    db: PgPool,
) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    match ensure_idp(&db, &id, &host).await {
        Ok(idp) => {
            let metadata = Metadata {
                entity_id: idp.entity_id,
                valid_until: idp.metadata_valid_until,
                certificate: base64::encode(idp.certificate),
                // This has come from the database so we expect it to be valid.
                name_id_format: NameIDFormat::from_str(&idp.name_id_format)
                    .expect("Received invalid name ID from the database"),
                redirect_url: idp.redirect_url,
            };

            Ok(Response::builder()
                .header(warp::http::header::CONTENT_TYPE, "application/xml")
                .body(metadata.render().unwrap()))
        }
        Err(e) => {
            tracing::error!("Failed to generate certificate: {}", e);
            Ok(Response::builder().status(500).body("".into()))
        }
    }
}


