use crate::{
    error::Error,
    templates::{Metadata, NameIDFormat, Template},
    x509::generate_cert,
};
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use std::str::FromStr;
use warp::{http::Response, Rejection, Reply};

pub struct IdP {
    pub id: String,
    pub private_key: Vec<u8>,
    pub entity_id: String,
    pub metadata_valid_until: DateTime<Utc>,
    pub certificate: Vec<u8>,
    pub name_id_format: String,
    pub redirect_url: String,
}

#[tracing::instrument(level = "info", skip(db))]
pub(crate) async fn ensure_idp(db: &PgPool, id: &str, host: &str) -> Result<IdP, Error> {
    match sqlx::query_as!(
        IdP,
        "
        SELECT id
            , private_key
            , entity_id
            , metadata_valid_until
            , certificate
            , name_id_format
            , redirect_url 
            FROM idps WHERE id = $1",
        id
    )
    .fetch_one(db)
    .await
    {
        Ok(idp) => {
            tracing::info!("IdP {} already exists, just returning", id);
            Ok(idp)
        }
        Err(sqlx::Error::RowNotFound) => {
            let (certificate, private_key, metadata_valid_until) = generate_cert()?;
            let entity_id = format!("https://{}/{}", host, id);
            let name_id_format = NameIDFormat::EmailAddress;
            let redirect_url = format!("https://{}/{}/sso", host, id);

            sqlx::query!(
                r#"
                INSERT INTO idps(
                    id
                    , certificate
                    , private_key
                    , entity_id
                    , metadata_valid_until
                    , name_id_format
                    , redirect_url
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7
                )
                "#,
                id,
                certificate.to_der()?,
                private_key,
                entity_id,
                metadata_valid_until,
                name_id_format.to_string(),
                redirect_url
            )
            .execute(db)
            .await?;

            tracing::info!("Created IDP {}", id);

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

#[tracing::instrument(level = "info", skip(db))]
pub async fn get_idp_metadata_handler(
    id: String,
    host: String,
    db: PgPool,
) -> Result<impl Reply, Rejection> {
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::db::create_db_pool;
    use chrono::{DateTime, Utc};
    use rand::Rng;

    #[derive(PartialEq, Debug)]
    struct CreatedAtAndModifiedAt {
        created_at: DateTime<Utc>,
        modified_at: DateTime<Utc>,
    }

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn test_ensure_idp_creates_one_if_it_is_missing() {
        let idp_id = random_string();
        let host = random_string();

        let db = create_db_pool().await;
        let _ = ensure_idp(&db, &idp_id, &host).await.unwrap();
        let exists = sqlx::query!("SELECT EXISTS (SELECT 1 FROM idps WHERE id = $1)", idp_id)
            .fetch_one(&db)
            .await
            .unwrap()
            .exists
            .unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn test_ensure_idp_does_not_create_one_if_it_exists() {
        let idp_id = random_string();
        let host = random_string();

        let db = create_db_pool().await;
        let _ = ensure_idp(&db, &idp_id, &host).await.unwrap();
        let dates = sqlx::query_as!(
            CreatedAtAndModifiedAt,
            "SELECT created_at, modified_at FROM idps WHERE id = $1",
            idp_id
        )
        .fetch_one(&db)
        .await
        .unwrap();

        let _ = ensure_idp(&db, &idp_id, &host).await.unwrap();
        let dates2 = sqlx::query_as!(
            CreatedAtAndModifiedAt,
            "SELECT created_at, modified_at FROM idps WHERE id = $1",
            idp_id
        )
        .fetch_one(&db)
        .await
        .unwrap();

        assert_eq!(dates, dates2);
    }
}
