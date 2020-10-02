use crate::{error::Error, templates::NameIDFormat};
use roxmltree::Document;
use sqlx::postgres::PgPool;
use warp::{http::Response, Rejection, Reply};
use std::str::FromStr;
use bytes::{Bytes, Buf};

struct SP {
    id: String,
    entity_id: String,
    name_id_format: String,
    consume_endpoint: String,
    keys: Vec<Vec<u8>>,
}

async fn upsert_sp_metadata(
    idp_id: &str,
    sp_id: &str,
    db: &PgPool,
    body: Bytes,
) -> Result<(), Error> {
    let doc = Document::parse(std::str::from_utf8(body.bytes())?)?;
    let entity_id = doc
        .descendants()
        .find_map(|n| {
            if n.tag_name().name() == "EntityDescriptor" {
                n.attribute("entityID")
            } else {
                None
            }
        })
        .ok_or(Error::MissingField("EntityDescriptor".into()))?;
    let name_id_format = doc
        .descendants()
        .find_map(|n| {
            if n.tag_name().name() == "NameIDFormat" {
                n.text()
            } else {
                None
            }
        })
        .ok_or(Error::MissingField("NameIDFormat".into()))?;

    if let Err(e) = NameIDFormat::from_str(name_id_format) {
        return Err(Error::InvalidField(
            "NameIDFormat".into(),
            name_id_format.into(),
        ));
    }

    let consume_endpoint = doc
        .descendants()
        .find_map(|n| {
            if n.tag_name().name() == "AssertionConsumerService" {
                n.attribute("Location")
            } else {
                None
            }
        })
        .ok_or(Error::MissingField("AssertionConsumerService".into()))?;

    let keys = doc
        .descendants()
        .filter_map(|n| {
            if n.tag_name().name() == "KeyInfo" {
                n.text()
            } else {
                None
            }
        })
        .collect::<Vec<&str>>();

    let mut tx = db.begin().await?;

    sqlx::query!(
        r#"INSERT INTO sps VALUES ($1, $2, $3, $4)"#,
        sp_id,
        entity_id,
        name_id_format,
        consume_endpoint
    )
    .execute(&mut tx)
    .await?;

    for key in keys {
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

pub async fn upsert_sp_metadata_handler(
    idp_id: String,
    sp_id: String,
    db: PgPool,
    body: Bytes,
) -> Result<impl Reply, Rejection> {
    match upsert_sp_metadata(&idp_id, &sp_id, &db, body).await {
        Ok(()) => Ok(Response::builder().status(201).body("")),
        Err(err @ Error::XmlError(_)) => {
            tracing::debug!("Received invalid XML doc for SP metadata: {}", err);
            Ok(Response::builder().status(400).body(""))
        }
        Err(err @ Error::MissingField(_)) => {
            tracing::debug!("Received SP metadata with missing field: {}", err);
            Ok(Response::builder().status(400).body(""))
        }
        Err(err @ Error::InvalidField(_, _)) => {
            tracing::debug!("Received invalid field in SP metadata: {}", err);
            Ok(Response::builder().status(400).body(""))
        }
        Err(e) => {
            tracing::debug!("Upserting SP metadata failed: {}", e);
            Ok(Response::builder().status(500).body(""))
        }
    }
}
