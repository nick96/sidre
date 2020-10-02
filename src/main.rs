mod error;
mod templates;

use chrono::{DateTime, Duration, Utc};
use error::Error;
use flate2::read::DeflateDecoder;
use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::X509};
use roxmltree::Document;
use serde::Deserialize;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::io::prelude::*;
use std::str::FromStr;
use templates::{LoginForm, Metadata, NameIDFormat, Template};
use tracing_subscriber::fmt::format::FmtSpan;
use warp::{http::Response, Filter, Rejection, Reply};
use bytes::{Bytes, Buf};

fn with_db(
    db: PgPool,
) -> impl Filter<Extract = (PgPool,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || db.clone())
}

struct IdP {
    id: String,
    private_key: Vec<u8>,
    entity_id: String,
    metadata_valid_until: DateTime<Utc>,
    certificate: Vec<u8>,
    name_id_format: String,
    redirect_url: String,
}

fn generate_cert() -> Result<(X509, Vec<u8>, DateTime<Utc>), Error> {
    let expiry = Utc::now() + Duration::days(365);
    let rsa = Rsa::generate(4096)?;
    let pk = PKey::from_rsa(rsa.clone())?;

    let mut builder = X509::builder()?;

    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::from_unix(expiry.timestamp())?.as_ref())?;
    builder.set_version(2)?;

    let pub_key = PKey::public_key_from_der(&pk.public_key_to_der()?)?;
    builder.set_pubkey(&pub_key)?;
    builder.sign(&pk, MessageDigest::sha256())?;

    let x509 = builder.build();
    let priv_key = rsa.private_key_to_der()?;
    Ok((x509, priv_key, expiry))
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

async fn get_idp_metadata_handler(
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

struct SP {
    id: String,
    entity_id: String,
    name_id_format: String,
    consume_endpoint: String,
    keys: Vec<Vec<u8>>,
}

async fn upsert_sp_metadata(idp_id: &str, sp_id: &str, db: &PgPool, body: Bytes) -> Result<(), Error> {
    let doc = Document::parse(std::str::from_utf8(body.bytes())?)?;
    let entity_id = doc.descendants().find_map(|n| {
        if n.tag_name().name() == "EntityDescriptor" {
            n.attribute("entityID")
        } else {
            None
        }
    }).ok_or(Error::MissingField("EntityDescriptor".into()))?;
    let name_id_format = doc.descendants().find_map(|n| {
        if n.tag_name().name() == "NameIDFormat" {
            n.text()
        } else {
            None
        }
    }).ok_or(Error::MissingField("NameIDFormat".into()))?;

    if let Err(e) = NameIDFormat::from_str(name_id_format) {
        return Err(Error::InvalidField("NameIDFormat".into(), name_id_format.into()));
    }

    let consume_endpoint = doc.descendants().find_map(|n| {
        if n.tag_name().name() == "AssertionConsumerService" {
            n.attribute("Location")
        } else {
            None
        }
    }).ok_or(Error::MissingField("AssertionConsumerService".into()))?;

    let keys = doc.descendants().filter_map(|n| {
        if n.tag_name().name() == "KeyInfo" {
            n.text()
        } else {
            None
        }
    }).collect::<Vec<&str>>();

    let mut tx = db.begin().await?;

    sqlx::query!(
        r#"INSERT INTO sps VALUES ($1, $2, $3, $4)"#,
        sp_id, entity_id, name_id_format, consume_endpoint
    ).execute(&mut tx).await?;

    for key in keys {
        let der_key = base64::decode(key)?;
        sqlx::query!(r#"INSERT INTO sp_keys(sp_id, key) VALUES ($1, $2)"#, sp_id, der_key).execute(&mut tx).await?;
    }

    sqlx::query!(r#"INSERT INTO idps_x_sps(idp_id, sp_id) VALUES ($1, $2)"#, idp_id, sp_id).execute(&mut tx).await?;

    tx.commit().await?;

    Ok(())
}

async fn upsert_sp_metadata_handler(idp_id: String, sp_id: String, db: PgPool, body: Bytes) -> Result<impl Reply, Rejection> {
    match upsert_sp_metadata(&idp_id, &sp_id, &db, body).await {
        Ok(()) => Ok(Response::builder().status(201).body("")),
        Err(err@Error::XmlError(_)) => {
            tracing::debug!("Received invalid XML doc for SP metadata: {}", err);
            Ok(Response::builder().status(400).body(""))
        },
        Err(err@Error::MissingField(_)) => {
            tracing::debug!("Received SP metadata with missing field: {}", err);
            Ok(Response::builder().status(400).body(""))
        },
        Err(err@Error::InvalidField(_, _)) => {
            tracing::debug!("Received invalid field in SP metadata: {}", err);
            Ok(Response::builder().status(400).body(""))
        }
        Err(e) => {
            tracing::debug!("Upserting SP metadata failed: {}", e);
            Ok(Response::builder().status(500).body(""))
        }
    }
}

async fn run_login(
    id: String,
    saml_request: String,
    relay_state: Option<String>,
) -> Result<String, Error> {
    let deflated_request = base64::decode(saml_request)?;
    let mut deflater = DeflateDecoder::new(&deflated_request[..]);
    let mut buf = String::new();
    deflater.read_to_string(&mut buf)?;

    let doc = Document::parse(&buf)?;
    if !doc.root().has_tag_name("samlp:AuthnRequest") {
        tracing::info!(
            "Expected AuthnRequest document, received {}",
            doc.root().tag_name().name()
        );
        return Err(Error::ExpectedAuthnRequestError);
    }

    Ok(LoginForm {
        sp_consume_endpoint: "".into(),
        saml_response: "".into(),
        relay_state: relay_state,
    }
    .render()?)
}

async fn login_handler(id: String, query: LoginRequestParams) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    match run_login(id, query.saml_request, query.relay_state).await {
        Ok(form) => Ok(Response::builder()
            .status(200)
            .header(warp::http::header::CONTENT_TYPE, "text/html")
            .body(form)),
        Err(e) => {
            tracing::error!("Failed to perform login: {}", e);
            Ok(Response::builder().status(500).body("".into()))
        }
    }
}

async fn config_handler(id: String) -> Result<impl Reply, Rejection> {
    tracing::info!("id={}", id);
    Ok(warp::reply())
}

#[derive(Deserialize)]
struct LoginRequestParams {
    #[serde(rename = "SAMLRequest")]
    saml_request: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

async fn app() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "tracing=info,sider=debug".to_owned());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::CLOSE)
        .try_init();

    let url = std::env::var("DATABASE_URL").expect("No DATABASE_URL environment variable");
    tracing::info!("url={}", url);
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("Failed to create Pg connection pool");

    let idp_metadata = warp::get().and(
        warp::path!(String / "metadata")
            .and(warp::header("Host"))
            .and(with_db(db.clone()))
            .and_then(get_idp_metadata_handler)
            .with(warp::trace::named("get-idp-metadata")),
    );

    let sp_metadata = warp::post().and(
        warp::path!(String / String)
            .and(with_db(db.clone()))
            .and(warp::body::bytes())
            .and_then(upsert_sp_metadata_handler)
            .with(warp::trace::named("upsert-sp-metadata")),
    );

    let login = warp::get().and(
        warp::path!(String / "sso")
            .and(warp::query::<LoginRequestParams>())
            .and_then(login_handler)
            .with(warp::trace::named("login")),
    );

    let config = warp::post().and(
        warp::path!(String / "config")
            .and_then(config_handler)
            .with(warp::trace::named("config")),
    );

    idp_metadata.or(login).or(config).or(sp_metadata)
}

#[tokio::main]
async fn main() {
    warp::serve(app().await).run(([0, 0, 0, 0], 8080)).await;
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    fn random_string() -> String {
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(5)
            .collect()
    }

    #[tokio::test]
    async fn test_metadata_same_idp_id_same_metadata() {
        let idp_id = random_string();
        let filter = app().await;
        let first_resp = warp::test::request()
            .header("Host", "http://localhost:8080")
            .path(&format!("/{}/metadata", idp_id))
            .reply(&filter)
            .await;
        let second_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;

        assert_eq!(first_resp.status(), 200);
        assert_eq!(second_resp.status(), 200);
        assert_eq!(first_resp.body(), second_resp.body());
    }

    #[tokio::test]
    async fn test_metadata_different_idp_different_metadata() {
        let idp_id = random_string();
        let idp2_id = random_string();
        let filter = app().await;
        let first_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;
        let second_resp = warp::test::request()
            .path(&format!("/{}/metadata", idp2_id))
            .header("Host", "http://localhost:8080")
            .reply(&filter)
            .await;

        assert_eq!(first_resp.status(), 200);
        assert_eq!(second_resp.status(), 200);
        assert_ne!(first_resp.body(), second_resp.body());
    }

    #[test]
    fn generate_valid_cert() {
        let (cert, pk, _) = generate_cert().unwrap();
        X509::from_der(&cert.to_der().unwrap()).unwrap();
        let rsa = Rsa::private_key_from_der(&pk).unwrap();
        let _ = PKey::from_rsa(rsa).unwrap();
    }
}
